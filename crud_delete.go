//go:build !cli

package main

// Record deletion and soft-delete cascades.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func handleDelete(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Coarse access gate (v2.7.12). `delete: admin` blocks non-admins
	// before the row lookup. Per-row scoping still applies for self/group.
	if !EnforceCRUDAccess(w, r, app, table, OpDelete, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// CSRF validation - HX-Request header is trivially forgeable, never bypass CSRF for it
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// SECURITY: enforce scoping on deletes
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	scopeSQL := ""
	var scopeArgs []any
	if pred, pargs, bypass := rowScopeClause(app, table, session, "delete"); !bypass && pred != "" {
		scopeSQL = " AND " + pred
		scopeArgs = append(scopeArgs, pargs...)
	}

	// Fetch row before delete (for hooks) - with same scoping as the delete
	prefetchArgs := append([]any{id}, scopeArgs...)
	deletedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?%s", table, scopeSQL), prefetchArgs...)

	// Fire before-hooks (can abort)
	if len(deletedRows) > 0 {
		beforeRow := deletedRows[0]
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "delete", table, beforeRow); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Soft delete: if table has deleted_at column, UPDATE instead of DELETE
	var deleteSQL string
	if hasColumn(app, table, "deleted_at") {
		deleteSQL = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id = ?%s AND deleted_at IS NULL", table, scopeSQL)
	} else {
		deleteSQL = fmt.Sprintf("DELETE FROM %s WHERE id = ?%s", table, scopeSQL)
	}
	deleteArgs := append([]any{id}, scopeArgs...)

	result, err := app.DB.Exec(deleteSQL, deleteArgs...)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			httpError(w, fmt.Sprintf("Cannot delete: other records reference this %s. Delete those first.", table), http.StatusConflict)
		} else {
			httpError(w, "Delete failed", http.StatusBadRequest)
		}
		return
	}
	// Check if anything was actually deleted (owner scoping may prevent it)
	rows, _ := result.RowsAffected()
	if rows == 0 {
		httpError(w, "Not found or not authorized", http.StatusNotFound)
		return
	}

	// Cascade soft deletes to child tables
	if hasColumn(app, table, "deleted_at") {
		cascadeSoftDelete(app, table, id)
	}

	// Fire delete hooks
	if len(deletedRows) > 0 {
		injectSessionContext(deletedRows[0], session)
		FireHooks(app, "delete", table, deletedRows[0])
		FireFlowsForEvent(app, "on_delete", table, deletedRows[0])
		FireWebhookSubscriptions(app, "delete", table, deletedRows[0], session)
		Broadcast(app, table, "delete", session)
		LogAudit(app, "delete", table, id, session, deletedRows[0], nil)
	}
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
}

// cascadeSoftDelete soft-deletes child rows in tables that have foreign keys
// pointing to the deleted parent. Only affects child tables that also have
// a deleted_at column (convention-based cascading).
func cascadeSoftDelete(app *App, parentTable string, parentID string) {
	// Walk the JoinMap to find child tables with FKs pointing at parentTable
	for childTable, fks := range app.JoinMap {
		for fkCol, fk := range fks {
			if fk.Table != parentTable || fk.Column != "id" {
				continue
			}
			// Only cascade if the child table also uses soft delete
			if !hasColumn(app, childTable, "deleted_at") {
				continue
			}
			result, err := app.DB.Exec(
				fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE %s = ? AND deleted_at IS NULL", childTable, fkCol),
				parentID,
			)
			if err != nil {
				log.Printf("CASCADE SOFT DELETE ERROR [%s.%s → %s]: %s", childTable, fkCol, parentTable, err)
			} else {
				affected, _ := result.RowsAffected()
				if affected > 0 {
					log.Printf("CASCADE SOFT DELETE: %d rows in %s (via %s = %s)", affected, childTable, fkCol, parentID)
					BroadcastUnscoped(app, childTable, "delete")
				}
			}
		}
	}
}

// getCascadedChildIDs returns IDs of rows that were just cascade soft-deleted.
func getCascadedChildIDs(app *App, childTable, fkCol, parentID string) []string {
	rows, err := QueryRows(app.DB,
		fmt.Sprintf("SELECT id FROM %s WHERE %s = ? AND deleted_at IS NOT NULL", childTable, fkCol),
		parentID)
	if err != nil {
		return nil
	}
	var ids []string
	for _, row := range rows {
		if id, ok := row["id"]; ok {
			ids = append(ids, fmt.Sprintf("%v", id))
		}
	}
	return ids
}
