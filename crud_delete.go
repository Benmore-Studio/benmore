//go:build !cli

package main

// Record deletion and soft-delete cascades.

import (
	"encoding/json"
	"errors"
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
	if !rowIDCanonical(app, table, id) {
		httpError(w, "Not found or not authorized", http.StatusNotFound)
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
	// Record locks bind DELETE exactly as they bind PATCH: a row someone
	// else holds cannot be removed underneath them. An anonymous caller
	// holds no lock, so any lock blocks it. Only a row in the caller's
	// delete scope answers 409; any other is the scoped prefetch's 404, so
	// a lock never confirms that an invisible row exists.
	var lockUID int64
	if session != nil {
		lockUID = session.UserID
	}
	if locked, lockedBy := CheckLock(app.DB, table, id, lockUID); locked && canAccessRowScoped(app, table, id, session, "delete") {
		httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, lockedBy))
		return
	}

	scopeSQL := ""
	var scopeArgs []any
	if pred, pargs, bypass := rowScopeClause(app, table, session, "delete"); !bypass && pred != "" {
		scopeSQL = " AND " + pred
		scopeArgs = append(scopeArgs, pargs...)
	}
	softDelete := hasColumn(app, table, "deleted_at")
	liveSQL := ""
	if softDelete {
		liveSQL = " AND deleted_at IS NULL"
	}

	// The read, before-hooks, delete and audit row share one transaction,
	// so the audit entry can't be lost and hooks judge the row being deleted.
	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" delete", err, "Delete failed")
		return
	}
	defer tx.Rollback()

	// Fetch row before delete (for hooks) - with same scoping as the delete
	prefetchArgs := append([]any{id}, scopeArgs...)
	deletedRows, err := queryNativeRowsWith(tx, app, table, fmt.Sprintf("SELECT * FROM %s WHERE id = ?%s%s", quoteIdent(table), scopeSQL, liveSQL), prefetchArgs...)
	if err != nil {
		serverError(w, r, app, table+" delete", err, "Delete failed")
		return
	}
	if len(deletedRows) == 0 {
		httpError(w, "Not found or not authorized", http.StatusNotFound)
		return
	}
	deletedRow := deletedRows[0]
	if writeMembershipManageDenial(w, membershipDeleteDenial(tx, app, table, session, deletedRow)) {
		return
	}

	// Fire before-hooks (can abort)
	beforeRow := make(map[string]any, len(deletedRow))
	for k, v := range deletedRow {
		beforeRow[k] = v
	}
	injectSessionContext(beforeRow, session)
	if err := fireBeforeHooksWith(tx, app, "delete", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Soft delete: if table has deleted_at column, UPDATE instead of DELETE
	var deleteSQL string
	if softDelete {
		deleteSQL = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id = ?%s AND deleted_at IS NULL", quoteIdent(table), scopeSQL)
	} else {
		deleteSQL = fmt.Sprintf("DELETE FROM %s WHERE id = ?%s", quoteIdent(table), scopeSQL)
	}
	deleteArgs := append([]any{id}, scopeArgs...)

	result, err := tx.Exec(deleteSQL, deleteArgs...)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			httpError(w, fmt.Sprintf("Cannot delete: other records reference this %s. Delete those first.", table), http.StatusConflict)
		} else if respondStorageFull(w, app, err) {
			// A soft delete is an UPDATE and can need a page; a hard delete never does.
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
	if !softDelete {
		if err := purgeRowKeyedState(tx, table, id); err != nil {
			if !respondStorageFull(w, app, err) {
				serverError(w, r, app, table+" delete", err, "Delete failed")
			}
			return
		}
	}
	if err := LogAuditTx(tx, app, "delete", table, id, session, deletedRow, nil); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, table+" delete", err, "Delete failed")
		return
	}
	if err := tx.Commit(); err != nil {
		if !respondStorageFull(w, app, err) {
			serverError(w, r, app, table+" delete", err, "Delete failed")
		}
		return
	}

	// Cascade soft deletes to child tables
	if softDelete {
		cascadeSoftDelete(app, table, deletedRow, session)
	}

	// Fire delete hooks
	injectSessionContext(deletedRow, session)
	FireHooks(app, "delete", table, deletedRow)
	FireFlowsForEvent(app, "on_delete", table, deletedRow)
	FireWebhookSubscriptions(app, "delete", table, deletedRow, session)
	Broadcast(app, table, "delete", session)
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
}

// cascadeSoftDelete soft-deletes the live children of a soft-deleted parent:
// rows of tables that have a foreign key on the parent's id and a deleted_at
// column of their own (convention-based cascading, one level deep).
//
// Each child goes through the ordinary delete pipeline as the caller who
// deleted the parent, so the cascade removes exactly the children that caller
// could have deleted one by one: the child table's delete mode and RBAC scope
// must admit the caller, the row must be in their delete scope
// (rowScopeClause) and not locked by someone else, and before-delete hooks may
// refuse it. A child the caller could not delete stays live. Each deleted
// child gets an audit row, and its after-delete hooks, on_delete flows and
// webhook subscriptions fire as for any delete. Children in another tenant
// than the parent (both tables carry the groups key) are never cascaded, for
// admins too.
//
// It used to be one unscoped UPDATE per child table: other owners' and other
// tenants' rows were deleted with the parent, with no audit row and no hook.
func cascadeSoftDelete(app *App, parentTable string, parent map[string]any, session *Session) {
	parentID, ok := parent["id"]
	if !ok || parentID == nil {
		return
	}
	// Walk the JoinMap to find child tables with FKs pointing at parentTable
	for childTable, fks := range app.joinMapSnapshot() {
		for fkCol, fk := range fks {
			if fk.Table != parentTable || fk.Column != "id" {
				continue
			}
			// Only cascade if the child table also uses soft delete
			if !hasColumn(app, childTable, "deleted_at") || !safeIdent(fkCol) {
				continue
			}
			if !SessionCanAccessTable(app, childTable, OpDelete, session) {
				continue
			}
			if session != nil && checkScope(session, childTable, "delete") != nil {
				continue
			}
			if n, err := cascadeSoftDeleteChildren(app, childTable, fkCol, parentTable, parent, session); err != nil {
				log.Printf("CASCADE SOFT DELETE ERROR [%s.%s → %s]: %s", childTable, fkCol, parentTable, err)
			} else if n > 0 {
				log.Printf("CASCADE SOFT DELETE: %d rows in %s (via %s = %v)", n, childTable, fkCol, parentID)
			}
		}
	}
}

// cascadeSoftDeleteChildren deletes the children of one child table in one
// transaction and fires their post-commit effects. It returns how many rows
// were deleted.
func cascadeSoftDeleteChildren(app *App, childTable, fkCol, parentTable string, parent map[string]any, session *Session) (int, error) {
	query := fmt.Sprintf("SELECT id FROM main.%s WHERE %s = ? AND deleted_at IS NULL", quoteIdent(childTable), quoteColumn(childTable, fkCol))
	args := []any{parent["id"]}
	if g := app.Group; g != nil && g.Key != "" && hasColumn(app, childTable, g.Key) && hasColumn(app, parentTable, g.Key) {
		var parentTenant any
		for col, v := range parent {
			if identIs(col, g.Key) {
				parentTenant = v
			}
		}
		query += fmt.Sprintf(" AND %s IS ?", quoteColumn(childTable, g.Key))
		args = append(args, parentTenant)
	}
	candidates, err := queryNativeRowsWith(app.DB, app, childTable, query, args...)
	if err != nil || len(candidates) == 0 {
		return 0, err
	}
	var lockUID int64
	if session != nil {
		lockUID = session.UserID
	}
	var ids []string
	for _, c := range candidates {
		id := fmt.Sprint(c["id"])
		if locked, _ := CheckLock(app.DB, childTable, id, lockUID); locked {
			continue // held by someone else, as for DELETE /api/<child>/<id>
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	tx, err := app.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var deleted []map[string]any
	for _, id := range ids {
		// A savepoint per child: a before-hook that refuses one row must not
		// leave its own writes behind while the cascade carries on.
		if _, err := tx.Exec("SAVEPOINT benmore_cascade_row"); err != nil {
			return 0, err
		}
		row, err := txDeleteRow(tx, app, childTable, id, session)
		if err == nil {
			err = LogAuditTx(tx, app, "delete", childTable, id, session, row, nil)
		}
		if err != nil {
			var refused *mutationValidationError
			var notManaged *membershipManageError
			if !errors.Is(err, errUpdateTarget) && !errors.As(err, &refused) && !errors.As(err, &notManaged) {
				return 0, err
			}
			// Out of the caller's delete scope, or refused by a before-hook.
			if _, rbErr := tx.Exec("ROLLBACK TO benmore_cascade_row"); rbErr != nil {
				return 0, rbErr
			}
			if _, rbErr := tx.Exec("RELEASE benmore_cascade_row"); rbErr != nil {
				return 0, rbErr
			}
			continue
		}
		if _, err := tx.Exec("RELEASE benmore_cascade_row"); err != nil {
			return 0, err
		}
		deleted = append(deleted, row)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, row := range deleted {
		injectSessionContext(row, session)
		FireHooks(app, "delete", childTable, row)
		FireFlowsForEvent(app, "on_delete", childTable, row)
		FireWebhookSubscriptions(app, "delete", childTable, row, session)
	}
	if len(deleted) > 0 {
		Broadcast(app, childTable, "delete", session)
	}
	return len(deleted), nil
}

// getCascadedChildIDs returns IDs of rows that were just cascade soft-deleted.
func getCascadedChildIDs(app *App, childTable, fkCol, parentID string) []string {
	rows, err := queryNativeRowsWith(app.DB, app, childTable,
		fmt.Sprintf("SELECT id FROM %s WHERE %s = ? AND deleted_at IS NOT NULL", quoteIdent(childTable), quoteColumn(childTable, fkCol)),
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
