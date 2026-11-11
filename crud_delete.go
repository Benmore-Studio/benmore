//go:build !cli

package main

// Record deletion and soft-delete cascades.

import (
	"database/sql"
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
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// SECURITY: enforce scoping on deletes
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, scopeDeniedBody(err))
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
	if err := refuseLastAdminRowDelete(app, tx, table, id); err != nil {
		var refused *mutationValidationError
		if errors.As(err, &refused) {
			httpError(w, refused.Error(), http.StatusConflict)
		} else {
			serverError(w, r, app, table+" delete", err, "Delete failed")
		}
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

	result, err := execVersioned(tx, table, id, session, deleteSQL, deleteArgs...)
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
	// Cascade soft deletes to child tables, in this transaction.
	var cascaded []cascadedDelete
	if softDelete {
		if cascaded, err = cascadeSoftDelete(tx, app, table, deletedRow, session); err != nil {
			if !respondStorageFull(w, app, err) {
				serverError(w, r, app, table+" delete", err, "Delete failed")
			}
			return
		}
	}
	// Hook jobs and webhook deliveries commit with the delete.
	// Subscriptions deliver the row as stored.
	stored := copyRow(deletedRow)
	injectSessionContext(deletedRow, session)
	if err := enqueueRowEffectsTx(tx, app, "delete", table, deletedRow, stored, session); err != nil {
		if !respondStorageFull(w, app, err) {
			serverError(w, r, app, table+" delete", err, "Delete failed")
		}
		return
	}
	if err := tx.Commit(); err != nil {
		if !respondStorageFull(w, app, err) {
			serverError(w, r, app, table+" delete", err, "Delete failed")
		}
		return
	}
	fireCascadedDeleteEvents(app, cascaded, session)
	FireFlowsForEvent(app, "on_delete", table, deletedRow)
	Broadcast(app, table, "delete", session)
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
}

// cascadeSoftDelete soft-deletes the live children of a soft-deleted parent,
// in the parent's own transaction: rows of tables that have a foreign key on
// the parent's id and a deleted_at column of their own (convention-based
// cascading, one level deep).
//
// Each child goes through the ordinary delete pipeline as the caller who
// deleted the parent, so the cascade removes exactly the children that caller
// could have deleted one by one: the child table's delete mode and RBAC scope
// must admit the caller, the row must be in their delete scope
// (rowScopeClause) and not locked by someone else, and before-delete hooks may
// refuse it. A child the caller could not delete stays live. Each deleted
// child gets an audit row and queues its after-delete hook jobs and webhook
// subscriptions in the transaction; the caller fires the returned children's
// on_delete flows and broadcasts after COMMIT, before the parent's (the order
// these effects always had). Children in another tenant than the parent (both
// tables carry the groups key) are never cascaded, for admins too.
//
// It used to be one unscoped UPDATE per child table: other owners' and other
// tenants' rows were deleted with the parent, with no audit row and no hook.
// It then ran in its own transaction after the parent's commit, so a crash or
// a write error between the two left the children live with a deleted parent;
// an error now fails the parent's delete instead.
func cascadeSoftDelete(tx *sql.Tx, app *App, parentTable string, parent map[string]any, session *Session) ([]cascadedDelete, error) {
	parentID, ok := parent["id"]
	if !ok || parentID == nil {
		return nil, nil
	}
	var all []cascadedDelete
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
			deleted, err := cascadeSoftDeleteChildren(tx, app, childTable, fkCol, parentTable, parent, session)
			if err != nil {
				return nil, fmt.Errorf("cascade soft delete %s.%s -> %s: %w", childTable, fkCol, parentTable, err)
			}
			if len(deleted) > 0 {
				log.Printf("CASCADE SOFT DELETE: %d rows in %s (via %s = %v)", len(deleted), childTable, fkCol, parentID)
			}
			all = append(all, deleted...)
		}
	}
	return all, nil
}

// cascadedDelete is a child row the cascade deleted, with the session context
// its on_delete flows read.
type cascadedDelete struct {
	table string
	row   map[string]any
}

// fireCascadedDeleteEvents runs a committed cascade's post-commit effects:
// each child's on_delete flows, then one broadcast per child table.
func fireCascadedDeleteEvents(app *App, deleted []cascadedDelete, session *Session) {
	var tables []string
	seen := map[string]bool{}
	for _, c := range deleted {
		FireFlowsForEvent(app, "on_delete", c.table, c.row)
		if !seen[c.table] {
			seen[c.table] = true
			tables = append(tables, c.table)
		}
	}
	for _, t := range tables {
		Broadcast(app, t, "delete", session)
	}
}

// cascadeSoftDeleteChildren deletes the children of one child table in tx and
// queues their hook jobs and webhook deliveries there.
func cascadeSoftDeleteChildren(tx *sql.Tx, app *App, childTable, fkCol, parentTable string, parent map[string]any, session *Session) ([]cascadedDelete, error) {
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
	candidates, err := queryNativeRowsWith(tx, app, childTable, query, args...)
	if err != nil || len(candidates) == 0 {
		return nil, err
	}
	var lockUID int64
	if session != nil {
		lockUID = session.UserID
	}
	var deleted []cascadedDelete
	for _, c := range candidates {
		id := valueText(c["id"])
		// Held by someone else, as for DELETE /api/<child>/<id>. Read in tx
		// (CheckLock writes through the pool and would wait on this
		// transaction); an expired lock does not count.
		var holder int64
		lockErr := tx.QueryRow(`SELECT user_id FROM main._benmore_locks WHERE table_name = ? AND row_id = ? AND datetime(expires_at) >= datetime('now')`, childTable, id).Scan(&holder)
		if lockErr == nil && holder != lockUID {
			continue
		}
		if lockErr != nil && !errors.Is(lockErr, sql.ErrNoRows) {
			return nil, lockErr
		}
		// A savepoint per child: a before-hook that refuses one row must not
		// leave its own writes (or its queued effects) behind while the
		// cascade carries on.
		if _, err := tx.Exec("SAVEPOINT benmore_cascade_row"); err != nil {
			return nil, err
		}
		row, err := txDeleteRow(tx, app, childTable, id, session)
		if err == nil {
			err = LogAuditTx(tx, app, "delete", childTable, id, session, row, nil)
		}
		if err != nil {
			var refused *mutationValidationError
			var notManaged *membershipManageError
			if !errors.Is(err, errUpdateTarget) && !errors.As(err, &refused) && !errors.As(err, &notManaged) {
				return nil, err
			}
			// Out of the caller's delete scope, or refused by a before-hook.
			if _, rbErr := tx.Exec("ROLLBACK TO benmore_cascade_row"); rbErr != nil {
				return nil, rbErr
			}
			if _, rbErr := tx.Exec("RELEASE benmore_cascade_row"); rbErr != nil {
				return nil, rbErr
			}
			continue
		}
		stored := copyRow(row)
		injectSessionContext(row, session)
		if err := enqueueRowEffectsTx(tx, app, "delete", childTable, row, stored, session); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("RELEASE benmore_cascade_row"); err != nil {
			return nil, err
		}
		deleted = append(deleted, cascadedDelete{table: childTable, row: row})
	}
	return deleted, nil
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
			ids = append(ids, valueText(id))
		}
	}
	return ids
}
