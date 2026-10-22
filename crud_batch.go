//go:build !cli

package main

// Batch record creation, updates, and deletion.
//
// Every item goes through the same per-row pipeline /api/_transaction uses
// (txInsertWithPlan, applyCanonicalUpdateTx, txDeleteRow) inside ONE
// transaction, so a batch enforces exactly what the single-row endpoints
// enforce: validators, before-hooks on the merged row, protected and computed
// columns, foreign-key visibility, record locks, and audit rows that commit
// with the data. All-or-nothing: a refused item rolls the whole batch back.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func handleBatchCreate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row create (M5, 2026-06-11
	// audit): before this, `access: write: admin` / `all: off` tables
	// were writable through /batch.
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	var items []map[string]any
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&items); err != nil {
		httpError(w, "Expected JSON array", http.StatusBadRequest)
		return
	}
	if len(items) == 0 {
		httpError(w, "Empty array", http.StatusBadRequest)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	// Command-owned columns: refuse the whole batch before the transaction opens.
	ownedCheck := ownedFieldChecker(app, table)
	for _, item := range items {
		if v := ownedCheck(mapKeys(item)...); v != nil {
			writeOwnedFieldRefusal(w, v)
			return
		}
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" batch create", err, "Server error")
		return
	}
	defer tx.Rollback()

	plan, err := newInsertPlan(tx, app, table)
	if err != nil {
		serverError(w, r, app, table+" batch create", err, "Server error")
		return
	}

	var ids []any
	var created []map[string]any
	for _, item := range items {
		// member-of: every batch item must land in a parent the caller is
		// a member of - same gate as single-row create (M5). All-or-
		// nothing: one bad item rolls the whole batch back.
		if d := memberOfCreateDenialWith(tx, app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			writeMemberOfDenial(w, r, d)
			return
		}

		data := prepareJSONCreateData(item, plan.schemaCols)
		id, err := txInsertWithPlan(tx, app, table, data, session, plan)
		if errors.Is(err, errNoValidFields) {
			continue // an item naming no writable column is skipped, as before
		}
		if err != nil {
			if respondOwnedField(w, err) || respondStorageFull(w, app, err) {
				return
			}
			status, msg := mutationErrorResponse(app, "batch insert "+table, err)
			if status == http.StatusBadRequest {
				msg = "Batch insert failed: " + msg
			}
			httpJSON(w, status, map[string]any{"error": msg})
			return
		}
		rows, err := queryNativeRowsWith(tx, app, table, "SELECT * FROM "+quoteIdent(table)+" WHERE id = ?", id)
		if err != nil || len(rows) != 1 {
			if err == nil {
				err = fmt.Errorf("inserted row %v read back %d rows", id, len(rows))
			}
			serverError(w, r, app, table+" batch create", err, "Batch insert failed: could not read inserted row")
			return
		}
		if err := LogAuditTx(tx, app, "create", table, fmt.Sprintf("%v", id), session, nil, rows[0]); err != nil {
			if respondStorageFull(w, app, err) {
				return
			}
			serverError(w, r, app, table+" batch create", err, "Batch insert failed: audit write failed")
			return
		}
		ids = append(ids, id)
		created = append(created, rows[0])
	}

	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, table+" batch create", err, "Commit failed")
		return
	}

	// After-hooks, flows and webhooks run after commit (hooks write through
	// the pool and would deadlock against the open transaction), per row
	// exactly as the single-row create fires them.
	for _, row := range created {
		injectSessionContext(row, session)
		FireHooks(app, "insert", table, row)
		FireFlowsForEvent(app, "on_insert", table, row)
		FireWebhookSubscriptions(app, "insert", table, row, session)
	}

	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ids": ids, "count": len(ids), "status": "created"})
}

// batchLockedBy reports the first of ids that a record lock held by someone
// else covers. Same rule as PATCH and /api/_transaction; an anonymous caller
// holds no lock, so any lock blocks it. Only rows in the caller's aclAction
// scope count: the rest are skipped as not found, so a lock never confirms
// that an invisible row exists.
func batchLockedBy(app *App, table string, ids []any, session *Session, aclAction string) (bool, string) {
	var uid int64
	if session != nil {
		uid = session.UserID
	}
	for _, id := range ids {
		if locked, by := CheckLock(app.DB, table, fmt.Sprint(id), uid); locked && canAccessRowScoped(app, table, fmt.Sprint(id), session, aclAction) {
			return true, by
		}
	}
	return false, ""
}

func handleBatchUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row update (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs    []any          `json:"ids"`
		Fields map[string]any `json:"fields"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids and fields", http.StatusBadRequest)
		return
	}
	for i, id := range body.IDs {
		body.IDs[i] = canonicalJSONNumberID(id)
	}
	if len(body.IDs) == 0 || len(body.Fields) == 0 {
		httpError(w, "ids and fields required", http.StatusBadRequest)
		return
	}
	if v := ownedFieldViolation(app, table, mapKeys(body.Fields)...); v != nil {
		writeOwnedFieldRefusal(w, v)
		return
	}

	// Refuse up front when nothing submitted is a writable column (the
	// canonical pipeline would otherwise skip every row as not found).
	cols, _ := GetTableColumns(app.DB, table)
	protected := protectedFields(protectedUpdateFields(app, table))
	writable := false
	for _, c := range cols {
		if _, ok := body.Fields[c.Name]; ok && !protected.has(c.Name) {
			writable = true
			break
		}
	}
	if !writable {
		httpError(w, "No valid fields", http.StatusBadRequest)
		return
	}

	if locked, by := batchLockedBy(app, table, body.IDs, session, "edit"); locked {
		httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, by))
		return
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" batch update", err, "Server error")
		return
	}
	defer tx.Rollback()

	type updated struct{ before, after map[string]any }
	var done []updated
	var refreshTables []string
	schemaCols := prismaWriteColumns(app, table)
	for _, rawID := range body.IDs {
		values := make(map[string]any, len(body.Fields))
		for k, v := range body.Fields {
			if _, declared := schemaCols[k]; declared {
				values[k] = v
			} else {
				values[k] = jsonToUpdateValue(v)
			}
		}
		// The canonical one-row pipeline: scoped edit read, member-of
		// re-point gate, validators and before-hooks on the current row
		// merged with the change, protected/computed/workflow columns,
		// foreign-key visibility, after-hooks, webhooks and audit - all
		// on this transaction.
		before, after, refresh, err := applyCanonicalUpdateTx(tx, app, session, table, fmt.Sprint(rawID), values, "")
		if err != nil {
			var requestErr *updateRequestError
			if errors.As(err, &requestErr) && (requestErr.noopEcho || errors.Is(err, errUpdateTarget)) {
				// Rows the caller may not edit (or that don't exist) are
				// skipped, as the scoped UPDATE always did.
				continue
			}
			if respondOwnedField(w, err) {
				return
			}
			var denied *memberOfUpdateError
			if errors.As(err, &denied) {
				writeMemberOfDenial(w, r, denied.denial)
				return
			}
			if respondStorageFull(w, app, err) {
				return
			}
			if errors.As(err, &requestErr) {
				writeUpdateRequestError(w, r, app, table+" batch update", requestErr)
				return
			}
			if respondDatabaseBusy(w, err) {
				return
			}
			httpError(w, "Batch update failed: "+publicConstraintMessage(app, "batch update "+table, err), http.StatusBadRequest)
			return
		}
		done = append(done, updated{before: before, after: after})
		refreshTables = append(refreshTables, refresh...)
	}

	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, table+" batch update", err, "Commit failed")
		return
	}

	// After-hooks and webhooks already ran inside the transaction; flows
	// fire after commit, as for a single PATCH.
	for _, u := range done {
		eventRow := make(map[string]any, len(u.after)+len(u.before))
		for k, v := range u.after {
			eventRow[k] = v
		}
		for k, v := range u.before {
			eventRow["old_"+k] = v
		}
		injectSessionContext(eventRow, session)
		FireFlowsForEvent(app, "on_update", table, eventRow)
	}

	Broadcast(app, table, "update", session)
	broadcastHookRefreshes(app, refreshTables, []transactionResult{{Table: table, Action: "update"}})
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"updated": int64(len(done)), "status": "updated"})
}

func handleBatchDelete(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row delete (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpDelete, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs []any `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		httpError(w, "ids required", http.StatusBadRequest)
		return
	}

	if locked, by := batchLockedBy(app, table, body.IDs, session, "delete"); locked {
		httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, by))
		return
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" batch delete", err, "Server error")
		return
	}
	defer tx.Rollback()

	// Hooks, cascades, flows, webhooks and audit only ever see rows this
	// caller may delete: txDeleteRow reads each row with the delete scope.
	var deleted []map[string]any
	for _, rawID := range body.IDs {
		idStr := fmt.Sprint(rawID)
		row, err := txDeleteRow(tx, app, table, idStr, session)
		if errors.Is(err, errUpdateTarget) {
			continue
		}
		if err != nil {
			var validationErr *mutationValidationError
			switch {
			case writeMembershipManageDenial(w, err):
			case errors.As(err, &validationErr):
				httpError(w, validationErr.Error(), http.StatusUnprocessableEntity)
			case strings.Contains(err.Error(), "FOREIGN KEY"):
				httpError(w, fmt.Sprintf("Cannot delete: other records reference this %s. Delete those first.", table), http.StatusConflict)
			case respondStorageFull(w, app, err):
			case respondDatabaseBusy(w, err):
			default:
				httpError(w, "Batch delete failed: "+publicConstraintMessage(app, "batch delete "+table, err), http.StatusBadRequest)
			}
			return
		}
		if err := LogAuditTx(tx, app, "delete", table, idStr, session, row, nil); err != nil {
			if respondStorageFull(w, app, err) {
				return
			}
			serverError(w, r, app, table+" batch delete", err, "Batch delete failed: audit write failed")
			return
		}
		deleted = append(deleted, row)
	}

	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, table+" batch delete", err, "Commit failed")
		return
	}

	// Cascade soft deletes for each deleted row
	if hasColumn(app, table, "deleted_at") {
		for _, row := range deleted {
			cascadeSoftDelete(app, table, row, session)
		}
	}

	// Fire after-hooks per row
	for _, row := range deleted {
		injectSessionContext(row, session)
		FireHooks(app, "delete", table, row)
		FireFlowsForEvent(app, "on_delete", table, row)
		FireWebhookSubscriptions(app, "delete", table, row, session)
	}

	Broadcast(app, table, "delete", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted": int64(len(deleted)), "status": "deleted"})
}
