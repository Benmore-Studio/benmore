//go:build !cli

package main

// Record updates and per-user singleton updates.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func handleUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Coarse access gate (v2.7.12). `update: admin` blocks non-admins
	// before we even look at the row. The existing owner-WHERE on the
	// UPDATE statement still enforces per-row in `self`/`group` modes.
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
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

	// Record lock check - reject if locked by another user
	if lockSession := getSession(app, r); lockSession != nil {
		if locked, lockedBy := CheckLock(app.DB, table, id, lockSession.UserID); locked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			resp := lockErrorResponse(app.DevMode, lockedBy)
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		httpError(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Accept both form values and JSON body
	fields := getUpdateFields(r)

	// Build allowlist of valid column names for this table
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	// Protected fields - never accept from user input
	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true, "_csrf": true,
		"password_change_required": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// H-10: the configurable in-tenant RoleField (e.g. member_role) must be
	// protected on the membership table, otherwise a tenant member could
	// PATCH their own membership row to elevate their role. The hard-coded
	// "role" above only covers the default column name; RoleField may differ.
	// invariant: a member must never self-set their in-tenant role via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
	}
	// Block workflow-controlled fields (must use transition API)
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	var sets []string
	var values []any
	for k, v := range fields {
		// SECURITY: only allow known column names, block protected fields
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}

	if len(sets) == 0 {
		httpError(w, "No fields to update", http.StatusBadRequest)
		return
	}

	// Fire before-hooks (can abort)
	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	// member-of: re-pointing a child row's join column (PATCHing a
	// message's room_id to a different room) must verify membership in
	// the NEW parent - the row-scope WHERE only proves membership in
	// the row's CURRENT parent. 404 so the target's existence doesn't
	// leak to non-members. (Shared with batch update via
	// memberOfRepointDenial.)
	if d := memberOfRepointDenial(app, table, session, func(col string) string { return fields[col] }); d != nil {
		writeMemberOfDenial(w, r, d)
		return
	}

	beforeRow := make(map[string]any)
	beforeRow["id"] = id
	for k, v := range fields {
		beforeRow[k] = v
	}
	injectSessionContext(beforeRow, session)
	// Cross-field validators on update - check rules against the MERGED data
	// (existing row + submitted changes)
	if err := ValidateCrossField(app.Validators, table, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := FireBeforeHooks(app, "update", table, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Capture old row for audit log before updating - with same scoping as the UPDATE
	oldScopeSQL := ""
	var oldScopeArgs []any
	if pred, pargs, bypass := rowScopeClause(app, table, session, "edit"); !bypass && pred != "" {
		oldScopeSQL = " AND " + pred
		oldScopeArgs = append(oldScopeArgs, pargs...)
	}
	prefetchArgs := append([]any{id}, oldScopeArgs...)
	oldRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?%s", table, oldScopeSQL), prefetchArgs...)

	// Auto-set updated_at if column exists
	if hasColumn(app, table, "updated_at") && !protected["updated_at"] {
		// updated_at is protected from user input but we set it here
		sets = append(sets, "updated_at = datetime('now')")
	}

	values = append(values, id)
	sql := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", "))

	// Soft delete filter: cannot update deleted records
	if hasColumn(app, table, "deleted_at") {
		sql += " AND deleted_at IS NULL"
	}

	// Optimistic concurrency: if client sends _expected_updated_at, enforce it
	if expected := r.FormValue("_expected_updated_at"); expected != "" && hasColumn(app, table, "updated_at") {
		sql += " AND updated_at = ?"
		values = append(values, expected)
	}

	// SECURITY: enforce scoping on updates (owner/org OR explicit ACL edit grant)
	if pred, pargs, bypass := rowScopeClause(app, table, session, "edit"); !bypass && pred != "" {
		sql += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := app.DB.Exec(sql, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Update failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	// Check rows affected for optimistic concurrency conflict
	affected, _ := result.RowsAffected()
	if affected == 0 {
		// Could be scoping (not authorized) or concurrency conflict
		if r.FormValue("_expected_updated_at") != "" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{"error": "conflict", "message": "Record was modified by another user"})
			return
		}
		httpError(w, "Not found or not authorized", http.StatusNotFound)
		return
	}

	// Fire update hooks - fetch the updated row for context
	updatedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table), id)
	if len(updatedRows) > 0 {
		injectSessionContext(updatedRows[0], session)
		// Inject old_* fields so hooks can reference previous values: {{old_status}}, {{old_amount}}
		if len(oldRows) > 0 {
			for k, v := range oldRows[0] {
				updatedRows[0]["old_"+k] = v
			}
		}
		FireHooks(app, "update", table, updatedRows[0])
		FireFlowsForEvent(app, "on_update", table, updatedRows[0])
		FireWebhookSubscriptions(app, "update", table, updatedRows[0], session)
		Broadcast(app, table, "update", session)
	}
	var oldRow map[string]any
	if len(oldRows) > 0 {
		oldRow = oldRows[0]
	}
	var newRow map[string]any
	if len(updatedRows) > 0 {
		newRow = updatedRows[0]
	}
	LogAudit(app, "update", table, id, session, oldRow, newRow)
	appendHXTrigger(w, "benmore:changed")

	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
}

// tableHasUniqueUserID reports whether `table` has a single-column UNIQUE
// constraint on user_id (a "one row per user" singleton). Used to gate the
// PATCH /api/{table} (no ID) upsert route.
func tableHasUniqueUserID(db *sql.DB, table string) bool {
	rows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	type idx struct {
		name   string
		unique bool
	}
	var indexes []idx
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin sql.NullString
		var partial sql.NullInt64
		// SQLite returns: seq, name, unique, origin, partial
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			continue
		}
		if unique == 1 {
			indexes = append(indexes, idx{name: name, unique: true})
		}
	}
	for _, ix := range indexes {
		colRows, err := db.Query(fmt.Sprintf("PRAGMA index_info(%s)", ix.name))
		if err != nil {
			continue
		}
		var cols []string
		for colRows.Next() {
			var seqno, cid int
			var cname string
			if err := colRows.Scan(&seqno, &cid, &cname); err != nil {
				continue
			}
			cols = append(cols, cname)
		}
		colRows.Close()
		if len(cols) == 1 && cols[0] == "user_id" {
			return true
		}
	}
	return false
}

// handleSingletonUpdate implements the upsert-by-user_id pattern used by
// profile/settings pages: PATCH /api/{table} with no ID resolves the current
// user's row (or creates it) and applies the patched fields.
//
// Requires the table to have a UNIQUE(user_id) constraint - otherwise the
// route is meaningless and we return a helpful 400 telling the developer how
// to enable it.
// handleSingletonUpdate has no EnforceCRUDAccess call of its own ON
// PURPOSE: it dispatches to handleUpdate (existing row) or handleCreate
// (first write), and each runs the gate for its actual op (OpUpdate vs
// OpWrite). Gating OpUpdate here would wrongly reject the create branch
// on tables whose update mode is stricter than write. The only ungated
// work before dispatch is a row-existence lookup whose result is never
// returned to the caller.
func handleSingletonUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	session := getSession(app, r)
	if session == nil {
		httpError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	if !hasColumn(app, table, "user_id") {
		httpError(w, fmt.Sprintf("PATCH /api/%s requires a user_id column. Add user_id Int @unique to the model, or PATCH /api/%s/{id} with a specific row ID.", table, table), http.StatusBadRequest)
		return
	}
	if !tableHasUniqueUserID(app.DB, table) {
		httpError(w, fmt.Sprintf("PATCH /api/%s (singleton upsert) requires UNIQUE(user_id). Add @unique to user_id in the model, or PATCH /api/%s/{id} with a specific row ID.", table, table), http.StatusBadRequest)
		return
	}

	// Look up the existing row by user_id. If it exists, dispatch through
	// the normal update path (so all hooks/audit/scoping run). If not, fall
	// through to handleCreate so the row is materialized with user_id set
	// from the session.
	var existingID sql.NullString
	row := app.DB.QueryRow(fmt.Sprintf("SELECT CAST(id AS TEXT) FROM %s WHERE user_id = ? LIMIT 1", table), session.UserID)
	_ = row.Scan(&existingID)

	if existingID.Valid && existingID.String != "" {
		// Rewrite path to /api/{table}/{id} so handleUpdate can extract it.
		r.URL.Path = fmt.Sprintf("/api/%s/%s", table, existingID.String)
		handleUpdate(w, r, app, table)
		return
	}

	// No existing row - let handleCreate auto-inject user_id from session.
	handleCreate(w, r, app, table)
}
