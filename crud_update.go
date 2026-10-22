//go:build !cli

package main

// Record updates and per-user singleton updates.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func handleUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
		return
	}
	id := extractID(r.URL.Path, table)
	if id == "" {
		httpError(w, "Missing ID", http.StatusBadRequest)
		return
	}
	if !rowIDCanonical(app, table, id) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": errUpdateTarget.Error()})
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	session := getSession(app, r)
	if session != nil {
		// A lock answers 409 only on a row the caller may edit; any other
		// row is the scoped update's 404, never a confirmation it exists.
		if locked, lockedBy := CheckLock(app.DB, table, id, session.UserID); locked && canAccessRowScoped(app, table, id, session, "edit") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(lockErrorResponse(app.DevMode, lockedBy))
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		httpError(w, "Bad request", http.StatusBadRequest)
		return
	}
	fields := getUpdateFields(r, app, table)
	expected := ""
	if value := fields["_expected_updated_at"]; value != nil {
		expected = jsonToFormValue(value)
	}
	if expected == "" {
		expected = r.FormValue("_expected_updated_at")
	}
	delete(fields, "_expected_updated_at")
	values := make(map[string]any, len(fields))
	for key, value := range fields {
		values[key] = value
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, table+" update", err, "Transaction start failed")
		return
	}
	defer tx.Rollback()
	before, after, refreshTables, err := applyCanonicalUpdateTx(tx, app, session, table, id, values, expected)
	if err != nil {
		if respondOwnedField(w, err) {
			return
		}
		var denied *memberOfUpdateError
		if errors.As(err, &denied) {
			writeMemberOfDenial(w, r, denied.denial)
			return
		}
		if errors.Is(err, errUpdateConflict) {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "conflict", "message": "Record was modified by another user"})
			return
		}
		if respondStorageFull(w, app, err) {
			return
		}
		var requestErr *updateRequestError
		if errors.As(err, &requestErr) && requestErr.noopEcho {
			// Only unchanged command-owned values were submitted: nothing to write.
			httpJSON(w, http.StatusOK, map[string]any{"status": "updated"})
			return
		}
		if errors.As(err, &requestErr) {
			writeUpdateRequestError(w, r, app, table+" update", requestErr)
		} else {
			serverErrorJSON(w, r, app, table+" update", err, "Update failed")
		}
		return
	}
	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, table+" update", err, "Commit failed")
		return
	}

	eventRow := make(map[string]any, len(after)+len(before))
	for k, v := range after {
		eventRow[k] = v
	}
	for k, v := range before {
		eventRow["old_"+k] = v
	}
	injectSessionContext(eventRow, session)
	FireFlowsForEvent(app, "on_update", table, eventRow)
	Broadcast(app, table, "update", session)
	broadcastHookRefreshes(app, refreshTables, []transactionResult{{Table: table, Action: "update"}})
	appendHXTrigger(w, "benmore:changed")
	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "updated"})
}

// tableHasUniqueUserID reports whether `table` has a single-column UNIQUE
// constraint on user_id (a "one row per user" singleton). Used to gate the
// PATCH /api/{table} (no ID) upsert route.
func tableHasUniqueUserID(db *sql.DB, table string) bool {
	rows, err := db.Query("PRAGMA index_list(" + quoteIdent(table) + ")")
	if err != nil {
		return false
	}
	defer rows.Close()

	var indexes []string
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin sql.NullString
		var partial sql.NullInt64
		// SQLite returns: seq, name, unique, origin, partial
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false
		}
		// A partial unique index only constrains rows matching its WHERE;
		// it cannot establish a global one-row-per-user invariant.
		if unique == 1 && partial.Valid && partial.Int64 == 0 {
			indexes = append(indexes, name)
		}
	}
	if rows.Err() != nil {
		return false
	}
	for _, name := range indexes {
		// An index is named by whoever created it; the name is not a plain
		// identifier by any rule.
		colRows, err := db.Query("PRAGMA index_info(" + quoteIdent(name) + ")")
		if err != nil {
			continue
		}
		var columns int
		var onlyUserID bool
		valid := true
		for colRows.Next() {
			var seqno, cid int
			var cname sql.NullString
			if err := colRows.Scan(&seqno, &cid, &cname); err != nil {
				valid = false
				break
			}
			// Expression keys have a NULL name and cid = -2. They still
			// count as keys; skipping them misclassifies a composite index.
			columns++
			onlyUserID = cid >= 0 && cname.Valid && identIs(cname.String, "user_id")
		}
		if colRows.Err() != nil {
			valid = false
		}
		if err := colRows.Close(); err != nil {
			valid = false
		}
		if valid && columns == 1 && onlyUserID {
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
	row := app.DB.QueryRow("SELECT CAST(id AS TEXT) FROM "+quoteIdent(table)+" WHERE user_id = ? LIMIT 1", session.UserID)
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
