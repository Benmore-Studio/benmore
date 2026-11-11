//go:build !cli

package main

// Record updates and per-user singleton updates.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
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
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	session := getSession(app, r)
	// A lock answers 409 only on a row the caller may edit; any other
	// row is the scoped update's 404, never a confirmation it exists.
	// An anonymous caller (an `update: anon` table) holds no lock, so any
	// lock blocks it, the rule DELETE and batch already apply; this check
	// used to run only with a session, so anonymous PATCH ignored locks.
	var lockUID int64
	if session != nil {
		lockUID = session.UserID
	}
	if locked, lockedBy := CheckLock(app.DB, table, id, lockUID); locked && canAccessRowScoped(app, table, id, session, "edit") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(lockErrorResponse(app.DevMode, lockedBy))
		return
	}
	// validateCSRF has already parsed a form body for a cookie request (it
	// reads the token with FormValue); a Bearer request skips it, so this is
	// its first parse. Either way parseFormBody reports a body cut by the cap.
	if err := parseFormBody(r); err != nil {
		if !answerIfRequestBodyTooLarge(w, err) {
			httpError(w, "Bad request", http.StatusBadRequest)
		}
		return
	}
	fields, err := getUpdateFields(r, app, table)
	if answerIfRequestBodyTooLarge(w, err) {
		return
	}
	expected := ""
	if value := fields["_expected_updated_at"]; value != nil {
		expected = jsonToFormValue(value)
	}
	if expected == "" {
		expected = r.FormValue("_expected_updated_at")
	}
	delete(fields, "_expected_updated_at")
	var stripped []string
	if cols, err := GetTableColumns(app.DB, table); err == nil {
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		setIgnoredFieldsHeader(w, r, names, cols)
		stripped = updateStrippedFields(app, table, id, session, fields, cols)
		if len(stripped) > 0 {
			w.Header().Set("X-Stripped-Fields", strings.Join(stripped, ","))
		}
	}
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
			httpJSON(w, http.StatusConflict, withRefusalDocs(map[string]any{"error": "conflict", "message": "Record was modified by another user"}, "conflict"))
			return
		}
		if respondStorageFull(w, app, err) {
			return
		}
		var requestErr *updateRequestError
		if errors.As(err, &requestErr) && requestErr.noopEcho {
			// Only unchanged echoes were submitted (command-owned values, or
			// the mask of an encrypted field): nothing to write.
			addIgnoredFields(w, requestErr.ignored)
			httpJSON(w, http.StatusOK, map[string]any{"status": "updated"})
			return
		}
		if errors.As(err, &requestErr) && requestErr.noFields && len(stripped) > 0 {
			// Everything submitted was a column PATCH never writes: say which
			// and where it does change, instead of a bare "No fields to update".
			httpJSON(w, http.StatusBadRequest, withRefusalDocs(map[string]any{
				"error":           requestErr.message,
				"stripped_fields": stripped,
				"hint":            strippedUpdateHint(app, table, id, stripped),
			}, refusalNoFields))
			return
		}
		if errors.As(err, &requestErr) && requestErr.noFields && multipartRequest(r) {
			// No field was read from a multipart body: say the body type is
			// the reason, not the field names.
			httpJSON(w, http.StatusBadRequest, withRefusalDocs(map[string]any{
				"error": requestErr.message,
				"hint":  multipartUpdateHint,
			}, refusalMultipartUpdate))
			return
		}
		if errors.As(err, &requestErr) {
			writeUpdateRequestError(w, r, app, table+" update", requestErr)
		} else {
			serverErrorJSON(w, r, app, table+" update", err, "Update failed")
		}
		return
	}
	// The same decision the pipeline made, on the same row in this tx.
	addIgnoredFields(w, maskedEchoFields(tx, app, session, table, before, values))
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
	broadcastHookRefreshes(app, session, refreshTables, []transactionResult{{Table: table, Action: "update"}})
	appendHXTrigger(w, "benmore:changed")
	if isHTMX(r) {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"status": "updated"}
	if len(stripped) > 0 {
		body["stripped_fields"] = stripped
		body["hint"] = strippedUpdateHint(app, table, id, stripped)
	}
	_ = json.NewEncoder(w).Encode(body)
}

// refusalMultipartUpdate names, in refusal_docs.go, the 400 of an update
// that read no field from a multipart body.
const refusalMultipartUpdate = "multipart_update"

// multipartUpdateHint is what that 400 says to send instead. An update
// never stores a file part, and a request with an API token or Bearer
// session reads no field of a multipart body at all, so `-F name=x` on a
// PATCH answered a bare "No fields to update" that pointed at the field
// names.
const multipartUpdateHint = "this PATCH has a multipart/form-data body, and an update reads no field from one and never stores a file part: send the fields as JSON or as a URL-encoded form. To change a file column, upload the file first (POST /api/_upload) and send the reference it returns as the column's value"

// multipartRequest reports a request whose body is multipart/form-data.
func multipartRequest(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "multipart/")
}

// updateStrippedFields names the submitted columns a PATCH drops because no
// update may write them: the workflow state column, the owner and tenant
// keys, timestamps, computed and credential columns (protectedUpdateFields).
// The update saved the other fields and answered 200 with no sign the state
// change was ignored (Round 2 B8); create already names its drops in
// X-Stripped-Fields. Like create, an echo of the caller's own user_id or
// tenant is harmless and not named, nor is an id equal to the path id (a
// form that sends the whole row back). The list is computed from the
// request and the schema alone, never from the stored row, so it reveals
// nothing about the row's values.
func updateStrippedFields(app *App, table, id string, session *Session, fields map[string]any, cols []Column) []string {
	if len(fields) == 0 {
		return nil
	}
	protected := protectedFields(protectedUpdateFields(app, table))
	columns := make(map[string]bool, len(cols))
	for _, c := range cols {
		columns[sqliteIdentifierFold(c.Name)] = true
	}
	groupKey := ""
	if app.Group != nil {
		groupKey = app.Group.Key
	}
	var stripped []string
	for name, value := range fields {
		if name == "" || strings.HasPrefix(name, "_") || !protected.has(name) || !columns[sqliteIdentifierFold(name)] {
			continue
		}
		text := ""
		if value != nil {
			text = strings.TrimSpace(valueText(value))
		}
		switch {
		case identIs(name, "id") && text == id:
			continue
		case identIs(name, "user_id") && session != nil && text == fmt.Sprint(session.UserID):
			continue
		case identIs(name, groupKey) && session != nil && session.EffectiveHasGroup() && text == session.EffectiveGroupID():
			continue
		}
		stripped = append(stripped, name)
	}
	slices.Sort(stripped)
	return stripped
}

// strippedUpdateHint says why each stripped column was dropped and, for a
// workflow state column, the route that does change it.
func strippedUpdateHint(app *App, table, id string, stripped []string) string {
	var parts, managed []string
	for _, field := range stripped {
		if wf := workflowForStateColumn(app, table, field); wf != nil {
			parts = append(parts, fmt.Sprintf("%s is the state column of the %q workflow and changes only through a transition: POST /api/%s/%s/transition with {\"to\":\"<state>\"} (GET /api/%s/%s/transitions lists the states you may move to)", field, wf.Name, table, id, table, id))
			continue
		}
		managed = append(managed, field)
	}
	if len(managed) > 0 {
		verb := "is"
		if len(managed) > 1 {
			verb = "are"
		}
		if identIs(table, "_benmore_users") {
			// Not "change it in a flow": these are the account's role,
			// password and sign-in factor.
			parts = append(parts, fmt.Sprintf("%s %s account state the admin panel never writes: role changes through POST /_admin/set-role, a password and a sign-in factor only through the account's own sign-in and account endpoints", strings.Join(managed, ", "), verb))
		} else {
			parts = append(parts, fmt.Sprintf("%s %s managed by the framework (owner, tenant, timestamps, computed or credential columns) and never written by PATCH; change it server-side in a flow if the app needs to", strings.Join(managed, ", "), verb))
		}
	}
	return strings.Join(parts, "; ")
}

// workflowForStateColumn returns the workflow whose state column on table is
// col, or nil.
func workflowForStateColumn(app *App, table, col string) *Workflow {
	if app == nil || app.Workflows == nil {
		return nil
	}
	for _, wf := range app.Workflows.Workflows {
		if wf != nil && wf.Table == table && identIs(wf.Field, col) {
			return wf
		}
	}
	return nil
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
