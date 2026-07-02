//go:build !cli

package main

// Tenant bootstrap - v2.7.164.
//
// Every multi-tenant app has a founding moment: a freshly signed-up
// user has no group yet, needs to create the org AND their own
// membership row, but the group key is (correctly) stripped from
// client bodies, so plain CRUD can't express it - the insert dies on
// a NOT NULL constraint. Pre-2.7.164 every app hand-rolled an atomic
// flow for this. `groups.bootstrap` in app.yaml declares it instead:
//
//	groups:
//	  table: company_members
//	  key: company_id
//	  user_field: email
//	  role_field: member_role          # optional - tenant roles
//	  bootstrap:
//	    org_table: companies
//	    founding_role: company_admin   # written to role_field
//
// which enables POST /api/_groups/create: inserts the org row (body
// fields validated against the org table's schema, protected fields
// stripped) + the caller's founding membership in ONE transaction,
// then attaches the new group to the live session so the very next
// request is fully tenant-scoped.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RegisterGroupBootstrapRoute wires POST /api/_groups/create when the
// app declares groups.bootstrap. No-op otherwise - the route 404s like
// any unknown path.
func RegisterGroupBootstrapRoute(mux *http.ServeMux, app *App) {
	if app.Group == nil || app.Group.Bootstrap == nil || app.Group.Bootstrap.OrgTable == "" {
		return
	}
	mux.HandleFunc("POST /api/_groups/create", func(w http.ResponseWriter, r *http.Request) {
		handleGroupBootstrap(w, r, app)
	})
}

func handleGroupBootstrap(w http.ResponseWriter, r *http.Request, app *App) {
	group := app.Group
	boot := group.Bootstrap
	orgTable := boot.OrgTable

	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	// One group per user through this door. Joining additional groups /
	// switching tenants is membership management, not bootstrap.
	if session.EffectiveHasGroup() {
		httpJSON(w, http.StatusConflict, map[string]any{
			"error":    "already a member of a group",
			"group_id": session.EffectiveGroupID(),
		})
		return
	}

	// Parse body - JSON object or form, same shapes handleCreate accepts.
	values := map[string]string{}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			for k, v := range body {
				values[k] = jsonToFormValue(v)
			}
		}
	} else {
		r.ParseForm()
		for k := range r.Form {
			values[k] = r.FormValue(k)
		}
	}

	orgCols, err := GetTableColumns(app.DB, orgTable)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("groups.bootstrap.org_table %q does not exist", orgTable),
		})
		return
	}

	// Build the org INSERT - same protections as auto-CRUD: protected
	// fields never come from the body, user_id auto-injects from the
	// session when the org table has it (the creator).
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true, "_csrf": true,
	}
	var fields []string
	var args []any
	for _, col := range orgCols {
		if col.PK {
			continue
		}
		if col.Name == "user_id" {
			fields = append(fields, "user_id")
			args = append(args, session.UserID)
			continue
		}
		if protected[col.Name] || col.Name == group.Key {
			continue
		}
		v, ok := values[col.Name]
		if !ok || v == "" {
			continue
		}
		fields = append(fields, col.Name)
		args = append(args, v)
	}
	if len(fields) == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("no fields provided for %s - send at least one column (e.g. name)", orgTable),
		})
		return
	}

	tx, err := app.DB.Begin()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(fields)), ", ")
	res, err := tx.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		orgTable, strings.Join(fields, ", "), placeholders), args...)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("org insert failed: %s", err.Error())})
		return
	}
	var orgID any
	if app.IsUUIDTable(orgTable) {
		var uuidID string
		if err := tx.QueryRow(fmt.Sprintf("SELECT id FROM %s WHERE rowid = last_insert_rowid()", orgTable)).Scan(&uuidID); err != nil {
			httpError(w, "org insert succeeded but failed to retrieve UUID", http.StatusInternalServerError)
			return
		}
		orgID = uuidID
	} else {
		intID, _ := res.LastInsertId()
		orgID = intID
	}

	// Founding membership: key=org id, user_field=session identity,
	// role_field=founding_role when both are declared.
	memberVal := any(session.UserID)
	if strings.Contains(group.UserField, "email") {
		memberVal = session.Email
	}
	mFields := []string{group.Key, group.UserField}
	mArgs := []any{orgID, memberVal}
	if group.RoleField != "" && boot.FoundingRole != "" {
		mFields = append(mFields, group.RoleField)
		mArgs = append(mArgs, boot.FoundingRole)
	}
	if group.UserField != "user_id" && hasColumn(app, group.Table, "user_id") {
		mFields = append(mFields, "user_id")
		mArgs = append(mArgs, session.UserID)
	}
	mPlaceholders := strings.TrimSuffix(strings.Repeat("?, ", len(mFields)), ", ")
	if _, err := tx.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		group.Table, strings.Join(mFields, ", "), mPlaceholders), mArgs...); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("founding membership insert into %s failed: %s - the org row was rolled back", group.Table, err.Error()),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Attach the new tenant to the live session so the very next
	// request scopes correctly (mirrors getSession's lazy-resolve).
	groupID := fmt.Sprintf("%v", orgID)
	session.GroupID = groupID
	if !strings.HasPrefix(session.ID, "apitoken:") {
		app.DB.Exec("UPDATE _benmore_sessions SET group_id = ? WHERE id = ?", groupID, session.ID)
	}

	// Post-commit bookkeeping - same signals a CRUD insert emits.
	orgRow := map[string]any{"id": orgID}
	for i, f := range fields {
		orgRow[f] = args[i]
	}
	idStr := fmt.Sprintf("%v", orgID)
	LogAudit(app, "insert", orgTable, idStr, session, nil, orgRow)
	LogAudit(app, "insert", group.Table, "", session, nil, map[string]any{
		group.Key: orgID, group.UserField: memberVal,
	})
	FireHooks(app, "insert", orgTable, orgRow)
	FireFlowsForEvent(app, "on_insert", orgTable, orgRow)
	Broadcast(app, orgTable, "insert", session)

	resp := map[string]any{"status": "created", "group_id": orgID}
	if full, ok := loadInsertedRow(app, orgTable, idStr); ok {
		resp["org"] = full
	} else {
		resp["org"] = orgRow
	}
	if boot.FoundingRole != "" && group.RoleField != "" {
		resp["founding_role"] = boot.FoundingRole
	}
	httpJSON(w, http.StatusOK, resp)
}
