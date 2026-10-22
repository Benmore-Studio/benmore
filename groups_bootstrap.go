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
func RegisterGroupBootstrapRoute(mux appRouteRegistrar, app *App) {
	if app.Group == nil || app.Group.Bootstrap == nil || app.Group.Bootstrap.OrgTable == "" {
		return
	}
	mux.HandleFunc("POST /api/_groups/create", func(w http.ResponseWriter, r *http.Request) {
		handleGroupBootstrap(w, r, app)
	})
}

// bootstrapOrgWriteAllowed applies the write mode the org table DECLARES
// on itself (access.<org_table>.write or .all) to the founder. Declaring
// `companies: {write: admin}` or `role:sales` means only those callers may
// create organizations, and bootstrap must not be the way around it.
//
// Not applied: the implicit default and the global `default:` block (an
// org table usually has no user_id, so the implicit mode is admin and
// enforcing it would disable every bootstrap - declaring groups.bootstrap
// is itself the grant); `group`, which a founder cannot hold before the
// group exists; and `off`, which disables the auto-CRUD route and is the
// usual way to make bootstrap the only door.
func bootstrapOrgWriteAllowed(app *App, orgTable string, session *Session) bool {
	mode, declared := app.Access.TableDeclaredModeFor(orgTable, OpWrite)
	if !declared || mode == "group" || mode == "off" {
		return true
	}
	return app.Access.Allowed(mode, session, 0)
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
	// Bootstrap writes the org row and the founding membership, so a
	// scoped credential needs write scope on both - the gate auto-CRUD
	// applies. Without it a read-only token could create a tenant.
	for _, t := range []string{orgTable, group.Table} {
		if err := checkScope(session, t, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	if !bootstrapOrgWriteAllowed(app, orgTable, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{
			"error": fmt.Sprintf("access.%s.write does not allow this account to create an organization", orgTable),
		})
		return
	}
	// An email-keyed founding membership counts only for a verified address,
	// so an unverified founder would create a tenant they can't enter.
	if emailKeyedColumn(group.UserField) && sessionGrantEmail(session) == "" && !session.IsAdmin() {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "email_unverified", "message": "verify your email before creating an organization"})
		return
	}
	if reason, blocked := checkStorageCap(app, 0); blocked {
		httpJSON(w, http.StatusInsufficientStorage, map[string]any{"error": "storage cap reached", "detail": reason})
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
	// JSON lands in r.Form so the :validate rules below read it the same
	// way they do on an auto-CRUD create.
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "expected a JSON object"})
			return
		}
		r.Form = make(map[string][]string)
		for k, v := range body {
			r.Form.Set(k, jsonToFormValue(v))
		}
	} else {
		r.ParseForm()
	}
	values := map[string]string{}
	for k := range r.Form {
		values[k] = r.FormValue(k)
	}
	// Command-owned org-table columns are never client-writable (the founding
	// membership row is built from session and config only, never from the body).
	if v := ownedFieldViolation(app, orgTable, mapKeys(values)...); v != nil {
		writeOwnedFieldRefusal(w, v)
		return
	}
	if rules := ExtractValidationRules(app, orgTable); len(rules) > 0 {
		if errs := ValidateFields(r, rules); len(errs) > 0 {
			FormatValidationErrors(w, r, errs)
			return
		}
	}

	orgCols, err := GetTableColumns(app.DB, orgTable)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("groups.bootstrap.org_table %q does not exist", orgTable),
		})
		return
	}

	// Build the org INSERT - same protections as auto-CRUD create: the
	// protected set (owner, timestamps, tenant key, computed columns; names
	// matched case-insensitively) never comes from the body, a workflow's
	// state column starts in its initial state, and user_id auto-injects
	// from the session when the org table has it (the creator).
	protected := protectedCreateFields(app, orgTable)
	var fields []string
	var args []any
	submitted := map[string]any{} // client-supplied values, for the FK visibility gate
	for _, col := range orgCols {
		if col.PK {
			continue
		}
		if identIs(col.Name, "user_id") {
			fields = append(fields, col.Name)
			args = append(args, session.UserID)
			continue
		}
		if protected.has(col.Name) {
			continue
		}
		v, ok := values[col.Name]
		if !ok || v == "" || workflowCreateStateRefused(app, orgTable, col.Name, v) {
			continue
		}
		fields = append(fields, col.Name)
		args = append(args, v)
		submitted[col.Name] = v
	}
	if len(fields) == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("no fields provided for %s - send at least one column (e.g. name)", orgTable),
		})
		return
	}

	memberVal := any(session.UserID)
	if strings.Contains(group.UserField, "email") {
		memberVal = session.Email
	}

	tx, err := app.DB.Begin()
	if err != nil {
		serverError(w, r, app, "_groups create", err, "Server error")
		return
	}
	defer tx.Rollback()

	// The session check above races: two concurrent bootstraps from a
	// groupless user both pass it. Re-check inside the transaction, where
	// SQLite serializes the writers.
	var member bool
	// Same notion of membership as session resolution: only live rows.
	if err := tx.QueryRow(fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE %s = ? AND %s IS NOT NULL%s)",
		quoteIdent(group.Table), quoteColumn(group.Table, group.UserField), quoteColumn(group.Table, group.Key),
		membershipLiveConds(group, group.Table, "", appColumnChecker(app, group.Table))), memberVal).Scan(&member); err != nil {
		serverError(w, r, app, "_groups create", err, "Server error")
		return
	}
	if member {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "already a member of a group"})
		return
	}

	// Same gates as an auto-CRUD insert into the org table: a submitted
	// foreign key must name a parent the founder can read, then declarative
	// cross-field validators, then before-hooks (which can abort).
	if writeFKTargetDenial(w, foreignKeyTargetDenial(tx, app, orgTable, session, submitted)) {
		return
	}
	if err := materializeValidatorDefaults(tx, app.validatorConfig(), orgTable, orgCols, &fields, &args); err != nil {
		serverErrorJSON(w, r, app, "_groups create", err, "could not resolve defaults")
		return
	}
	beforeRow := make(map[string]any, len(fields))
	for i, f := range fields {
		beforeRow[f] = args[i]
	}
	injectSessionContext(beforeRow, session)
	if err := ValidateCrossField(app.validatorConfig(), orgTable, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := fireBeforeHooksWith(tx, app, "insert", orgTable, beforeRow); err != nil {
		httpError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	writeFields, writeArgs, err := sealNativeCiphertextLiterals(tx, app, orgTable, fields, args)
	if err != nil {
		serverErrorJSON(w, r, app, "_groups create", err, "could not seal encrypted input")
		return
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(writeFields)), ", ")
	res, err := tx.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		quoteIdent(orgTable), strings.Join(quoteIdents(writeFields), ", "), placeholders), writeArgs...)
	if err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "org insert failed: " + publicConstraintMessage(app, "bootstrap insert "+orgTable, err)})
		return
	}
	var orgID any
	if app.IsUUIDTable(orgTable) {
		var uuidID string
		if err := tx.QueryRow("SELECT id FROM " + quoteIdent(orgTable) + " WHERE rowid = last_insert_rowid()").Scan(&uuidID); err != nil {
			serverError(w, r, app, "_groups create", err, "org insert succeeded but failed to retrieve UUID")
			return
		}
		orgID = uuidID
	} else {
		intID, _ := res.LastInsertId()
		orgID = intID
	}

	// Founding membership: key=org id, user_field=session identity,
	// role_field=founding_role when both are declared.
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
		quoteIdent(group.Table), strings.Join(quoteIdents(mFields), ", "), mPlaceholders), mArgs...); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("founding membership insert into %s failed: %s - the org row was rolled back", group.Table, publicConstraintMessage(app, "bootstrap insert "+group.Table, err)),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverError(w, r, app, "_groups create", err, "Server error")
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
		sanitizeResponseRows(app, orgTable, []map[string]any{full}, session)
		resp["org"] = full
	} else {
		echo := make(map[string]any, len(orgRow))
		for k, v := range orgRow {
			echo[k] = v
		}
		sanitizeResponseRows(app, orgTable, []map[string]any{echo}, session)
		resp["org"] = echo
	}
	if boot.FoundingRole != "" && group.RoleField != "" {
		resp["founding_role"] = boot.FoundingRole
	}
	httpJSON(w, http.StatusOK, resp)
}
