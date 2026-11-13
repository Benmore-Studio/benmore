//go:build !cli

package main

// Scoped credentials on the side routes of a table.
//
// Auto-CRUD narrows a scoped credential (scopedCredential: an API token or
// Bearer session minted with explicit scopes, a connector grant) table by
// table. The routes beside it that are about one table's rows - approvals on
// a record, scheduled tasks naming a record, saved views of a table, presence
// in a room bound to a membership table - looked only at the account, so a
// notes:read token listed, requested and decided approvals on every table,
// read the account's reminders and saved views, and joined any room.
//
// The rule is auto-CRUD's: the credential needs the scope of the table the
// request names, read to read and write to change, decided by checkScope on
// the session exactly as GET or POST /api/<table> decides it. A request that
// names no table has no scope a narrowed credential could have been minted
// for and is refused, unless its scopes hold a wildcard resource for the
// action (*:read), which covers every name. Unscoped credentials ("" or "*"),
// an ordinary sign-in included, never reach checkScope here: role scopes keep
// deciding only what they decided before on these routes.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// credentialTableScopeError is nil unless session is a scoped credential
// whose scopes do not allow action on table. what names the surface for the
// refusal of a request that names no table; only a wildcard resource
// (scopeAnyNameProbe) reaches such a request.
func credentialTableScopeError(session *Session, table, action, what string) error {
	if !scopedCredential(session) {
		return nil
	}
	if table == "" {
		if checkScope(session, scopeAnyNameProbe, action) == nil {
			return nil
		}
		return fmt.Errorf("scope denied: this credential is limited to the scopes it was issued with, and %s names no table: a scoped API token or session reaches this route only through the %s scope of the table a request names", what, action)
	}
	return checkScope(session, table, action)
}

// requireCredentialTableScope answers the standard scope refusal (403,
// scopeDeniedBody) for credentialTableScopeError and reports whether the
// handler may continue.
func requireCredentialTableScope(w http.ResponseWriter, session *Session, table, action, what string) bool {
	err := credentialTableScopeError(session, table, action, what)
	if err == nil {
		return true
	}
	httpJSON(w, http.StatusForbidden, scopeDeniedBody(err))
	return false
}

// What a request that names no table is called in its refusal.
const (
	approvalScopeSubject      = "an approval request"
	scheduledTaskScopeSubject = "a scheduled task"
	savedViewScopeSubject     = "a saved view"
)

// scopeAnyNameProbe is a name no table or label can have (validateScopes
// admits letters, digits and underscores): a credential that passes
// checkScope for it holds a wildcard resource.
const scopeAnyNameProbe = "\x00"

// credentialTableFilter narrows a list that spans tables (approvals,
// scheduled tasks) to what a scoped credential may read: an SQL condition on
// column with its arguments, empty for an unscoped credential and for a
// wildcard scope. The names are every schema table and every resource the
// credential's scopes name (a free-form approval label can be one) that
// checkScope allows; rows naming anything else, or nothing, are left out.
func credentialTableFilter(app *App, session *Session, column, action string) (string, []any) {
	if !scopedCredential(session) || checkScope(session, scopeAnyNameProbe, action) == nil {
		return "", nil
	}
	var args []any
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || name == "*" || seen[name] || checkScope(session, name, action) != nil {
			return
		}
		seen[name] = true
		args = append(args, name)
	}
	for _, t := range app.Tables {
		add(t.Name)
	}
	for _, scope := range strings.Fields(session.Scopes) {
		resource, _ := parseScope(scope)
		add(resource)
	}
	if len(args) == 0 {
		return " AND 0", nil
	}
	return " AND " + column + " IN (?" + strings.Repeat(",?", len(args)-1) + ")", args
}

// presenceScopeError applies the rule to a presence slug. A slug is a room
// name: a room declared under ws_rooms is bound to its membership table, so
// that table's scope decides; a slug no ws_rooms pattern matches names no
// table.
func presenceScopeError(app *App, session *Session, slug, action string) error {
	if !scopedCredential(session) {
		return nil
	}
	table := ""
	for _, wr := range app.wsRoomRules() {
		if _, ok := matchWSRoomPattern(wr.Pattern, slug); ok && wr.Rule != nil {
			table = wr.Rule.Table
			break
		}
	}
	return credentialTableScopeError(session, table, action, "a presence room no ws_rooms pattern binds to a membership table")
}

// savedViewTable is the table a saved view's spec queries, "" when the spec
// names none or cannot be read.
func savedViewTable(spec string) string {
	var s struct {
		Table string `json:"table"`
	}
	if json.Unmarshal([]byte(spec), &s) != nil {
		return ""
	}
	return strings.TrimSpace(s.Table)
}
