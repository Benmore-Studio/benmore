//go:build !cli

package main

// Who may manage the groups membership table through generic CRUD.
//
// The membership table (groups.table) decides who is in a tenant, so writing
// it is tenant administration. Its implicit default access is tenant-wide,
// which let any member add an outsider (who then resolves into the tenant),
// delete the tenant admin's row or switch another member off. When the app
// declares no access rule on the table for the operation, generic CRUD
// creates, updates and deletes on it need a tenant admin:
//
//   - a global admin (bypassing, or stepped into the row's tenant), or
//   - a caller inside the row's tenant who passes a literal `role:admin` gate
//     there or holds groups.bootstrap.founding_role (the role the framework
//     itself gives a tenant's founder), or
//   - when no founding role is declared, the owner (user_id) of the tenant's
//     org row: groups.bootstrap.org_table, else the table the membership
//     table's groups.key column references.
//
// A member may still leave: delete their own row, or switch only
// groups.active_field off on it. Reads are unchanged. Locking or sharing a
// membership row takes the same right as editing it (a member's rolling lock
// would otherwise keep the admin from changing or removing them).
//
// A rule the app declares on the table itself (access.<groups.table>.<op> or
// .all) is the app's own policy and is applied as written; the global
// `default:` block is not such a declaration. Flows, hooks, commands,
// bootstrap and the member-of founder auto-join write the table directly and
// are not affected.

import (
	"fmt"
	"net/http"
	"strings"
)

// membershipManageError refuses a generic CRUD write on the membership table.
type membershipManageError struct{ table string }

func (e *membershipManageError) Error() string {
	return fmt.Sprintf("only a tenant admin can add, change or remove %s rows (a member may remove their own); declare access.%s in app.yaml or use a flow to change who manages members", e.table, e.table)
}

// writeMembershipManageDenial renders a membership refusal.
func writeMembershipManageDenial(w http.ResponseWriter, err error) bool {
	denied, ok := err.(*membershipManageError)
	if !ok {
		return false
	}
	httpJSON(w, http.StatusForbidden, map[string]any{"error": denied.Error()})
	return true
}

// membershipManageGated reports whether op on table is a write to the groups
// membership table that the app left to the implicit default.
func membershipManageGated(app *App, table string, op AccessOp) bool {
	if app == nil || app.Group == nil {
		return false
	}
	g := app.Group
	if g.Table == "" || g.Key == "" || g.UserField == "" || !identIs(table, g.Table) {
		return false
	}
	_, declared := app.Access.TableDeclaredModeFor(table, op)
	return !declared
}

// membershipOrgTable returns the table whose rows are the tenants.
func membershipOrgTable(app *App) string {
	g := app.Group
	if g.Bootstrap != nil && g.Bootstrap.OrgTable != "" {
		return g.Bootstrap.OrgTable
	}
	for table, fks := range app.joinMapSnapshot() {
		if !identIs(table, g.Table) {
			continue
		}
		for col, fk := range fks {
			if identIs(col, g.Key) && (fk.Column == "" || identIs(fk.Column, "id")) {
				return fk.Table
			}
		}
	}
	return ""
}

// membershipTenantAdmin reports whether session administers tenant, the group
// key value of the membership rows being written.
func membershipTenantAdmin(q rowQuerier, app *App, session *Session, tenant string) bool {
	if session == nil {
		return false
	}
	if session.IsAdminBypass() {
		return true
	}
	if tenant == "" || tenant == "0" || !session.EffectiveHasGroup() || session.EffectiveGroupID() != tenant {
		return false
	}
	g := app.Group
	roles := []string{"admin"}
	founding := ""
	if g.RoleField != "" && g.Bootstrap != nil {
		founding = strings.TrimSpace(g.Bootstrap.FoundingRole)
	}
	if founding != "" {
		roles = append(roles, founding)
	}
	if HasAnyRole(session, roles) {
		return true
	}
	if founding != "" {
		return false
	}
	org := membershipOrgTable(app)
	if org == "" || !safeIdent(org) || !hasColumn(app, org, "user_id") {
		return false
	}
	query := fmt.Sprintf("SELECT 1 FROM main.%s WHERE id = ? AND user_id = ?", quoteIdent(org))
	if hasColumn(app, org, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}
	var one int
	return q.QueryRow(query+" LIMIT 1", tenant, session.UserID).Scan(&one) == nil
}

// membershipOwnRow reports whether row id of the membership table names the
// caller: the row a member removes to leave. The comparison is the one
// membership resolution makes (the column's own collation, a verified address
// for an email-keyed table).
func membershipOwnRow(q rowQuerier, app *App, session *Session, id any) bool {
	g := app.Group
	if session == nil || id == nil || !membershipIdentRe.MatchString(g.UserField) || !safeIdent(g.Table) {
		return false
	}
	member, ok := groupMemberValue(g, session)
	if !ok {
		return false
	}
	var one int
	return q.QueryRow(fmt.Sprintf("SELECT 1 FROM main.%s WHERE id = ? AND %s = ? LIMIT 1", quoteIdent(g.Table), quoteColumn(g.Table, g.UserField)), id, member).Scan(&one) == nil
}

func membershipRowTenant(app *App, row map[string]any) string {
	for col, v := range row {
		if identIs(col, app.Group.Key) && v != nil {
			return fmt.Sprint(v)
		}
	}
	return ""
}

// membershipCreateDenial gates a generic CRUD create on the membership table.
// The new row lands in the caller's effective tenant (the key is never taken
// from a non-admin's request), so that is the tenant they must administer.
func membershipCreateDenial(q rowQuerier, app *App, table string, session *Session) error {
	if !membershipManageGated(app, table, OpWrite) {
		return nil
	}
	if membershipTenantAdmin(q, app, session, session.EffectiveGroupID()) {
		return nil
	}
	return &membershipManageError{table: table}
}

// membershipUpdateDenial gates a generic CRUD update of membership row `row`
// (as stored, before the change). changed holds the submitted columns whose
// value differs. A non-admin may only switch their own membership off.
func membershipUpdateDenial(q rowQuerier, app *App, table string, session *Session, row, changed map[string]any) error {
	if !membershipManageGated(app, table, OpUpdate) {
		return nil
	}
	if membershipTenantAdmin(q, app, session, membershipRowTenant(app, row)) {
		return nil
	}
	leaving := len(changed) > 0 && app.Group.ActiveField != ""
	for col, v := range changed {
		if !identIs(col, app.Group.ActiveField) || !membershipInactiveValue(v) {
			leaving = false
		}
	}
	if leaving && membershipOwnRow(q, app, session, row["id"]) {
		return nil
	}
	return &membershipManageError{table: table}
}

// membershipDeleteDenial gates a generic CRUD delete of membership row `row`.
func membershipDeleteDenial(q rowQuerier, app *App, table string, session *Session, row map[string]any) error {
	if !membershipManageGated(app, table, OpDelete) {
		return nil
	}
	if membershipTenantAdmin(q, app, session, membershipRowTenant(app, row)) || membershipOwnRow(q, app, session, row["id"]) {
		return nil
	}
	return &membershipManageError{table: table}
}

// membershipRowControlDenied reports whether session may NOT take edit-level
// control of membership row id: hold a record lock on it (which blocks every
// other editor) or share it. Both ride on "may edit the row", and on the
// membership table under its implicit default that is the tenant admin.
func membershipRowControlDenied(app *App, table, id string, session *Session) bool {
	if !membershipManageGated(app, table, OpUpdate) {
		return false
	}
	g := app.Group
	if !membershipIdentRe.MatchString(g.Key) || !safeIdent(g.Table) {
		return true
	}
	var tenant any
	if err := app.DB.QueryRow(fmt.Sprintf("SELECT %s FROM main.%s WHERE id = ?", quoteColumn(g.Table, g.Key), quoteIdent(g.Table)), id).Scan(&tenant); err != nil {
		return true
	}
	rowTenant := ""
	if tenant != nil {
		if b, ok := tenant.([]byte); ok {
			rowTenant = string(b)
		} else {
			rowTenant = fmt.Sprint(tenant)
		}
	}
	return !membershipTenantAdmin(app.DB, app, session, rowTenant)
}

// membershipInactiveValue reports a value membershipLiveConds reads as "not
// active" once stored in groups.active_field.
func membershipInactiveValue(v any) bool {
	if v == nil {
		return true
	}
	switch strings.ToLower(fmt.Sprint(v)) {
	case "", "0", "false", "no", "off":
		return true
	}
	return false
}
