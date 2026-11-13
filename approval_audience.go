package main

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode/utf8"
)

// approval_audience.go - an approval on a tenant's record stays in the tenant.
//
// POST /api/_approvals checked that the REQUESTER can read the record and
// then accepted any account as approver. A member of tenant A named an
// account of tenant B as approver of a tenant A record: that account was
// notified with the requester's text, read the requester's email, the table
// and the row id under ?mine=1, and its decision was stored in the approval
// history every reader of the record sees.
//
// The rule (approvalRecordAudience): on a table that carries the groups: key,
// the approver of a record that has a tenant must be in that tenant (the
// tenant clause of rowScopeClause, for the approver's identity) or be able to
// read the record (rowScopeClause itself: a global admin, a record share, an
// owner). It is the tenant that is bounded, not row access: approvals are
// used on owner-only tables, where the approver (a manager) is by design
// someone who cannot read the requester's row, and requiring read access
// would end those inside one tenant too.
//
// Two kinds of table have a tenant without carrying the key. The
// groups.bootstrap org table: its row id IS the tenant, so the approver is in
// the tenant the row is. A table whose read rule is `member-of:`: the
// approver is a member of what the record belongs to (the rule's own
// predicate, through rowScopeClause).
//
// A free-form label that names no table has no record to take a tenant from,
// so it takes the requester's (approvalLabelAudience): the approver is in a
// tenant the requester is a live member of. A requester with no tenant names
// only a global admin; a global admin's request reaches any account.
//
// Not bounded, so any account can be named, as before: a record with no
// tenant value, any other table without the tenant key, and every label in
// an app without groups:.
//
// The requester is bounded the same way (approvalAudienceSQL, requester):
// they list a request, and are notified of its decision, only while the
// record admits them. The approver's address, the decision and its note are
// the tenant's, and a member who has left it kept reading them.
//
// The rule is evaluated for the approver's identity at the time of each
// action, never stored: when the request is made (binding and notifying the
// account), in the list and at /decide (approvalApproverSQL). An approver
// removed from the tenant stops listing and deciding; an account that joins
// later picks up the requests addressed to it. A request naming an account
// outside the tenant is answered and stored exactly like one naming an
// address nobody holds, so the answer does not say whether the address has
// an account or which tenant it is in.

// approvalRecordAudience returns the predicate over the rows of app table
// `table` "an approval on this record can be assigned to this session", with
// its arguments. bounded is false when the table has no tenant to stay
// inside or the session is an admin outside any tenant: every row admits.
func approvalRecordAudience(app *App, table string, s *Session) (pred string, args []any, bounded bool) {
	keyed, root := memberOfTenantKeyed(app, table), tenantRootTable(app, table)
	if s.IsAdminBypass() || !keyed && !root && memberOfFor(app, table, OpRead) == nil {
		return "", nil, false
	}
	var parts []string
	if keyed {
		// A record that carries no tenant (Session.HasGroup's "" and "0") has
		// none to stay inside.
		parts = append(parts, fmt.Sprintf("COALESCE(CAST(%s AS TEXT), '') IN ('', '0')", quoteIdent(app.Group.Key)))
		if tenant, targs, ok := rowTenantClause(app, table, s); ok {
			parts = append(parts, tenant)
			args = append(args, targs...)
		}
	}
	// The tenant root's row id is the tenant (tenantRootRoleScope).
	if root && s.EffectiveHasGroup() {
		parts = append(parts, quoteColumn(table, "id")+" = ?")
		args = append(args, s.EffectiveGroupID())
	}
	// A reader of the record is in its audience whatever tenant they are in;
	// on a `member-of:` table without the tenant key the readers are the
	// members, and the whole audience. The row scope alone says nothing on a
	// table the session's read mode refuses, so the mode gate comes first
	// (as in canAccessRow).
	if SessionCanAccessTable(app, table, OpRead, s) {
		if reader, rargs, _ := rowScopeClause(app, table, s, "view"); reader != "" {
			parts = append(parts, reader)
			args = append(args, rargs...)
		}
	}
	if len(parts) == 0 {
		return "0", nil, true
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, true
}

// approvalRequesterIsAdminSQL is the predicate over _benmore_approvals rows
// "the account that made this request is a global admin" (Session.IsAdmin:
// the users.role column or a live grant with no group).
const approvalRequesterIsAdminSQL = `(EXISTS (SELECT 1 FROM _benmore_users u WHERE u.id = _benmore_approvals.requested_by AND u.role = 'admin')
	OR EXISTS (SELECT 1 FROM main._benmore_user_roles r WHERE r.user_id = _benmore_approvals.requested_by AND r.role = 'admin' AND r.group_id IS NULL
		AND (r.expires_at IS NULL OR datetime(r.expires_at) > datetime('now'))))`

// approvalLabelAudience is the predicate over _benmore_approvals rows whose
// table_name is a free-form label "this request can be assigned to this
// session", with its arguments: "1" in an app without groups: and for an
// admin outside any tenant. Otherwise the requester is a global admin, or a
// live member of the tenant the session is in. Membership is what
// groupMembershipLive checks for a session (the user id, or the proven
// address for an email-keyed table) plus what ResolveGroupID accepts (a
// proven address in a column of another name), for the requester's account.
func approvalLabelAudience(app *App, s *Session) (string, []any) {
	g := app.Group
	if s.IsAdminBypass() || g == nil || g.Table == "" || g.Key == "" || g.UserField == "" {
		return "1", nil
	}
	if !s.EffectiveHasGroup() {
		return approvalRequesterIsAdminSQL, nil
	}
	const m = "_benmore_membership"
	member := quoteColumn(m, g.UserField)
	byAddress := member + " IN (SELECT u.email FROM _benmore_users u WHERE u.id = _benmore_approvals.requested_by AND " + emailTrustedSQL("u")
	requester := byAddress + ")"
	if !emailKeyedColumn(g.UserField) {
		requester = "(" + member + " = _benmore_approvals.requested_by OR " + byAddress + " AND u.email LIKE '%@%'))"
	}
	return fmt.Sprintf("(%s OR EXISTS (SELECT 1 FROM %s AS %s WHERE %s = ? AND %s%s))", approvalRequesterIsAdminSQL,
		quoteIdent(g.Table), m, quoteColumn(m, g.Key), requester, membershipLiveConds(g, g.Table, m, dbColumnChecker(app.DB, g.Table))), []any{s.EffectiveGroupID()}
}

// approvalNotificationTextMax is how many characters of an approval's title
// its notifications carry. The title is the requester's text and lands in
// another account's notification list; the approval keeps it as written.
const approvalNotificationTextMax = 200

// approvalNotificationText is title as a notification carries it.
func approvalNotificationText(title string) string {
	if utf8.RuneCountInString(title) <= approvalNotificationTextMax {
		return title
	}
	return string([]rune(title)[:approvalNotificationTextMax]) + "…"
}

// approvalTableName is the schema's spelling of the app table that name
// names in any ASCII letter case, the way SQLite resolves a table name, and
// name itself when it names no table (a free-form label). A request that
// wrote `Docs` for the table `docs` was stored as a label: no read check on
// the record for the requester and no tenant bound on its approver.
func approvalTableName(app *App, name string) string {
	for _, t := range app.Tables {
		if identIs(t.Name, name) {
			return t.Name
		}
	}
	return name
}

// approvalAudienceSQL is the predicate over _benmore_approvals rows "what
// this request names admits this session", with its arguments:
// approvalRecordAudience for the table each row names, approvalLabelAudience
// for a label, and every row for a table that has no tenant.
//
// As approver (requester false), a record that no longer exists has no
// tenant to check and admits nobody, or deleting it would hand the request
// to the outside account it named. As requester, the same record audience
// decides whether the session still lists its own request; a removed record
// and a label keep their requester.
func approvalAudienceSQL(app *App, s *Session, requester bool) (string, []any) {
	label, labelArgs := "1", []any(nil)
	if !requester {
		label, labelArgs = approvalLabelAudience(app, s)
	}
	var b strings.Builder
	var args []any
	for _, t := range app.Tables {
		pred, pargs, bounded := approvalRecordAudience(app, t.Name, s)
		switch {
		case !bounded && label == "1":
			continue // the ELSE below
		case !bounded, requester && !hasColumn(app, t.Name, "id"):
			b.WriteString(" WHEN ? THEN 1")
			args = append(args, t.Name)
		case !hasColumn(app, t.Name, "id"):
			b.WriteString(" WHEN ? THEN 0")
			args = append(args, t.Name)
		default:
			record := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = _benmore_approvals.row_id", quoteIdent(t.Name), quoteColumn(t.Name, "id"))
			args = append(args, t.Name)
			if requester {
				fmt.Fprintf(&b, " WHEN ? THEN (NOT EXISTS (%s) OR EXISTS (%s AND %s))", record, record, pred)
			} else {
				fmt.Fprintf(&b, " WHEN ? THEN EXISTS (%s AND %s)", record, pred)
			}
			args = append(args, pargs...)
		}
	}
	if b.Len() == 0 {
		return label, labelArgs
	}
	// NOCASE: a request stored under another letter case of a table name,
	// before requests resolved it (approvalTableName), is bounded as well.
	return "(CASE _benmore_approvals.table_name COLLATE NOCASE" + b.String() + " ELSE " + label + " END)", append(args, labelArgs...)
}

// approvalRequesterSQL is the predicate "this _benmore_approvals row is this
// session's own request, to list": it made the request and what the request
// names still admits it (approvalAudienceSQL).
func approvalRequesterSQL(app *App, s *Session) (string, []any) {
	audience, args := approvalAudienceSQL(app, s, true)
	return "(requested_by = ? AND " + audience + ")", append([]any{s.UserID}, args...)
}

// approvalNotifiesRequester reports whether the requester of approval id is
// told its decision: while the account exists and what the request names
// admits it, with the tenant a request by the account would resolve to
// (approvalAccountIdentity). Any failure tells nobody.
func approvalNotifiesRequester(app *App, id string) bool {
	var requestedBy int64
	var table, rowID string
	if err := app.DB.QueryRow("SELECT requested_by, table_name, row_id FROM _benmore_approvals WHERE id = ?", id).Scan(&requestedBy, &table, &rowID); err != nil {
		return false
	}
	requester := approvalAccountIdentity(app, requestedBy, approvalTableName(app, table), rowID, "")
	if requester == nil {
		return false
	}
	mine, args := approvalRequesterSQL(app, requester)
	var admitted bool
	return app.DB.QueryRow("SELECT "+mine+" FROM _benmore_approvals WHERE id = ?", append(args, id)...).Scan(&admitted) == nil && admitted
}

// approvalApproverSQL is the predicate "this _benmore_approvals row is this
// session's to decide": assigned to its account (approvalAssignedSQL) on a
// record that admits it (approvalAudienceSQL). The list, ?mine=1 and /decide
// share it, so they cannot drift apart.
func approvalApproverSQL(app *App, s *Session) (string, []any) {
	assigned, args := approvalAssignedSQL(s)
	audience, audienceArgs := approvalAudienceSQL(app, s, false)
	return "(" + assigned + " AND " + audience + ")", append(args, audienceArgs...)
}

// approvalBindApprover records account userID as the approver of the request
// just stored (approvalID, on table/rowID, by a requester in requesterTenant)
// when the request is that account's to decide, and reports whether it did.
// Only then is the account notified. It applies approvalApproverSQL, the
// test the list and /decide apply, to the stored row.
func approvalBindApprover(app *App, approvalID, userID int64, table, rowID, requesterTenant string) (bool, error) {
	approver := approvalAccountIdentity(app, userID, table, rowID, requesterTenant)
	if approver == nil {
		return false, nil
	}
	mine, args := approvalApproverSQL(app, approver)
	res, err := app.DB.Exec("UPDATE _benmore_approvals SET approver_id = ? WHERE id = ? AND "+mine, append([]any{userID, approvalID}, args...)...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// approvalAccountIdentity is account userID as a request by it would be
// resolved, for evaluating the audience of table/rowID when the account is
// not the caller (the approver when the approval is requested, the requester
// when it is decided). Its tenant is the one the request belongs to
// (approvalTenant) when the account holds a live membership there, the check
// behind a tenant switch and the per-request revalidation of a session's
// tenant (getSession), and none otherwise. nil when the account is gone.
func approvalAccountIdentity(app *App, userID int64, table, rowID, labelTenant string) *Session {
	s := &Session{UserID: userID}
	var verified, grandfathered int
	if err := app.DB.QueryRow("SELECT COALESCE(email,''), COALESCE(role,'user'), COALESCE(verified,0), COALESCE(email_grandfathered,0) FROM _benmore_users WHERE id = ?", userID).
		Scan(&s.Email, &s.Role, &verified, &grandfathered); err != nil {
		return nil
	}
	s.Verified, s.EmailGrandfathered = verified == 1, grandfathered == 1
	s.GlobalAdmin = s.Role == "admin"
	if !s.GlobalAdmin {
		s.GlobalAdmin, _ = userHasGlobalAdminGrantWith(app.DB, userID)
	}
	if g := app.Group; g != nil && !s.IsAdmin() {
		// A request by the account would be in that tenant: a live
		// membership row, or the tenant its proven address resolves to (a
		// membership column that holds addresses under another name).
		if tenant := approvalTenant(app, table, rowID, labelTenant); tenant != "" && tenant != "0" &&
			(groupMembershipLive(app.DB, g, s, tenant) ||
				sessionGrantEmail(s) != "" && ResolveGroupID(app.DB, g, s.Email) == tenant) {
			s.GroupID = tenant
		}
	}
	s.Roles = LoadSessionRoles(app.DB, userID, s.Role, s.EffectiveGroupID())
	return applySessionRoleScopes(app, s)
}

// approvalTenant is the tenant a request on table/rowID belongs to: the
// record's groups: key, the row itself on the tenant root, labelTenant (the
// requester's) for a label that names no table, and none for any other
// table or a record that does not exist.
func approvalTenant(app *App, table, rowID, labelTenant string) string {
	if !appHasTable(app, table) {
		return labelTenant
	}
	col := "id"
	switch {
	case !hasColumn(app, table, "id"):
		return ""
	case memberOfTenantKeyed(app, table):
		col = app.Group.Key
	case !tenantRootTable(app, table):
		return ""
	}
	var tenant sql.NullString
	_ = app.DB.QueryRow(fmt.Sprintf("SELECT CAST(%s AS TEXT) FROM %s WHERE %s = ?", quoteIdent(col), quoteIdent(table), quoteColumn(table, "id")), rowID).Scan(&tenant)
	return tenant.String
}
