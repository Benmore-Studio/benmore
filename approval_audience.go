package main

import (
	"database/sql"
	"fmt"
	"strings"
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
// Not bounded, so any account can be named, as before: a record with no
// tenant value, a table without the tenant key, and a free-form label that
// names no table.
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
	if s.IsAdminBypass() || !memberOfTenantKeyed(app, table) {
		return "", nil, false
	}
	// A record that carries no tenant (Session.HasGroup's "" and "0") has
	// none to stay inside.
	parts := []string{fmt.Sprintf("COALESCE(CAST(%s AS TEXT), '') IN ('', '0')", quoteIdent(app.Group.Key))}
	if tenant, targs, ok := rowTenantClause(app, table, s); ok {
		parts = append(parts, tenant)
		args = append(args, targs...)
	}
	// A reader of the record is in its audience whatever tenant they are in.
	// The row scope alone says nothing on a table the session's read mode
	// refuses, so the mode gate comes first (as in canAccessRow).
	if SessionCanAccessTable(app, table, OpRead, s) {
		if reader, rargs, _ := rowScopeClause(app, table, s, "view"); reader != "" {
			parts = append(parts, reader)
			args = append(args, rargs...)
		}
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, true
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

// approvalAudienceSQL is the predicate over _benmore_approvals rows "the
// record this request names admits this session as its approver", with its
// arguments: approvalRecordAudience for the table each row names. A row
// whose table_name is no tenant-keyed app table (a label, a table without
// the tenant key) is admitted. A record that no longer exists has no tenant
// to check and admits nobody, or deleting it would hand the request to the
// outside account it named.
func approvalAudienceSQL(app *App, s *Session) (string, []any) {
	var b strings.Builder
	var args []any
	for _, t := range app.Tables {
		pred, pargs, bounded := approvalRecordAudience(app, t.Name, s)
		if !bounded {
			continue
		}
		args = append(args, t.Name)
		if !hasColumn(app, t.Name, "id") {
			b.WriteString(" WHEN ? THEN 0")
			continue
		}
		fmt.Fprintf(&b, " WHEN ? THEN EXISTS (SELECT 1 FROM %s WHERE %s = _benmore_approvals.row_id AND %s)",
			quoteIdent(t.Name), quoteColumn(t.Name, "id"), pred)
		args = append(args, pargs...)
	}
	if b.Len() == 0 {
		return "1", nil
	}
	// NOCASE: a request stored under another letter case of a table name,
	// before requests resolved it (approvalTableName), is bounded as well.
	return "(CASE _benmore_approvals.table_name COLLATE NOCASE" + b.String() + " ELSE 1 END)", args
}

// approvalApproverSQL is the predicate "this _benmore_approvals row is this
// session's to decide": assigned to its account (approvalAssignedSQL) on a
// record that admits it (approvalAudienceSQL). The list, ?mine=1 and /decide
// share it, so they cannot drift apart.
func approvalApproverSQL(app *App, s *Session) (string, []any) {
	assigned, args := approvalAssignedSQL(s)
	audience, audienceArgs := approvalAudienceSQL(app, s)
	return "(" + assigned + " AND " + audience + ")", append(args, audienceArgs...)
}

// approvalBindApprover records account userID as the approver of the request
// just stored (approvalID, on table/rowID) when the request is that
// account's to decide, and reports whether it did. Only then is the account
// notified. It applies approvalApproverSQL, the test the list and /decide
// apply, to the stored row.
func approvalBindApprover(app *App, approvalID, userID int64, table, rowID string) (bool, error) {
	approver := approvalApproverIdentity(app, userID, table, rowID)
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

// approvalApproverIdentity is account userID as a request by it would be
// resolved, for evaluating the audience of the record table/rowID when the
// approval is requested (the approver is not the caller then). Its tenant is
// the record's when the account holds a live membership there, the check
// behind a tenant switch and the per-request revalidation of a session's
// tenant (getSession), and none otherwise. nil when the account is gone.
func approvalApproverIdentity(app *App, userID int64, table, rowID string) *Session {
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
	if g := app.Group; !s.IsAdmin() && appHasTable(app, table) && memberOfTenantKeyed(app, table) && hasColumn(app, table, "id") {
		var tenant sql.NullString
		_ = app.DB.QueryRow(fmt.Sprintf("SELECT CAST(%s AS TEXT) FROM %s WHERE id = ?", quoteIdent(g.Key), quoteIdent(table)), rowID).Scan(&tenant)
		// A request by the account would be in the record's tenant: a live
		// membership row, or the tenant its proven address resolves to (a
		// membership column that holds addresses under another name).
		if tenant.String != "" && tenant.String != "0" &&
			(groupMembershipLive(app.DB, g, s, tenant.String) ||
				sessionGrantEmail(s) != "" && ResolveGroupID(app.DB, g, s.Email) == tenant.String) {
			s.GroupID = tenant.String
		}
	}
	s.Roles = LoadSessionRoles(app.DB, userID, s.Role, s.EffectiveGroupID())
	return applySessionRoleScopes(app, s)
}
