//go:build !cli

package main

// Live membership.
//
// A membership row only grants access while it is live: not soft-deleted
// (deleted_at IS NULL, when the table has that column) and - for the
// groups: membership table with groups.active_field set - active (the
// column is truthy). Every membership check shares membershipLiveConds:
// tenant resolution (ResolveGroupID, role_field, _switch_group, the cached
// session group, the group user directory, bootstrap), member-of: EXISTS
// guards and ws_rooms: joins. A malformed or missing active_field column
// grants nothing (fail closed) rather than falling back to "any row".

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// membershipIdentRe matches the identifiers interpolated into membership
// SQL; configuration values outside it never reach a query.
var membershipIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// rowQuerier is the QueryRow half of *sql.DB / *sql.Tx.
type rowQuerier interface {
	QueryRow(string, ...any) *sql.Row
}

// membershipLiveConds returns the conditions (each with a leading " AND ")
// a row of membership table `table` must meet to grant access. qual
// qualifies the column names ("" for none). hasCol reports whether the
// table has a column. Both columns are written bare: deleted_at is a
// constant, and active_field is used only once it is a plain identifier the
// table has.
func membershipLiveConds(group *GroupConfig, table, qual string, hasCol func(string) bool) string {
	col := func(c string) string {
		if qual == "" {
			return c
		}
		return quoteIdent(qual) + "." + c
	}
	var b strings.Builder
	if hasCol("deleted_at") {
		b.WriteString(" AND " + col("deleted_at") + " IS NULL")
	}
	if group != nil && group.ActiveField != "" && strings.EqualFold(table, group.Table) {
		if !membershipIdentRe.MatchString(group.ActiveField) || !hasCol(group.ActiveField) {
			return " AND 0" // declared but unusable: no membership is live
		}
		fmt.Fprintf(&b, " AND COALESCE(LOWER(CAST(%s AS TEXT)), '') NOT IN ('', '0', 'false', 'no', 'off')", col(group.ActiveField))
	}
	return b.String()
}

// dbColumnChecker reports columns from the live schema, for callers that
// have a database handle but not the app's loaded table list.
func dbColumnChecker(db rowQuerier, table string) func(string) bool {
	has, _ := dbColumnCheckerWith(db, table, "")
	return has
}

// Ordinary SQL keeps SQLite's schema resolution; connector callers pin main.
// Report Scan errors, which can occur after QueryRow has returned successfully.
func dbColumnCheckerWith(db rowQuerier, table, schema string) (func(string) bool, func() error) {
	if prefix, bare, qualified := strings.Cut(table, "."); qualified && strings.EqualFold(prefix, "main") && isValidColumnName(bare) {
		schema, table = "main", bare
	}
	var checkErr error
	return func(col string) bool {
		var n int
		var err error
		if schema == "" {
			err = db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ? COLLATE NOCASE", table, col).Scan(&n)
		} else {
			pragma := "pragma_table_info"
			if schema == "main" {
				pragma = "main.pragma_table_info"
			}
			err = db.QueryRow("SELECT COUNT(*) FROM "+pragma+"(?,?) WHERE name = ? COLLATE NOCASE", table, schema, col).Scan(&n)
		}
		if err != nil {
			checkErr = err
		}
		return err == nil && n > 0
	}, func() error { return checkErr }
}

// appColumnChecker reports columns from the app's loaded schema.
func appColumnChecker(app *App, table string) func(string) bool {
	return func(col string) bool { return hasColumn(app, table, col) }
}

// groupMemberValue is the value the groups membership table's user_field is
// compared against for session: the verified email for email-keyed tables,
// else the user id. ok=false when the session can hold no membership.
func groupMemberValue(group *GroupConfig, session *Session) (any, bool) {
	if emailKeyedColumn(group.UserField) {
		email := sessionGrantEmail(session)
		return email, email != ""
	}
	return session.UserID, true
}

// groupMembershipLive reports whether session holds a live membership row
// in groupID - the check behind _switch_group and the per-request
// revalidation of a session's cached tenant.
func groupMembershipLive(db rowQuerier, group *GroupConfig, session *Session, groupID string) bool {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" || groupID == "" {
		return false
	}
	member, ok := groupMemberValue(group, session)
	if !ok {
		return false
	}
	var x int
	q := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ?%s LIMIT 1",
		quoteIdent(group.Table), quoteColumn(group.Table, group.Key), quoteColumn(group.Table, group.UserField),
		membershipLiveConds(group, group.Table, "", dbColumnChecker(db, group.Table)))
	return db.QueryRow(q, groupID, member).Scan(&x) == nil
}
