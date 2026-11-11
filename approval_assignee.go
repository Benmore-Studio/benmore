package main

import (
	"database/sql"
	"errors"
	"strings"
)

// approval_assignee.go - who an approval (_benmore_approvals) is assigned to.
//
// POST /api/_approvals names its approver by email address, so an approval
// is an email-keyed grant like an invite or a record share (email_grants.go):
// the address identifies a person only once they have proven control of it.
// Otherwise someone who signs up as the approver's address ahead of the
// request reads it and decides it.
//
//   - A row that carries approver_email belongs to the account whose trusted
//     address (verified or grandfathered, sessionGrantEmail) is that address,
//     in any letter case. approver_id on such a row only records who was
//     notified: rows stored before the lookup below required a trusted
//     address hold the id of whichever account had registered the address,
//     and an account can verify a different address later, so the id alone
//     decides nothing there.
//   - A row with no approver_email names its approver by id (written by app
//     or operator SQL); no address is involved, so the id is the assignment.
//
// The list and decide handlers both use approvalAssignedSQL, so who sees a
// request under ?mine=1 and who may decide it cannot drift apart.

// approvalApproverByEmail is the account a request addressed to email is
// bound to and notifies: the one holding that address with a trusted email.
// Not valid when no such account exists yet; the request then waits for
// whoever proves the address. email is already normalized.
func approvalApproverByEmail(db *sql.DB, email string) (sql.NullInt64, error) {
	var id sql.NullInt64
	if email == "" {
		return id, nil
	}
	err := db.QueryRow("SELECT u.id FROM _benmore_users u WHERE u.email = ? COLLATE NOCASE AND "+emailTrustedSQL("u")+" ORDER BY u.id LIMIT 1", email).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.NullInt64{}, nil
	}
	return id, err
}

// approvalAssignedSQL is the predicate "this _benmore_approvals row is
// assigned to this session's account", with its arguments.
func approvalAssignedSQL(s *Session) (string, []any) {
	byID := "(COALESCE(approver_email, '') = '' AND approver_id = ?)"
	email := sessionGrantEmail(s)
	if email == "" {
		return byID, []any{s.UserID}
	}
	return "(" + byID + " OR approver_email = ? COLLATE NOCASE)", []any{s.UserID, email}
}

// approvalAddressKey is the stored form of a request's approver address:
// trimmed, with ASCII letters lowercased and every other character kept.
// Every lookup of it compares with COLLATE NOCASE, which folds ASCII only,
// and OAuth sign-up stores a provider's address as given. normalizeEmail
// lowercases all of Unicode, so a request to an account stored as
// "Élise@example.com" became "élise@example.com", which no NOCASE comparison matches:
// nobody was notified and Élise could never list or decide it.
func approvalAddressKey(addr string) string {
	addr = strings.TrimSpace(addr)
	b := []byte(addr)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
