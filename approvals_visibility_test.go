//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// GET /api/_approvals without ?mine=1 read `WHERE 1=1`: any signed-in user
// got every approval in the app - requester and approver emails, titles and
// decision notes - across users and tenants, and could filter by any record.
func TestApprovalsListIsScopedToParticipantsAndReaders(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	session := func(name, role string) (string, int64) {
		t.Helper()
		email := name + "@example.com"
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)", name, email, role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return CreateSession(app.DB, id, email, "", time.Hour), id
	}
	alice, aliceID := session("alice", "user") // owns docs row 1
	bob, _ := session("bob", "user")
	carol, _ := session("carol", "user")
	boss, _ := session("boss", "admin")
	if aliceID != 1 {
		t.Fatalf("fixture: alice must own docs row 1, got id %d", aliceID)
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, approver_email, title, note)
		VALUES ('docs', '1', 1, 'alice@example.com', 3, 'carol@example.com', 'Approve the Q3 layoffs memo', 'confidential')`)

	list := func(token, path string) string {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	const secret = "Q3 layoffs"
	for _, path := range []string{"/api/_approvals", "/api/_approvals?table=docs&row_id=1"} {
		if body := list(bob, path); strings.Contains(body, secret) || strings.Contains(body, "carol@example.com") {
			t.Errorf("bob (no part, cannot read the record) sees the approval via %s: %s", path, body)
		}
	}
	for name, token := range map[string]string{"alice (requester, record owner)": alice, "carol (approver)": carol, "boss (admin)": boss} {
		if body := list(token, "/api/_approvals"); !strings.Contains(body, secret) {
			t.Errorf("%s lost the approval: %s", name, body)
		}
	}
	if body := list(alice, "/api/_approvals?table=docs&row_id=1"); !strings.Contains(body, secret) {
		t.Errorf("record reader lost the record's approval history: %s", body)
	}
}
