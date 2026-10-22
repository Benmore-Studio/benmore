//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Session.Email was read from the session row, a copy made at sign-in. After
// an operator (SQL console, an admin flow, a support tool) changed an
// account's email, its open sessions kept answering as the OLD address for
// up to 30 days, and everything keyed by email (tenant membership, member-of
// rules, record shares, invites) kept resolving for an address the account
// no longer has - or that now belongs to someone else.
func TestSessionEmailFollowsTheAccount(t *testing.T) {
	app, _ := auditApp(t) // groups: members(org_id, email)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'moved', 'old@corp.example', 'x', 'user', 1)")
	passwordChangeExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'old@corp.example')")
	token := CreateSession(app.DB, 1, "old@corp.example", ResolveGroupID(app.DB, app.Group, "old@corp.example"), time.Hour)
	resolve := func() *Session {
		r := httptest.NewRequest(http.MethodGet, "/api/orgdocs", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return getSession(app, r)
	}
	if s := resolve(); s == nil || s.Email != "old@corp.example" || s.GroupID != "tenant-a" {
		t.Fatalf("control: %+v", s)
	}

	// The operator corrects the account's address.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET email = 'new@corp.example' WHERE id = 1")
	s := resolve()
	if s == nil {
		t.Fatal("the session ended; it should follow the account")
	}
	if s.Email != "new@corp.example" {
		t.Fatalf("session email = %q after the account moved to new@corp.example", s.Email)
	}
	if s.GroupID != "" {
		t.Fatalf("the session kept tenant %q, a membership addressed to the account's previous email", s.GroupID)
	}

	// A membership addressed to the new address applies to the same session.
	passwordChangeExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-b', 'new@corp.example')")
	if s := resolve(); s == nil || s.GroupID != "tenant-b" {
		t.Fatalf("the session did not pick up the membership of the account's current email: %+v", s)
	}
}
