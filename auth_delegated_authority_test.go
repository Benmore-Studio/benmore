//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func delegatedAuthoritySession(app *App, token string) *Session {
	r := httptest.NewRequest(http.MethodGet, "/api/orgdocs", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return getSession(app, r)
}

// Step-in (POST /api/_auth/act_as) is an admin's state: it replaces the
// session's tenant with the one stepped into. It lives on the session row, so
// when the admin was demoted the session kept answering in that tenant - now
// as an ordinary member of a tenant the account never belonged to - for the
// rest of its lifetime.
func TestStepInEndsWhenTheAccountIsNoLongerAdmin(t *testing.T) {
	app, mux := auditApp(t) // groups: members(org_id, email); orgdocs: group
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'boss', 'boss@corp.example', 'x', 'admin', 1)")
	// The account's own tenant, as a member.
	passwordChangeExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'boss@corp.example')")
	token := CreateSession(app.DB, 1, "boss@corp.example", "tenant-a", time.Hour)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_sessions SET acting_as_group = 'tenant-b' WHERE id = ?", sessionStorageKey(token))

	if s := delegatedAuthoritySession(app, token); s == nil || s.EffectiveGroupID() != "tenant-b" {
		t.Fatalf("control: a stepped-in admin = %+v", s)
	}

	// The account loses the admin role.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET role = 'user' WHERE id = 1")
	s := delegatedAuthoritySession(app, token)
	if s == nil {
		t.Fatal("the session ended; the account is still active")
	}
	if s.EffectiveGroupID() != "tenant-a" {
		t.Fatalf("a demoted account kept the stepped-into tenant: effective=%q", s.EffectiveGroupID())
	}
	// The stale step-in still marks the session as not a plain sign-in, so
	// the direct-sign-in gates keep refusing it until it steps out.
	if s.ActingAsGroup == "" || credentialManagementSession(app, s) {
		t.Fatalf("a session with a stale step-in passes as a direct sign-in: acting_as=%q", s.ActingAsGroup)
	}
	// What it reads is its own tenant's rows, not the other tenant's.
	r := httptest.NewRequest(http.MethodGet, "/api/orgdocs", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, "private-a") || strings.Contains(body, "private-b") {
		t.Fatalf("list as the demoted account: %d %s", w.Code, body)
	}

	// An admin by global grant keeps its step-in.
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (1, 'admin')")
	if s := delegatedAuthoritySession(app, token); s == nil || s.EffectiveGroupID() != "tenant-b" {
		t.Fatalf("an admin by global grant lost its step-in: %+v", s)
	}
}

// A support impersonation session acts on the authority of the admin who
// started it. It is a row under the target user's id, so nothing about the
// admin was checked again: an admin who was demoted or deactivated mid-session
// kept acting as the customer until the hour ran out.
func TestSupportSessionEndsWhenItsAdminLosesAuthority(t *testing.T) {
	for _, c := range []struct{ name, change string }{
		{"demoted", "UPDATE _benmore_users SET role = 'user' WHERE id = 1"},
		{"deactivated", "UPDATE _benmore_users SET deactivated_at = datetime('now') WHERE id = 1"},
		{"must replace a temporary password", "UPDATE _benmore_users SET password_change_required = 1 WHERE id = 1"},
		{"deleted", "DELETE FROM _benmore_users WHERE id = 1"},
	} {
		app, _ := auditApp(t)
		if err := EnsureUserRolesTable(app.DB); err != nil {
			t.Fatal(err)
		}
		passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'boss', 'boss@corp.example', 'x', 'admin', 1), (2, 'customer', 'customer@corp.example', 'x', 'user', 1)")
		support := CreateSession(app.DB, 2, "customer@corp.example", "", time.Hour)
		passwordChangeExec(t, app.DB, "UPDATE _benmore_sessions SET is_impersonation = 1, impersonator_user_id = 1, impersonator_email = 'boss@corp.example' WHERE id = ?", sessionStorageKey(support))
		// Tooling sessions name no impersonator and are unaffected.
		delegated := createDelegatedSession(app.DB, 2, "customer@corp.example", "", time.Hour)
		own := CreateSession(app.DB, 2, "customer@corp.example", "", time.Hour)

		if s := delegatedAuthoritySession(app, support); s == nil || s.UserID != 2 || s.ImpersonatorUserID != 1 {
			t.Fatalf("%s: control: the support session does not resolve: %+v", c.name, s)
		}
		passwordChangeExec(t, app.DB, c.change)
		if s := delegatedAuthoritySession(app, support); s != nil {
			t.Errorf("%s: the support session outlived its admin's authority: %+v", c.name, s)
		}
		if delegatedAuthoritySession(app, delegated) == nil || delegatedAuthoritySession(app, own) == nil {
			t.Errorf("%s: the customer's own or a delegated session stopped resolving", c.name)
		}
	}

	// An admin by global grant keeps its support session.
	app, _ := auditApp(t)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'granted', 'granted@corp.example', 'x', 'user', 1), (2, 'customer', 'customer@corp.example', 'x', 'user', 1)")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (1, 'admin')")
	support := CreateSession(app.DB, 2, "customer@corp.example", "", time.Hour)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_sessions SET is_impersonation = 1, impersonator_user_id = 1 WHERE id = ?", sessionStorageKey(support))
	if s := delegatedAuthoritySession(app, support); s == nil {
		t.Fatal("the support session of an admin by global grant does not resolve")
	}
}
