//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setupTokenFromRecorder(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == flowCookieName(flowCookieMFASetup, true) && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// A social login must honour auth.require_mfa_for_roles: a user whose role
// requires MFA and who has no factor gets the setup token, never a session.
func TestOAuthMFAGateRoutesRequiredRoleToEnrollment(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureMFAColumns(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, role) VALUES (7, 'mgr', 'mgr@example.com', 'manager'), (8, 'plain', 'plain@example.com', 'user')`)

	rec := httptest.NewRecorder()
	if !oauthMFAGate(rec, httptest.NewRequest("GET", "/auth/google/callback", nil), app, 7, "mgr@example.com", "") {
		t.Fatal("required-role social login without a factor was not withheld")
	}
	tok := setupTokenFromRecorder(rec)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/mfa-setup" || tok == nil {
		t.Fatalf("not sent to enrollment: %d %q token=%v", rec.Code, rec.Header().Get("Location"), tok)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName || c.Name == devSessionCookieName {
			t.Fatal("session issued before enrollment")
		}
	}
	req := httptest.NewRequest("POST", "/api/_auth/mfa/setup", nil)
	req.Header.Set("X-MFA-Setup-Token", tok.Value)
	if uid, _, fromSetup, err := mfaCallerIdentity(app, req); err != nil || uid != 7 || !fromSetup {
		t.Fatalf("setup token does not identify the user: %d %v %v", uid, fromSetup, err)
	}

	// Unrelated role and apps without the setting behave as before.
	if oauthMFAGate(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), app, 8, "plain@example.com", "") {
		t.Fatal("role not listed in require_mfa_for_roles was gated")
	}
	app.Design = &DesignConfig{Auth: map[string]string{}}
	if oauthMFAGate(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), app, 7, "mgr@example.com", "") {
		t.Fatal("app without require_mfa_for_roles was gated")
	}
}

// The managed callback shares the gate: no session for a required role.
func TestManagedCallbackRequiredRoleGetsEnrollmentNotSession(t *testing.T) {
	t.Setenv("BENMORE_OAUTH_BROKER_URL", "https://broker.example.com")
	t.Setenv("BENMORE_OAUTH_BROKER_PROVIDERS", "google")
	t.Setenv("BENMORE_APP_NAME", "fixture")
	t.Setenv("BENMORE_OAUTH_REQUIRE_NONCE", "")
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureMFAColumns(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "user"}}
	mux := http.NewServeMux()
	RegisterOAuthRoutes(mux, app)

	rec := managedCallback(mux, managedAssertionToken(t, ""), "")
	if sessionIssued(rec) {
		t.Fatal("managed sign-in issued a session to a role that requires MFA enrollment")
	}
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "mfa-setup") {
		t.Fatalf("managed sign-in = %d %q, want enrollment redirect", rec.Code, rec.Header().Get("Location"))
	}
}
