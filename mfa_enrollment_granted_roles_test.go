//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// auth.require_mfa_for_roles named only the primary role column, so a member
// who holds the role through a _benmore_user_roles grant (the multi-role
// store every other gate honours, e.g. IsAdmin) signed in on a password alone.
func TestMFAEnrollmentAppliesToGrantedRoles(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	EnsureUserRolesTable(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('ops', 'ops@example.com', ?, 'user', 1)", string(hash))
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) SELECT id, 'manager' FROM _benmore_users WHERE username = 'ops'")
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}

	form := url.Values{"email": {"ops@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	sawSetup, sawSession := false, false
	for _, c := range w.Result().Cookies() {
		if c.Name == flowCookieName("_benmore_mfa_setup", true) && c.Value != "" {
			sawSetup = true
		}
		if c.Name == sessionCookieName && c.Value != "" {
			sawSession = true
		}
	}
	if sawSession || !sawSetup {
		t.Fatalf("a manager granted through _benmore_user_roles skipped MFA enrollment: session=%v setup=%v", sawSession, sawSetup)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(`{"email":"ops@example.com","password":"`+fixturePassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	tw := httptest.NewRecorder()
	handleTokenAuth(tw, r, app)
	if !strings.Contains(tw.Body.String(), "mfa_setup_required") || strings.Contains(tw.Body.String(), `"token"`) {
		t.Fatalf("token exchange for a granted role: %d %s", tw.Code, tw.Body.String())
	}
}
