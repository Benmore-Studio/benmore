//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A bcrypt comparison costs ~250ms; skipping it for an unknown account made
// the response time an oracle for which addresses are registered.
func TestUnknownAccountSignInSpendsAPasswordCheck(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	const floor = 40 * time.Millisecond

	form := url.Values{"email": {"nobody@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	start := time.Now()
	handleLogin(httptest.NewRecorder(), r, app)
	if d := time.Since(start); d < floor {
		t.Fatalf("login for an unknown account returned in %v", d)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(`{"email":"nobody2@example.com","password":"`+fixturePassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	start = time.Now()
	handleTokenAuth(w, r, app)
	if d := time.Since(start); d < floor || w.Code != http.StatusUnauthorized {
		t.Fatalf("token exchange for an unknown account: %d in %v", w.Code, d)
	}
}
