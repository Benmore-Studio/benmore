//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// `benmore host` serves many tenants from one process, and these limiters are
// package-level. Keyed by email or IP alone, one tenant's requests spent the
// budget of every other tenant: three reset requests at app A silenced
// password reset for that address at app B, and 30 token exchanges at A locked
// the client IP out of B's token endpoint.
func TestAuthLimitersAreScopedPerApp(t *testing.T) {
	newApp := func() *App {
		app, cleanup := newTestApp(t)
		t.Cleanup(cleanup)
		EnsureUsersTable(app.DB)
		EnsurePasswordResetsTable(app.DB)
		app.Paths = DiscoverAuthPaths(nil)
		app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
		mustExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('v', 'victim@example.com', 'x', 1)")
		return app
	}
	a, b := newApp(), newApp()
	forgot := func(app *App) {
		r := httptest.NewRequest(http.MethodPost, app.Paths.ForgotPassword, strings.NewReader(url.Values{"email": {"victim@example.com"}, "_csrf": {authMintCSRFToken("")}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handleForgotPassword(httptest.NewRecorder(), r, app)
	}
	resets := func(app *App) int {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_password_resets WHERE type = 'reset'").Scan(&n)
		return n
	}
	for i := 0; i < 5; i++ {
		forgot(a)
	}
	if resets(a) != 3 {
		t.Fatalf("app A minted %d reset links; the per-address cap is 3", resets(a))
	}
	forgot(b)
	if resets(b) != 1 {
		t.Fatal("reset requests at another app spent this app's per-address budget")
	}

	// A malformed body is refused after the limiter check and before any
	// password work, so it is a cheap way to spend the per-IP budget.
	token := func(app *App) int {
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader("not json"))
		r.RemoteAddr = "192.0.2.9:4000"
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		return w.Code
	}
	for i := 0; i < 31; i++ {
		token(a)
	}
	if code := token(a); code != http.StatusTooManyRequests {
		t.Fatalf("app A was not rate limited: %d", code)
	}
	if code := token(b); code == http.StatusTooManyRequests {
		t.Fatal("token exchanges at another app spent this app's per-IP budget")
	}
}
