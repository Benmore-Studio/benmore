//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A self-hosted app with no configured public origin used to build reset /
// verify / email-change links from the request's Host header, so a forged
// Host sent the genuine token to the attacker's domain. With no trustworthy
// origin the framework now refuses to send the link at all.
func TestCredentialLinksNeedConfiguredOrigin(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "")
	t.Setenv("CORS_ORIGIN", "")
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	mustExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('victim', 'victim@example.com', 'x', 1), ('victim2', 'victim2@example.com', 'x', 1)")
	resetRows := func(email string) int {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_password_resets WHERE email = ?", email).Scan(&n)
		return n
	}
	forgot := func(email string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, app.Paths.ForgotPassword, strings.NewReader(url.Values{"email": {email}, "_csrf": {authMintCSRFToken("")}}.Encode()))
		r.Host = "attacker.example"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		handleForgotPassword(w, r, app)
		return w
	}

	w := forgot("victim@example.com")
	if resetRows("victim@example.com") != 0 {
		t.Fatal("reset link minted from a client-supplied Host with no configured origin")
	}
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("forgot-password response changed shape (account enumeration): %d %q", w.Code, w.Header().Get("Location"))
	}

	// Email change fails closed as well, leaving nothing pending.
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)
	r.Host = "attacker.example"
	if err := requestEmailChange(app, r, 1, "new@example.com"); err == nil || !strings.Contains(err.Error(), "BENMORE_PUBLIC_URL") {
		t.Fatalf("email change without an origin: %v", err)
	}
	var pending int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes").Scan(&pending)
	if pending != 0 {
		t.Fatalf("pending email changes: %d", pending)
	}

	// Signup verification links too.
	app.Design = &DesignConfig{Auth: map[string]string{"verify_email": "true"}, SEO: map[string]string{}}
	form := url.Values{"email": {"new-user@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	sr := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	sr.Host = "attacker.example"
	sr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSignup(httptest.NewRecorder(), sr, app)
	var verifyRows int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_password_resets WHERE type = 'verify'").Scan(&verifyRows)
	if verifyRows != 0 {
		t.Fatal("verification link minted from a client-supplied Host")
	}

	// Control: a configured origin is used and the link is sent.
	app.Design.SEO["url"] = "https://app.real"
	forgot("victim2@example.com")
	if resetRows("victim2@example.com") != 1 {
		t.Fatal("configured origin did not produce a reset link")
	}

	// Only the platform router's loopback hop counts as a vetted Host.
	lr := httptest.NewRequest(http.MethodPost, "/forgot-password", nil)
	lr.RemoteAddr = "127.0.0.1:5000"
	lr.Header.Set("X-Benmore-App", "demo")
	// Unsigned, the marker never vouches for a Host - not even with the
	// rollout switch off: another tenant can reach this loopback port.
	t.Setenv("BENMORE_REQUIRE_ROUTER_SIG", "0")
	if routerVettedHost(lr) {
		t.Fatal("an unsigned router marker vouched for the request Host")
	}
	signRouterHeaders(lr.Header, lr.Method, lr.Host, "", serverSecret)
	if routerVettedHost(lr) != platformBuild {
		t.Fatalf("router hop vetted=%v in a platformBuild=%v edition", routerVettedHost(lr), platformBuild)
	}
	lr.RemoteAddr = "203.0.113.7:5000"
	if routerVettedHost(lr) {
		t.Fatal("a remote client's X-Benmore-App header was trusted")
	}
}
