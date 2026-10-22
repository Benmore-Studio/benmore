//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Browsers delete ASCII tab and newline from a URL before parsing it, so a
// post-login "next" of "/\t/evil.example" is followed as //evil.example.
// net/http writes such a Location through unchanged.
func TestIsSafeNextRejectsControlCharacters(t *testing.T) {
	for _, next := range []string{"/\t/evil.example", "/\t\\evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00/evil.example", "/ok\x7f"} {
		if isSafeNext(next) {
			t.Errorf("isSafeNext(%q) = true", next)
		}
	}
	for _, next := range []string{"/", "/dashboard", "/auth/cli-session?port=8123", "/search?q=%09a"} {
		if !isSafeNext(next) {
			t.Errorf("isSafeNext(%q) = false", next)
		}
	}

	// End to end through the OTP completion redirect.
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (7, 'u', 'u@example.com', 'x')")
	mustExec(t, app.DB, "CREATE TABLE _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
	mustExec(t, app.DB, "INSERT INTO _benmore_otp (email, code, expires_at) VALUES ('u@example.com', '123456', datetime('now', '+10 minutes'))")
	form := url.Values{"code": {"123456"}, "next": {"/\t/evil.example"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "_benmore_otp_uid", Value: mintSignInChallenge(app, tempCookieOTP, 7, "u@example.com", "u@example.com")})
	w := httptest.NewRecorder()
	handleVerifyOTP(w, r, app)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || strings.ContainsAny(loc, "\t\r\n") || strings.Contains(loc, "evil.example") {
		t.Fatalf("unsafe post-login redirect: %d %q", w.Code, loc)
	}
	var sessions int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = 7").Scan(&sessions)
	if sessions != 1 {
		t.Fatalf("the OTP step did not complete, so the redirect under test was not the post-login one (sessions=%d)", sessions)
	}
}
