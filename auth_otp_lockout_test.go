//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Each correct-password login issues a fresh emailed code with five tries,
// and a correct password resets the login lockout. Failed codes therefore
// have to count across rounds, or anyone holding the password can simply log
// in again and keep guessing the 6-digit second factor.
func TestOTPFailuresLockAcrossCodes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	// The step completes only for an existing account under its own email.
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (7, 'u', 'u@example.com', 'x')")
	mustExec(t, app.DB, "CREATE TABLE _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
	issue := func(code string) {
		mustExec(t, app.DB, "DELETE FROM _benmore_otp WHERE email = 'u@example.com'")
		mustExec(t, app.DB, "INSERT INTO _benmore_otp (email, code, expires_at) VALUES ('u@example.com', '"+code+"', datetime('now', '+10 minutes'))")
	}
	verify := func(code string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "_benmore_otp_uid", Value: mintSignInChallenge(app, tempCookieOTP, 7, "u@example.com", "u@example.com")})
		w := httptest.NewRecorder()
		handleVerifyOTP(w, r, app)
		return w
	}

	issue("111111")
	for i := 0; i < 5; i++ {
		verify(fmt.Sprintf("00000%d", i))
	}
	issue("222222") // the attacker logs in again with the password
	w := verify("222222")
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatal("session issued right after five failed codes")
		}
	}
	var sessions int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = 7").Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("sessions: %d", sessions)
	}
}
