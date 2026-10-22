//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// tokenAuthFixture seeds one password account and returns a caller for
// POST /api/_auth/token from a per-test client address (the endpoint's IP
// limiter is process-wide).
func tokenAuthFixture(t *testing.T, email, password, ip string) (*App, int64, func(body map[string]string) *httptest.ResponseRecorder) {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES (?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	call := func(body map[string]string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		return w
	}
	return app, uid, call
}

// auth.otp makes every password login prove the emailed code before a
// session exists. The password-only Bearer exchange must not mint a session
// around that second factor.
func TestTokenAuthDoesNotBypassEmailOTP(t *testing.T) {
	app, uid, call := tokenAuthFixture(t, "otp@example.com", fixturePassword, "192.0.2.41")
	app.Design = &DesignConfig{Auth: map[string]string{"otp": "true"}}

	w := call(map[string]string{"email": "otp@example.com", "password": fixturePassword})
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("password-only token issued despite auth.otp: %d %s", w.Code, w.Body.String())
	}
	var sessions int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", uid).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions minted without OTP: %d %v", sessions, err)
	}

	// Control: without auth.otp the exchange still works.
	app.Design = &DesignConfig{Auth: map[string]string{}}
	if w := call(map[string]string{"email": "otp@example.com", "password": fixturePassword}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("token exchange broken without otp: %d %s", w.Code, w.Body.String())
	}
}
