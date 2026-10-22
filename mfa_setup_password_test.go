//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// A stolen session cookie must not be enough to enroll the thief's
// authenticator on someone else's account (which would also lock the owner
// out at their next login). Enabling MFA from a session re-proves the
// current password; the login-issued setup token keeps its own path.
func TestMFASetupFromSessionRequiresPassword(t *testing.T) {
	app, mux := auditApp(t)
	EnsureLoginAttemptsTable(app.DB)
	sid := createCrudScopeSession(t, app, "enroll@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	auditExec(t, app.DB, "UPDATE _benmore_users SET password_hash=? WHERE id=?", string(hash), uid)
	pending := func() bool {
		var secret string
		app.DB.QueryRow("SELECT COALESCE(totp_secret,'') FROM _benmore_users WHERE id=?", uid).Scan(&secret)
		return strings.HasPrefix(secret, "pending:")
	}

	wrong := "not-" + fixturePassword
	for _, body := range []string{"{}", `{"password":"` + wrong + `"}`} {
		w := auditPost(mux, sid, "/api/_auth/mfa/setup", "", body, true)
		if w.Code == 200 || strings.Contains(w.Body.String(), "otpauth") || pending() {
			t.Fatalf("setup with %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	w := auditPost(mux, sid, "/api/_auth/mfa/setup", "", `{"password":"`+fixturePassword+`"}`, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "otpauth") || !pending() {
		t.Fatalf("setup with the current password: %d %s", w.Code, w.Body.String())
	}

	// The enrollment token minted at login still needs no password.
	auditExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=NULL WHERE id=?", uid)
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-MFA-Setup-Token", mintMFASetupToken(app, uid, "enroll@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 200 || !pending() {
		t.Fatalf("setup token enrollment: %d %s", rec.Code, rec.Body.String())
	}
}
