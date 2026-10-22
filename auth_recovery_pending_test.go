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

// Someone who learned the password can request an email change to an inbox
// they control. When the owner then resets or changes the password, that
// pending change (and any unused reset link) must die with the old
// credential, or confirming it afterwards still hands over the account.
func TestPasswordReplacementCancelsPendingRecovery(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	ensureEmailChangesTable(app.DB)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash = ? WHERE id = ?", string(hash), uid)
	pending := func(token string) {
		passwordChangeExec(t, app.DB, "DELETE FROM _benmore_email_changes WHERE user_id = ?", uid)
		passwordChangeExec(t, app.DB, "INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'attacker@evil.example', ?, datetime('now', '+1 hour'))", uid, hashResetToken(token))
	}
	resetLink := func(token string) {
		passwordChangeExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'member@test.local', datetime('now', '+1 hour'), 'reset')", hashResetToken(token))
	}

	// Recovery through a reset link.
	pending("change-1")
	resetLink("reset-1")
	form := url.Values{"token": {"reset-1"}, "password": {"Recovered!123"}, "confirm": {"Recovered!123"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleResetPassword(httptest.NewRecorder(), r, app)
	if _, _, _, err := confirmEmailChange(app, "change-1"); err == nil {
		t.Fatal("email change requested before the reset still applied")
	}

	// Voluntary change from settings.
	sid = CreateSession(app.DB, uid, "member@test.local", "", 0)
	pending("change-2")
	resetLink("reset-2")
	form = url.Values{"current_password": {"Recovered!123"}, "new_password": {"Changed!456"}, "confirm_password": {"Changed!456"}, "_csrf": {authMintCSRFToken(sid)}}
	r = httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	mux.ServeHTTP(httptest.NewRecorder(), r)
	var h string
	app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&h)
	if bcrypt.CompareHashAndPassword([]byte(h), []byte("Changed!456")) != nil {
		t.Fatal("fixture: settings password change did not apply")
	}
	if _, _, _, err := confirmEmailChange(app, "change-2"); err == nil {
		t.Fatal("email change requested before the password change still applied")
	}
	var used int
	app.DB.QueryRow("SELECT used FROM _benmore_password_resets WHERE token = ?", hashResetToken("reset-2")).Scan(&used)
	if used != 1 {
		t.Fatal("reset link issued before the password change still works")
	}
}
