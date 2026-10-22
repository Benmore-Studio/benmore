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

func unverifiedFixture(t *testing.T, verified int) (*App, int64) {
	t.Helper()
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureMFAColumns(app.DB)
	sid := seedMemberSession(t, app)
	_ = sid
	var uid int64
	app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email='member@test.local'").Scan(&uid)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET verified=?, totp_secret='SEALED-ATTACKER', backup_codes='[\"x\"]', mfa_last_totp='s:1' WHERE id=?", verified, uid)
	return app, uid
}

func insertLink(t *testing.T, app *App, token, kind string) {
	t.Helper()
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'member@test.local', datetime('now', '+1 hour'), ?)", hashResetToken(token), kind)
}

func completeReset(t *testing.T, app *App, token string) {
	t.Helper()
	form := url.Values{"token": {token}, "password": {"Recovered!123"}, "confirm": {"Recovered!123"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleResetPassword(httptest.NewRecorder(), r, app)
}

func mfaState(app *App, uid int64) (secret, codes, last string) {
	app.DB.QueryRow("SELECT COALESCE(totp_secret,''), COALESCE(backup_codes,''), COALESCE(mfa_last_totp,'') FROM _benmore_users WHERE id=?", uid).Scan(&secret, &codes, &last)
	return
}

// A reset proves mailbox ownership, so on an account nobody ever verified it
// must also remove a factor the registrant may have enrolled.
func TestResetOnUnverifiedAccountClearsRegistrantMFA(t *testing.T) {
	app, uid := unverifiedFixture(t, 0)
	insertLink(t, app, "reset-1", "reset")
	tok := generateToken(16)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'k', ?, '*')", uid, hashResetToken(tok))
	completeReset(t, app, "reset-1")
	if s, c, l := mfaState(app, uid); s != "" || c != "" || l != "" {
		t.Fatalf("registrant MFA survived the reset: %q %q %q", s, c, l)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid).Scan(&n)
	if n != 0 {
		t.Fatalf("sessions survived the reset: %d", n)
	}
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id=?", uid).Scan(&n)
	if n != 0 {
		t.Fatalf("API tokens survived the reset: %d", n)
	}
}

// A verified account keeps its factor across a reset, as before.
func TestResetOnVerifiedAccountKeepsMFA(t *testing.T) {
	app, uid := unverifiedFixture(t, 1)
	insertLink(t, app, "reset-2", "reset")
	completeReset(t, app, "reset-2")
	if s, _, _ := mfaState(app, uid); s != "SEALED-ATTACKER" {
		t.Fatalf("verified account lost its factor: %q", s)
	}
}

func clickVerify(app *App, token, sessionCookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/verify-email?token="+token, nil)
	if sessionCookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sessionCookie})
	}
	rec := httptest.NewRecorder()
	handleVerifyEmail(rec, r, app)
	return rec
}

func countSessions(app *App, uid int64) (n int) {
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid).Scan(&n)
	return
}

// Consuming a signup link drops every session and token the account holds
// except the one presenting the click, so what a squatting registrant made
// before the owner proved the mailbox does not persist.
func TestVerifyLinkRevokesOtherCredentials(t *testing.T) {
	app, uid := unverifiedFixture(t, 0)
	squatter := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	clicker := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'k', 'h', '*')", uid)
	insertLink(t, app, "verify-1", "verify")

	clickVerify(app, "verify-1", clicker)

	if GetSessionFromDB(app.DB, squatter) != nil {
		t.Fatal("another session survived the verification click")
	}
	if GetSessionFromDB(app.DB, clicker) == nil {
		t.Fatal("the session that clicked the link was revoked")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id=?", uid).Scan(&n)
	if n != 0 {
		t.Fatalf("API tokens survived the verification click: %d", n)
	}
	var v int
	app.DB.QueryRow("SELECT verified FROM _benmore_users WHERE id=?", uid).Scan(&v)
	if v != 1 {
		t.Fatal("account not verified")
	}
	// The registrant's MFA and password are deliberately untouched here.
	if s, _, _ := mfaState(app, uid); s == "" {
		t.Fatal("verify click must not clear MFA")
	}
}

// Clicking from a different browser (no session) changes nothing until the
// account's password is proven - the mailbox alone doesn't vouch for whoever
// chose it - and then leaves no session behind. A click on an
// already-verified account revokes nothing.
func TestVerifyLinkOtherBrowserAndAlreadyVerified(t *testing.T) {
	app, uid := unverifiedFixture(t, 0)
	insertLink(t, app, "verify-2", "verify")
	if w := clickVerify(app, "verify-2", ""); w.Code != http.StatusOK {
		t.Fatalf("sessionless click on a password account: %d, want the password prompt", w.Code)
	}
	var v int
	app.DB.QueryRow("SELECT verified FROM _benmore_users WHERE id=?", uid).Scan(&v)
	if v != 0 || countSessions(app, uid) != 1 {
		t.Fatalf("a sessionless click changed the account before the password proof: verified=%d sessions=%d", v, countSessions(app, uid))
	}
	hash, _ := generateBcryptHash([]byte("Registrant!1"))
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=? WHERE id=?", string(hash), uid)
	form := url.Values{"token": {"verify-2"}, "password": {"Registrant!1"}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, "/verify-email", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleVerifyEmailConfirm(httptest.NewRecorder(), r, app)
	if n := countSessions(app, uid); n != 0 {
		t.Fatalf("sessions left after a sessionless verification: %d", n)
	}

	s := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	insertLink(t, app, "verify-3", "verify")
	clickVerify(app, "verify-3", "")
	if GetSessionFromDB(app.DB, s) == nil {
		t.Fatal("a click on an already-verified account revoked a session")
	}
}
