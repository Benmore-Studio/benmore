//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A password changed from /settings must end every credential the old
// password could have produced - API tokens and OAuth codes included, not
// only the other sessions - exactly like the reset path. The session that
// proved the old password stays signed in.
func TestSettingsPasswordChangeRevokesTokensAndCodes(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	appOAuthEnsureTables(app)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash = ? WHERE id = ?", string(hash), uid)
	other := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	userToken := auditToken(t, app, sid, "*")
	oauthToken := "bma_" + generateToken(32)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id,name,token_hash,scopes) VALUES (?, 'oauth', ?, '*')", uid, hashToken(oauthToken))
	passwordChangeExec(t, app.DB, `INSERT INTO _benmore_oauth_codes (client_id,user_id,code,code_challenge,code_challenge_method,redirect_uri,expires_at)
		VALUES ('client', ?, 'pending-code', 'challenge', 'S256', 'https://client.example/cb', datetime('now','+10 minutes'))`, uid)

	next := "Changed!" + generateToken(6)
	form := url.Values{"current_password": {fixturePassword}, "new_password": {next}, "confirm_password": {next}, "_csrf": {authMintCSRFToken(sid)}}
	r := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "success=") {
		t.Fatalf("password change did not succeed: %d %s", w.Code, loc)
	}
	var stored string
	app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&stored)
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(next)) != nil {
		t.Fatal("new password was not stored")
	}
	if GetSessionFromDB(app.DB, sid) == nil {
		t.Fatal("the session that changed the password was signed out")
	}
	if GetSessionFromDB(app.DB, other) != nil {
		t.Fatal("another session survived the password change")
	}
	for name, tok := range map[string]string{"bmr_": userToken, "bma_": oauthToken} {
		if GetSessionFromAPIToken(app.DB, tok) != nil {
			t.Fatalf("%s API token survived the password change", name)
		}
	}
	var codes, audits int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_oauth_codes WHERE user_id = ?", uid).Scan(&codes)
	if codes != 0 {
		t.Fatalf("%d OAuth codes survived the password change", codes)
	}
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'password_change' AND user_id = ?", uid).Scan(&audits)
	if audits != 1 {
		t.Fatalf("password change audit rows = %d, want 1", audits)
	}
}
