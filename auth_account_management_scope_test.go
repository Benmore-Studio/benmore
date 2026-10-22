//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A token scoped to notes:read (handed to an integration, say) is delegated
// access. It must not rewrite the owner's profile or manage the owner's
// sessions, tokens, MFA or password - only an unscoped credential may.
func TestScopedCredentialsCannotManageAccount(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	RegisterOAuthTokensAPI(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash = ?, first_name = 'Owner' WHERE id = ?", string(hash), uid)
	mfaMux := http.NewServeMux()
	RegisterMFARoutes(mfaMux, app)

	other := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)
	otherHash := sha256.Sum256([]byte(other))
	otherOpaque := hex.EncodeToString(otherHash[:])[:12]
	full := auditToken(t, app, sid, "*")
	var fullID int64
	app.DB.QueryRow("SELECT id FROM _benmore_api_tokens WHERE token_hash = ?", hashToken(full)).Scan(&fullID)
	scopedToken := auditToken(t, app, sid, "notes:read")
	scopedSession := CreateSession(app.DB, uid, "member@test.local", "", time.Hour, "notes:read")

	call := func(m *http.ServeMux, method, path, cred, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if strings.HasPrefix(body, "{") {
			r.Header.Set("Content-Type", "application/json")
		} else {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.Header.Set("Authorization", "Bearer "+cred)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	next := "Changed!" + generateToken(6)
	pwForm := url.Values{"current_password": {fixturePassword}, "new_password": {next}, "confirm_password": {next}}.Encode()
	for _, cred := range []string{scopedToken, scopedSession} {
		for _, c := range []struct {
			m                  *http.ServeMux
			method, path, body string
		}{
			{mux, "PATCH", "/api/_auth/profile", `{"first_name":"Integration"}`},
			{mux, "GET", "/api/_auth/sessions", ""},
			{mux, "DELETE", "/api/_auth/sessions/" + otherOpaque, ""},
			{mux, "GET", "/api/_auth/api-tokens", ""},
			{mux, "DELETE", "/api/_auth/api-tokens/" + itoa(int(fullID)), ""},
			{mux, "DELETE", "/api/_auth/oauth-tokens/google", ""},
			{mfaMux, "POST", "/api/_auth/mfa/setup", `{"password":"` + fixturePassword + `"}`},
			{mux, "POST", "/settings/password", pwForm},
		} {
			if w := call(c.m, c.method, c.path, cred, c.body); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with scoped credential: %d %s", c.method, c.path, w.Code, w.Body.String())
			}
		}
	}
	var first, secret string
	var tokens int
	app.DB.QueryRow("SELECT first_name, COALESCE(totp_secret,'') FROM _benmore_users WHERE id = ?", uid).Scan(&first, &secret)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?", uid).Scan(&tokens)
	if first != "Owner" || secret != "" || tokens != 2 || GetSessionFromDB(app.DB, other) == nil {
		t.Fatalf("scoped credential changed the account: first=%q mfa=%q tokens=%d otherSession=%v", first, secret, tokens, GetSessionFromDB(app.DB, other) != nil)
	}
	var h string
	app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&h)
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(fixturePassword)) != nil {
		t.Fatal("scoped credential changed the password")
	}

	// Controls: unscoped credentials keep working.
	if w := call(mux, "PATCH", "/api/_auth/profile", full, `{"first_name":"Owner2"}`); w.Code != http.StatusOK {
		t.Fatalf("full-access token profile edit: %d %s", w.Code, w.Body.String())
	}
	if w := call(mux, "DELETE", "/api/_auth/sessions/"+otherOpaque, sid, ""); w.Code != http.StatusOK {
		t.Fatalf("login session revoke: %d %s", w.Code, w.Body.String())
	}
}
