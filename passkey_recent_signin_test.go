//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recentSignInApp serves password and managed (Google) sign-in on a database
// opened with production settings.
func recentSignInApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	t.Setenv("BENMORE_OAUTH_BROKER_URL", "https://broker.example.com")
	t.Setenv("BENMORE_OAUTH_BROKER_PROVIDERS", "google")
	t.Setenv("BENMORE_APP_NAME", "fixture")
	t.Setenv("BENMORE_OAUTH_REQUIRE_NONCE", "")
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsureMFAColumns(app.DB)
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	mux := http.NewServeMux()
	RegisterOAuthRoutes(mux, app)
	return app, mux
}

// responseSessionToken is the session credential a sign-in response set.
func responseSessionToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if (c.Name == sessionCookieName || c.Name == devSessionCookieName) && c.Value != "" && c.MaxAge >= 0 {
			return c.Value
		}
	}
	t.Fatalf("sign-in set no session cookie: %d %s", rec.Code, rec.Header().Get("Location"))
	return ""
}

// passkeyOptionsWith asks for passkey creation options with the session token
// sent as the browser cookie (or, with bearer, only as a Bearer header).
func passkeyOptionsWith(app *App, token string, bearer bool, body map[string]any) (int, map[string]any) {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/api/_auth/passkeys/register/options", &buf)
	req.Host = testRP
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
	if bearer {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	rec := httptest.NewRecorder()
	passkeyRegisterOptions(app)(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Someone who signed up with Google has a random password and no
// authenticator, so the password-or-code proof locked them out of passkeys.
// A sign-in made in the last few minutes is the proof instead: Google,
// password and passkey sign-ins count; an older sign-in, a Bearer-presented
// token and a session minted outside a sign-in do not.
func TestPasskeyRegistrationAcceptsRecentDirectSignIn(t *testing.T) {
	app, mux := recentSignInApp(t)

	// Google sign-in through the managed broker creates the account.
	now := time.Now()
	payload, _ := json.Marshal(managedAssertion{Email: "google-only@example.com", Provider: "google", Aud: "fixture",
		Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), JTI: generateToken(16)})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/managed/callback?token="+url.QueryEscape(brokerSign(payload, serverSecret)), nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("managed sign-in: %d %s", rec.Code, rec.Body.String())
	}
	google := responseSessionToken(t, rec)

	if code, out := passkeyOptionsWith(app, google, false, map[string]any{}); code != http.StatusOK || out["challenge"] == nil {
		t.Fatalf("fresh Google sign-in, no password: %d %v", code, out)
	}
	// The profile page posts an empty password field.
	if code, out := passkeyOptionsWith(app, google, false, map[string]any{"password": ""}); code != http.StatusOK {
		t.Fatalf("fresh Google sign-in, empty password field: %d %v", code, out)
	}
	// A password that is sent is still checked.
	if code, _ := passkeyOptionsWith(app, google, false, map[string]any{"password": "not-the-password"}); code != http.StatusForbidden {
		t.Fatalf("a wrong password was ignored: %d", code)
	}
	// The same credential presented as a Bearer token is not a browser sign-in.
	if code, _ := passkeyOptionsWith(app, google, true, map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("Bearer-presented sign-in counted as recent: %d", code)
	}
	// Ten minutes later the sign-in no longer counts.
	mustExec(t, app.DB, "UPDATE _benmore_sessions SET login_at = login_at - 660 WHERE id = '"+sessionStorageKey(google)+"'")
	if code, _ := passkeyOptionsWith(app, google, false, map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("an 11-minute-old sign-in counted as recent: %d", code)
	}

	// A session minted outside a sign-in (tooling, test identities, rows from
	// before sign-in times were recorded) never counts.
	var uid int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'google-only@example.com'").Scan(&uid); err != nil {
		t.Fatal(err)
	}
	minted := CreateSession(app.DB, uid, "google-only@example.com", "", time.Hour)
	if code, _ := passkeyOptionsWith(app, minted, false, map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("a session minted outside a sign-in counted as recent: %d", code)
	}

	// A password sign-in counts too.
	hash, err := generateBcryptHash([]byte("Pass!word123"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('pw', 'pw@example.com', '"+string(hash)+"', 1)")
	form := url.Values{"email": {"pw@example.com"}, "password": {"Pass!word123"}, "_csrf": {authMintCSRFToken("")}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handleLogin(rec, req, app)
	password := responseSessionToken(t, rec)
	if code, out := passkeyOptionsWith(app, password, false, map[string]any{}); code != http.StatusOK {
		t.Fatalf("fresh password sign-in, no password: %d %v", code, out)
	}
}
