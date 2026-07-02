package main

// Tests for the per-app OAuth 2.1 provider (app_oauth.go): dynamic client
// registration, discovery metadata, and the PKCE code exchange minting a
// _benmore_api_tokens row that the existing bearer path validates.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newOAuthTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	appOAuthEnsureTables(app)
	EnsureAPITokensTable(app.DB)
	mustExec(t, app.DB, `CREATE TABLE IF NOT EXISTS _benmore_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT, role TEXT DEFAULT 'user', verified INTEGER DEFAULT 1,
		deactivated_at DATETIME
	)`)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (email) VALUES ('alice@example.com')`)
	return app, cleanup
}

func TestAppOAuthRegisterAndMetadata(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()

	// DCR
	body := `{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`
	req := httptest.NewRequest("POST", "https://myapp.example.com/oauth/register", strings.NewReader(body))
	w := httptest.NewRecorder()
	appOAuthRegister(w, req, app)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body %s", w.Code, w.Body.String())
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &reg)
	if !strings.HasPrefix(reg.ClientID, "app_") {
		t.Fatalf("client_id = %q, want app_ prefix", reg.ClientID)
	}

	// http (non-localhost) redirect must be refused
	req = httptest.NewRequest("POST", "https://myapp.example.com/oauth/register",
		strings.NewReader(`{"client_name":"evil","redirect_uris":["http://evil.example.com/cb"]}`))
	w = httptest.NewRecorder()
	appOAuthRegister(w, req, app)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("insecure redirect accepted: %d", w.Code)
	}

	// AS metadata reflects the app origin
	req = httptest.NewRequest("GET", "https://myapp.example.com/.well-known/oauth-authorization-server", nil)
	w = httptest.NewRecorder()
	appOAuthMetadata(w, req, app)
	var meta map[string]any
	json.Unmarshal(w.Body.Bytes(), &meta)
	if meta["issuer"] != "https://myapp.example.com" {
		t.Fatalf("issuer = %v", meta["issuer"])
	}
	if meta["token_endpoint"] != "https://myapp.example.com/oauth/token" {
		t.Fatalf("token_endpoint = %v", meta["token_endpoint"])
	}
}

func TestAppOAuthTokenExchange(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes)
		VALUES ('app_test1', 'Claude', '["https://claude.ai/cb"]', '*')`)

	verifier := "test-verifier-string-with-enough-entropy-123456"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	expires := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_oauth_codes
		(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
		VALUES ('app_test1', 1, 'code-abc', ?, 'S256', 'https://claude.ai/cb', '', '*', ?)`,
		challenge, expires); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-abc"},
		"client_id":     {"app_test1"},
		"redirect_uri":  {"https://claude.ai/cb"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "https://myapp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	appOAuthToken(w, req, app)
	if w.Code != http.StatusOK {
		t.Fatalf("token status = %d, body %s", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	json.Unmarshal(w.Body.Bytes(), &tok)
	if !strings.HasPrefix(tok.AccessToken, "bma_") || tok.TokenType != "Bearer" {
		t.Fatalf("unexpected token payload: %s", w.Body.String())
	}

	// The minted token must resolve through the normal bearer path.
	sess := GetSessionFromAPIToken(app.DB, tok.AccessToken)
	if sess == nil || sess.UserID != 1 || sess.Email != "alice@example.com" {
		t.Fatalf("minted token did not resolve to user 1: %+v", sess)
	}
	// GetSessionFromAPIToken updates last_used_at fire-and-forget; let it
	// finish before TempDir teardown or the -wal file races RemoveAll.
	time.Sleep(50 * time.Millisecond)

	// Codes are one-time: replay must fail.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "https://myapp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	appOAuthToken(w, req, app)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code replay accepted: %d", w.Code)
	}
}

func TestAppOAuthTokenRejectsBadPKCE(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes)
		VALUES ('app_test1', 'Claude', '["https://claude.ai/cb"]', '*')`)
	sum := sha256.Sum256([]byte("right-verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	expires := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_codes
		(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
		VALUES ('app_test1', 1, 'code-xyz', '`+challenge+`', 'S256', 'https://claude.ai/cb', '', '*', '`+expires+`')`)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-xyz"},
		"client_id":     {"app_test1"},
		"redirect_uri":  {"https://claude.ai/cb"},
		"code_verifier": {"WRONG-verifier"},
	}
	req := httptest.NewRequest("POST", "https://myapp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	appOAuthToken(w, req, app)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad PKCE accepted: %d body %s", w.Code, w.Body.String())
	}
	var count int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_api_tokens`).Scan(&count)
	if count != 0 {
		t.Fatalf("token minted despite PKCE failure")
	}
}
