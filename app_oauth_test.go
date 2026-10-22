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
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (username,email,verified) VALUES ('alice','alice@example.com',1)`)
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

func TestAppOAuthTokenRejectsPendingPasswordChange(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=1")
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('pending-client','test','["https://client.example/cb"]','*')`)
	verifier := "synthetic-pending-verifier"
	sum := sha256.Sum256([]byte(verifier))
	_, err := app.DB.Exec(`INSERT INTO _benmore_oauth_codes(client_id,user_id,code,code_challenge,code_challenge_method,redirect_uri,expires_at)
		VALUES ('pending-client',1,?,?,'S256','https://client.example/cb',?)`, hashAPIToken("pending-code"), base64.RawURLEncoding.EncodeToString(sum[:]), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"pending-client"}, "code": {"pending-code"}, "code_verifier": {verifier}, "redirect_uri": {"https://client.example/cb"}}
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	appOAuthToken(w, r, app)
	if w.Code != 400 {
		t.Fatalf("pending OAuth exchange: %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens").Scan(&n); err != nil || n != 0 {
		t.Fatalf("pending exchange minted tokens: %d %v", n, err)
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
		VALUES ('app_test1', 1, ?, ?, 'S256', 'https://claude.ai/cb', '', '*', ?)`,
		hashAPIToken("code-abc"), challenge, expires); err != nil {
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
		VALUES ('app_test1', 1, '`+hashAPIToken("code-xyz")+`', '`+challenge+`', 'S256', 'https://claude.ai/cb', '', '*', '`+expires+`')`)

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

// Any website can register a client (DCR is open), so a signed-in user
// following a link to /oauth/authorize must NOT hand that site a code.
func TestAppOAuthAuthorizeRequiresSameOriginConsent(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()
	EnsureSessionsTable(app.DB)
	mux := http.NewServeMux()
	RegisterAppOAuthProvider(mux, app)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "https://myapp.example.com/oauth/register",
		strings.NewReader(`{"client_name":"Totally Legit","redirect_uris":["https://attacker.example/cb"]}`)))
	var reg struct {
		ClientID string `json:"client_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &reg)

	var uid int64
	app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='alice@example.com'`).Scan(&uid)
	sid := CreateSession(app.DB, uid, "alice@example.com", "", time.Hour)
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {"https://attacker.example/cb"},
		"state": {"s1"}, "code_challenge": {"abc123"}, "code_challenge_method": {"S256"}}
	codes := func() int {
		var n int
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_oauth_codes`).Scan(&n)
		return n
	}

	// 1. The link click (GET) renders consent and issues nothing.
	req := httptest.NewRequest("GET", "https://myapp.example.com/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK || codes() != 0 || strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("GET issued a code or redirected: status=%d codes=%d loc=%q", w.Code, codes(), w.Header().Get("Location"))
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("consent page is frameable")
	}
	body := w.Body.String()
	i := strings.Index(body, `name="consent" value="`)
	if i < 0 {
		t.Fatalf("no consent token on page: %s", body)
	}
	consent := body[i+len(`name="consent" value="`):]
	consent = consent[:strings.Index(consent, `"`)]

	post := func(form url.Values, site string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://myapp.example.com/oauth/authorize", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("decision", "approve")

	// 2. A cross-site auto-submitted approval is refused.
	form.Set("consent", consent)
	if rec := post(form, "cross-site"); rec.Code != http.StatusForbidden || codes() != 0 {
		t.Fatalf("cross-site approval accepted: %d", rec.Code)
	}
	// 3. Same-origin but without a valid consent token is refused.
	form.Set("consent", "forged")
	if rec := post(form, "same-origin"); rec.Code != http.StatusForbidden || codes() != 0 {
		t.Fatalf("forged consent accepted: %d", rec.Code)
	}
	// 4. A genuine same-origin approval issues exactly one code.
	form.Set("consent", consent)
	rec := post(form, "same-origin")
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "code=") || codes() != 1 {
		t.Fatalf("genuine approval failed: %d loc=%q codes=%d", rec.Code, rec.Header().Get("Location"), codes())
	}
}
