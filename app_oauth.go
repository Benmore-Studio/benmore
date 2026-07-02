package main

// Per-app OAuth 2.1 authorization server.
//
// Every app with auth gets an OAuth provider on its OWN origin, so external
// MCP clients (Claude.ai connectors, ChatGPT connectors, Cursor) can
// authenticate an APP user - not a platform user - without the user pasting
// raw API tokens. The app builds its MCP surface as ordinary flows with
// `auth: required`; the tokens minted here land in `_benmore_api_tokens`,
// which the existing bearer path (GetSessionFromAPIToken) already validates,
// so no auth-layer changes are needed anywhere else.
//
// Spec surface (mirrors the platform-level oauth_provider.go):
//   - RFC 8414 metadata     GET  /.well-known/oauth-authorization-server
//   - RFC 9728 PR metadata  GET  /.well-known/oauth-protected-resource[/...]
//   - RFC 7591 DCR          POST /oauth/register
//   - OAuth 2.1 + PKCE      GET  /oauth/authorize + POST /oauth/token
//
// MVP decisions (same rationale as the platform provider):
//   - Auto-approve on /authorize: the user initiated the flow from inside
//     their LLM client; they must already hold an app session (or pass the
//     app's own login first via ?next=). A future "connected apps" section
//     in the profile UI lets users revoke via the api-tokens endpoints.
//   - PKCE (S256) mandatory; all clients public; no refresh tokens yet -
//     access tokens live 30 days, then the client re-runs the flow.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	appOAuthCodeTTL  = 10 * time.Minute
	appOAuthTokenTTL = 30 * 24 * time.Hour
)

// RegisterAppOAuthProvider mounts the per-app OAuth endpoints. Called for
// every app that has auth configured (same gate as RegisterAuthRoutes).
func RegisterAppOAuthProvider(mux *http.ServeMux, app *App) {
	appOAuthEnsureTables(app)

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		appOAuthMetadata(w, r, app)
	})
	// RFC 9728: metadata for a path-scoped resource lives at
	// /.well-known/oauth-protected-resource/<path-of-resource>. Serve both
	// the bare document and any path-suffixed variant.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		appOAuthPRMetadata(w, r, app, "")
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		appOAuthPRMetadata(w, r, app, "/"+r.PathValue("rest"))
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		appOAuthRegister(w, r, app)
	})
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		appOAuthAuthorize(w, r, app)
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		appOAuthToken(w, r, app)
	})
}

func appOAuthEnsureTables(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	app.DB.Exec(`CREATE TABLE IF NOT EXISTS _benmore_oauth_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		redirect_uris TEXT NOT NULL,
		scopes TEXT NOT NULL DEFAULT '*',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	app.DB.Exec(`CREATE TABLE IF NOT EXISTS _benmore_oauth_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		code TEXT UNIQUE NOT NULL,
		code_challenge TEXT NOT NULL,
		code_challenge_method TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		resource TEXT NOT NULL DEFAULT '',
		scopes TEXT NOT NULL DEFAULT '*',
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	app.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_oauth_codes_code ON _benmore_oauth_codes(code)`)
}

// appOAuthOrigin derives the app's public origin from the request. Hosted
// apps sit behind TLS-terminating infrastructure, so anything that isn't
// localhost is https.
func appOAuthOrigin(r *http.Request) string {
	host := r.Host
	scheme := "https"
	h := host
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	if h == "localhost" || h == "127.0.0.1" {
		scheme = "http"
	}
	return scheme + "://" + host
}

// SetAppOAuthChallenge attaches the RFC 9728 discovery pointer to a 401 so
// MCP clients can find this app's authorization server.
func SetAppOAuthChallenge(w http.ResponseWriter, r *http.Request) {
	origin := appOAuthOrigin(r)
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, origin))
}

// ===== Metadata =====

func appSiteName(app *App) string {
	if app != nil && app.Design != nil && app.Design.SEO != nil && app.Design.SEO["site_name"] != "" {
		return app.Design.SEO["site_name"]
	}
	return "Benmore app"
}

func appOAuthMetadata(w http.ResponseWriter, r *http.Request, app *App) {
	issuer := appOAuthOrigin(r)
	name := appSiteName(app)
	httpJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"registration_endpoint":                 issuer + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"*"},
		"resource_parameter_supported":          true,
		"service_documentation":                 issuer + "/",
		"op_policy_uri":                         issuer + "/privacy",
		"op_tos_uri":                            issuer + "/terms",
		"resource_name":                         name,
	})
}

func appOAuthPRMetadata(w http.ResponseWriter, r *http.Request, app *App, resourcePath string) {
	issuer := appOAuthOrigin(r)
	name := appSiteName(app)
	httpJSON(w, http.StatusOK, map[string]any{
		"resource":                 issuer + resourcePath,
		"resource_name":            name,
		"authorization_servers":    []string{issuer},
		"scopes_supported":         []string{"*"},
		"bearer_methods_supported": []string{"header"},
		"resource_policy_uri":      issuer + "/privacy",
		"resource_tos_uri":         issuer + "/terms",
	})
}

// ===== Dynamic client registration (RFC 7591) =====

func appOAuthRegister(w http.ResponseWriter, r *http.Request, app *App) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		Scope        string   `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": "client_name and redirect_uris are required",
		})
		return
	}
	for _, u := range req.RedirectURIs {
		parsed, err := url.Parse(u)
		if err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_redirect_uri"})
			return
		}
		if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_redirect_uri",
				"error_description": "redirect URIs must use HTTPS",
			})
			return
		}
	}

	clientID := "app_" + generateToken(16)
	redirectJSON, _ := json.Marshal(req.RedirectURIs)
	scopes := req.Scope
	if scopes == "" {
		scopes = "*"
	}
	if _, err := app.DB.Exec(
		`INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes) VALUES (?, ?, ?, ?)`,
		clientID, req.ClientName, string(redirectJSON), scopes,
	); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	httpJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      scopes,
	})
}

// ===== Authorization endpoint =====

func appOAuthAuthorize(w http.ResponseWriter, r *http.Request, app *App) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	resource := q.Get("resource")

	if q.Get("response_type") != "code" {
		http.Error(w, "response_type must be 'code'", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE required (code_challenge with S256)", http.StatusBadRequest)
		return
	}

	var name, redirectJSON, clientScopes string
	if err := app.DB.QueryRow(
		`SELECT name, redirect_uris, scopes FROM _benmore_oauth_clients WHERE client_id = ?`, clientID,
	).Scan(&name, &redirectJSON, &clientScopes); err != nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	var uris []string
	json.Unmarshal([]byte(redirectJSON), &uris)
	allowed := false
	for _, u := range uris {
		if u == redirectURI {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// The user must hold an app session. Otherwise bounce through the
	// app's own login page and return here with identical params.
	session := getSession(app, r)
	if session == nil {
		loginURL := app.Paths.Login + "?next=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	scope := q.Get("scope")
	if scope == "" {
		scope = clientScopes
	}
	code := generateToken(32)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_oauth_codes
		(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
		VALUES (?, ?, ?, ?, 'S256', ?, ?, ?, ?)
	`, clientID, session.UserID, code, codeChallenge, redirectURI, resource, scope,
		time.Now().Add(appOAuthCodeTTL).UTC().Format(time.RFC3339)); err != nil {
		http.Error(w, "failed to issue code", http.StatusInternalServerError)
		return
	}

	ru, _ := url.Parse(redirectURI)
	rq := ru.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	ru.RawQuery = rq.Encode()
	http.Redirect(w, r, ru.String(), http.StatusFound)
}

// ===== Token endpoint =====

func appOAuthToken(w http.ResponseWriter, r *http.Request, app *App) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")
	if code == "" || clientID == "" || codeVerifier == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	var (
		rowID          int64
		userID         int64
		storedClient   string
		storedRedirect string
		challenge      string
		scopes         string
		storedResource string
		expiresAtStr   string
		clientName     string
	)
	err := app.DB.QueryRow(`
		SELECT c.id, c.user_id, c.client_id, c.redirect_uri, c.code_challenge, c.scopes,
		       COALESCE(c.resource, ''), c.expires_at, COALESCE(cl.name, 'MCP client')
		FROM _benmore_oauth_codes c
		LEFT JOIN _benmore_oauth_clients cl ON cl.client_id = c.client_id
		WHERE c.code = ?
	`, code).Scan(&rowID, &userID, &storedClient, &storedRedirect, &challenge, &scopes, &storedResource, &expiresAtStr, &clientName)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	// One-time use: burn the code no matter how the rest goes.
	app.DB.Exec(`DELETE FROM _benmore_oauth_codes WHERE id = ?`, rowID)

	if storedClient != clientID || storedRedirect != redirectURI {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	if t, err := time.Parse(time.RFC3339, expiresAtStr); err != nil || time.Now().After(t) {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code expired"})
		return
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}
	if reqResource := r.Form.Get("resource"); reqResource != "" && storedResource != "" && reqResource != storedResource {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_target",
			"error_description": "resource does not match authorization grant",
		})
		return
	}

	// Mint the access token as a plain _benmore_api_tokens row - the
	// existing bearer path validates it with zero extra plumbing, and the
	// user can see + revoke it via GET/DELETE /api/_auth/api-tokens.
	rawToken := "bma_" + generateToken(32)
	expiresAt := time.Now().Add(appOAuthTokenTTL).UTC().Format(time.RFC3339)
	if _, err := app.DB.Exec(
		`INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)`,
		userID, "oauth: "+clientName, hashToken(rawToken), "*", expiresAt,
	); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"access_token": rawToken,
		"token_type":   "Bearer",
		"expires_in":   int(appOAuthTokenTTL.Seconds()),
		"scope":        scopes,
	})
}
