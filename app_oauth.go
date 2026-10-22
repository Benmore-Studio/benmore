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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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
func RegisterAppOAuthProvider(mux appRouteRegistrar, app *App) {
	appOAuthEnsureTables(app)
	registerAppOAuthProvider(mux, app)
}

func registerAppOAuthProvider(mux appRouteRegistrar, app *App) {
	registerAppOAuthProviderAt(mux, app, "")
}

func registerAppOAuthProviderAt(mux appRouteRegistrar, app *App, resource string) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if appMCPManifestSnapshot(app) != nil {
			appMCPOAuthMetadata(w, r, app, resource, false)
			return
		}
		appOAuthMetadata(w, r, app)
	})
	// RFC 9728: metadata for a path-scoped resource lives at
	// /.well-known/oauth-protected-resource/<path-of-resource>. Serve both
	// the bare document and any path-suffixed variant.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		if appMCPManifestSnapshot(app) != nil {
			appMCPOAuthMetadata(w, r, app, resource, true)
			return
		}
		appOAuthPRMetadata(w, r, app, "")
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		if appMCPManifestSnapshot(app) != nil || r.PathValue("rest") == "api/_mcp" {
			if r.PathValue("rest") != "api/_mcp" {
				http.NotFound(w, r)
				return
			}
			appMCPOAuthMetadata(w, r, app, resource, true)
			return
		}
		appOAuthPRMetadata(w, r, app, "/"+r.PathValue("rest"))
	})
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		appMCPOAuthRegister(w, r, app, resource)
	})
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if appMCPManifestSnapshot(app) != nil || appMCPOAuthTarget(r.URL.Query()) {
			appMCPOAuthAuthorize(w, r, app, resource)
			return
		}
		appOAuthAuthorize(w, r, app)
	})
	mux.HandleFunc("POST /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.ParseForm() != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if appMCPManifestSnapshot(app) != nil || appMCPOAuthTarget(r.Form) {
			appMCPOAuthDecision(w, r, app, resource)
			return
		}
		appOAuthAuthorizeDecision(w, r, app)
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.ParseForm() != nil {
			httpJSON(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		if appMCPOAuthTokenTarget(r.Form) {
			appMCPOAuthToken(w, r, app, resource)
			return
		}
		appOAuthToken(w, r, app)
	})
	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, r *http.Request) { appMCPOAuthRevoke(w, r, app, resource) })
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
	// Same rule as the platform's MCP OAuth server: the scheme is checked,
	// not just the host (javascript://localhost/... would otherwise pass).
	for _, u := range req.RedirectURIs {
		if !validOAuthClientRedirect(u) {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_redirect_uri",
				"error_description": "redirect URIs must use https, or http to localhost/127.0.0.1/[::1]",
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
		serverErrorCode(w, r, app, "oauth register", err, "server_error")
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

// appParseAuthorize validates an authorize request from the query (GET) or
// the approval form (POST) against this app's registered clients.
func appParseAuthorize(app *App, v url.Values) (oauthAuthorizeParams, int, string) {
	return appParseAuthorizeWith(app.DB, v, false)
}

func appParseAuthorizeWith(db rowQuerier, v url.Values, strict bool) (oauthAuthorizeParams, int, string) {
	p := oauthAuthorizeParams{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"),
		Scope: v.Get("scope"), CodeChallenge: v.Get("code_challenge"), CodeChallengeMethod: v.Get("code_challenge_method"),
		Resource: v.Get("resource"),
	}
	if v.Get("response_type") != "code" {
		return p, http.StatusBadRequest, "response_type must be 'code'"
	}
	if p.CodeChallenge == "" || p.CodeChallengeMethod != "S256" {
		return p, http.StatusBadRequest, "PKCE required (code_challenge with S256)"
	}
	var name, redirectJSON, clientScopes string
	table := "_benmore_oauth_clients"
	if strict {
		table = "main." + table
	}
	if err := db.QueryRow(
		`SELECT name, redirect_uris, scopes FROM `+table+` WHERE client_id = ?`, p.ClientID,
	).Scan(&name, &redirectJSON, &clientScopes); err != nil {
		return p, http.StatusBadRequest, "unknown client_id"
	}
	var uris []string
	json.Unmarshal([]byte(redirectJSON), &uris)
	allowed := false
	for _, u := range uris {
		if u == p.RedirectURI {
			allowed = true
			break
		}
	}
	if !allowed {
		return p, http.StatusBadRequest, "redirect_uri not registered for this client"
	}
	if p.Scope == "" {
		p.Scope = clientScopes
	}
	p.clientName, p.clientScopes = name, clientScopes
	return p, 0, ""
}

// appOAuthGrantScope is the API-token scope an authorization grants, and the
// scope the consent page shows. A list of valid resource:action scopes
// (validateScopes) narrows the token to exactly that list. Anything else -
// no scope, `*`, or names that are not framework scopes such as `openid` -
// grants full access, and the consent page says so instead of echoing the
// client's text.
func appOAuthGrantScope(requested string) string {
	s := strings.Join(strings.Fields(requested), " ")
	if s == "" || s == "*" || validateScopes(s) != nil {
		return "*"
	}
	return s
}

// appOAuthSubject binds consent to the exact app account.
func appOAuthSubject(s *Session) string {
	return fmt.Sprintf("app-user:%d|%s", s.UserID, s.Email)
}

// appOAuthAuthorize (GET) validates, requires an app session, and shows the
// consent page. It never issues a code (see oauth_consent.go).
func appOAuthAuthorize(w http.ResponseWriter, r *http.Request, app *App) {
	p, status, msg := appParseAuthorize(app, r.URL.Query())
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	session := getSession(app, r)
	if session == nil {
		loginURL := app.Paths.Login + "?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	// Approval mints a full-access token, so it takes the user's own login -
	// not an API token, scoped session, act-as or support session.
	if !directLoginSession(app, session) {
		http.Error(w, "sign in directly to connect an app", http.StatusForbidden)
		return
	}
	redirectHost := p.RedirectURI
	if ru, err := url.Parse(p.RedirectURI); err == nil && ru.Host != "" {
		redirectHost = ru.Host
	}
	scopeText := "full access to your account"
	if g := appOAuthGrantScope(p.Scope); g != "*" {
		scopeText = g
	}
	writeOAuthConsentPage(w, p.clientName, appSiteName(app), session.Email, redirectHost, scopeText, map[string]string{
		"response_type": "code", "client_id": p.ClientID, "redirect_uri": p.RedirectURI, "state": p.State, "scope": p.Scope,
		"code_challenge": p.CodeChallenge, "code_challenge_method": p.CodeChallengeMethod, "resource": p.Resource,
		"consent": mintOAuthConsent(appOAuthSubject(session), p, time.Now()),
	}, "")
}

// appOAuthAuthorizeDecision (POST) issues a code only for an explicit,
// same-origin approval whose consent token matches this user and request.
func appOAuthAuthorizeDecision(w http.ResponseWriter, r *http.Request, app *App) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	p, status, msg := appParseAuthorize(app, r.PostForm)
	if status != 0 {
		http.Error(w, msg, status)
		return
	}
	session := getSession(app, r)
	if session == nil || !directLoginSession(app, session) || !sameOriginPost(r) || !verifyOAuthConsent(r.PostForm.Get("consent"), appOAuthSubject(session), p, time.Now()) {
		http.Error(w, "authorization not confirmed - start the connection again from your tool", http.StatusForbidden)
		return
	}
	ru, _ := url.Parse(p.RedirectURI)
	rq := ru.Query()
	if p.State != "" {
		rq.Set("state", p.State)
	}
	if r.PostForm.Get("decision") != "approve" {
		rq.Set("error", "access_denied")
		ru.RawQuery = rq.Encode()
		http.Redirect(w, r, ru.String(), http.StatusFound)
		return
	}
	// Only the code's SHA-256 is stored (as on the platform's MCP OAuth
	// server), so a database read doesn't yield a redeemable code.
	code := generateToken(32)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_oauth_codes
		(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
		VALUES (?, ?, ?, ?, 'S256', ?, ?, ?, ?)
	`, p.ClientID, session.UserID, hashAPIToken(code), p.CodeChallenge, p.RedirectURI, p.Resource, p.Scope,
		time.Now().Add(appOAuthCodeTTL).UTC().Format(time.RFC3339)); err != nil {
		serverError(w, r, app, "oauth authorize", err, "failed to issue code")
		return
	}
	rq.Set("code", code)
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
	tx, err := app.DB.Begin()
	if err != nil {
		serverErrorCode(w, r, app, "oauth token", err, "server_error")
		return
	}
	defer tx.Rollback()
	err = tx.QueryRow(`
		SELECT c.id, c.user_id, c.client_id, c.redirect_uri, c.code_challenge, c.scopes,
		       COALESCE(c.resource, ''), c.expires_at, COALESCE(cl.name, 'MCP client')
		FROM _benmore_oauth_codes c
		JOIN _benmore_users u ON u.id=c.user_id
		LEFT JOIN _benmore_oauth_clients cl ON cl.client_id = c.client_id
		WHERE c.code = ? AND COALESCE(u.password_change_required,0)=0
		AND COALESCE(u.deactivated_at,'')=''
	`, hashAPIToken(code)).Scan(&rowID, &userID, &storedClient, &storedRedirect, &challenge, &scopes, &storedResource, &expiresAtStr, &clientName)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	// One-time use: burn the code no matter how the rest goes.
	result, err := tx.Exec(`DELETE FROM _benmore_oauth_codes WHERE id = ?`, rowID)
	if err != nil {
		serverErrorCode(w, r, app, "oauth token", err, "server_error")
		return
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}

	if storedClient != clientID || storedRedirect != redirectURI {
		_ = tx.Commit()
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	if t, err := time.Parse(time.RFC3339, expiresAtStr); err != nil || time.Now().After(t) {
		_ = tx.Commit()
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code expired"})
		return
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) {
		_ = tx.Commit()
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}
	if reqResource := r.Form.Get("resource"); reqResource != "" && storedResource != "" && reqResource != storedResource {
		_ = tx.Commit()
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
	grantScope := appOAuthGrantScope(scopes)
	expiresAt := time.Now().Add(appOAuthTokenTTL).UTC().Format(time.RFC3339)
	stored, err := insertAPITokenWithinCap(tx, userID, "oauth: "+clientName, hashToken(rawToken), grantScope, expiresAt)
	if err != nil {
		serverErrorCode(w, r, app, "oauth token", err, "server_error")
		return
	}
	if !stored {
		// The account is at its API-token cap. The code stays spent.
		_ = tx.Commit()
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "access_denied", "error_description": apiTokenCapMessage})
		return
	}
	if err := tx.Commit(); err != nil {
		serverErrorCode(w, r, app, "oauth token", err, "server_error")
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"access_token": rawToken,
		"token_type":   "Bearer",
		"expires_in":   int(appOAuthTokenTTL.Seconds()),
		"scope":        grantScope,
	})
}

// validOAuthClientRedirect accepts https, or http to a loopback host, with no
// userinfo or fragment (RFC 6749 §3.1.2).
func validOAuthClientRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
	return false
}
