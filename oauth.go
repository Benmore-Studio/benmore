//go:build !cli

package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// OAuthProvider defines an OAuth2 provider configuration.
// Built-in providers (Google, GitHub, Microsoft) are defaults.
// Apps can override or add custom providers via app.yaml auth.oauth section.
type OAuthProvider struct {
	Name          string
	ClientID      string
	ClientSecret  string
	AuthURL       string
	TokenURL      string
	UserInfoURL   string
	Scopes        []string
	EmailField    string   // JSON field containing email in userinfo response
	NameField     string   // JSON field containing display name
	EmailFallback []string // Alternative JSON fields to check for email (e.g., "userPrincipalName")
	EmailEndpoint string   // Separate endpoint to fetch email if not in userinfo (e.g., GitHub /user/emails)
}

// Default OAuth providers. Apps can override via env vars or app.yaml.
var oauthProviders = map[string]OAuthProvider{
	"google": {
		Name:        "Google",
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:      []string{"email", "profile"},
		EmailField:  "email",
		NameField:   "name",
	},
	"github": {
		Name:          "GitHub",
		AuthURL:       "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		UserInfoURL:   "https://api.github.com/user",
		Scopes:        []string{"user:email"},
		EmailField:    "email",
		NameField:     "login",
		EmailEndpoint: "https://api.github.com/user/emails", // GitHub may not return email in userinfo
	},
	"microsoft": {
		Name:          "Microsoft",
		AuthURL:       "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:   "https://graph.microsoft.com/v1.0/me",
		Scopes:        []string{"openid", "email", "profile", "User.Read"},
		EmailField:    "mail",
		NameField:     "displayName",
		EmailFallback: []string{"userPrincipalName"}, // Microsoft may use this instead of mail
	},
}

// LoadCustomOAuthProviders reads custom OAuth providers from app.yaml oauth: section.
// This allows developers to add ANY OAuth2 provider without framework changes.
//
//	oauth:
//	  discord:
//	    auth_url: https://discord.com/api/oauth2/authorize
//	    token_url: https://discord.com/api/oauth2/token
//	    userinfo_url: https://discord.com/api/users/@me
//	    scopes: "identify email"
//	    email_field: email
//	    name_field: username
func LoadCustomOAuthProviders(dir string) {
	path := dir + "/app.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return
	}
	oauthRaw, ok := raw["oauth"].(map[string]any)
	if !ok {
		return
	}
	for name, v := range oauthRaw {
		cfg, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// Don't override built-in providers unless explicitly configured
		if _, exists := oauthProviders[name]; exists {
			continue
		}
		provider := OAuthProvider{
			Name:       strings.Title(name),
			EmailField: "email",
			NameField:  "name",
		}
		if v, ok := cfg["auth_url"].(string); ok {
			provider.AuthURL = v
		}
		if v, ok := cfg["token_url"].(string); ok {
			provider.TokenURL = v
		}
		if v, ok := cfg["userinfo_url"].(string); ok {
			provider.UserInfoURL = v
		}
		if v, ok := cfg["email_field"].(string); ok {
			provider.EmailField = v
		}
		if v, ok := cfg["name_field"].(string); ok {
			provider.NameField = v
		}
		if v, ok := cfg["email_endpoint"].(string); ok {
			provider.EmailEndpoint = v
		}
		if v, ok := cfg["scopes"].(string); ok {
			provider.Scopes = strings.Fields(v)
		}
		// Security: warn if OAuth endpoints are not HTTPS (tokens leak in transit)
		for _, u := range []string{provider.AuthURL, provider.TokenURL, provider.UserInfoURL} {
			if u != "" && !strings.HasPrefix(u, "https://") {
				log.Printf("  WARNING: oauth provider '%s' has non-HTTPS URL: %s", name, u)
			}
		}
		oauthProviders[name] = provider
		log.Printf("  oauth: custom provider '%s' registered", name)
	}
}

// RegisterOAuthRoutes sets up OAuth login/callback routes for configured providers.
func RegisterOAuthRoutes(mux *http.ServeMux, app *App) {
	// Load custom providers from app.yaml before registering routes
	LoadCustomOAuthProviders(app.Dir)

	for providerName, provider := range oauthProviders {
		clientID := GetEnv(app.Dir, strings.ToUpper(providerName)+"_CLIENT_ID")
		clientSecret := GetEnv(app.Dir, strings.ToUpper(providerName)+"_CLIENT_SECRET")

		if clientID == "" || clientSecret == "" {
			continue // skip unconfigured providers
		}

		p := provider
		p.ClientID = clientID
		p.ClientSecret = clientSecret
		name := providerName

		// /auth/{provider} → redirect to OAuth consent screen
		mux.HandleFunc(fmt.Sprintf("GET /auth/%s", name), func(w http.ResponseWriter, r *http.Request) {
			handleOAuthRedirect(w, r, app, &p, name)
		})

		// /auth/{provider}/callback → handle OAuth response
		mux.HandleFunc(fmt.Sprintf("GET /auth/%s/callback", name), func(w http.ResponseWriter, r *http.Request) {
			handleOAuthCallback(w, r, app, &p, name)
		})

		log.Printf("  oauth: %s (/auth/%s)", p.Name, name)
	}
}

func handleOAuthRedirect(w http.ResponseWriter, r *http.Request, app *App, provider *OAuthProvider, name string) {
	state := generateToken(16)

	// If cli_port is set, this is a CLI auth flow - store the port so the callback can redirect
	cliPort := r.URL.Query().Get("cli_port")
	stateValue := state
	if cliPort != "" {
		stateValue = state + "|cli:" + cliPort
	}

	// Store state in session for CSRF protection
	http.SetCookie(w, &http.Cookie{
		Name:     "_oauth_state",
		Value:    stateValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   !app.DevMode,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	// Build callback URL from the actual request (works in both dev and hosted mode).
	// Use protoOf() so we honor X-Forwarded-Proto when running behind a
	// TLS-terminating proxy (Cloudflare → benmore router → app). Otherwise
	// r.TLS is always nil on the inbound HTTP connection and we'd hand
	// Google an http:// redirect URI it refuses to accept.
	callbackURL := fmt.Sprintf("%s://%s/auth/%s/callback", protoOf(r), r.Host, name)

	params := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {callbackURL},
		"scope":         {strings.Join(provider.Scopes, " ")},
		"response_type": {"code"},
		"state":         {state},
	}

	http.Redirect(w, r, provider.AuthURL+"?"+params.Encode(), http.StatusTemporaryRedirect)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request, app *App, provider *OAuthProvider, name string) {
	// Verify state - cookie may contain "|cli:PORT" suffix for CLI auth flow
	stateCookie, err := r.Cookie("_oauth_state")
	if err != nil {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	cookieState := stateCookie.Value
	cliPort := ""

	// Extract CLI port from state cookie if present
	if idx := strings.Index(cookieState, "|cli:"); idx > 0 {
		cliPort = cookieState[idx+5:]
		cookieState = cookieState[:idx]
	}

	requestState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(cookieState), []byte(requestState)) != 1 {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "_oauth_state", Value: "", MaxAge: -1, Path: "/"})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No authorization code", http.StatusBadRequest)
		return
	}

	// Build callback URL from the request (matches what was sent in the
	// redirect). Same X-Forwarded-Proto handling as the redirect path -
	// must match exactly or Google rejects the token exchange.
	callbackURL := fmt.Sprintf("%s://%s/auth/%s/callback", protoOf(r), r.Host, name)

	// Exchange code for token
	tokenData := url.Values{
		"client_id":     {provider.ClientID},
		"client_secret": {provider.ClientSecret},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"grant_type":    {"authorization_code"},
	}

	if isPrivateURL(provider.TokenURL) {
		log.Printf("OAuth blocked: provider %s TokenURL is private/internal", provider.Name)
		http.Error(w, "OAuth provider misconfigured", http.StatusBadGateway)
		return
	}
	req, _ := http.NewRequest("POST", provider.TokenURL, strings.NewReader(tokenData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := safeHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("OAuth token exchange failed: %s", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tokenResp map[string]any
	json.Unmarshal(body, &tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok {
		// GitHub returns access_token in form-encoded format sometimes
		parsed, _ := url.ParseQuery(string(body))
		accessToken = parsed.Get("access_token")
	}
	if accessToken == "" {
		log.Printf("OAuth no access token in response: %s", string(body))
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Get user info
	if isPrivateURL(provider.UserInfoURL) {
		log.Printf("OAuth blocked: provider %s UserInfoURL is private/internal", provider.Name)
		http.Error(w, "OAuth provider misconfigured", http.StatusBadGateway)
		return
	}
	req, _ = http.NewRequest("GET", provider.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		log.Printf("OAuth user info failed: %s", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var userInfo map[string]any
	json.Unmarshal(body, &userInfo)

	email, _ := userInfo[provider.EmailField].(string)
	if email == "" {
		// Try fallback fields (e.g., Microsoft's userPrincipalName)
		for _, field := range provider.EmailFallback {
			if v, ok := userInfo[field].(string); ok && v != "" {
				email = v
				break
			}
		}
	}
	if email == "" && provider.EmailEndpoint != "" {
		// Try separate email endpoint (e.g., GitHub /user/emails)
		email = fetchOAuthEmail(accessToken, provider.EmailEndpoint)
	}

	if email == "" {
		http.Error(w, "Could not get email from provider", http.StatusBadRequest)
		return
	}

	// Enforce the same auth.domain / auth.allow_emails gate the
	// password signup + login paths use. Without this, an OAuth
	// provider (Google/GitHub/Microsoft) was a silent bypass: any
	// Gmail could sign in to a domain-locked platform. Redirect back
	// to login with the reason rather than auto-provisioning.
	if ok, reason := emailAllowedForApp(app, email); !ok {
		log.Printf("OAuth login rejected for %s: %s", email, reason)
		authRedirect(w, r, app.Paths.Login, reason)
		return
	}

	// Find or create user
	var userID int64
	err = app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		// Create new user (no password - OAuth only)
		// Store a bcrypt hash of a random value instead of a marker string,
		// so the auth method isn't leaked if the DB is compromised.
		oauthUsername := GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0)
		randomPass := generateToken(32)
		oauthHash, _ := generateBcryptHash([]byte(randomPass))
		result, err := app.DB.Exec(
			"INSERT INTO _benmore_users (username, email, password_hash) VALUES (?, ?, ?)",
			oauthUsername, email, string(oauthHash),
		)
		if err != nil {
			log.Printf("OAuth user creation failed: %s", err)
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			return
		}
		userID, _ = result.LastInsertId()

		// Save name from OAuth provider if available
		if oauthName, ok := userInfo["name"].(string); ok && oauthName != "" {
			parts := strings.SplitN(oauthName, " ", 2)
			firstName := parts[0]
			lastName := ""
			if len(parts) > 1 {
				lastName = parts[1]
			}
			app.DB.Exec("UPDATE _benmore_users SET first_name = ?, last_name = ? WHERE id = ?", firstName, lastName, userID)
		}

		// Activate any pending invites for this email
		app.DB.Exec("UPDATE user_roles SET user_id = ?, is_active = 1, invite_accepted_at = datetime('now') WHERE email = ? AND user_id IS NULL AND is_active = 0", userID, email)
	}

	// Dashboard OAuth sign-in → ensure a platform_users row exists (covers
	// both brand-new users and pre-existing OAuth-only users who never got
	// one). No-op for every app other than _platform.
	syncPlatformUserFromOAuth(app, email)

	// Store OAuth tokens for API access (refresh, external API calls from flows)
	refreshToken, _ := tokenResp["refresh_token"].(string)
	expiresIn := 0
	if ei, ok := tokenResp["expires_in"].(float64); ok {
		expiresIn = int(ei)
	}
	scopeStr, _ := tokenResp["scope"].(string)
	StoreOAuthToken(app.DB, userID, name, accessToken, refreshToken, "Bearer", expiresIn, scopeStr)

	// Create session
	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, userID, email, groupID, app.SessionDuration)
	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

	// CLI auth flow (platform only): mint a hosted-platform CLI api_token and
	// redirect to the caller's localhost callback. This is a hosted-platform
	// concern - oauthMintCLIToken is a no-op stub in the open-source framework
	// build, where OAuth just creates the session above and falls through to
	// the normal redirect below.
	if cliPort != "" {
		if oauthMintCLIToken(w, r, email, cliPort) {
			return
		}
		// No CLI token issued (framework build or invalid port) - fall through.
	}

	redirectTo := "/"
	if app.Design != nil {
		if rd := app.Design.Auth["redirect"]; rd != "" {
			redirectTo = rd
		}
	}
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

// fetchOAuthEmail fetches email from a separate endpoint (e.g., GitHub /user/emails).
// Works with any provider that returns a JSON array with "email" and optional "primary" fields.
func fetchOAuthEmail(accessToken, endpoint string) string {
	if isPrivateURL(endpoint) {
		return ""
	}
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := safeHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var emails []map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &emails)

	for _, e := range emails {
		if primary, ok := e["primary"].(bool); ok && primary {
			if email, ok := e["email"].(string); ok {
				return email
			}
		}
	}
	if len(emails) > 0 {
		if email, ok := emails[0]["email"].(string); ok {
			return email
		}
	}
	return ""
}

// HasOAuthProviders returns true if any OAuth provider is configured.
func HasOAuthProviders(appDir string) bool {
	for name := range oauthProviders {
		if GetEnv(appDir, strings.ToUpper(name)+"_CLIENT_ID") != "" {
			return true
		}
	}
	return false
}

// GetConfiguredProviders returns names of configured OAuth providers.
func GetConfiguredProviders(appDir string) []string {
	var configured []string
	for name := range oauthProviders {
		if GetEnv(appDir, strings.ToUpper(name)+"_CLIENT_ID") != "" {
			configured = append(configured, name)
		}
	}
	return configured
}
