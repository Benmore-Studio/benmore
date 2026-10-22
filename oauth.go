//go:build !cli

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// oauthPKCEChallenge derives the S256 PKCE code_challenge from a code_verifier
// (RFC 7636): BASE64URL(SHA256(verifier)), no padding. Sending the challenge in
// the authorization request and the verifier in the token exchange binds the
// returned code to THIS client, so an intercepted code can't be redeemed by an
// attacker who never held the verifier. Defense-in-depth on top of the state
// (CSRF) cookie.
func oauthPKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// OAuthProvider defines an OAuth2 provider configuration.
// Built-in providers (Google, GitHub, Microsoft) are defaults.
// Apps can add custom providers via the top-level app.yaml oauth section.
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
	// TrustEmail (app.yaml oauth.<name>.trust_email: true) declares that this
	// custom provider only ever returns addresses it has verified, so its
	// email counts as proven without an email_verified claim. Built-in
	// providers establish verification with their own checks instead.
	TrustEmail bool
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

// oauthProvidersForApp reads custom OAuth providers from app.yaml oauth: section.
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
func oauthProvidersForApp(dir string) map[string]OAuthProvider {
	providers := make(map[string]OAuthProvider, len(oauthProviders))
	for name, provider := range oauthProviders {
		providers[name] = provider
	}
	path := dir + "/app.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return providers
	}
	var raw map[string]any
	if err := yamlUnmarshal(data, &raw); err != nil {
		return providers
	}
	oauthRaw, ok := raw["oauth"].(map[string]any)
	if !ok {
		return providers
	}
	for name, v := range oauthRaw {
		cfg, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// Don't override built-in providers unless explicitly configured
		if _, exists := providers[name]; exists {
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
		switch v := cfg["trust_email"].(type) {
		case bool:
			provider.TrustEmail = v
		case string:
			provider.TrustEmail = strings.EqualFold(strings.TrimSpace(v), "true")
		}
		// Security: warn if OAuth endpoints are not HTTPS (tokens leak in transit)
		for _, u := range []string{provider.AuthURL, provider.TokenURL, provider.UserInfoURL} {
			if u != "" && !strings.HasPrefix(u, "https://") {
				log.Printf("  WARNING: oauth provider '%s' has non-HTTPS URL: %s", name, u)
			}
		}
		providers[name] = provider
	}
	return providers
}

// RegisterOAuthRoutes sets up OAuth login/callback routes for configured providers.
func RegisterOAuthRoutes(mux appRouteRegistrar, app *App) {
	// Load custom providers from app.yaml before registering routes
	providers := oauthProvidersForApp(app.Dir)
	available := []oauthProviderAvailability{}

	byoConfigured := map[string]bool{}
	for providerName, provider := range providers {
		clientID := appRouteEnv(app, strings.ToUpper(providerName)+"_CLIENT_ID")
		clientSecret := appRouteEnv(app, strings.ToUpper(providerName)+"_CLIENT_SECRET")

		if clientID == "" || clientSecret == "" {
			continue // skip unconfigured providers
		}
		byoConfigured[providerName] = true
		available = append(available, oauthProviderAvailability{Provider: providerName, TokenStorage: true})

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

	// Managed mode: platform-brokered providers for everything the app
	// didn't bring its own credentials for (oauth_managed.go). No-op
	// off-platform.
	for _, name := range registerManagedOAuthRoutes(mux, app, byoConfigured) {
		available = append(available, oauthProviderAvailability{Provider: name})
	}
	sort.Slice(available, func(i, j int) bool { return available[i].Provider < available[j].Provider })
	// This is the actual route snapshot, not a second guess at configuration.
	// Managed login deliberately does not hand provider API tokens to the app.
	mux.HandleFunc("GET /api/_auth/oauth-providers", func(w http.ResponseWriter, r *http.Request) {
		if getSession(app, r) == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		httpJSON(w, http.StatusOK, available)
	})
}

type oauthProviderAvailability struct {
	Provider     string `json:"provider"`
	TokenStorage bool   `json:"token_storage"`
}

func handleOAuthRedirect(w http.ResponseWriter, r *http.Request, app *App, provider *OAuthProvider, name string) {
	state := generateToken(16)

	// If cli_port is set, this is a CLI auth flow - store the port so the
	// callback can redirect. Only the platform dashboard's built-in providers
	// may finish one (oauthCLIPortAllowed); anywhere else the parameter is
	// ignored and this is an ordinary sign-in. The CLI's login nonce is
	// required, so a link without one can't rotate the account's CLI token.
	cliPort := r.URL.Query().Get("cli_port")
	stateValue := state
	if cliPort != "" && oauthCLIPortAllowed(app, name) {
		rawPort, cliState, ok := parseCLIPortState(cliPort)
		if !ok || cliState == "" || !validCLIPort(rawPort) {
			http.Error(w, "This sign-in link is missing its login check. Run `benmore login` again (update the CLI if this keeps happening).", http.StatusBadRequest)
			return
		}
		// The nonce is the CLI's own check, not proof the person started
		// this: anyone can put one in a link. A CLI login starts from the
		// /cli-auth page's button (same-origin); a link from another site,
		// a sibling tenant or the address bar would otherwise rotate the
		// account's CLI token without a click whenever Google remembers the
		// consent. Browsers without fetch metadata send no header.
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(w, "Start the CLI sign-in from the page `benmore login` opened.", http.StatusBadRequest)
			return
		}
		stateValue = state + "|cli:" + cliPort
	}

	// Store state in session for CSRF protection
	setFlowCookie(w, flowCookieOAuthState, stateValue, !app.DevMode, 600) // 10 minutes

	// PKCE (RFC 7636) + OIDC nonce, defense-in-depth. The verifier and nonce
	// stay server-side in HttpOnly cookies (never exposed to JS, never sent to
	// the IdP); only the derived challenge and the nonce go on the wire. The
	// callback re-reads these from the cookies to (a) prove possession of the
	// verifier in the token exchange and (b) bind any returned id_token to this
	// login attempt, blocking authorization-code interception and token replay.
	codeVerifier := generateToken(32) // 64 hex chars, within RFC 7636's 43-128 range
	oidcNonce := generateToken(16)
	setFlowCookie(w, flowCookieOAuthPKCE, codeVerifier, !app.DevMode, 600) // matches state
	setFlowCookie(w, flowCookieOAuthNonce, oidcNonce, !app.DevMode, 600)

	// Build callback URL from the actual request (works in both dev and hosted mode).
	// Use protoOf() so we honor X-Forwarded-Proto when running behind a
	// TLS-terminating proxy (Cloudflare → benmore router → app). Otherwise
	// r.TLS is always nil on the inbound HTTP connection and we'd hand
	// Google an http:// redirect URI it refuses to accept.
	callbackURL := fmt.Sprintf("%s://%s/auth/%s/callback", protoOf(r), r.Host, name)

	params := url.Values{
		"client_id":             {provider.ClientID},
		"redirect_uri":          {callbackURL},
		"scope":                 {strings.Join(provider.Scopes, " ")},
		"response_type":         {"code"},
		"state":                 {state},
		"code_challenge":        {oauthPKCEChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"nonce":                 {oidcNonce},
	}

	http.Redirect(w, r, provider.AuthURL+"?"+params.Encode(), http.StatusTemporaryRedirect)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request, app *App, provider *OAuthProvider, name string) {
	// Verify state - cookie may contain "|cli:PORT" suffix for CLI auth flow
	stateCookie, err := requestFlowCookie(r, flowCookieOAuthState)
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
	// The redirect leg only stores a port for the dashboard's built-in
	// providers; re-check here so no other provider or app can finish a CLI
	// login whatever the cookie says.
	if !oauthCLIPortAllowed(app, name) {
		cliPort = ""
	}

	requestState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(cookieState), []byte(requestState)) != 1 {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	// Read the PKCE verifier + OIDC nonce stashed at redirect time, then clear
	// all three flow cookies (single-use: never replay a verifier/nonce).
	codeVerifier := ""
	if c, err := requestFlowCookie(r, flowCookieOAuthPKCE); err == nil {
		codeVerifier = c.Value
	}
	expectedNonce := ""
	if c, err := requestFlowCookie(r, flowCookieOAuthNonce); err == nil {
		expectedNonce = c.Value
	}
	clearFlowCookie(w, flowCookieOAuthState)
	clearFlowCookie(w, flowCookieOAuthPKCE)
	clearFlowCookie(w, flowCookieOAuthNonce)

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
	// Present the PKCE verifier so the IdP can match it against the challenge
	// it stored with the code. Omitted only if the redirect never set it (e.g.
	// an in-flight upgrade); providers that didn't see a challenge ignore it.
	if codeVerifier != "" {
		tokenData.Set("code_verifier", codeVerifier)
	}

	if isPrivateURL(provider.TokenURL) {
		serverErrorStatus(w, r, app, http.StatusBadGateway, "oauth "+name, fmt.Errorf("OAuth blocked: provider %s TokenURL is private/internal", provider.Name), "OAuth provider misconfigured")
		return
	}
	req, _ := http.NewRequest("POST", provider.TokenURL, strings.NewReader(tokenData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := oauthProviderHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		serverError(w, r, app, "oauth "+name, fmt.Errorf("OAuth token exchange failed: %w", err), "Authentication failed")
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
		// Don't log the raw token-endpoint body - some IdP error shapes
		// include refresh tokens / PII. Length is enough to debug.
		serverError(w, r, app, "oauth "+name, fmt.Errorf("OAuth no access token in token-endpoint response (%d bytes)", len(body)), "Authentication failed")
		return
	}

	// OIDC nonce check (defense-in-depth). When the IdP returns an id_token
	// (OpenID Connect), it MUST echo the nonce we sent. A mismatch means the
	// id_token was minted for a DIFFERENT login attempt - reject as replay.
	// When no id_token is returned, or it carries no nonce claim (plain OAuth2
	// providers), behavior is unchanged: we can't verify what we weren't told.
	// Signature verification is out of scope here (no JWKS fetch); the access
	// token from the same response is what actually authenticates downstream,
	// so this only adds a binding check, never a new trust assumption.
	if expectedNonce != "" {
		if idTok, _ := tokenResp["id_token"].(string); idTok != "" {
			if claimNonce, present := oauthIDTokenNonce(idTok); present && claimNonce != expectedNonce {
				log.Printf("OAuth nonce mismatch for provider %s: rejecting id_token", provider.Name)
				http.Error(w, "Authentication failed", http.StatusBadRequest)
				return
			}
		}
	}

	// Get user info
	if isPrivateURL(provider.UserInfoURL) {
		serverErrorStatus(w, r, app, http.StatusBadGateway, "oauth "+name, fmt.Errorf("OAuth blocked: provider %s UserInfoURL is private/internal", provider.Name), "OAuth provider misconfigured")
		return
	}
	req, _ = http.NewRequest("GET", provider.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		serverError(w, r, app, "oauth "+name, fmt.Errorf("OAuth user info failed: %w", err), "Authentication failed")
		return
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var userInfo map[string]any
	json.Unmarshal(body, &userInfo)

	email, _ := userInfo[provider.EmailField].(string)
	if oauthGitHubBuiltIn(provider, name) {
		// GitHub's profile `email` is the public address the user chose to
		// show, and it carries no verification flag. oauthEmailVerified
		// treats the built-in provider as proving the address, so the
		// address must come from /user/emails, where GitHub says which one
		// is the verified primary.
		email = fetchOAuthEmail(accessToken, provider.EmailEndpoint, true)
	}
	if email == "" {
		// Try fallback fields (e.g., Microsoft's userPrincipalName)
		for _, field := range provider.EmailFallback {
			if v, ok := userInfo[field].(string); ok && v != "" {
				email = v
				break
			}
		}
	}
	if email == "" && provider.EmailEndpoint != "" && !oauthGitHubBuiltIn(provider, name) {
		// Try a custom provider's separate email endpoint
		email = fetchOAuthEmail(accessToken, provider.EmailEndpoint, false)
	}

	if email == "" {
		http.Error(w, "Could not get email from provider", http.StatusBadRequest)
		return
	}
	// A provider value is input like any other: one plain mailbox, or no
	// account is matched or created from it (validAuthEmail). The address is
	// not logged; it is whatever the provider's user typed.
	email = strings.TrimSpace(email)
	if !validAuthEmail(email) {
		log.Printf("OAuth login rejected: provider %s returned a value that is not a single plain email address", provider.Name)
		authRedirect(w, r, app.Paths.Login, "Your sign-in provider returned an email address this app can't use. Sign in another way.")
		return
	}
	// Microsoft Graph's mail / userPrincipalName are set by the account's
	// tenant admin and never carry a verification claim, so any Entra
	// tenant could present someone else's address (the "nOAuth" pattern)
	// and be matched to that person's account below.
	if isMicrosoftGraphProvider(provider) {
		idTok, _ := tokenResp["id_token"].(string)
		if !microsoftEmailTrusted(accessToken, idTok, email) {
			log.Printf("OAuth login rejected for %s: Microsoft email domain is not verified by the account's tenant", logAddressRef(email))
			authRedirect(w, r, app.Paths.Login, "Your Microsoft account's email isn't verified by your organization, so it can't be used to sign in here.")
			return
		}
	}

	// Enforce the same auth.domain / auth.allow_emails gate the
	// password signup + login paths use. Without this, an OAuth
	// provider (Google/GitHub/Microsoft) was a silent bypass: any
	// Gmail could sign in to a domain-locked platform. Redirect back
	// to login with the reason rather than auto-provisioning.
	if ok, reason := emailAllowedForApp(app, email); !ok {
		log.Printf("OAuth login rejected for %s: %s", logAddressRef(email), reason)
		authRedirect(w, r, app.Paths.Login, reason)
		return
	}

	// If the provider EXPLICITLY says this email is unverified, refuse - both
	// linking to an existing account and provisioning a new one. Standard OIDC
	// exposes `email_verified`; Google also sends `verified_email`. Both bool
	// and the string "false" are handled. When the claim is ABSENT (many
	// custom providers don't send it) behavior is unchanged - we can't verify
	// what we aren't told - so this never breaks a correctly-configured
	// provider, it only closes the unverified-email account-takeover vector
	// for providers that do report verification status.
	if ev, present := userInfo["email_verified"]; present && !truthyClaim(ev) {
		log.Printf("OAuth login rejected for %s: provider reports email not verified", logAddressRef(email))
		authRedirect(w, r, app.Paths.Login, "Your email isn't verified with the provider. Verify it there, then try again.")
		return
	}
	if ev, present := userInfo["verified_email"]; present && !truthyClaim(ev) {
		log.Printf("OAuth login rejected for %s: provider reports email not verified", logAddressRef(email))
		authRedirect(w, r, app.Paths.Login, "Your email isn't verified with the provider. Verify it there, then try again.")
		return
	}

	emailVerified := oauthEmailVerified(provider, name, userInfo)

	// Find or create user (shared with managed-mode logins).
	displayName, _ := userInfo["name"].(string)
	userID, ferr := oauthFindOrCreateUser(app, email, displayName, emailVerified)
	if errors.Is(ferr, errOAuthUnverifiedLink) {
		log.Printf("OAuth login rejected for %s: provider %s did not verify the email, so it cannot sign in to the existing account (set oauth.%s.trust_email only if the provider verifies every address)", logAddressRef(email), provider.Name, name)
		authRedirect(w, r, app.Paths.Login, "This sign-in provider didn't confirm your email address, so it can't open an existing account. Sign in another way.")
		return
	}
	if ferr != nil {
		serverError(w, r, app, "oauth "+name, fmt.Errorf("OAuth user creation failed: %w", ferr), "Authentication failed")
		return
	}

	// Dashboard OAuth sign-in → ensure a platform_users row exists (covers
	// both brand-new users and pre-existing OAuth-only users who never got
	// one). No-op for every app other than _platform.
	cliPort = oauthPlatformProof(app, email, emailVerified, cliPort)

	// Store OAuth tokens for API access (refresh, external API calls from flows)
	refreshToken, _ := tokenResp["refresh_token"].(string)
	expiresIn := 0
	if ei, ok := tokenResp["expires_in"].(float64); ok {
		expiresIn = int(ei)
	}
	scopeStr, _ := tokenResp["scope"].(string)
	StoreOAuthToken(app.DB, userID, name, accessToken, refreshToken, "Bearer", expiresIn, scopeStr)

	// A social login is ONE factor. An account with MFA enrolled must pass
	// its second factor before any session (or CLI token) is issued.
	if oauthMFAGate(w, r, app, userID, email, cliPort) {
		return
	}

	// Create session
	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := createSignInSession(app.DB, userID, email, groupID, app.SessionDuration)
	http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

	// CLI auth flow (platform only): mint a hosted-platform CLI api_token and
	// redirect to the caller's localhost callback. This is a hosted-platform
	// concern - oauthMintCLIToken is a no-op stub in the open-source framework
	// build, where OAuth just creates the session above and falls through to
	// the normal redirect below.
	if cliPort != "" {
		if oauthMintCLIToken(w, r, app, email, cliPort) {
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

// oauthFindOrCreateUser resolves an OAuth-authenticated email to a local
// _benmore_users row, provisioning one on first login (no password - a
// bcrypt hash of random bytes, so the auth method isn't leaked if the DB
// is compromised). Shared by the BYO OAuth callback and the platform
// managed-mode callback (oauth_managed.go) so both paths provision users
// identically.
//
// emailVerified says the provider proved the address. Only then does the
// account count as verified (email-keyed memberships, shares and invites
// apply - email_grants.go); an existing account that never verified is
// claimed for the provider-proven owner first (claimUnverifiedAccount).
// oauthPlatformProof applies the hosted dashboard's side of an OAuth sign-in
// and returns the CLI port to honor. Only a provider-verified address proves
// the platform account or earns a platform CLI token: a custom provider that
// doesn't verify email may still create a new app account, but its unproved
// address must not become a platform credential.
func oauthPlatformProof(app *App, email string, emailVerified bool, cliPort string) string {
	if !emailVerified {
		return ""
	}
	syncPlatformUserFromOAuth(app, email)
	return cliPort
}

func oauthFindOrCreateUser(app *App, email, displayName string, emailVerified bool) (int64, error) {
	var userID int64
	var verified, grandfathered int
	// Case-insensitive, like password login and recovery (auth_recovery.go):
	// providers return whatever case the person typed at them, and an exact
	// match would provision a second account beside Alice@x for alice@x
	// instead of linking (or refusing to link) the existing one. The oldest
	// row wins if case-variants already exist.
	email = strings.TrimSpace(email)
	// Both callbacks check this first; it is repeated here so no caller can
	// match or create an account from a value that isn't one plain mailbox.
	if !validAuthEmail(email) {
		return 0, errOAuthInvalidEmail
	}
	err := app.DB.QueryRow("SELECT id, COALESCE(verified, 0), COALESCE(email_grandfathered, 0) FROM _benmore_users WHERE email = ? COLLATE NOCASE ORDER BY id LIMIT 1", email).Scan(&userID, &verified, &grandfathered)
	if err == nil {
		// Linking by email hands over an existing account: only an address
		// the provider proved may do that. A provider that merely echoes an
		// address would let anyone sign in as any registered user.
		if !emailVerified {
			return 0, errOAuthUnverifiedLink
		}
		if verified == 0 {
			// A grandfathered account predates the verification rule and
			// keeps its credentials; it simply becomes verified now.
			if grandfathered == 0 {
				if err := claimUnverifiedAccount(app, userID, email); err != nil {
					return 0, err
				}
			}
			markEmailVerified(app, userID, email)
		}
		return userID, nil
	}
	if authFeatureDisabled(app, "signup") {
		return 0, errAuthSignupDisabled
	}
	oauthUsername := GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0)
	randomPass := generateToken(32)
	oauthHash, _ := generateBcryptHash([]byte(randomPass))
	result, err := app.DB.Exec(
		"INSERT INTO _benmore_users (username, email, password_hash) VALUES (?, ?, ?)",
		oauthUsername, email, string(oauthHash),
	)
	if err != nil {
		return 0, err
	}
	userID, _ = result.LastInsertId()
	if displayName != "" {
		parts := strings.SplitN(displayName, " ", 2)
		lastName := ""
		if len(parts) > 1 {
			lastName = parts[1]
		}
		app.DB.Exec("UPDATE _benmore_users SET first_name = ?, last_name = ? WHERE id = ?", parts[0], lastName, userID)
	}
	// A provider-proven address verifies the new account and activates the
	// invites waiting on it; an unproven one leaves both for later.
	if emailVerified {
		markEmailVerified(app, userID, email)
	}
	return userID, nil
}

// errOAuthInvalidEmail refuses a provider-supplied address that is not one
// plain mailbox (validAuthEmail).
var errOAuthInvalidEmail = errors.New("oauth: provider returned a malformed email address")

// errOAuthUnverifiedLink refuses to link a provider identity whose email the
// provider did not verify to an existing account with that email.
var errOAuthUnverifiedLink = errors.New("oauth: provider did not verify the email of an existing account")

var errAuthSignupDisabled = errors.New("auth: self-service signup is disabled")

// oauthEmailVerified reports whether the provider proved the address.
// Built-in providers establish it through their own checks in the callback
// (Google's claims, GitHub's verified-email endpoint, Microsoft's
// tenant-domain check). A custom provider must send a truthy
// email_verified / verified_email claim, or be configured trust_email.
func oauthEmailVerified(provider *OAuthProvider, name string, userInfo map[string]any) bool {
	if _, builtIn := oauthProviders[name]; builtIn {
		return true
	}
	return provider.TrustEmail || oauthClaimsEmailVerified(userInfo)
}

// oauthClaimsEmailVerified reports an explicit, truthy provider claim that
// the address is verified (OIDC email_verified, Google's verified_email).
func oauthClaimsEmailVerified(userInfo map[string]any) bool {
	for _, claim := range []string{"email_verified", "verified_email"} {
		if v, ok := userInfo[claim]; ok && truthyClaim(v) {
			return true
		}
	}
	return false
}

// oauthProviderHTTPClient serves the token, userinfo and email endpoints,
// which custom providers take from app.yaml. isPrivateURL only vets the
// configured hostname; the strict client re-checks the address actually
// dialed, so a name that re-resolves to loopback between the check and the
// request cannot reach co-resident services.
func oauthProviderHTTPClient() *http.Client {
	return safeHTTPClientStrict(10 * time.Second)
}

// fetchOAuthEmail fetches email from a separate endpoint (e.g., GitHub /user/emails).
// Works with any provider that returns a JSON array with "email" and optional "primary" fields.
// primaryOnly accepts only the verified PRIMARY address (the built-in GitHub
// provider); otherwise any verified address is the fallback.
func fetchOAuthEmail(accessToken, endpoint string, primaryOnly bool) string {
	if isPrivateURL(endpoint) {
		return ""
	}
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := oauthProviderHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return pickVerifiedOAuthEmail(body, primaryOnly)
}

// oauthGitHubBuiltIn reports the framework's own GitHub provider (not an
// app.yaml provider that happens to be named or shaped like it).
func oauthGitHubBuiltIn(provider *OAuthProvider, name string) bool {
	builtIn, ok := oauthProviders["github"]
	return ok && name == "github" && provider != nil && provider.UserInfoURL == builtIn.UserInfoURL && provider.EmailEndpoint == builtIn.EmailEndpoint
}

// pickVerifiedOAuthEmail selects an address from a /user/emails-shaped JSON
// array ([{email, primary, verified}]).
func pickVerifiedOAuthEmail(body []byte, primaryOnly bool) string {
	var emails []map[string]any
	if json.Unmarshal(body, &emails) != nil {
		return ""
	}

	// Require the primary email to be VERIFIED by GitHub. Returning an
	// unverified address would let an attacker who added (but never confirmed)
	// a victim's email to their GitHub account sign into the victim's existing
	// Benmore account via the link-by-email path.
	for _, e := range emails {
		primary, _ := e["primary"].(bool)
		verified, _ := e["verified"].(bool)
		if primary && verified {
			if email, ok := e["email"].(string); ok {
				return email
			}
		}
	}
	if primaryOnly {
		return ""
	}
	// Fall back to any verified address (still must be verified).
	for _, e := range emails {
		if verified, _ := e["verified"].(bool); verified {
			if email, ok := e["email"].(string); ok {
				return email
			}
		}
	}
	return ""
}

// truthyClaim interprets a JSON claim value as a boolean. Providers send
// email_verified as a real bool, but some send the string "true"/"false".
// Anything not recognizably true is treated as false (used only to detect an
// EXPLICIT false, so an unknown shape erring toward false is safe here -
// callers already guard on the claim being present).
func truthyClaim(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}

// oauthIDTokenNonce extracts the `nonce` claim from an OIDC id_token's payload
// WITHOUT verifying the signature - it's used only for the defense-in-depth
// nonce-binding check (the access token from the same response is the real
// credential). Returns (nonce, true) only when the claim is present and a
// string; (.., false) for absent/unparseable tokens so callers leave behavior
// unchanged for plain OAuth2 providers that send no id_token.
func oauthIDTokenNonce(idToken string) (string, bool) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	n, ok := claims["nonce"].(string)
	if !ok || n == "" {
		return "", false
	}
	return n, true
}

// HasOAuthProviders returns true if any OAuth provider is configured.
func HasOAuthProviders(appDir string) bool {
	return len(GetConfiguredProviders(appDir)) > 0
}

// GetConfiguredProviders returns names of usable OAuth providers: BYO
// (app-level client credentials) plus platform-managed ones the broker
// serves (oauth_managed.go). Drives the login page's provider buttons.
func GetConfiguredProviders(appDir string) []string {
	var configured []string
	seen := map[string]bool{}
	for name := range oauthProvidersForApp(appDir) {
		if GetEnv(appDir, strings.ToUpper(name)+"_CLIENT_ID") != "" && GetEnv(appDir, strings.ToUpper(name)+"_CLIENT_SECRET") != "" {
			configured = append(configured, name)
			seen[name] = true
		}
	}
	if managedBrokerURL() != "" && strings.TrimSpace(os.Getenv("BENMORE_APP_NAME")) != "" {
		for _, name := range managedBrokerProviders() {
			if !seen[name] {
				configured = append(configured, name)
			}
		}
	}
	sort.Strings(configured)
	return configured
}

// microsoftConsumerTenantID is the fixed tenant id of personal Microsoft
// accounts (MSA), whose sign-in addresses Microsoft itself verifies.
const microsoftConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

func isMicrosoftGraphProvider(p *OAuthProvider) bool {
	if p == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(p.UserInfoURL), "https://graph.microsoft.com/")
}

// oauthIDTokenClaim reads one string claim from an id_token received over the
// back channel from the provider's token endpoint.
func oauthIDTokenClaim(idToken, claim string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	v, _ := claims[claim].(string)
	return v
}

// microsoftEmailTrusted reports whether a Microsoft identity may use email to
// match or create an account. Personal accounts (consumer tenant) are trusted.
// For work/school accounts the email's domain must be one of the tenant's
// VERIFIED domains per Microsoft Graph (/organization, readable with
// User.Read); anything else, including lookup failures, is refused.
func microsoftEmailTrusted(accessToken, idToken, email string) bool {
	if strings.EqualFold(oauthIDTokenClaim(idToken, "tid"), microsoftConsumerTenantID) {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := safeHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var org struct {
		Value []struct {
			VerifiedDomains []struct {
				Name string `json:"name"`
			} `json:"verifiedDomains"`
		} `json:"value"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&org) != nil {
		return false
	}
	return microsoftDomainInOrg(domain, org.Value)
}

func microsoftDomainInOrg(domain string, orgs []struct {
	VerifiedDomains []struct {
		Name string `json:"name"`
	} `json:"verifiedDomains"`
}) bool {
	for _, o := range orgs {
		for _, d := range o.VerifiedDomains {
			if strings.EqualFold(strings.TrimSpace(d.Name), domain) {
				return true
			}
		}
	}
	return false
}

// oauthMFAGate sends an MFA-enrolled user to the second-factor step instead
// of issuing a session from a social login, and returns true when it did.
// A pending platform CLI login is carried in its own signed cookie so the
// MFA step can finish it; that value's format ("cli|…") can never parse as
// the MFA step cookie (encodeStepValue), and it is signed for its own purpose.
func oauthMFAGate(w http.ResponseWriter, r *http.Request, app *App, userID int64, email, cliPort string) bool {
	if !CheckMFA(app.DB, userID) {
		// No factor yet. A role listed in auth.require_mfa_for_roles must
		// enroll before any session, exactly as after a password login:
		// the setup-token cookie authorises /api/_auth/mfa/setup + /verify,
		// and verify issues the session. A pending platform CLI login is not
		// carried through enrollment; the CLI retries and then meets the
		// ordinary second-factor step.
		if userRequiresMFAEnrollment(app, userID) {
			redirectToMFAEnrollment(w, r, app, userID, email)
			return true
		}
		return false
	}
	token := mintSignInChallenge(app, tempCookieMFA, userID, email, "")
	if token == "" {
		authRedirect(w, r, app.Paths.Login, "Credentials changed. Sign in again.")
		return true
	}
	setFlowCookie(w, flowCookieMFA, token, !app.DevMode, 300)
	if cliPort != "" {
		setFlowCookie(w, flowCookieMFACLI, signTempCookieFor(app, tempCookieMFACLI, fmt.Sprintf("cli|%d|%s", userID, cliPort)), !app.DevMode, 300)
	}
	verifyPath := "/verify-mfa"
	if app.Paths != nil && app.Paths.VerifyMFA != "" {
		verifyPath = app.Paths.VerifyMFA
	}
	http.Redirect(w, r, verifyPath, http.StatusSeeOther)
	return true
}

// oauthPendingCLIPort returns the CLI port carried through the MFA step for
// userID (and clears the cookie), or "".
func oauthPendingCLIPort(w http.ResponseWriter, r *http.Request, app *App, userID int64) string {
	c, err := requestFlowCookie(r, flowCookieMFACLI)
	if err != nil || c.Value == "" {
		return ""
	}
	clearFlowCookie(w, flowCookieMFACLI)
	parts := strings.SplitN(verifyTempCookieFor(app, tempCookieMFACLI, c.Value), "|", 3)
	if len(parts) != 3 || parts[0] != "cli" || parseTempCookieUserID(parts[1]) != userID {
		return ""
	}
	return parts[2]
}
