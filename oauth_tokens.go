//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth token storage: stores access and refresh tokens per user per provider.
// Tokens are encrypted at rest (reuses field-level encryption from encryption.go).
// Available in flows/hooks as {{user_oauth_token.provider}} for external API calls.

// EnsureOAuthTokensTable creates the token storage table.
func EnsureOAuthTokensTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_oauth_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		provider TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		token_type TEXT DEFAULT 'Bearer',
		expires_at DATETIME,
		scopes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, provider),
		FOREIGN KEY (user_id) REFERENCES _benmore_users(id)
	)`)
}

// StoreOAuthToken saves or updates an OAuth token for a user+provider.
func StoreOAuthToken(db *sql.DB, userID int64, provider, accessToken, refreshToken, tokenType string, expiresIn int, scopes string) {
	var expiresAt *string
	if expiresIn > 0 {
		t := time.Now().Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
		expiresAt = &t
	}
	if tokenType == "" {
		tokenType = "Bearer"
	}

	// Encrypt tokens at rest if ENCRYPTION_KEY is configured
	encAccess, encErr := fieldEncryptForDB(db, accessToken)
	if encErr != nil {
		log.Printf("OAUTH TOKEN: encryption failed for user %d", userID)
		return
	}
	// No refresh token in this response (providers send one on the first
	// consent and usually none on later sign-ins) stores NULL, which the
	// upsert below reads as "keep the one already stored". Encrypting the
	// empty string instead replaced it with a token that refreshes nothing.
	var encRefresh any
	if refreshToken != "" {
		enc, encErr := fieldEncryptForDB(db, refreshToken)
		if encErr != nil {
			log.Printf("OAUTH TOKEN: encryption failed for user %d", userID)
			return
		}
		encRefresh = enc
	}
	_, err := db.Exec(`
		INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token, refresh_token, token_type, expires_at, scopes, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(user_id, provider) DO UPDATE SET
			access_token = ?, refresh_token = COALESCE(?, refresh_token),
			token_type = ?, expires_at = ?, scopes = ?, updated_at = datetime('now')`,
		userID, provider, encAccess, encRefresh, tokenType, expiresAt, scopes,
		encAccess, encRefresh, tokenType, expiresAt, scopes)
	if err != nil {
		log.Printf("OAUTH TOKEN: store error for user %d provider %s: %s", userID, provider, err)
	}
}

// GetOAuthToken retrieves the access token for a user+provider.
// Auto-refreshes if expired and a refresh token is available.
func GetOAuthToken(db *sql.DB, appDir string, userID int64, provider string) string {
	var accessToken, refreshToken, tokenURL string
	var expiresAt sql.NullString

	err := db.QueryRow(
		"SELECT access_token, COALESCE(refresh_token, ''), expires_at FROM _benmore_oauth_tokens WHERE user_id = ? AND provider = ?",
		userID, provider).Scan(&accessToken, &refreshToken, &expiresAt)
	if err != nil {
		return ""
	}
	storedAccess := accessToken // as stored: what a refresh replaces
	// Decrypt if encrypted
	accessToken, _ = fieldDecryptForDB(db, accessToken)
	refreshToken, _ = fieldDecryptForDB(db, refreshToken)

	// Check if expired
	if expiresAt.Valid && expiresAt.String != "" {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err == nil && t.Before(time.Now()) && refreshToken != "" {
			// Try to refresh
			p, ok := oauthProvidersForApp(appDir)[provider]
			if ok {
				tokenURL = p.TokenURL
			}
			if tokenURL != "" {
				clientID := GetEnv(appDir, strings.ToUpper(provider)+"_CLIENT_ID")
				clientSecret := GetEnv(appDir, strings.ToUpper(provider)+"_CLIENT_SECRET")
				if refreshed, ok := oauthRefreshExchange(tokenURL, clientID, clientSecret, refreshToken); ok {
					storeRefreshedOAuthToken(db, userID, provider, storedAccess, refreshed)
					return refreshed.AccessToken
				}
			}
		}
	}

	return accessToken
}

// storeRefreshedOAuthToken keeps what a refresh returned: the new access
// token and its expiry, and the new refresh token when the provider rotated
// it. Without it the row stayed expired, so every call refreshed again, and a
// provider that rotates refresh tokens accepted only the first: later calls
// sent the spent one and fell back to the expired access token. The update
// applies only to the row the refresh started from (same stored access
// token): a connection the user removed, or one a sign-in replaced while the
// provider was answering, is left as it is.
func storeRefreshedOAuthToken(db *sql.DB, userID int64, provider, storedAccess string, refreshed oauthRefreshResult) {
	encAccess, err := fieldEncryptForDB(db, refreshed.AccessToken)
	if err != nil {
		log.Printf("OAUTH TOKEN: encryption failed for user %d", userID)
		return
	}
	var encRefresh any
	if refreshed.RefreshToken != "" {
		enc, err := fieldEncryptForDB(db, refreshed.RefreshToken)
		if err != nil {
			log.Printf("OAUTH TOKEN: encryption failed for user %d", userID)
			return
		}
		encRefresh = enc
	}
	var expiresAt any
	if refreshed.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if _, err := db.Exec(`UPDATE _benmore_oauth_tokens
		SET access_token = ?, refresh_token = COALESCE(?, refresh_token), expires_at = ?, updated_at = datetime('now')
		WHERE user_id = ? AND provider = ? AND access_token = ?`,
		encAccess, encRefresh, expiresAt, userID, provider, storedAccess); err != nil {
		log.Printf("OAUTH TOKEN: storing the refreshed token for user %d provider %s: %s", userID, provider, err)
	}
}

// oauthRefreshResult is what a provider's token endpoint answered a refresh
// with. RefreshToken is empty unless the provider rotated it.
type oauthRefreshResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
}

// oauthRefreshExchange performs the refresh. A variable so a test can stand
// in for the provider: the real exchange refuses loopback and private hosts.
var oauthRefreshExchange = refreshOAuthToken

// refreshOAuthToken exchanges a refresh token for a new access token.
func refreshOAuthToken(tokenURL, clientID, clientSecret, refreshToken string) (oauthRefreshResult, bool) {
	none := oauthRefreshResult{}
	if isPrivateURL(tokenURL) {
		log.Printf("OAUTH REFRESH: refusing to send credentials to private/internal URL %q", tokenURL)
		return none, false
	}
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	// Route the refresh through the SSRF-safe strict client rather than
	// http.PostForm (the default client follows redirects with no private-IP
	// guard and re-resolves DNS at dial time). isPrivateURL above blocks the
	// host up front; safeHTTPClientStrict additionally validates the ACTUAL
	// resolved dial IP, closing the DNS-rebinding TOCTOU so a hostile token
	// endpoint can't redirect/rebind these long-lived OAuth credentials to an
	// internal address (e.g. IMDS).
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("OAUTH REFRESH: build request failed: %s", err)
		return none, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := safeHTTPClientStrict(10 * time.Second).Do(req)
	if err != nil {
		log.Printf("OAUTH REFRESH: request failed: %s", err)
		return none, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("OAUTH REFRESH: server returned %d", resp.StatusCode)
		return none, false
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.AccessToken == "" {
		return none, false
	}
	return oauthRefreshResult{AccessToken: result.AccessToken, RefreshToken: result.RefreshToken, TokenType: result.TokenType, ExpiresIn: result.ExpiresIn}, true
}

// RegisterOAuthTokensAPI sets up endpoints for managing stored OAuth tokens.
func RegisterOAuthTokensAPI(mux appRouteRegistrar, app *App) {
	EnsureOAuthTokensTable(app.DB)
	registerOAuthTokensAPI(mux, app)
}

func registerOAuthTokensAPI(mux appRouteRegistrar, app *App) {
	// GET /api/_auth/oauth-tokens - list connected providers for current user
	mux.HandleFunc("GET /api/_auth/oauth-tokens", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !requireAccountManagement(w, session) {
			return
		}

		rows, err := queryMetadataRows(app.DB,
			"SELECT provider, token_type, scopes, expires_at, updated_at FROM _benmore_oauth_tokens WHERE user_id = ?",
			session.UserID)
		if err != nil {
			serverErrorJSON(w, r, app, "oauth tokens", err, "query failed")
			return
		}
		httpJSON(w, http.StatusOK, rows)
	})

	// DELETE /api/_auth/oauth-tokens/{provider} - disconnect a provider
	mux.HandleFunc("DELETE /api/_auth/oauth-tokens/{provider}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !requireOwnAccountManagement(w, app, session) {
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		provider := r.PathValue("provider")
		result, err := app.DB.Exec(
			"DELETE FROM _benmore_oauth_tokens WHERE user_id = ? AND provider = ?",
			session.UserID, provider)
		if err != nil {
			serverErrorJSON(w, r, app, "oauth tokens", err, "disconnect failed")
			return
		}
		affected, err := result.RowsAffected()
		if err != nil {
			serverErrorJSON(w, r, app, "oauth tokens", err, "disconnect failed")
			return
		}
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "provider not connected"})
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"status": "disconnected"})
	})
}
