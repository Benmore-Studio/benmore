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
	encAccess, _ := fieldEncrypt(accessToken)
	encRefresh, _ := fieldEncrypt(refreshToken)

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
	// Decrypt if encrypted
	accessToken, _ = fieldDecrypt(accessToken)
	refreshToken, _ = fieldDecrypt(refreshToken)

	// Check if expired
	if expiresAt.Valid && expiresAt.String != "" {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err == nil && t.Before(time.Now()) && refreshToken != "" {
			// Try to refresh
			p, ok := oauthProviders[provider]
			if ok {
				tokenURL = p.TokenURL
			}
			if tokenURL != "" {
				clientID := GetEnv(appDir, strings.ToUpper(provider) + "_CLIENT_ID")
				clientSecret := GetEnv(appDir, strings.ToUpper(provider) + "_CLIENT_SECRET")
				newToken := refreshOAuthToken(tokenURL, clientID, clientSecret, refreshToken)
				if newToken != "" {
					return newToken
				}
			}
		}
	}

	return accessToken
}

// refreshOAuthToken exchanges a refresh token for a new access token.
func refreshOAuthToken(tokenURL, clientID, clientSecret, refreshToken string) string {
	if isPrivateURL(tokenURL) {
		log.Printf("OAUTH REFRESH: refusing to send credentials to private/internal URL %q", tokenURL)
		return ""
	}
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		log.Printf("OAUTH REFRESH: request failed: %s", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("OAUTH REFRESH: server returned %d", resp.StatusCode)
		return ""
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return result.AccessToken
}

// RegisterOAuthTokensAPI sets up endpoints for managing stored OAuth tokens.
func RegisterOAuthTokensAPI(mux *http.ServeMux, app *App) {
	EnsureOAuthTokensTable(app.DB)

	// GET /api/_auth/oauth-tokens — list connected providers for current user
	mux.HandleFunc("GET /api/_auth/oauth-tokens", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		rows, err := QueryRows(app.DB,
			"SELECT provider, token_type, scopes, expires_at, updated_at FROM _benmore_oauth_tokens WHERE user_id = ?",
			session.UserID)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		httpJSON(w, http.StatusOK, rows)
	})

	// DELETE /api/_auth/oauth-tokens/{provider} — disconnect a provider
	mux.HandleFunc("DELETE /api/_auth/oauth-tokens/{provider}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		provider := r.PathValue("provider")
		result, _ := app.DB.Exec(
			"DELETE FROM _benmore_oauth_tokens WHERE user_id = ? AND provider = ?",
			session.UserID, provider)
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "provider not connected"})
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"status": "disconnected"})
	})
}
