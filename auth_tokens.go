//go:build !cli

package main

// Persistent API token storage, authentication, and management handlers.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// EnsureAPITokensTable creates the persistent API tokens table.
func EnsureAPITokensTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_api_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		scopes TEXT NOT NULL,
		last_used_at DATETIME,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES _benmore_users(id)
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON _benmore_api_tokens(token_hash)")
}

// hashToken computes SHA-256 of a raw token for storage.
// The raw token is returned once on creation, never stored.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GetSessionFromAPIToken resolves a Bearer token as a persistent API token.
// Returns nil if not found or expired.
func GetSessionFromAPIToken(db *sql.DB, rawToken string) *Session {
	tokenHash := hashToken(rawToken)

	var userID int64
	var scopes string
	var expiresAt sql.NullString
	err := db.QueryRow(
		"SELECT user_id, scopes, expires_at FROM _benmore_api_tokens WHERE token_hash = ?",
		tokenHash,
	).Scan(&userID, &scopes, &expiresAt)
	if err != nil {
		return nil
	}

	// Check expiry
	if expiresAt.Valid && expiresAt.String != "" {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err != nil || !t.After(time.Now()) {
			return nil // invalid or expired
		}
	}

	// Look up user details + deactivation status in one query
	var email, role string
	var deactivatedAt sql.NullString
	var verified int
	err = db.QueryRow("SELECT COALESCE(email, ''), COALESCE(role, 'user'), deactivated_at, COALESCE(verified, 0) FROM _benmore_users WHERE id = ? AND COALESCE(password_change_required, 0) = 0", userID).Scan(&email, &role, &deactivatedAt, &verified)
	if err != nil {
		return nil // user deleted
	}
	if deactivatedAt.Valid && deactivatedAt.String != "" {
		return nil // deactivated users blocked
	}

	// Update last_used_at (fire-and-forget)
	_, _ = db.Exec("UPDATE _benmore_api_tokens SET last_used_at = datetime('now') WHERE token_hash = ? AND (last_used_at IS NULL OR datetime(last_used_at) < datetime('now', '-5 minutes'))", tokenHash)

	return &Session{
		ID:          fmt.Sprintf("apitoken:%s", tokenHash[:16]),
		UserID:      userID,
		Email:       email,
		GroupID:     "", // resolved lazily by getSession
		Role:        role,
		Scopes:      scopes,
		Verified:    verified == 1,
		GlobalAdmin: role == "admin" || UserHasGlobalAdminGrant(db, userID),
		Roles:       LoadSessionRoles(db, userID, role, ""),
	}
}

// Credential changes require an actual login, not delegated or support identity.
func credentialManagementSession(app *App, session *Session) bool {
	if session == nil || session.ActingAsGroup != "" || strings.HasPrefix(session.ID, "apitoken:") || strings.HasPrefix(session.ID, "edge:") {
		return false
	}
	var valid int
	return app.DB.QueryRow("SELECT 1 FROM _benmore_sessions WHERE id=? AND user_id=? AND COALESCE(is_impersonation,0)=0", session.ID, session.UserID).Scan(&valid) == nil
}

// handleCreateAPIToken creates a persistent API token.
// POST /api/_auth/api-tokens {name, scopes, expires_in?}
func handleCreateAPIToken(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	// Persistent credentials cannot mint descendants that survive revocation
	// or expiry of the original token. Mint from an interactive login session.
	if !credentialManagementSession(app, session) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "create API tokens from a login session outside act-as mode"})
		return
	}
	// CSRF: this mint is a cookie-session mutation like its siblings
	// (settings/mfa/profile, and handleRevokeAPIToken below). Without it a
	// logged-in victim could be navigated to /bmp-auth (or have this endpoint
	// POSTed cross-site) and a full-scope bmr_ token minted on their behalf.
	// requireCSRF exempts Bearer callers, so the CLI/MCP/SDK are unaffected;
	// bmp-auth.html already sends X-CSRF-Token, so no legitimate browser
	// client breaks. (Task 22 folded in.)
	if !requireCSRF(w, r) {
		return
	}

	var body struct {
		Name      string `json:"name"`
		Scopes    string `json:"scopes"`
		ExpiresIn string `json:"expires_in"` // "30d", "90d", "1y", "" for no expiry
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	if body.Name == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "name required"})
		return
	}
	if body.Scopes == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "scopes required (use '*' for full access)"})
		return
	}
	if err := validateScopes(body.Scopes); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !scopesWithin(session.Scopes, body.Scopes) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "requested scopes exceed your permissions"})
		return
	}

	// Generate raw token with identifiable prefix
	rawToken := "bmr_" + generateToken(32)
	tokenHash := hashToken(rawToken)

	// Parse expiry
	var expiresAt *string
	if body.ExpiresIn != "" {
		dur := parseTokenExpiry(body.ExpiresIn)
		if dur == 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid expires_in (use 30d, 90d, 1y)"})
			return
		}
		t := time.Now().Add(dur).UTC().Format(time.RFC3339)
		expiresAt = &t
	}

	_, err := app.DB.Exec(
		"INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)",
		session.UserID, body.Name, tokenHash, body.Scopes, expiresAt,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create token"})
		return
	}

	// Return raw token ONCE - it's never stored or retrievable again
	httpJSON(w, http.StatusOK, map[string]any{
		"token":  rawToken,
		"name":   body.Name,
		"scopes": body.Scopes,
	})
}

// handleListAPITokens lists the authenticated user's API tokens.
// GET /api/_auth/api-tokens
func handleListAPITokens(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	rows, err := QueryRows(app.DB,
		"SELECT id, name, scopes, last_used_at, expires_at, created_at FROM _benmore_api_tokens WHERE user_id = ? ORDER BY created_at DESC",
		session.UserID,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

// handleRevokeAPIToken deletes a persistent API token.
// DELETE /api/_auth/api-tokens/{id}
func handleRevokeAPIToken(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "token id required"})
		return
	}

	// SECURITY: users can only revoke their own tokens
	result, err := app.DB.Exec(
		"DELETE FROM _benmore_api_tokens WHERE id = ? AND user_id = ?",
		id, session.UserID,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "revoke failed"})
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

// parseTokenExpiry parses "30d", "90d", "1y" into a time.Duration.
func parseTokenExpiry(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 && days <= 365 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	if strings.HasSuffix(s, "y") {
		var years int
		if _, err := fmt.Sscanf(s, "%dy", &years); err == nil && years > 0 && years <= 5 {
			return time.Duration(years) * 365 * 24 * time.Hour
		}
	}
	return 0
}
