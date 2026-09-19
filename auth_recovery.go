//go:build !cli

package main

// Password recovery and email-verification token storage and handlers.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// EnsurePasswordResetsTable creates the password reset tokens table.
func EnsurePasswordResetsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_password_resets (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		used INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	// Add type column to distinguish reset vs verify tokens (migration-safe)
	db.Exec("ALTER TABLE _benmore_password_resets ADD COLUMN type TEXT DEFAULT 'reset'")
	// Cleanup expired tokens
	db.Exec("DELETE FROM _benmore_password_resets WHERE datetime(expires_at) < datetime('now')")
}

// hashResetToken returns the SHA-256 hex of a password-reset / email-verify
// token. Tokens are stored hashed (2026-06-11 audit) so a DB-read leak
// (backup, SQL console) can't expose live account-takeover links - same
// posture as API tokens. The raw token only ever exists inside the email.
func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	email := normalizeEmail(r.FormValue("email"))
	if email == "" {
		authRedirect(w, r, app.Paths.ForgotPassword, "Email is required")
		return
	}

	// Per-target cooldown: cap reset emails per address so an attacker can't
	// inbox-bomb a known user or flood _benmore_password_resets. Checked
	// before the existence lookup so the response timing/behavior is uniform
	// regardless of whether the account exists (no enumeration signal). The
	// always-success redirect below is unchanged.
	if !forgotPasswordLimiter.Allow("fp:" + strings.ToLower(email)) {
		http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
		return
	}

	// Always show success (don't leak whether email exists)
	// But only send email if account exists
	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE email = ? COLLATE NOCASE", email).Scan(&count)
	if count > 0 {
		token := generateToken(32)
		expires := time.Now().Add(1 * time.Hour)
		app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'reset')",
			hashResetToken(token), email, expires.UTC().Format(time.RFC3339))

		// Build reset URL - prefer configured SEO URL over r.Host to prevent header injection
		resetURL := fmt.Sprintf("%s%s?token=%s", securityLinkBaseURL(app, r), app.Paths.ResetPassword, token)

		siteName := "App"
		if app.Design != nil {
			if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
				siteName = sn
			}
		}

		body := RenderBrandedEmail(
			AppEmailBrand(app, r),
			"Reset your password",
			fmt.Sprintf("Click the button below to set a new password for your %s account. This link expires in 1 hour.", html.EscapeString(siteName)),
			"Reset password",
			resetURL,
			"If you didn't request this, you can safely ignore this email - no changes will be made to your account.",
		)
		if err := SendEmail(app.Dir, email, "Reset your password · "+siteName, body); err != nil {
			log.Printf("auth: password-reset email failed (to=%s): %v", email, err)
		}
	}

	// Always show success (don't reveal whether email exists)
	http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
}

func handleResetPassword(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	token := r.FormValue("token")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if token == "" {
		authRedirect(w, r, app.Paths.ResetPassword, "Invalid reset link")
		return
	}
	if password == "" {
		authRedirect(w, r, app.Paths.ResetPassword, "Password is required")
		return
	}
	if password != confirm {
		authRedirect(w, r, app.Paths.ResetPassword, "Passwords do not match")
		return
	}
	if msg := validatePasswordComplexity(password); msg != "" {
		authRedirect(w, r, app.Paths.ResetPassword, msg)
		return
	}

	// Resolve proof without consuming it until the credential update can commit.
	var email, previousHash string
	var userID int64
	var pending int
	err := app.DB.QueryRow(`SELECT u.id,COALESCE(u.email,''),COALESCE(u.password_hash,''),COALESCE(u.password_change_required,0)
  FROM _benmore_password_resets p JOIN _benmore_users u ON u.email=p.email COLLATE NOCASE
  WHERE p.token IN (?,?) AND datetime(p.expires_at)>datetime('now') AND p.used=0 AND p.type='reset'`,
		hashResetToken(token), token).Scan(&userID, &email, &previousHash, &pending)
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Invalid or expired reset link")
		return
	}
	if len(password) > maxBcryptBytes {
		authRedirect(w, r, app.Paths.ResetPassword, "Password must be at most 72 bytes")
		return
	}
	if pending != 0 && bcrypt.CompareHashAndPassword([]byte(previousHash), []byte(password)) == nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Choose a different password from the temporary password")
		return
	}
	hash, err := generateBcryptHash([]byte(password))
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	tx, err := app.DB.Begin()
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE _benmore_password_resets SET used=1 WHERE token IN (?,?) AND used=0 AND type='reset' AND datetime(expires_at)>datetime('now')", hashResetToken(token), token)
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		authRedirect(w, r, app.Paths.ResetPassword, "Reset link already used")
		return
	}
	result, err = tx.Exec("UPDATE _benmore_users SET password_hash=?,password_change_required=0 WHERE id=? AND COALESCE(password_hash,'')=?", string(hash), userID, previousHash)
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		authRedirect(w, r, app.Paths.ResetPassword, "Credentials changed. Request a new reset link.")
		return
	}
	if err := revokePasswordCredentials(tx, userID); err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email) VALUES ('password_reset','_benmore_users',?,?,?)`, userID, userID, email); err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	if err := tx.Commit(); err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	syncPlatformUserFromDashboard(app, email, string(hash))

	// Redirect to login with a success message the page can surface.
	http.Redirect(w, r, app.Paths.Login+"?success="+url.QueryEscape("Password updated. Sign in with your new password."), http.StatusSeeOther)
}

func handleVerifyEmail(w http.ResponseWriter, r *http.Request, app *App) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Validate token - only accept 'verify' type tokens (not 'reset').
	// Stored hashed; IN(hash, raw) covers links issued pre-deploy (1h TTL).
	var email string
	err := app.DB.QueryRow(
		"SELECT email FROM _benmore_password_resets WHERE token IN (?, ?) AND datetime(expires_at) > datetime('now') AND used = 0 AND type = 'verify'",
		hashResetToken(token), token,
	).Scan(&email)
	if err != nil {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Mark token as used atomically - prevents replay
	result, _ := app.DB.Exec("UPDATE _benmore_password_resets SET used = 1 WHERE token IN (?, ?) AND used = 0 AND type = 'verify'", hashResetToken(token), token)
	if affected, _ := result.RowsAffected(); affected == 0 {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Mark user as verified
	app.DB.Exec("UPDATE _benmore_users SET verified = 1 WHERE email = ?", email)

	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}
