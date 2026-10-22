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

// maxLiveResetLinks is how many unused, unexpired reset links one address
// may hold at once (handleForgotPassword).
const maxLiveResetLinks = 3

// dispatchAuthEmail runs a credential email's delivery off the request
// path. Tests replace it to deliver synchronously.
var dispatchAuthEmail = func(send func()) { safeGo("auth.email", send) }

func handleForgotPassword(w http.ResponseWriter, r *http.Request, app *App) {
	if refuseDisabledAuthFeature(w, r, app, "password_reset") {
		return
	}
	mergeJSONBodyIntoForm(r)
	// Same CSRF rule as login and signup: framework-served forms carry the
	// token (injected field or <meta>), and a cross-site page must not be
	// able to fire reset mail at an address.
	if !validateCSRF(r) {
		authCSRFRefused(w, r, app.Paths.ForgotPassword)
		return
	}
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
	if !forgotPasswordLimiter.Allow(appLimiterKey(app, "fp", mailboxRateKey(email))) {
		http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
		return
	}

	// Always show success (don't leak whether email exists)
	// But only send email if account exists
	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE email = ? COLLATE NOCASE", email).Scan(&count)
	// Build the reset URL from a configured origin, never a client-supplied
	// Host: without one no link is sent (securityLinkBaseURL logs the fix),
	// and the response stays the same so account existence isn't revealed.
	// Resolved for every address, so this work doesn't time the lookup.
	linkBase, linkOK := securityLinkBaseURL(app, r)
	brand := AppEmailBrand(app, r)
	// A new request does not retire the address's earlier unused links:
	// anyone can ask for a link to any address, and retiring them let a
	// stranger kill the link the owner was about to click. Every link still
	// dies when it expires (1 hour) or when one of them is used (the reset
	// revokes the rest, cancelPendingRecovery). At most maxLiveResetLinks are
	// live per address; past that a request sends nothing until one ends,
	// which also caps reset mail per address beyond the in-memory limiter.
	token := generateToken(32)
	if count > 0 && linkOK && storeResetLink(app.DB, email, token) {
		resetURL := fmt.Sprintf("%s%s?token=%s", linkBase, app.Paths.ResetPassword, token)

		siteName := "App"
		if app.Design != nil {
			if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
				siteName = sn
			}
		}

		body := RenderBrandedEmail(
			brand,
			"Reset your password",
			fmt.Sprintf("Click the button below to set a new password for your %s account. This link expires in 1 hour.", html.EscapeString(siteName)),
			"Reset password",
			resetURL,
			"If you didn't request this, you can safely ignore this email - no changes will be made to your account.",
		)
		// Delivery (the email broker or SMTP round trip) is the slow step
		// that only a real account takes; sending it off the request keeps
		// the response time the same whether or not the address exists.
		dispatchAuthEmail(func() {
			if err := SendEmail(app.Dir, email, "Reset your password · "+siteName, body); err != nil {
				log.Printf("auth: password-reset email failed (to=%s): %s", logAddressRef(email), logSendError(err, email))
			}
		})
	}

	// Always show success (don't reveal whether email exists)
	http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
}

// storeResetLink records a one-hour reset link for email unless the address
// already holds maxLiveResetLinks live ones. Reports whether it was stored,
// so mail goes out only for a link that works.
func storeResetLink(db *sql.DB, email, token string) bool {
	res, err := db.Exec(`INSERT INTO _benmore_password_resets (token, email, expires_at, type)
		SELECT ?, ?, ?, 'reset' WHERE (SELECT COUNT(*) FROM _benmore_password_resets
			WHERE type = 'reset' AND used = 0 AND email = ? COLLATE NOCASE AND datetime(expires_at) > datetime('now')) < ?`,
		hashResetToken(token), email, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), email, maxLiveResetLinks)
	if err != nil {
		log.Printf("auth: password-reset link not stored: %v", err)
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

func handleResetPassword(w http.ResponseWriter, r *http.Request, app *App) {
	if refuseDisabledAuthFeature(w, r, app, "password_reset") {
		return
	}
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
  WHERE p.token = ? AND datetime(p.expires_at)>datetime('now') AND p.used=0 AND p.type='reset'`,
		hashResetToken(token)).Scan(&userID, &email, &previousHash, &pending)
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
	result, err := tx.Exec("UPDATE _benmore_password_resets SET used=1 WHERE token = ? AND used=0 AND type='reset' AND datetime(expires_at)>datetime('now')", hashResetToken(token))
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
	if err := clearUnverifiedAccountMFA(tx, userID); err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	if err := revokePasswordCredentials(tx, userID); err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	// Passkeys are sign-ins of their own, registered from sessions the old
	// password produced. A reset is how an owner takes an account back (from
	// someone who registered the address first, or who held a session), so
	// they go with the sessions; the owner can add new ones once signed in.
	if _, err := revokeAccountPasskeys(tx, userID); err != nil {
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
	invalidateRequestSession(r) // the account's sessions are gone
	revokeEdgeGrantsAfterCredentialChange(app, userID)
	// A completed reset link proves the address and replaces the password:
	// on the hosted dashboard it also revokes the account's CLI and MCP
	// credentials.
	platformPasswordChanged(app, email, string(hash), true)

	// Redirect to login with a success message the page can surface.
	http.Redirect(w, r, app.Paths.Login+"?success="+url.QueryEscape("Password updated. Sign in with your new password."), http.StatusSeeOther)
}

// clearUnverifiedAccountMFA removes the second factor (secret, backup codes,
// a pending enrollment and its replay marker) from an account whose address
// was never verified. A reset link proves the mailbox, but an unverified
// account may have been registered, and enrolled, by someone else; their
// authenticator would survive the reset and lock the real owner out. A
// verified account keeps its factor.
func clearUnverifiedAccountMFA(tx *sql.Tx, userID int64) error {
	var cols int
	if err := tx.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name IN ('totp_secret', 'backup_codes', 'mfa_last_totp', 'mfa_last_totp_at')").Scan(&cols); err != nil {
		return err
	}
	if cols != 4 {
		return nil // MFA columns are added together at startup
	}
	_, err := tx.Exec(`UPDATE _benmore_users SET totp_secret = NULL, backup_codes = NULL, mfa_last_totp = NULL, mfa_last_totp_at = NULL
		WHERE id = ? AND COALESCE(verified, 0) = 0`, userID)
	return err
}

// revokeOtherCredentials deletes every session and API token of an account
// except the session keepSessionID ("" keeps none) and revokes its connector
// grants, in one transaction.
func revokeOtherCredentials(db *sql.DB, userID int64, keepSessionID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"_benmore_sessions", "_benmore_api_tokens"} {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		query, args := "DELETE FROM "+table+" WHERE user_id=?", []any{userID}
		if table == "_benmore_sessions" && keepSessionID != "" {
			query += " AND id<>?"
			args = append(args, keepSessionID)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
	}
	if err := revokeAppMCPUserGrants(tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}
