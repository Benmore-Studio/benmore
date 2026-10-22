//go:build !cli

package main

// Email-keyed authorization.
//
// Tenant memberships (groups.user_field on an email column), member-of: and
// ws_rooms: rules keyed on an email column, record shares
// (_benmore_permissions.grantee_id) and pending user_roles invites all name a
// person by email address. An address identifies someone only after they
// have proven control of it, otherwise anyone could sign up as an invited
// address and inherit its tenant, rooms and shares. These grants therefore
// apply to an account only while _benmore_users.verified = 1, which is set by
// the verification link, an emailed OTP login, a confirmed email change, or a
// provider-verified OAuth sign-in (markEmailVerified).

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
)

// emailKeyedColumn reports whether a membership column identifies members by
// email - the same heuristic member-of: uses to pick the session value.
func emailKeyedColumn(col string) bool {
	return strings.Contains(strings.ToLower(col), "email")
}

// Grandfathering. Accounts that already existed when email-keyed grants
// started requiring verification keep them: _benmore_users.email_grandfathered
// is set once, for every account present when the column is added, so apps
// that key tenants by email and never sent verification links don't lock
// their current members out. Accounts created afterwards must verify. It
// counts only for email-keyed grants; `verified` (require_verified, page
// require gates) is unchanged.

// emailTrustedSQL is the predicate "this account's email may carry
// email-keyed grants" for a _benmore_users alias.
func emailTrustedSQL(alias string) string {
	return fmt.Sprintf("(COALESCE(%[1]s.verified, 0) = 1 OR COALESCE(%[1]s.email_grandfathered, 0) = 1)", alias)
}

// verifiedAccountEmailSQL is true when its single argument is the email of
// an account whose email may carry grants. The alias keeps it unambiguous
// inside queries that already read _benmore_users.
var verifiedAccountEmailSQL = verifiedAccountEmailSQLForSchema("")

func verifiedAccountEmailSQLForSchema(schema string) string {
	prefix := ""
	if schema == "main" {
		prefix = "main."
	}
	return "EXISTS (SELECT 1 FROM " + prefix + "_benmore_users vu WHERE vu.email = ? COLLATE NOCASE AND " + emailTrustedSQL("vu") + ")"
}

// ensureEmailGrandfathering adds the grandfathering column and, only when
// the column is new, marks every existing unverified account.
func ensureEmailGrandfathering(db *sql.DB) {
	var n int
	db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name = 'email_grandfathered'").Scan(&n)
	if n > 0 {
		return
	}
	if _, err := db.Exec("ALTER TABLE _benmore_users ADD COLUMN email_grandfathered INTEGER NOT NULL DEFAULT 0"); err != nil {
		return // another process added it first; it grandfathered the same rows
	}
	if _, err := db.Exec("UPDATE _benmore_users SET email_grandfathered = 1 WHERE COALESCE(verified, 0) = 0"); err != nil {
		log.Printf("email grants: grandfathering existing accounts failed: %v", err)
	}
}

// sessionGrantEmail is the address email-keyed grants may match for this
// session: its email once verified (or grandfathered), "" before (which
// matches nothing).
func sessionGrantEmail(s *Session) string {
	if s == nil || !(s.Verified || s.EmailGrandfathered) {
		return ""
	}
	return s.Email
}

// markEmailVerified records that userID has just proven control of email
// and attaches the invites that were waiting on it. The email must be the
// account's current one; a stale proof for an old address changes nothing.
func markEmailVerified(app *App, userID int64, email string) {
	if app == nil || app.DB == nil || userID == 0 || email == "" {
		return
	}
	app.DB.Exec("UPDATE _benmore_users SET verified = 1 WHERE id = ? AND email = ? COLLATE NOCASE", userID, email)
	activateEmailInvites(app, userID, email)
}

// claimUnverifiedAccount hands an existing, never-verified account to the
// person who just proved its address through a verified OAuth sign-in. Its
// password, MFA factor, passkeys, sessions, tokens and pending recovery were set up by
// whoever registered the address without proving it - possibly someone
// squatting it ahead of the real owner - so none of them survive the claim.
func claimUnverifiedAccount(app *App, userID int64, email string) error {
	return claimUnverifiedAccountAs(app, userID, email, "oauth_claim_unverified")
}

// claimUnverifiedAccountAs is claimUnverifiedAccount with the audit action
// naming how the address was proven.
func claimUnverifiedAccountAs(app *App, userID int64, email, action string) error {
	hash, err := generateBcryptHash([]byte(generateToken(32)))
	if err != nil {
		return err
	}
	EnsureAuditLogTable(app.DB) // rare path; the claim is audited in its transaction
	tx, err := app.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE _benmore_users SET password_hash = ? WHERE id = ? AND COALESCE(verified, 0) = 0", string(hash), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return tx.Commit() // verified meanwhile: nothing to claim
	}
	// A temporary password the account was told to replace is gone with the
	// hash above, so nothing is left to replace: keeping the flag would lock
	// the proven owner out of every sign-in, with no credential to clear it.
	var pendingCol int
	if err := tx.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name = 'password_change_required'").Scan(&pendingCol); err != nil {
		return err
	}
	if pendingCol == 1 {
		if _, err := tx.Exec("UPDATE _benmore_users SET password_change_required = 0 WHERE id = ?", userID); err != nil {
			return err
		}
	}
	var mfaCols int
	if err := tx.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name IN ('totp_secret', 'backup_codes')").Scan(&mfaCols); err != nil {
		return err
	}
	if mfaCols == 2 {
		if _, err := tx.Exec("UPDATE _benmore_users SET totp_secret = NULL, backup_codes = NULL WHERE id = ?", userID); err != nil {
			return err
		}
	}
	if err := revokePasswordCredentials(tx, userID); err != nil {
		return err
	}
	// A passkey the registrant enrolled is a sign-in of its own.
	if _, err := revokeAccountPasskeys(tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email)
		VALUES (?,'_benmore_users',?,?,?)`, action, userID, userID, email); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	revokeEdgeGrantsAfterCredentialChange(app, userID)
	syncPlatformUserFromDashboard(app, email, string(hash))
	return nil
}

// activateEmailInvites attaches pending invites addressed to email (the
// app-level user_roles table, when it exists) to userID - only once that
// account has verified the address.
func activateEmailInvites(app *App, userID int64, email string) {
	if app == nil || app.DB == nil || userID == 0 || email == "" {
		return
	}
	app.DB.Exec(`UPDATE user_roles SET user_id = ?, is_active = 1, invite_accepted_at = datetime('now')
		WHERE email = ? AND user_id IS NULL AND is_active = 0
		AND EXISTS (SELECT 1 FROM _benmore_users WHERE id = ? AND email = ? COLLATE NOCASE AND COALESCE(verified, 0) = 1)`,
		userID, email, userID, email)
}
