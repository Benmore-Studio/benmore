//go:build !cli

package main

// Self-service account deletion (/settings/delete-account) and small form
// helpers for the settings handlers.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// formFlagTrue reads an opt-in checkbox or flag value.
func formFlagTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// deleteOwnAccount erases the signed-in account the same way
// purge_current_user and the operator's delete_app_user do (purgeAccountTx):
// every framework credential - sessions, API tokens, OAuth tokens and codes,
// passkeys, role grants, MCP grants, pending recovery - goes in one
// transaction, and the row stays as a non-login tombstone so app tables keep
// valid references. The old handler deleted the user row and its sessions
// only, which left API tokens, OAuth tokens, passkeys and role grants
// pointing at a reusable id. The app's last usable durable admin gets
// errLastDurableAdmin and nothing is deleted.
func deleteOwnAccount(app *App, session *Session) error {
	email, err := purgeOwnAccount(app, session)
	if err != nil {
		return err
	}
	platformAccountDeleted(app, email)
	return nil
}

// purgeOwnAccount is deleteOwnAccount without the platform step: it erases
// the signed-in account in the app's own database and returns the address it
// had. The hosted dashboard's Delete account calls it, then deletes the
// control-plane account itself (platform_account_delete_dashboard.go).
func purgeOwnAccount(app *App, session *Session) (string, error) {
	return purgeOwnAccountWith(app, session, nil)
}

// purgeOwnAccountWith is purgeOwnAccount with an extra step run in the same
// transaction once the row is a tombstone (the dashboard also empties its
// own profile columns).
func purgeOwnAccountWith(app *App, session *Session, extra func(tx *sql.Tx, userCols map[string]bool) error) (string, error) {
	if app == nil || app.DB == nil || session == nil || session.UserID <= 0 {
		return "", errors.New("no account")
	}
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	userCols, exists, err := purgeTableColumns(tx, "_benmore_users")
	if err != nil {
		return "", err
	}
	if !exists {
		return "", errors.New("users table missing")
	}
	if err := purgeRequireColumns("_benmore_users", userCols,
		"id", "username", "email", "phone", "password_hash", "first_name", "last_name", "avatar_url", "role", "verified", "deactivated_at", "last_login_at"); err != nil {
		return "", err
	}
	sessionCols, exists, err := purgeTableColumns(tx, "_benmore_sessions")
	if err != nil {
		return "", err
	}
	if !exists {
		return "", errors.New("sessions table missing")
	}
	if err := purgeRequireColumns("_benmore_sessions", sessionCols, "id", "user_id", "email"); err != nil {
		return "", err
	}
	// The app's last usable durable admin cannot delete itself: the app
	// would have no admin left (last_admin_guard.go). Callers show
	// errLastDurableAdmin to the person.
	if err := refuseLastDurableAdmin(app, tx, session.UserID, dropsAccount); err != nil {
		return "", err
	}
	var email string
	tx.QueryRow(`SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?`, session.UserID).Scan(&email)
	_, artifactRefs, err := purgeAccountTx(context.Background(), app, tx, session.UserID, userCols, sessionCols, session.UserID, "")
	if err != nil {
		return "", err
	}
	if extra != nil {
		if err := extra(tx, userCols); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	deleteAppMCPArtifactBytes(app, artifactRefs)
	return email, nil
}
