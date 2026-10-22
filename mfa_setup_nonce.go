//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const mfaSetupNonceColumn = "mfa_setup_nonce"

// ensureMFASetupNonce installs the enrollment revocation marker atomically.
// Credential writes rotate even when their values do not change: a supported
// operator reset may write the same precomputed temporary-password hash again.
// Triggers cover those app-authored SQL writes as well as the auth handlers.
func ensureMFASetupNonce(db *sql.DB) error {
	var tx *sql.Tx
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		tx, err = db.Begin()
		if err == nil {
			// Not every caller uses the app DSN's _txlock=immediate. Acquire
			// the writer before schema reads so a deferred transaction cannot
			// become an un-upgradable read snapshot. No row or trigger changes.
			_, err = tx.Exec("UPDATE main._benmore_users SET id=id WHERE 0")
		}
		if err == nil {
			break
		}
		if tx != nil {
			tx.Rollback()
		}
		if !isDatabaseBusyError(err) || !time.Now().Before(deadline) {
			return fmt.Errorf("ensure MFA enrollment revocation: %w", err)
		}
		// Retry only the writer acquisition, before any migration read/write.
		// This also supports connections with a short or zero busy_timeout.
		time.Sleep(10 * time.Millisecond)
	}
	defer tx.Rollback()
	var kind string
	err = tx.QueryRow("SELECT type FROM pragma_table_info('_benmore_users') WHERE name=?", mfaSetupNonceColumn).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec("ALTER TABLE main._benmore_users ADD COLUMN mfa_setup_nonce TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("ensure MFA enrollment nonce column: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect MFA enrollment nonce column: %w", err)
	} else if !strings.EqualFold(kind, "TEXT") {
		return fmt.Errorf("MFA enrollment nonce column must have TEXT affinity")
	}
	for _, statement := range []string{
		"DROP TRIGGER IF EXISTS main._benmore_mfa_setup_nonce_insert",
		"DROP TRIGGER IF EXISTS main._benmore_mfa_setup_nonce_reset",
		`CREATE TRIGGER main._benmore_mfa_setup_nonce_insert AFTER INSERT ON _benmore_users BEGIN
			UPDATE _benmore_users SET mfa_setup_nonce=lower(hex(randomblob(16))) WHERE id=NEW.id;
		END`,
		`CREATE TRIGGER main._benmore_mfa_setup_nonce_reset AFTER UPDATE OF password_hash,password_change_required ON _benmore_users BEGIN
			UPDATE _benmore_users SET mfa_setup_nonce=lower(hex(randomblob(16))) WHERE id=NEW.id;
		END`,
		// Preserve valid markers across startup/reload so in-flight enrollment
		// remains usable. Missing or malformed markers cannot authorize tokens.
		`UPDATE main._benmore_users SET mfa_setup_nonce=lower(hex(randomblob(16)))
			WHERE typeof(mfa_setup_nonce)<>'text' OR length(mfa_setup_nonce)<>32
			OR mfa_setup_nonce GLOB '*[^0-9a-f]*'`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("install MFA enrollment revocation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MFA enrollment revocation: %w", err)
	}
	return nil
}

func validMFASetupNonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	for _, ch := range nonce {
		if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
