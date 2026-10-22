//go:build !cli

package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
)

// appMCPCommandStorageRows reports whether command storage exists and how many
// sealed rows (operations, approvals and the marker) a key rotation must move.
func appMCPCommandStorageRows(db *sql.DB) (bool, int, error) {
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='table' AND name IN ('_benmore_mcp_operations','_benmore_mcp_command_approvals','_benmore_mcp_command_attempts','_benmore_encryption_state')`).Scan(&tables); err != nil {
		return false, 0, err
	}
	if tables == 0 {
		return false, 0, nil
	}
	rows := 0
	for _, table := range []string{"_benmore_mcp_operations", "_benmore_mcp_command_approvals", "_benmore_mcp_command_attempts", "_benmore_encryption_state"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM main.` + table).Scan(&n); err != nil { // constant identifiers
			return false, 0, fmt.Errorf("count %s: %w", table, err)
		}
		rows += n
	}
	return true, rows, nil
}

// rotateAppEncryptionStateTx reseals the marker under newKey with a fresh key
// generation and rotation id. It compares the stored ciphertext, so a
// concurrent change makes the swap fail and the caller roll back.
func rotateAppEncryptionStateTx(ctx context.Context, tx *sql.Tx, ownerID string, oldKey, newKey []byte) error {
	if len(oldKey) != 32 || len(newKey) != 32 || subtle.ConstantTimeCompare(oldKey, newKey) == 1 {
		return errors.New("invalid encryption state rotation keys")
	}
	state, err := readAppEncryptionState(ctx, tx, ownerID, oldKey)
	if err != nil || state == nil {
		return errors.New("encryption state cannot be verified for rotation")
	}
	oldCiphertext, err := appMCPReadLifecycleCiphertext(ctx, tx)
	if err != nil {
		return errors.New("encryption state ciphertext cannot be read for rotation")
	}
	generation, err1 := appMCPRandomHex(32)
	rotation, err2 := appMCPRandomHex(32)
	if err := errors.Join(err1, err2); err != nil {
		return err
	}
	next := *state
	next.KeyGeneration, next.LastRotationID = generation, rotation
	sealed, err := sealAppEncryptionState(newKey, next)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE main._benmore_encryption_state SET key_generation=?, last_rotation_id=?, verification_ciphertext=? WHERE singleton=1 AND verification_ciphertext COLLATE BINARY=?`,
		generation, rotation, sealed, oldCiphertext)
	if err != nil {
		return errors.New("encryption state reseal failed")
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return errors.New("encryption state reseal compare-and-swap failed")
	}
	return nil
}

// rotateAppMCPCommandStorageTx moves the whole command store to newKey in the
// caller's transaction: approvals (validated against the full union under the
// old key first), operations, then the marker, and finally proves the result
// authenticates under newKey. Any error requires the caller to roll back.
func rotateAppMCPCommandStorageTx(ctx context.Context, tx *sql.Tx, app *App, oldKey, newKey []byte) (int, error) {
	appID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		return 0, err
	}
	approvals, err := rotateAppMCPCommandApprovalsTx(ctx, tx, appID, oldKey, newKey)
	if err != nil {
		return 0, fmt.Errorf("rotate command approvals: %w", err)
	}
	attempts, err := rotateAppMCPAttemptsTx(ctx, tx, appID, oldKey, newKey)
	if err != nil {
		return 0, fmt.Errorf("rotate command attempts: %w", err)
	}
	operations, err := rotateAppMCPOperationRowsWithKeys(ctx, tx, appID, oldKey, newKey)
	if err != nil {
		return 0, fmt.Errorf("rotate command operations: %w", err)
	}
	if err := rotateAppEncryptionStateTx(ctx, tx, appID, oldKey, newKey); err != nil {
		return 0, fmt.Errorf("rotate encryption state: %w", err)
	}
	if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, appID, newKey); err != nil {
		return 0, fmt.Errorf("verify rotated command storage: %w", err)
	}
	if _, _, err := appMCPValidateCommandStoreUnion(ctx, tx, appID, newKey); err != nil {
		return 0, fmt.Errorf("verify rotated command union: %w", err)
	}
	return approvals + attempts + operations + 1, nil
}
