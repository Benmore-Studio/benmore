//go:build !cli

package main

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"fmt"
)

// A configuration reload must never rotate the key of the live database.
// Initializing/changing the durable key requires the startup/rotation path.
func validateReloadEncryptionKey(app *App, encrypted *EncryptedFieldConfig, nextEnv map[string]string) error {
	if encrypted == nil || len(encrypted.Fields) == 0 {
		return nil
	}
	if nextEnv["ENCRYPTION_KEY"] == "" {
		return fmt.Errorf("encryption: restart the app to initialize a durable ENCRYPTION_KEY before enabling encrypted fields")
	}
	next, err := cryptoDeriveAppKey(nextEnv["ENCRYPTION_KEY"])
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	current, err := cryptoKeyForQuerierChecked(app.DB)
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if !hmac.Equal(current, next) {
		return fmt.Errorf("encryption: ENCRYPTION_KEY differs from the running database key; use the key rotation workflow for existing encrypted data, or restart to initialize encryption")
	}
	return nil
}

// Reconcile all dependent storage machinery together. A failed history or
// blind-index installation must not change the active encryption policy.
func installReloadStorage(db *sql.DB, versioned *VersionedConfig, encrypted *EncryptedFieldConfig) error {
	key := cryptoKeyForQuerier(db)
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "reload storage install"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Encrypted config never covers a framework table; a trigger an earlier
	// load put on one goes (config_framework_tables.go).
	if err := dropConfigTriggersOnFrameworkTables(tx); err != nil {
		return fmt.Errorf("framework-table triggers: %w", err)
	}
	if err := ensureBlindColumnsWith(tx, encrypted); err != nil {
		return fmt.Errorf("blind columns: %w", err)
	}
	if err := installEncryptionTriggersWith(tx, encrypted); err != nil {
		return fmt.Errorf("encrypted-field triggers: %w", err)
	}
	if err := installBlindIndexTriggersWith(tx, encrypted); err != nil {
		return fmt.Errorf("blind triggers: %w", err)
	}
	if err := installVersioningTriggersTx(tx, versioned, encrypted, key); err != nil {
		return fmt.Errorf("versioning: %w", err)
	}
	// The encryption and blind-index triggers were just created again, so they
	// are newer than an enrolled table's revision triggers; put those first
	// again in this transaction (app_mcp_revision_order.go).
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return fmt.Errorf("revision trigger order: %w", err)
	}
	return tx.Commit()
}

// Migrations may introduce a configured table/column. Protect existing fields
// while migrations execute, then strictly reconcile the full declaration after
// them. This phase only adds machinery; it never removes prior protections if
// a later migration or final installation fails.
func installEncryptionBeforeMigrations(db *sql.DB, encrypted *EncryptedFieldConfig) error {
	if encrypted == nil {
		return nil
	}
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "encryption install"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := encryptedFieldsThatExist(tx, encrypted)
	if err != nil {
		return err
	}
	if err := ensureBlindColumnsWith(tx, existing); err != nil {
		return err
	}
	if err := installEncryptionTriggersMode(tx, existing, false); err != nil {
		return err
	}
	if err := installBlindIndexTriggersMode(tx, existing, false); err != nil {
		return err
	}
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		return fmt.Errorf("revision trigger order: %w", err)
	}
	return tx.Commit()
}

// encryptedFieldsThatExist is the part of encrypted whose columns the
// database has: what a start protects before its migration files run (they
// may create the rest). nil for a nil config.
func encryptedFieldsThatExist(q mutationQuerier, encrypted *EncryptedFieldConfig) (*EncryptedFieldConfig, error) {
	if encrypted == nil {
		return nil, nil
	}
	existing := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{}}
	for table, defs := range encrypted.Fields {
		cols, err := mainTableColumnsWith(q, table)
		if err != nil {
			return nil, err
		}
		for _, def := range defs {
			if versionHasColumn(cols, def.Column) {
				existing.Fields[table] = append(existing.Fields[table], def)
			}
		}
	}
	return existing, nil
}
