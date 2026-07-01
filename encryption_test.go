//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

func TestEncryptedFieldYAMLSimpleFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts: [notes, ssn]
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if raw.Encrypted["contacts"][1].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if len(raw.Encrypted["contacts"][0].Roles) != 0 {
		t.Errorf("simple format should have no roles, got %v", raw.Encrypted["contacts"][0].Roles)
	}
}

func TestEncryptedFieldYAMLDetailedFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts:
    - column: ssn
      roles: [admin, manager]
    - column: notes
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if len(raw.Encrypted["contacts"][0].Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(raw.Encrypted["contacts"][0].Roles))
	}
	if raw.Encrypted["contacts"][0].Roles[0] != "admin" {
		t.Errorf("expected 'admin', got '%s'", raw.Encrypted["contacts"][0].Roles[0])
	}
	// Second field has no roles
	if raw.Encrypted["contacts"][1].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if len(raw.Encrypted["contacts"][1].Roles) != 0 {
		t.Errorf("notes should have no roles, got %v", raw.Encrypted["contacts"][1].Roles)
	}
}

func TestEncryptedFieldYAMLMixedFormat(t *testing.T) {
	yamlStr := `
encrypted:
  contacts:
    - notes
    - column: ssn
      roles: [admin]
`
	var raw EncryptedYAML
	if err := yaml.Unmarshal([]byte(yamlStr), &raw); err != nil {
		t.Fatalf("parse error: %s", err)
	}

	if len(raw.Encrypted["contacts"]) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(raw.Encrypted["contacts"]))
	}
	if raw.Encrypted["contacts"][0].Column != "notes" {
		t.Errorf("expected 'notes', got '%s'", raw.Encrypted["contacts"][0].Column)
	}
	if raw.Encrypted["contacts"][1].Column != "ssn" {
		t.Errorf("expected 'ssn', got '%s'", raw.Encrypted["contacts"][1].Column)
	}
	if raw.Encrypted["contacts"][1].Roles[0] != "admin" {
		t.Errorf("expected 'admin' role, got '%s'", raw.Encrypted["contacts"][1].Roles[0])
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"123-45-6789", "*******6789"},
		{"abc", "****"},
		{"", "****"},
		{"secret data here", "************here"},
	}
	for _, tt := range tests {
		got := maskValue(tt.input)
		if got != tt.expected {
			t.Errorf("maskValue(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// newEncTestDB opens a fresh sqlite3_benmore database in a temp dir and
// initialises a fixed 32-byte encryption key.  It returns the *sql.DB and a
// cleanup function that resets appEncryptionKey to its previous value so
// other tests in the binary are not affected.
func newEncTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	oldKey := appEncryptionKey
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i + 1)
	}
	appEncryptionKey = testKey
	if err := SetBlindIndexKey(testKey); err != nil {
		t.Fatalf("SetBlindIndexKey: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "enc_test.db")
	db, err := sql.Open("sqlite3_benmore", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	cleanup := func() {
		db.Close()
		appEncryptionKey = oldKey
	}
	return db, cleanup
}

// TestEncryptionTriggerIntegerPKInsideTransaction verifies that:
//   - an AFTER INSERT encryption trigger fires correctly when the INSERT is
//     executed inside an explicit sql.Tx (the "flow transaction" scenario), and
//   - the stored value is ciphertext (starts with "enc:") after commit, and
//   - the value round-trips through fieldDecryptCtx back to the original plaintext.
//
// This is the baseline case (integer PK named "id") that must continue to work.
func TestEncryptionTriggerIntegerPKInsideTransaction(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`CREATE TABLE payments (id INTEGER PRIMARY KEY AUTOINCREMENT, routing_number TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	config := &EncryptedFieldConfig{
		Fields: map[string][]EncryptedFieldDef{
			"payments": {{Column: "routing_number"}},
		},
	}
	InstallEncryptionTriggers(db, config)

	// INSERT inside a transaction (mirrors a flow with transaction: true).
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.Exec("INSERT INTO payments (routing_number) VALUES (?)", "021000021"); err != nil {
		tx.Rollback()
		t.Fatalf("insert in tx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	// The on-disk value must be ciphertext.
	var stored string
	if err := db.QueryRow("SELECT routing_number FROM payments").Scan(&stored); err != nil {
		t.Fatalf("read routing_number: %v", err)
	}
	if !cryptoIsEncrypted(stored) {
		t.Fatalf("routing_number should be encrypted after INSERT trigger, got %q", stored)
	}

	// Round-trip: decrypt must recover the original plaintext.
	got, err := fieldDecryptCtx(appEncryptionKey, "routing_number", stored)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "021000021" {
		t.Fatalf("decrypted routing_number = %q, want %q", got, "021000021")
	}
}

// TestEncryptionTriggerNonIdPrimaryKey is the regression test for the bug that
// caused encrypted writes to fail for tables whose primary-key column is NOT
// named "id".
//
// Before the fix, InstallEncryptionTriggers emitted:
//
//	UPDATE <table> SET <col> = benmore_encrypt(...) WHERE id = NEW.id
//
// For a table whose PK column is named something other than "id" (e.g.
// "account_id"), SQLite would raise "no such column: id" inside the trigger
// body, which propagated back and caused the original INSERT to fail entirely.
// This is exactly what happened with mt_external_accounts / mt_webhook_events
// in a client app (its migrations 0007/0008 dropped the triggers as a
// workaround).
//
// The fix changes the WHERE clause to use the SQLite built-in pseudo-column
// rowid:
//
//	UPDATE <table> SET <col> = benmore_encrypt(...) WHERE rowid = NEW.rowid
//
// rowid is available on every SQLite table regardless of the PK column name
// (the only exception is WITHOUT ROWID tables, which the framework never emits).
func TestEncryptionTriggerNonIdPrimaryKey(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()

	// Use a PK column named "account_id" (not "id") to reproduce the failure.
	if _, err := db.Exec(`CREATE TABLE mt_external_accounts (
		account_id TEXT PRIMARY KEY,
		routing_number TEXT,
		account_number TEXT
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	config := &EncryptedFieldConfig{
		Fields: map[string][]EncryptedFieldDef{
			"mt_external_accounts": {
				{Column: "routing_number"},
				{Column: "account_number"},
			},
		},
	}
	InstallEncryptionTriggers(db, config)

	// INSERT must NOT fail even though the table has no "id" column.
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	_, insertErr := tx.Exec(
		"INSERT INTO mt_external_accounts (account_id, routing_number, account_number) VALUES (?, ?, ?)",
		"ext_acc_test001", "021000021", "123456789",
	)
	if insertErr != nil {
		tx.Rollback()
		t.Fatalf("INSERT inside tx failed (trigger bug?): %v", insertErr)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	// Both columns must be stored as ciphertext.
	var storedRouting, storedAccount string
	if err := db.QueryRow("SELECT routing_number, account_number FROM mt_external_accounts").Scan(&storedRouting, &storedAccount); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if !cryptoIsEncrypted(storedRouting) {
		t.Fatalf("routing_number must be encrypted, got %q", storedRouting)
	}
	if !cryptoIsEncrypted(storedAccount) {
		t.Fatalf("account_number must be encrypted, got %q", storedAccount)
	}
	if !strings.HasPrefix(storedRouting, "enc:v2:") {
		t.Fatalf("routing_number should use v2 (AAD-bound) format, got %q", storedRouting)
	}

	// Round-trip both columns.
	if plain, err := fieldDecryptCtx(appEncryptionKey, "routing_number", storedRouting); err != nil || plain != "021000021" {
		t.Fatalf("routing_number round-trip: got %q err %v", plain, err)
	}
	if plain, err := fieldDecryptCtx(appEncryptionKey, "account_number", storedAccount); err != nil || plain != "123456789" {
		t.Fatalf("account_number round-trip: got %q err %v", plain, err)
	}
}

// TestEncryptionTriggerUpdatePath verifies the AFTER UPDATE OF trigger: a
// subsequent UPDATE to a plaintext value on a non-id-PK table must also
// encrypt the new value and not re-encrypt already-encrypted values.
func TestEncryptionTriggerUpdatePath(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()

	if _, err := db.Exec(`CREATE TABLE mt_external_accounts2 (
		account_id TEXT PRIMARY KEY,
		routing_number TEXT
	)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	config := &EncryptedFieldConfig{
		Fields: map[string][]EncryptedFieldDef{
			"mt_external_accounts2": {{Column: "routing_number"}},
		},
	}
	InstallEncryptionTriggers(db, config)

	// Seed row (INSERT trigger encrypts).
	if _, err := db.Exec(
		"INSERT INTO mt_external_accounts2 (account_id, routing_number) VALUES (?, ?)",
		"ext_acc_upd001", "021000021",
	); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// UPDATE to a new plaintext value – the AFTER UPDATE trigger must encrypt it.
	if _, err := db.Exec(
		"UPDATE mt_external_accounts2 SET routing_number = ? WHERE account_id = ?",
		"026009593", "ext_acc_upd001",
	); err != nil {
		t.Fatalf("update routing_number: %v", err)
	}

	var stored string
	if err := db.QueryRow("SELECT routing_number FROM mt_external_accounts2").Scan(&stored); err != nil {
		t.Fatalf("read after update: %v", err)
	}
	if !cryptoIsEncrypted(stored) {
		t.Fatalf("routing_number must be encrypted after UPDATE trigger, got %q", stored)
	}
	if plain, err := fieldDecryptCtx(appEncryptionKey, "routing_number", stored); err != nil || plain != "026009593" {
		t.Fatalf("routing_number round-trip after update: got %q err %v", plain, err)
	}

	// Updating an already-encrypted value (e.g. after rotation) must be idempotent.
	encryptedValue := stored
	if _, err := db.Exec(
		"UPDATE mt_external_accounts2 SET routing_number = ? WHERE account_id = ?",
		encryptedValue, "ext_acc_upd001",
	); err != nil {
		t.Fatalf("update with already-encrypted value: %v", err)
	}
	var stored2 string
	if err := db.QueryRow("SELECT routing_number FROM mt_external_accounts2").Scan(&stored2); err != nil {
		t.Fatalf("read after idempotent update: %v", err)
	}
	// Value must still decrypt to the same plaintext – not double-encrypted.
	if plain, err := fieldDecryptCtx(appEncryptionKey, "routing_number", stored2); err != nil || plain != "026009593" {
		t.Fatalf("idempotent update broke decryption: got %q err %v", plain, err)
	}
}
