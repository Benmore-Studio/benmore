//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Plaintext that merely starts with "enc:" (any case) is sealed by the
// encryption trigger like any other value, so the blind triggers must index
// it too. Their guard was NOT LIKE 'enc:%', which left email_blind NULL on
// insert and stale on update for such values.
func TestBlindIndexCoversPlaintextWithEncPrefix(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(dbPath, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	RegisterDBEncryptionKey(dbPath, key)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(dbPath)) })
	crudScopeMustExec(t, db, `CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"contacts": {{Column: "email", BlindIndex: true}},
	}}
	if err := EnsureBlindColumns(db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := InstallEncryptionTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := InstallBlindIndexTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}

	assertBlind := func(label, plaintext string) {
		t.Helper()
		var got, want sql.NullString
		if err := db.QueryRow(`SELECT email_blind, benmore_blind_index(?) FROM contacts WHERE id = 1`, plaintext).Scan(&got, &want); err != nil {
			t.Fatal(err)
		}
		if !got.Valid || got.String != want.String {
			t.Fatalf("%s: email_blind = %v, want the index of %q (%v)", label, got, plaintext, want)
		}
		var stored string
		if err := db.QueryRow(`SELECT email FROM contacts WHERE id = 1`).Scan(&stored); err != nil || stored == plaintext {
			t.Fatalf("%s: stored email = %q (%v), want it sealed", label, stored, err)
		}
	}

	crudScopeMustExec(t, db, `INSERT INTO contacts (email) VALUES ('ENC:1')`)
	assertBlind("insert", "ENC:1")
	crudScopeMustExec(t, db, `UPDATE contacts SET email = 'enc:x' WHERE id = 1`)
	assertBlind("update", "enc:x")
	crudScopeMustExec(t, db, `UPDATE contacts SET email = 'plain@example.com' WHERE id = 1`)
	assertBlind("ordinary update", "plain@example.com")
}
