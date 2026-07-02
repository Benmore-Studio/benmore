//go:build !cli

package main

// Tests for the per-DB crypto key registry (v2.7.194) - the fix for the
// router↔app encryption key mismatch. The router process opens many
// tenants' databases side by side; before the registry, every crypto
// path in that process used the single process-global appEncryptionKey
// (some other app's key, or nil), so router-side writes produced
// ciphertext the owning app could never read and router-side reads
// passed raw ciphertext through to callers.

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// testKeyBytes returns a deterministic 32-byte key seeded by b.
func testKeyBytes(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i) ^ b
	}
	return k
}

// TestSQLFunctionsUsePerDBRegistryKey simulates the router: the process
// global is app B's key, but the connection's database is app A's, whose
// key is registered in dbCryptoRegistry. benmore_encrypt (via the
// encryption trigger) must use app A's registered key - the owning app
// process (which holds A's key as ITS global) must be able to decrypt.
func TestSQLFunctionsUsePerDBRegistryKey(t *testing.T) {
	keyA := testKeyBytes(0xA1) // the tenant app's real key (registered)
	keyB := testKeyBytes(0xB2) // some other app's key (the process global)

	oldKey := appEncryptionKey
	appEncryptionKey = keyB
	defer func() { appEncryptionKey = oldKey }()

	dbPath := filepath.Join(t.TempDir(), "tenant_a.db")
	RegisterDBEncryptionKey(dbPath, keyA)

	db, err := sql.Open("sqlite3_benmore", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE clients (id INTEGER PRIMARY KEY, ssn TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	config := &EncryptedFieldConfig{
		Fields: map[string][]EncryptedFieldDef{"clients": {{Column: "ssn"}}},
	}
	// InstallEncryptionTriggers requires a non-nil global; the trigger
	// body itself resolves the per-conn key at execution time.
	InstallEncryptionTriggers(db, config)

	if _, err := db.Exec("INSERT INTO clients (ssn) VALUES (?)", "123-45-6789"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var stored string
	if err := db.QueryRow("SELECT ssn FROM clients").Scan(&stored); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !cryptoIsEncrypted(stored) {
		t.Fatalf("ssn should be ciphertext, got %q", stored)
	}

	// The OWNING app's key must decrypt it; the process-global (wrong
	// app's) key must NOT.
	if got, err := fieldDecryptCtx(keyA, "ssn", stored); err != nil || got != "123-45-6789" {
		t.Fatalf("decrypt under registered tenant key = %q, %v; want plaintext", got, err)
	}
	if _, err := fieldDecryptCtx(keyB, "ssn", stored); err == nil {
		t.Fatalf("ciphertext decrypted under the WRONG (process-global) key - registry not honored")
	}

	// benmore_decrypt on the same connection must also use the
	// registered key (SELECT-with-decrypt path).
	var plain string
	if err := db.QueryRow("SELECT benmore_decrypt(ssn, 'clients', 'ssn') FROM clients").Scan(&plain); err != nil {
		t.Fatalf("benmore_decrypt: %v", err)
	}
	if plain != "123-45-6789" {
		t.Fatalf("benmore_decrypt = %q, want plaintext", plain)
	}
}

// TestDecryptRowFieldsRegistryFallback: the process global is the wrong
// key, but the value's true key is registered for SOME db path.
// DecryptRowFields (which has no connection to resolve a path from) must
// recover the plaintext by trying registered keys - AES-GCM authentication
// guarantees only the correct key can succeed.
func TestDecryptRowFieldsRegistryFallback(t *testing.T) {
	keyA := testKeyBytes(0xC3)
	keyB := testKeyBytes(0xD4)

	oldKey := appEncryptionKey
	appEncryptionKey = keyB
	defer func() { appEncryptionKey = oldKey }()

	RegisterDBEncryptionKey(filepath.Join(t.TempDir(), "data.db"), keyA)

	cipher, err := fieldEncryptCtx(keyA, "clients", "email", "pii@example.com")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	row := map[string]any{"email": cipher, "name": "unencrypted"}
	DecryptRowFields(row)
	if row["email"] != "pii@example.com" {
		t.Fatalf("registry fallback failed: email = %q", row["email"])
	}
	if row["name"] != "unencrypted" {
		t.Fatalf("plaintext column must pass through, got %q", row["name"])
	}
}

// TestDecryptRowFieldsMasksOnFailure: ciphertext written under a key NO
// process knows must come back masked - never the raw enc:… string
// (pre-v2.7.194 behavior, which leaked ciphertext to API clients and
// looked like silent data corruption).
func TestDecryptRowFieldsMasksOnFailure(t *testing.T) {
	lostKey := testKeyBytes(0xE5) // never registered, not the global

	oldKey := appEncryptionKey
	appEncryptionKey = testKeyBytes(0xF6)
	defer func() { appEncryptionKey = oldKey }()

	cipher, err := fieldEncryptCtx(lostKey, "clients", "notes", "secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	row := map[string]any{"notes": cipher}
	DecryptRowFields(row)
	if row["notes"] == cipher {
		t.Fatalf("raw ciphertext passed through to the caller - must be masked")
	}
	if row["notes"] != decryptFailMask {
		t.Fatalf("notes = %q, want %q", row["notes"], decryptFailMask)
	}
}

// TestWritableByOwningUser: a dir owned by the CURRENT uid returns false
// (the probe's own result is authoritative); a nonexistent path walks up
// to the nearest existing ancestor.
func TestWritableByOwningUser(t *testing.T) {
	dir := t.TempDir()
	if writableByOwningUser(dir) {
		t.Fatalf("same-uid dir must return false (probe result is authoritative)")
	}
	if writableByOwningUser(filepath.Join(dir, "does", "not", "exist")) {
		t.Fatalf("nonexistent path under same-uid dir must return false")
	}
}
