//go:build !cli

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkEncryptionFixture(t *testing.T, encrypted bool) string {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", "")
	oldIsolation := isolateAppEnvironment.Swap(true)
	oldKey, oldEphemeral := appEncryptionKey, appEncryptionKeyEphemeral
	t.Cleanup(func() {
		isolateAppEnvironment.Store(oldIsolation)
		appEncryptionKey, appEncryptionKeyEphemeral = oldKey, oldEphemeral
	})
	dir := writeApp(t, map[string]string{
		"app.yaml":   "site_name: Encryption validation fixture\n",
		"schema.sql": "CREATE TABLE documents (id INTEGER PRIMARY KEY, secret TEXT);\n",
	})
	if encrypted {
		writeTestFile(t, dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [secret]\n    blind_index: [secret]\n")
	}
	var err error
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	return dir
}

func TestCheckLoadRefusesNewEncryptionBeforePersistentEffects(t *testing.T) {
	dir := checkEncryptionFixture(t, true)
	message := tryLoadApp(dir)
	if !strings.Contains(message, "durable ENCRYPTION_KEY") {
		t.Errorf("validation must refuse missing durable key, got diagnostic %q", message)
	}
	for _, name := range []string{"env.yaml", "data.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("validation created %s before refusing missing durable encryption key", name)
		}
	}
	if cryptoKeysForDBPath(filepath.Join(dir, "data.db")) != nil {
		t.Error("validation registered a generated database encryption key")
	}
}

func TestCheckLoadPreservesRunningDatabaseWithoutDurableEncryptionKey(t *testing.T) {
	dir := checkEncryptionFixture(t, false)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	if _, err := app.DB.Exec("INSERT INTO documents (secret) VALUES ('original')"); err != nil {
		t.Fatal(err)
	}
	beforeKey := cryptoKeysForDBPath(filepath.Join(dir, "data.db"))
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [secret]\n    blind_index: [secret]\n")
	if message := tryLoadApp(dir); !strings.Contains(message, "durable ENCRYPTION_KEY") {
		t.Fatalf("missing key validation: %q", message)
	}
	if _, err := os.Stat(filepath.Join(dir, "env.yaml")); !os.IsNotExist(err) {
		t.Error("validation created env.yaml for a running database")
	}
	if afterKey := cryptoKeysForDBPath(filepath.Join(dir, "data.db")); afterKey != beforeKey {
		t.Error("validation replaced the running database key registration")
	}
	var blindColumns, triggers int
	if err := app.DB.QueryRow("SELECT count(*) FROM pragma_table_info('documents') WHERE name='secret_blind'").Scan(&blindColumns); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND tbl_name='documents'").Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if blindColumns != 0 || triggers != 0 {
		t.Fatalf("validation changed live crypto storage: blind columns=%d triggers=%d", blindColumns, triggers)
	}
	if _, err := app.DB.Exec("UPDATE documents SET secret='after rejected validation'"); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := app.DB.QueryRow("SELECT secret FROM documents").Scan(&stored); err != nil || stored != "after rejected validation" {
		t.Fatalf("running policy changed after validation: ciphertext=%t err=%v", strings.HasPrefix(stored, encPrefixV2), err)
	}
}

func TestCheckLoadKeepsStartupEncryptionAndConfiguredKeyWorking(t *testing.T) {
	for _, configured := range []bool{false, true} {
		name := "startup-generated"
		if configured {
			name = "preconfigured"
		}
		t.Run(name, func(t *testing.T) {
			dir := checkEncryptionFixture(t, true)
			if configured {
				writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
				if message := tryLoadApp(dir); message != "" {
					t.Fatalf("configured key validation: %s", message)
				}
			}
			app, err := startServedApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			before, err := os.ReadFile(filepath.Join(dir, "env.yaml"))
			if err != nil || !bytes.Contains(before, []byte("ENCRYPTION_KEY:")) {
				t.Fatalf("startup did not persist a durable key: %v", err)
			}
			if _, err := app.DB.Exec("INSERT INTO documents (secret) VALUES ('private control')"); err != nil {
				t.Fatal(err)
			}
			if message := tryLoadApp(dir); message != "" {
				t.Fatalf("validation with initialized key: %s", message)
			}
			after, err := os.ReadFile(filepath.Join(dir, "env.yaml"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("validation changed the durable key file: %v", err)
			}
			var stored, plaintext, blind string
			if err := app.DB.QueryRow("SELECT secret, benmore_decrypt(secret, 'documents', 'secret'), secret_blind FROM documents").Scan(&stored, &plaintext, &blind); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(stored, encPrefixV2) || plaintext != "private control" || blind == "" {
				t.Fatal("startup/validation did not preserve ciphertext, decryption and blind index")
			}
		})
	}
}
