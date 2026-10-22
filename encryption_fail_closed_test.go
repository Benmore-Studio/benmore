//go:build !cli

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestPlaintextEncryptionSQLAndTriggersSealPrefixLiterals(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, secret TEXT)`); err != nil {
		t.Fatal(err)
	}
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "secret"}}}}
	if err := InstallEncryptionTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}

	for i, plaintext := range []string{"enc:v1:literal plaintext", "enc:v2:literal plaintext"} {
		if _, err := db.Exec(`INSERT INTO notes (id, secret) VALUES (?, ?)`, i+1, plaintext); err != nil {
			t.Fatalf("insert prefix literal: %v", err)
		}
		var stored, roundTrip string
		if err := db.QueryRow(`SELECT secret, benmore_decrypt(secret, 'notes', 'secret') FROM notes WHERE id=?`, i+1).Scan(&stored, &roundTrip); err != nil {
			t.Fatalf("read/decrypt prefix literal: %v", err)
		}
		if !strings.HasPrefix(stored, encPrefixV2) || stored == plaintext || roundTrip != plaintext {
			t.Fatalf("stored=%q roundTrip=%q, want encrypted v2 and original literal %q", stored, roundTrip, plaintext)
		}
		var matches bool
		if err := db.QueryRow(`SELECT benmore_ciphertext_matches(?, 'notes', 'secret')`, stored).Scan(&matches); err != nil || !matches {
			t.Fatalf("stored ciphertext match=%t err=%v", matches, err)
		}
	}

	for _, query := range []string{
		`SELECT benmore_encrypt_plaintext('secret', '', 'secret')`,
		`SELECT benmore_encrypt_plaintext('secret', 'notes', '')`,
	} {
		var ignored string
		if err := db.QueryRow(query).Scan(&ignored); err == nil {
			t.Fatalf("missing AAD context accepted: %s", query)
		}
	}
	var directlyEncrypted string
	if err := db.QueryRow(`SELECT benmore_encrypt_plaintext(?, 'notes', 'secret')`, "enc:v1:literal plaintext").Scan(&directlyEncrypted); err != nil {
		t.Fatal(err)
	}
	if got, err := fieldDecryptCtx(appEncryptionKey, "secret", directlyEncrypted); err != nil || got != "enc:v1:literal plaintext" {
		t.Fatalf("explicit plaintext SQL function round trip=%q err=%v", got, err)
	}
}

func TestInstallEncryptionTriggersFailurePreservesPriorTriggers(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, secret TEXT)`); err != nil {
		t.Fatal(err)
	}
	valid := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "secret"}}}}
	if err := InstallEncryptionTriggers(db, valid); err != nil {
		t.Fatal(err)
	}
	triggerNames := func() []string {
		t.Helper()
		rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_benmore_enc_%' ORDER BY name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return names
	}
	before := triggerNames()
	broken := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"missing_table": {{Column: "secret"}}}}
	if err := InstallEncryptionTriggers(db, broken); err == nil {
		t.Fatal("trigger installation against missing table unexpectedly succeeded")
	}
	if after := triggerNames(); !reflect.DeepEqual(after, before) {
		t.Fatalf("prior triggers changed after failed replacement: before=%v after=%v", before, after)
	}
	if _, err := db.Exec(`INSERT INTO notes (secret) VALUES ('enc:v2:literal')`); err != nil {
		t.Fatalf("prior trigger did not remain usable: %v", err)
	}
	var stored string
	if err := db.QueryRow(`SELECT secret FROM notes`).Scan(&stored); err != nil || !strings.HasPrefix(stored, encPrefixV2) || stored == "enc:v2:literal" {
		t.Fatalf("prior trigger failed to seal prefix literal: %q err=%v", stored, err)
	}
}

func TestPlaintextEncryptionSQLFailsWithoutKeyAndCorruptReadMasks(t *testing.T) {
	db, cleanup := newEncTestDB(t)
	defer cleanup()
	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	registered, hadRegistration := dbCryptoRegistry.Load(canonicalDBPath(path))
	oldKey := appEncryptionKey
	dbCryptoRegistry.Delete(canonicalDBPath(path))
	appEncryptionKey = nil
	t.Cleanup(func() {
		appEncryptionKey = oldKey
		if hadRegistration {
			dbCryptoRegistry.Store(canonicalDBPath(path), registered)
		}
	})
	var ignored string
	if err := db.QueryRow(`SELECT benmore_encrypt_plaintext('secret', 'notes', 'secret')`).Scan(&ignored); err == nil {
		t.Fatal("plaintext encryption succeeded without a key")
	}

	row := map[string]any{"secret": "enc:v2:corrupt"}
	DecryptRowFields(row, oldKey)
	if row["secret"] != decryptFailMask {
		t.Fatalf("corrupt ciphertext was returned to the caller: %#v", row)
	}
}

func TestLoadAppRejectsBrokenEncryptionConfigAndKeepsPriorTriggers(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	dir := writeApp(t, map[string]string{
		"app.yaml":       "name: encryption-reload-fixture\n",
		"schema.sql":     "CREATE TABLE notes (id INTEGER PRIMARY KEY, secret TEXT);\n",
		"encrypted.yaml": "tables:\n  notes:\n    fields: [secret]\n",
		"env.yaml":       "ENCRYPTION_KEY: " + key + "\n",
	})
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  missing_table:\n    fields: [secret]\n")
	if _, err := loadApp(dir); err == nil || !strings.Contains(err.Error(), "encrypted-field triggers") {
		t.Fatalf("broken encrypted config did not fail app load: %v", err)
	}
	if _, err := app.DB.Exec(`INSERT INTO notes (secret) VALUES ('still protected')`); err != nil {
		t.Fatalf("existing runtime lost its encryption trigger: %v", err)
	}
	var stored string
	if err := app.DB.QueryRow(`SELECT secret FROM notes`).Scan(&stored); err != nil || !strings.HasPrefix(stored, encPrefixV2) {
		t.Fatalf("prior trigger did not remain active: %q err=%v", stored, err)
	}
}
