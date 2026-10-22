//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func reloadStorageApp(t *testing.T) *App {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsurePermissionsTable(app.DB)
	EnsureLocksTable(app.DB)
	t.Cleanup(func() { app.Shutdown(); dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	return app
}

func TestReloadStorageRefreshesRelationshipMetadata(t *testing.T) {
	app := reloadStorageApp(t)
	writeTestFile(t, app.Dir, "schema.sql", `CREATE TABLE wallets (
 id INTEGER PRIMARY KEY,
 user_id INTEGER,
 name TEXT
);
CREATE TABLE entries (
 id INTEGER PRIMARY KEY,
 user_id INTEGER,
 wallet_id INTEGER REFERENCES wallets(id),
 title TEXT
);
`)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	uid, sid := gateUser(t, app, "owner@example.test")
	other, _ := gateUser(t, app, "other@example.test")
	if _, err := app.DB.Exec(`INSERT INTO wallets(id,user_id,name) VALUES(1,?,'mine'),(2,?,'other')`, uid, other); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []int{2, 999} {
		w := gateCall(app, handleCreate, "entries", "POST", "/api/entries", "application/json", fmt.Sprintf(`{"title":"entry","wallet_id":%d}`, parent), sid)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("parent %d: %d %s", parent, w.Code, w.Body.String())
		}
	}
	w := gateCall(app, handleCreate, "entries", "POST", "/api/entries", "application/json", `{"title":"valid","wallet_id":1}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("own parent: %d %s", w.Code, w.Body.String())
	}
	w = gateCall(app, handleList, "entries", "GET", "/api/entries?include=wallet", "", "", sid)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"wallet":{`) || !strings.Contains(w.Body.String(), `"name":"mine"`) {
		t.Fatalf("relationship include after reload: %d %s", w.Code, w.Body.String())
	}
}

func TestReloadStorageEnablesEncryptionAndBlindIndex(t *testing.T) {
	app := reloadStorageApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY,\n private_note TEXT\n);\n")
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [private_note]\n    blind_index: [private_note]\n")
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO documents(id,private_note) VALUES(1,'private canary')`)
	var stored string
	if err := app.DB.QueryRow(`SELECT private_note FROM documents WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !cryptoIsEncrypted(stored) {
		t.Errorf("reload left a new write in plaintext")
	}
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM documents WHERE private_note_blind=benmore_blind_index('private canary')`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("blind-index lookup: count=%d err=%v", count, err)
	}
	crudScopeMustExec(t, app.DB, `UPDATE documents SET private_note='updated canary' WHERE id=1`)
	if err := app.DB.QueryRow(`SELECT count(*) FROM documents WHERE private_note_blind=benmore_blind_index('updated canary') AND benmore_ciphertext_matches(private_note,'documents','private_note')`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("encrypted update: count=%d err=%v", count, err)
	}
}

func TestReloadStorageRejectedCandidateKeepsPolicy(t *testing.T) {
	app := reloadStorageApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY,\n private_note TEXT,\n extra TEXT\n);\n")
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [private_note]\n    blind_index: [private_note]\n")
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	old := app.Encrypted
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [extra]\n    blind_index: [extra]\n")
	writeTestFile(t, app.Dir, "app.yaml", "versioned: [missing_table]\n")
	if err := reloadAppConfig(app); err == nil {
		t.Fatal("invalid history candidate accepted")
	}
	if app.Encrypted != old {
		t.Fatal("rejected candidate published policy")
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO documents(id,private_note,extra) VALUES(1,'protected','unchanged')`)
	var stored, extra string
	if err := app.DB.QueryRow(`SELECT private_note,extra FROM documents WHERE id=1`).Scan(&stored, &extra); err != nil {
		t.Fatal(err)
	}
	if !cryptoIsEncrypted(stored) || extra != "unchanged" {
		t.Fatal("failed candidate replaced encryption triggers")
	}
}

func TestReloadStorageRejectsKeyChangesBeforeMutation(t *testing.T) {
	for _, nextKey := range []string{"", strings.Repeat("cd", 32)} {
		t.Run(fmt.Sprint(len(nextKey)), func(t *testing.T) {
			app := reloadStorageApp(t)
			oldKey, err := cryptoKeyForQuerierChecked(app.DB)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, app.Dir, "env.yaml", "ENCRYPTION_KEY: '"+nextKey+"'\n")
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE rejected (\n id INTEGER PRIMARY KEY,\n secret TEXT\n);\n")
			writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  rejected:\n    fields: [secret]\n")
			if err := reloadAppConfig(app); err == nil || !strings.Contains(err.Error(), "encryption") {
				t.Fatalf("key change accepted: %v", err)
			}
			var count int
			if err := app.DB.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='rejected'`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("key rejection reached DDL: %d %v", count, err)
			}
			key, err := cryptoKeyForQuerierChecked(app.DB)
			if err != nil || string(key) != string(oldKey) {
				t.Fatal("rejection changed live key")
			}
		})
	}
}

func TestReloadStorageBlindFailureRollsBackEncryptionPolicy(t *testing.T) {
	app := reloadStorageApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY,\n secret TEXT,\n extra TEXT\n);\n")
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [secret]\n    blind_index: [secret]\n")
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, `CREATE TABLE idx_blind_documents_extra(id INTEGER)`)
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [extra]\n    blind_index: [extra]\n")
	if err := reloadAppConfig(app); err == nil {
		t.Fatal("conflicting blind index accepted")
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO documents(id,secret,extra) VALUES(1,'still sealed','plain')`)
	var sealed, extra string
	if err := app.DB.QueryRow(`SELECT secret,extra FROM documents WHERE id=1`).Scan(&sealed, &extra); err != nil || !cryptoIsEncrypted(sealed) || extra != "plain" {
		t.Fatalf("active policy lost: %v", err)
	}
	var columns int
	if err := app.DB.QueryRow(`SELECT count(*) FROM pragma_table_info('documents') WHERE name='extra_blind'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("candidate blind column not rolled back: %d %v", columns, err)
	}
}

func TestEncryptionStartupInstallsMigratedFields(t *testing.T) {
	for _, newTable := range []bool{false, true} {
		t.Run(fmt.Sprint(newTable), func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
			writeTestFile(t, dir, "encrypted.yaml", "tables:\n  documents:\n    fields: [secret]\n    blind_index: [secret]\n")
			writeTestFile(t, dir, "app.yaml", "versioned: [documents]\n")
			if newTable {
				writeTestFile(t, dir, "migrations/0001_documents.sql", "CREATE TABLE documents(id INTEGER PRIMARY KEY,secret TEXT);\n")
			} else {
				writeTestFile(t, dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY\n);\n")
				writeTestFile(t, dir, "migrations/0001_secret.sql", "ALTER TABLE documents ADD COLUMN secret TEXT;\n")
			}
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			crudScopeMustExec(t, app.DB, `INSERT INTO documents(id,secret) VALUES(1,'initial')`)
			crudScopeMustExec(t, app.DB, `UPDATE documents SET secret='changed' WHERE id=1`)
			var count int
			if err := app.DB.QueryRow(`SELECT count(*) FROM documents WHERE benmore_ciphertext_matches(secret,'documents','secret') AND secret_blind=benmore_blind_index('changed')`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("migrated encryption: %d %v", count, err)
			}
			if err := app.DB.QueryRow(`SELECT count(*) FROM documents_history WHERE NOT benmore_ciphertext_matches(secret,'documents','secret') AND secret IS NOT NULL`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("unsealed history: %d %v", count, err)
			}
		})
	}
}
