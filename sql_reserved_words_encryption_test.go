//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Encrypted columns named with reserved words (a message's `from` and `to`):
// the encryption and blind-index triggers named the column bare and could not
// be installed. They install, seal what auto-CRUD writes, keep the blind index
// current, and an equality filter on the blind-indexed column finds the row.
func TestEncryptedColumnsNamedWithReservedWords(t *testing.T) {
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
	crudScopeMustExec(t, db, `CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT, "from" TEXT, "to" TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"messages": {{Column: "from", BlindIndex: true}, {Column: "to"}},
	}}
	if err := EnsureBlindColumns(db, cfg); err != nil {
		t.Fatalf("blind column: %v", err)
	}
	if err := InstallEncryptionTriggers(db, cfg); err != nil {
		t.Fatalf("encryption triggers: %v", err)
	}
	if err := InstallBlindIndexTriggers(db, cfg); err != nil {
		t.Fatalf("blind-index triggers: %v", err)
	}
	for _, name := range []string{"_benmore_enc_messages_from_insert", "_benmore_enc_messages_to_update", "_benmore_blind_messages_from_insert", "_benmore_blind_messages_from_update"} {
		var ddl string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, name).Scan(&ddl); err != nil {
			t.Fatalf("trigger %s was not installed: %v", name, err)
		}
		if !strings.Contains(ddl, `NEW."`) {
			t.Errorf("trigger %s does not quote its column: %s", name, ddl)
		}
	}

	cols, err := GetTableColumns(db, "messages")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"messages": {"all": "self"}}},
		Tables:    []Table{{Name: "messages", Columns: cols}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")

	assertStatus(t, mux, http.MethodPost, "/api/messages", token, map[string]any{"body": "hello", "from": "ada", "to": "grace"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/messages", token, map[string]any{"body": "other", "from": "linus", "to": "grace"}, http.StatusOK)
	var from, to, blind sql.NullString
	if err := db.QueryRow(`SELECT "from", "to", from_blind FROM messages WHERE body = 'hello'`).Scan(&from, &to, &blind); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(from.String, "enc:") || !strings.HasPrefix(to.String, "enc:") || blind.String == "" {
		t.Fatalf(`stored from=%q to=%q from_blind=%q, want both sealed and a blind index`, from.String, to.String, blind.String)
	}

	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/messages?from=ada&fields=body,from,to", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("filter on the blind-indexed column: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"body":"hello"`) || strings.Contains(body, `"body":"other"`) || !strings.Contains(body, `"from":"ada"`) || !strings.Contains(body, `"to":"grace"`) {
		t.Fatalf("filter on the blind-indexed column returned %s", body)
	}

	assertStatus(t, mux, http.MethodPatch, "/api/messages/1", token, map[string]any{"from": "ada l.", "to": "hopper"}, http.StatusOK)
	var after sql.NullString
	if err := db.QueryRow(`SELECT from_blind FROM messages WHERE id = 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after.String == "" || after.String == blind.String {
		t.Fatalf("the blind index did not follow the update: before=%q after=%q", blind.String, after.String)
	}
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/messages/1", token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"from":"ada l."`) || !strings.Contains(rec.Body.String(), `"to":"hopper"`) {
		t.Fatalf("read after update: %d %s", rec.Code, rec.Body.String())
	}
}
