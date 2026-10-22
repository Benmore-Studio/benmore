//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// A blind-indexed encrypted column gets a sibling `<col>_blind` holding a
// deterministic HMAC of the plaintext. That hash must never reach an API
// reader: it links equal plaintexts across rows for anyone who can list the
// table. The versioning/query/DSAR paths already drop it; the main auto-CRUD
// read path returned it on a plain SELECT * and via ?fields=.
func TestCRUDReadOmitsBlindIndexColumns(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	appEncryptionKey = key
	if err := SetBlindIndexKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appEncryptionKey = oldKey })

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"contacts": {{Column: "email", BlindIndex: true}},
	}}
	EnsureBlindColumns(db, cfg)
	InstallEncryptionTriggers(db, cfg)
	InstallBlindIndexTriggers(db, cfg)

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"contacts": {"all": "self"}}},
		Tables: []Table{{Name: "contacts", Columns: []Column{
			{Name: "id", PK: true}, {Name: "user_id"}, {Name: "email"}, {Name: "email_blind"},
		}}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO contacts (user_id, email) VALUES (1, 'alice@secret.example')`)

	for _, path := range []string{"/api/contacts", "/api/contacts?fields=email_blind,id", "/api/contacts/1"} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		var row map[string]any
		if path == "/api/contacts/1" {
			mustDecodeBody(t, rec, &row)
		} else {
			var rows []map[string]any
			mustDecodeBody(t, rec, &rows)
			if len(rows) != 1 {
				t.Fatalf("GET %s returned %d rows, want 1", path, len(rows))
			}
			row = rows[0]
		}
		if v, present := row["email_blind"]; present {
			t.Fatalf("GET %s exposed blind-index HMAC email_blind=%v", path, v)
		}
	}
	// The blind column still drives server-side equality search.
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/contacts?email=alice@secret.example", token, nil)
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("blind-index equality filter returned %d rows, want 1: %s", len(rows), rec.Body.String())
	}
}
