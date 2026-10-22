//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// A blind-index sibling (`<col>_blind`) is derived by triggers from the
// encrypted column, like a computed column. It was not in the protected set,
// so a client could write it directly: a create without the base column kept
// the submitted value, and a PATCH of the blind column alone was never
// recomputed - detaching the row from equality search and from any uniqueness
// the app builds on the index.
func TestBlindIndexColumnIsNotClientWritable(t *testing.T) {
	oldKey := appEncryptionKey
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
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
	crudScopeMustExec(t, db, `CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, email TEXT)`)
	cfg := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"contacts": {{Column: "email", BlindIndex: true}},
	}}
	EnsureBlindColumns(db, cfg)
	InstallEncryptionTriggers(db, cfg)
	InstallBlindIndexTriggers(db, cfg)
	cols, err := GetTableColumns(db, "contacts")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Encrypted: cfg,
		Access:    &AccessConfig{rules: map[string]map[AccessOp]string{"contacts": {"all": "self"}}},
		Tables:    []Table{{Name: "contacts", Columns: cols}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	blind := func(id int) string {
		t.Helper()
		var v sql.NullString
		if err := db.QueryRow("SELECT email_blind FROM contacts WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String
	}

	// Create without the base column: the submitted blind value must not land.
	assertStatus(t, mux, http.MethodPost, "/api/contacts", token, map[string]any{"name": "a", "email_blind": "forged"}, http.StatusOK)
	crudScopeRequest(t, mux, http.MethodPost, "/api/contacts/batch", token, []any{map[string]any{"name": "b", "email_blind": "forged"}})
	crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", token, map[string]any{"operations": []any{map[string]any{"table": "contacts", "action": "insert", "data": map[string]any{"name": "c", "email_blind": "forged"}}}})
	var forged int
	if err := db.QueryRow("SELECT COUNT(*) FROM contacts WHERE email_blind = 'forged'").Scan(&forged); err != nil {
		t.Fatal(err)
	}
	if forged != 0 {
		t.Fatalf("%d create(s) stored a client-supplied blind index", forged)
	}

	// Update: the trigger-derived value must survive a direct write.
	assertStatus(t, mux, http.MethodPost, "/api/contacts", token, map[string]any{"name": "d", "email": "d@example.com"}, http.StatusOK)
	var id int
	if err := db.QueryRow("SELECT id FROM contacts WHERE name = 'd'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	want := blind(id)
	if want == "" || want == "forged" {
		t.Fatalf("fixture: blind index not derived (%q)", want)
	}
	crudScopeRequest(t, mux, http.MethodPatch, "/api/contacts/"+itoa(id), token, map[string]any{"email_blind": "forged"})
	crudScopeRequest(t, mux, http.MethodPatch, "/api/contacts/"+itoa(id), token, map[string]any{"name": "d2", "email_blind": "forged"})
	crudScopeRequest(t, mux, http.MethodPatch, "/api/contacts/batch", token, map[string]any{"ids": []any{id}, "fields": map[string]any{"email_blind": "forged", "name": "d3"}})
	if got := blind(id); got != want {
		t.Fatalf("a client overwrote the blind index: %q, want the derived value", got)
	}
	// The equality search it backs still finds the row.
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/contacts?email=d@example.com", token, nil)
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("blind-index equality search returned %d rows, want 1: %s", len(rows), rec.Body.String())
	}
}
