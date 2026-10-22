//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// With a hidden column in @@fulltext, ?q= answered "which rows contain this
// substring" for a value no response returns: a reader could recover a
// share token three characters (or, through the short-query LIKE path, one
// character) at a time. Search now matches only returned columns.
func TestFTSSearchSkipsHiddenColumns(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, share_token TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE vaults (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, api_secret TEXT)`)
	tables := []Table{
		{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title", Type: "TEXT"}, {Name: "share_token", Type: "TEXT"}},
			FullText: [][]string{{"title", "share_token"}}},
		{Name: "vaults", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "api_secret", Type: "TEXT"}},
			FullText: [][]string{{"api_secret"}}},
	}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"notes":  {"read": "everyone"},
			"vaults": {"read": "everyone"},
		}},
		Tables: tables,
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO notes (user_id, title, share_token) VALUES (1, 'alpha note', 'zq9secretvalue')`)
	crudScopeMustExec(t, db, `INSERT INTO vaults (user_id, api_secret) VALUES (1, 'zq9secretvalue')`)

	assertListIDs(t, mux, bob, "/api/notes?q=zq9", []float64{})
	assertListIDs(t, mux, bob, "/api/notes?q=secretvalue", []float64{})
	assertListIDs(t, mux, bob, "/api/notes?q=zq", []float64{}) // LIKE path
	assertListIDs(t, mux, bob, "/api/notes?q=alpha", []float64{1})
	assertListIDs(t, mux, bob, "/api/notes?q=alpha%20note", []float64{1})
	assertListIDs(t, mux, bob, "/api/notes?q=al", []float64{1})
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?q=zq9&count=true", bob, nil); rec.Body.String() != "{\"count\":0}\n" {
		t.Errorf("count path matched a hidden column: %s", rec.Body.String())
	}

	// Every indexed column hidden: refuse rather than return unfiltered rows.
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/vaults?q=zq9", bob, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("all-hidden @@fulltext search: %d %s", rec.Code, rec.Body.String())
	}
}
