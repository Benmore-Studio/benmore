//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// FTS5 search internals (`<t>_fts` plus its _data/_idx/_docsize/_config
// shadow tables) carry the indexed text of the source table but no owner or
// tenant column. Registered as CRUD tables they inherit only the coarse
// `default:` access mode, so any reader passing that gate could pull another
// user's owner-scoped rows straight out of `notes_fts`.
func TestFTSIndexTablesAreNotCRUDExposed(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, body TEXT)`)
	tables := []Table{{Name: "notes", Columns: []Column{
		{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}, {Name: "body"},
	}, FullText: [][]string{{"title", "body"}}}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}

	names, err := GetTableNames(db)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "notes") {
		t.Fatalf("source table missing from GetTableNames: %v", names)
	}
	for _, internal := range []string{"notes_fts", "notes_fts_data", "notes_fts_idx", "notes_fts_docsize", "notes_fts_config"} {
		if slices.Contains(names, internal) {
			t.Fatalf("FTS internal table %s exposed by GetTableNames: %v", internal, names)
		}
	}

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"default": {"read": "everyone"},
			"notes":   {"all": "self"},
		}},
		Tables: tables,
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	crudScopeMustExec(t, db, `INSERT INTO notes (user_id, title, body) VALUES (1, 'alice private', 'alice diary')`)

	// Owner scoping on the source table still holds...
	assertListIDs(t, mux, alice, "/api/notes", []float64{1})
	assertListIDs(t, mux, bob, "/api/notes", []float64{})
	// ...and the index tables are no longer a side door around it.
	for _, path := range []string{"/api/notes_fts", "/api/notes_fts_data", "/api/notes_fts_docsize"} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, bob, nil)
		if rec.Code == http.StatusOK {
			t.Fatalf("GET %s = 200 for a non-owner: %s", path, rec.Body.String())
		}
	}
	// Full-text search through the source table keeps working and scoped.
	assertListIDs(t, mux, alice, "/api/notes?q=diary", []float64{1})
	assertListIDs(t, mux, bob, "/api/notes?q=diary", []float64{})
}
