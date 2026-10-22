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

// A record share is keyed by (table, row id) and was never removed with the
// row. On a table whose key is a plain INTEGER PRIMARY KEY (no AUTOINCREMENT)
// SQLite hands a deleted top id to the next insert, so someone else's new row
// inherited the old row's grants: the former grantee could read and edit it.
// Deleting a row now deletes its grants and locks in the same transaction.
func TestRecordGrantsDoNotOutliveTheRow(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)`)
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	cols, err := GetTableColumns(db, "notes")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "notes", Columns: cols}}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	carol := createCrudScopeSession(t, app, "carol@example.com", "user", "", "")

	for _, path := range []string{"single", "batch", "transaction"} {
		assertStatus(t, mux, http.MethodPost, "/api/notes", alice, map[string]any{"title": "alice-note"}, http.StatusOK)
		assertStatus(t, mux, http.MethodPost, "/api/notes/1/share", alice, map[string]any{"email": "carol@example.com", "permission": "edit"}, http.StatusOK)
		assertStatus(t, mux, http.MethodGet, "/api/notes/1", carol, nil, http.StatusOK)
		switch path {
		case "single":
			assertStatus(t, mux, http.MethodDelete, "/api/notes/1", alice, nil, http.StatusOK)
		case "batch":
			assertStatus(t, mux, http.MethodDelete, "/api/notes/batch", alice, map[string]any{"ids": []any{1}}, http.StatusOK)
		case "transaction":
			assertStatus(t, mux, http.MethodPost, "/api/_transaction", alice, map[string]any{"operations": []any{map[string]any{"table": "notes", "action": "delete", "id": 1}}}, http.StatusOK)
		}

		// Bob's new row takes the freed id.
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", bob, map[string]any{"title": "bob-private"})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":1`) {
			t.Fatalf("%s: fixture: bob's row should reuse id 1: %d %s", path, rec.Code, rec.Body.String())
		}
		if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1", carol, nil); rec.Code == http.StatusOK {
			t.Fatalf("%s: a share on a deleted row still opens the row that reused its id: %s", path, rec.Body.String())
		}
		crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", carol, map[string]any{"title": "overwritten"})
		var title string
		if err := db.QueryRow("SELECT title FROM notes WHERE id = 1").Scan(&title); err != nil || title != "bob-private" {
			t.Fatalf("%s: the former grantee edited the new row: title=%q err=%v", path, title, err)
		}
		assertStatus(t, mux, http.MethodDelete, "/api/notes/1", bob, nil, http.StatusOK)
	}
}
