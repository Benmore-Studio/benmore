//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func newRowIDFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
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
	for _, stmt := range []string{
		`CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
		`CREATE TABLE slugs (id TEXT PRIMARY KEY, title TEXT)`,
		`INSERT INTO docs (id, title) VALUES (1, 'orig')`,
		`INSERT INTO slugs (id, title) VALUES ('01', 'zero-one'), ('1.0', 'one-point-zero')`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: accessFromYAML(t, "access:\n  docs: everyone\n  slugs: everyone\n"),
	}
	for _, name := range []string{"docs", "slugs"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.UUIDTables = DetectUUIDTables(app.Tables)
	app.JoinMap = BuildJoinMap(db)
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

// Locks, shares and audit rows are keyed by the id text a request used,
// while SQLite's integer affinity matches `id = '1.0'`, `'01'` or `' 1'` to
// row 1. A lock held on "1" therefore did not stop PATCH /api/docs/1.0, and
// the audit trail recorded the edit under row "1.0". An id that is not the
// canonical spelling of an integer key is refused on every row-addressed
// route.
func TestNonCanonicalRowIDsAreRefused(t *testing.T) {
	app, mux := newRowIDFixture(t)
	sidA := createCrudScopeSession(t, app, "a@example.com", "user", "", "")
	createCrudScopeSession(t, app, "b@example.com", "user", "", "")
	var uidB int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'b@example.com'").Scan(&uidB); err != nil {
		t.Fatal(err)
	}
	lock := func() {
		t.Helper()
		if _, err := app.DB.Exec("INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('docs', '1', ?, 'b@example.com', datetime('now', '+1 hour'))", uidB); err != nil {
			t.Fatal(err)
		}
	}
	scalar := func(q string) string {
		t.Helper()
		var v sql.NullString
		if err := app.DB.QueryRow(q).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String
	}
	lock()

	for _, id := range []string{"1.0", "01", "+1", " 1", "1 ", "1e0", "1.", "1.00", "0x1"} {
		path := "/api/docs/" + url.PathEscape(id)
		crudScopeRequest(t, mux, http.MethodPatch, path, sidA, map[string]any{"title": "changed"})
		crudScopeRequest(t, mux, http.MethodPatch, "/api/docs/batch", sidA, map[string]any{"ids": []any{id}, "fields": map[string]any{"title": "changed"}})
		crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sidA, map[string]any{"operations": []any{map[string]any{"table": "docs", "action": "update", "id": id, "data": map[string]any{"title": "changed"}}}})
		if got := scalar("SELECT title FROM docs WHERE id = 1"); got != "orig" {
			t.Fatalf("id spelling %q wrote through a lock held on row 1 (title %q)", id, got)
		}
		crudScopeRequest(t, mux, http.MethodDelete, path, sidA, nil)
		crudScopeRequest(t, mux, http.MethodDelete, "/api/docs/batch", sidA, map[string]any{"ids": []any{id}})
		crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sidA, map[string]any{"operations": []any{map[string]any{"table": "docs", "action": "delete", "id": id}}})
		if n := scalar("SELECT COUNT(*) FROM docs"); n != "1" {
			t.Fatalf("id spelling %q deleted the locked row", id)
		}
		// Taking or sharing under an alias would key the lock / grant to a
		// row id nothing else uses.
		crudScopeRequest(t, mux, http.MethodPost, path+"/lock", sidA, nil)
		crudScopeRequest(t, mux, http.MethodPost, path+"/share", sidA, map[string]any{"email": "b@example.com", "action": "view"})
	}
	if n := scalar("SELECT COUNT(*) FROM _benmore_locks WHERE row_id <> '1'") + scalar("SELECT COUNT(*) FROM _benmore_permissions WHERE resource_id <> '1'"); n != "00" {
		t.Fatalf("locks/shares were stored under a non-canonical row id (%s)", n)
	}

	// Without the lock a non-canonical spelling is still not a row: nothing
	// is read or written, and nothing lands in the audit log under an alias.
	crudScopeMustExec(t, app.DB, "DELETE FROM _benmore_locks")
	for _, id := range []string{"1.0", "01"} {
		assertStatus(t, mux, http.MethodPatch, "/api/docs/"+id, sidA, map[string]any{"title": "changed"}, http.StatusNotFound)
		assertStatus(t, mux, http.MethodGet, "/api/docs/"+id, sidA, nil, http.StatusNotFound)
		assertStatus(t, mux, http.MethodDelete, "/api/docs/"+id, sidA, nil, http.StatusNotFound)
	}
	if got := scalar("SELECT title FROM docs WHERE id = 1"); got != "orig" {
		t.Fatalf("a non-canonical id wrote the row: %q", got)
	}
	if n := scalar("SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name = 'docs' AND row_id <> '1'"); n != "0" {
		t.Fatalf("%s audit row(s) were written under a non-canonical row id", n)
	}

	// Canonical ids work as before, and a text key is matched exactly.
	assertStatus(t, mux, http.MethodPatch, "/api/docs/1", sidA, map[string]any{"title": "changed"}, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/slugs/01", sidA, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, "/api/slugs/1.0", sidA, map[string]any{"title": "renamed"}, http.StatusOK)
	if got := scalar("SELECT title FROM slugs WHERE id = '1.0'"); got != "renamed" {
		t.Fatalf("text-keyed row not updated by its exact id: %q", got)
	}
}
