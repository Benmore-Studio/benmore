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

// An admin can hand a narrowly scoped API token (notes:read) to an
// integration. The generated types, the docs and the schema descriptor gated
// their full view on IsAdmin, so that token read the whole data model,
// including admin-only tables the token's scope refuses. Like the other
// admin-only management surfaces they now need IsAdminConsole: an admin on an
// unscoped credential. A scoped admin token gets what its scope allows.
func TestScopedAdminTokenDoesNotReadWholeSchema(t *testing.T) {
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
	EnsureAPITokensTable(db)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE payroll_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, salary_cents INTEGER)`)
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: accessFromYAML(t, "access:\n  notes: self\n  payroll_runs: admin\n")}
	for _, name := range []string{"notes", "payroll_runs"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	mux := http.NewServeMux()
	RegisterBMTypesRoute(mux, app)
	RegisterAPIDocsRoutes(mux, app)

	sid := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	scoped := auditToken(t, app, sid, "notes:read")
	full := auditToken(t, app, sid, "*")

	get := func(path, tok string) (int, string) {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, tok, nil)
		return rec.Code, rec.Body.String()
	}
	for _, path := range []string{"/_internal/types.d.ts", "/_internal/bm.d.ts"} {
		if code, body := get(path, scoped); code != http.StatusForbidden || strings.Contains(body, "salary_cents") {
			t.Fatalf("scoped admin token GET %s = %d, want 403 without the schema: %.200s", path, code, body)
		}
		for name, tok := range map[string]string{"admin session": sid, "unscoped admin token": full} {
			if code, body := get(path, tok); code != http.StatusOK || !strings.Contains(body, "salary_cents") {
				t.Fatalf("%s GET %s = %d, want the generated types", name, path, code)
			}
		}
	}
	for _, path := range []string{"/api/_schema", "/api/_docs", "/api/_openapi", "/docs?format=md"} {
		code, body := get(path, scoped)
		if code != http.StatusOK || strings.Contains(body, "payroll_runs") || strings.Contains(body, "salary_cents") {
			t.Fatalf("scoped admin token GET %s = %d, want 200 without the admin-only table: %.300s", path, code, body)
		}
		if !strings.Contains(body, "notes") {
			t.Fatalf("scoped admin token GET %s lost the table its scope reads: %.300s", path, body)
		}
		for name, tok := range map[string]string{"admin session": sid, "unscoped admin token": full} {
			if code, body := get(path, tok); code != http.StatusOK || !strings.Contains(body, "payroll_runs") {
				t.Fatalf("%s GET %s = %d, want the full view: %.300s", name, path, code, body)
			}
		}
	}
}
