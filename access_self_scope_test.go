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

// newAccessScopeFixture builds a served app with a group-keyed `records`
// table (org_id + user_id) governed by the given access rules. Users are
// created by createCrudScopeSession in call order, so the first session is
// user id 1, the second user id 2.
func newAccessScopeFixture(t *testing.T, rules map[string]map[AccessOp]string, seed ...string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	// Open the database the way production does (WAL, busy timeout, BEGIN
	// IMMEDIATE): the app's background writers share it, and a default DSN
	// lets a batch write transaction fail with "database is locked".
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`)
	for _, stmt := range seed {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Key: "org_id"},
		Access:          &AccessConfig{rules: rules},
		Tables: []Table{
			{Name: "records", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "title"}}},
		},
	}
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

// Explicit `self` is documented as owner-only. On a table that also carries
// the tenant key it used to fall into the group branch of rowScopeClause and
// expose every row of the caller's tenant to every member.
func TestExplicitSelf_OwnerOnlyOnGroupKeyedTable(t *testing.T) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (org_id, user_id, title) VALUES
			('org-a', 1, 'alice-own'),
			('org-a', 2, 'bob-own'),
			('org-b', 1, 'alice-other-tenant')`,
	)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
	_ = createCrudScopeSession(t, app, "bob@example.com", "user", "org-a", "")

	// Alice sees only her own row in her tenant - not her coworker's, and not
	// her own row in another tenant (tenant clause still AND'd).
	assertListIDs(t, mux, alice, "/api/records", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/records/2", alice, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/records/2", alice, map[string]any{"title": "overwrite"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/records/2", alice, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/records/3", alice, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/records/1", alice, nil, http.StatusOK)
	assertRecordTitle(t, app.DB, 2, "bob-own")
	assertRowExists(t, app.DB, "records", 2, true)

	batch := crudScopeRequest(t, mux, http.MethodPatch, "/api/records/batch", alice, map[string]any{
		"ids":    []any{1, 2},
		"fields": map[string]any{"title": "batched"},
	})
	if batch.Code != http.StatusOK {
		t.Fatalf("batch update status = %d body=%s", batch.Code, batch.Body.String())
	}
	assertRecordTitle(t, app.DB, 1, "batched")
	assertRecordTitle(t, app.DB, 2, "bob-own")
}

// A `default:` declaration is just as explicit as a per-table one.
func TestExplicitSelf_DefaultRuleIsOwnerOnly(t *testing.T) {
	app := &App{
		Group:  &GroupConfig{Key: "org_id"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"default": {OpRead: "self"}}},
		Tables: []Table{{Name: "records", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}}}},
	}
	s := &Session{Role: "user", UserID: 7, Email: "u@example.com", GroupID: "org-a"}
	pred, args, bypass := rowScopeClause(app, "records", s, "view")
	if bypass {
		t.Fatal("unexpected bypass")
	}
	if !strings.HasPrefix(pred, `("org_id" = ? AND (user_id = ? OR `) {
		t.Fatalf("default self should be tenant AND owner, got %q", pred)
	}
	if args[0] != "org-a" || args[1] != int64(7) {
		t.Fatalf("args = %v, want [org-a 7 ...]", args)
	}
	// Writes are not covered by the read-only default rule: the implicit
	// (tenant-wide) default still applies to them.
	pred, _, _ = rowScopeClause(app, "records", s, "edit")
	if strings.Contains(pred, "user_id = ?") {
		t.Fatalf("implicit write default should stay tenant-scoped, got %q", pred)
	}
}
