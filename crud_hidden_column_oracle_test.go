//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// A hidden column is stripped from every response, but ?col__like= / ?col__gt=
// / ?sort=col on it still narrowed and ordered rows, so a caller could recover
// a secret one character at a time from the match/no-match answer.
func TestHiddenColumnsAreNotFilterOrSortOracles(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE links (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, share_token TEXT)`)
	crudScopeMustExec(t, db, `INSERT INTO links (user_id, name, share_token) VALUES (1, 'a', 'aaa-secret'), (1, 'b', 'zzz-secret')`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		JoinMap: BuildJoinMap(db),
		Access:  &AccessConfig{rules: map[string]map[AccessOp]string{"links": {"all": "self"}}},
		Tables: []Table{{Name: "links", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"},
			{Name: "name", Type: "TEXT"}, {Name: "share_token", Type: "TEXT"}}}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")

	list := func(path string) []map[string]any {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var rows []map[string]any
		mustDecodeBody(t, rec, &rows)
		return rows
	}
	// A dropped filter would silently return every row (a token lookup would
	// hand back somebody else's row), so each probe is refused outright.
	for _, path := range []string{
		"/api/links?share_token__like=zzz%25",
		"/api/links?share_token=zzz-secret",
		"/api/links?share_token__gt=m",
		"/api/links?where[share_token]=zzz-secret",
		"/api/links?sort=share_token&order=asc",
		"/api/links?orderBy=share_token:asc",
		"/api/links?share_token=zzz-secret&count=true",
		"/api/links?share_token=zzz-secret&cursor=0",
	} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s status=%d, want 400 body=%s", path, rec.Code, rec.Body.String())
		}
	}
	// Ordinary columns still filter and sort.
	if n := len(list("/api/links?name=b")); n != 1 {
		t.Fatalf("ordinary filter broken: %d rows", n)
	}
	if rows := list("/api/links?sort=name&order=asc"); rows[0]["name"] != "a" {
		t.Fatalf("ordinary sort broken: %#v", rows)
	}
}
