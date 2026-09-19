//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestPagedTotal_HonorsWhereFilters pins the fix for the 2026-08-05 incident:
// the `?page=` envelope's `total` was computed from baseSQL (scope only),
// ignoring the request's `where[...]` filters, while `data` honored them. A
// filtered paged request therefore reported the WHOLE scope's row count as
// total — `?where[project_id]=44&page=1` against a project with zero documents
// in a group holding 38 answered `{data: [], total: 38}`. Any client that
// trusts total for completeness (the app-side fetchAllPaged did) then loops
// chasing rows that never come, or fails closed; a production Roadmap tab died
// on exactly this. The `?count=true` branch always filtered its count; this
// test holds the `?page=` branch to the same answer.
func TestPagedTotal_HonorsWhereFilters(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, project_id INTEGER, filename TEXT)`)
	mustExec(t, db, `INSERT INTO docs (user_id, project_id, filename) VALUES (1, 60, 'a.pdf'), (1, 60, 'b.pdf'), (1, 99, 'c.pdf')`)

	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"docs": {OpRead: "everyone"}}},
		Tables: []Table{{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "project_id"}, {Name: "filename"}}}},
	}
	mux := buildAppMux(app, true, "http://localhost")
	tok := createCrudScopeSession(t, app, "paged-total@example.com", "user", "", "")

	page := func(path string) (dataLen, total int) {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, path, tok, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var envelope struct {
			Data  []map[string]any `json:"data"`
			Total int              `json:"total"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("GET %s: not a paged envelope: %v (%s)", path, err, rec.Body.String())
		}
		return len(envelope.Data), envelope.Total
	}

	// Filtered: 2 of 3 rows match. Pre-fix this answered total=3.
	if dataLen, total := page("/api/docs?where[project_id]=60&page=1&per_page=500"); dataLen != 2 || total != 2 {
		t.Fatalf("filtered page: data=%d total=%d, want data=2 total=2 — total is not honoring where filters", dataLen, total)
	}

	// Filtered to nothing: the incident's exact shape. Pre-fix: total=3.
	if dataLen, total := page("/api/docs?where[project_id]=7&page=1&per_page=500"); dataLen != 0 || total != 0 {
		t.Fatalf("empty filtered page: data=%d total=%d, want data=0 total=0 — the {data:[], total:N} incident shape is back", dataLen, total)
	}

	// Unfiltered: total is the full (scoped) table, unchanged by the fix.
	if dataLen, total := page("/api/docs?page=1&per_page=500"); dataLen != 3 || total != 3 {
		t.Fatalf("unfiltered page: data=%d total=%d, want data=3 total=3", dataLen, total)
	}

	// Operator-style filter (`col__op=`) goes through the same where builder
	// and must agree with its own data too.
	if dataLen, total := page("/api/docs?project_id__gte=90&page=1&per_page=500"); dataLen != 1 || total != 1 {
		t.Fatalf("operator-filtered page: data=%d total=%d, want data=1 total=1", dataLen, total)
	}
}
