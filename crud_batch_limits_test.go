//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A batch or transaction naming more than maxBatchItems rows answers 413
// before anything runs; only the 10 MB body bounded it before.
func TestBatchAndTransactionItemCaps(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	sid := createCrudScopeSession(t, app, "bulk@example.com", "user", "", "")

	items := make([]map[string]any, maxBatchItems+1)
	ids := make([]any, maxBatchItems+1)
	ops := make([]map[string]any, maxBatchItems+1)
	for i := range items {
		items[i] = map[string]any{"title": "x"}
		ids[i] = i + 1
		ops[i] = map[string]any{"table": "notes", "action": "insert", "data": map[string]any{"title": "x"}}
	}
	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/notes/batch", items},
		{http.MethodPatch, "/api/notes/batch", map[string]any{"ids": ids, "fields": map[string]any{"title": "y"}}},
		{http.MethodDelete, "/api/notes/batch", map[string]any{"ids": ids}},
		{http.MethodPost, "/api/_transaction", map[string]any{"operations": ops}},
	}
	for _, c := range cases {
		rec := crudScopeRequest(t, mux, c.method, c.path, sid, c.body)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s %s with %d items = %d %s, want 413", c.method, c.path, maxBatchItems+1, rec.Code, rec.Body.String())
		}
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("notes = %d (%v), want the fixture's 2 rows untouched", n, err)
	}

	// At the cap the batch still runs.
	atCap := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/batch", sid, items[:maxBatchItems])
	if atCap.Code != http.StatusOK {
		t.Fatalf("batch of %d = %d %s, want 200", maxBatchItems, atCap.Code, atCap.Body.String())
	}
}

// Batch DELETE decodes ids as exact numbers: an id past 2^53 used to be
// rounded through float64 to a neighbouring row, which was deleted instead.
func TestBatchDeleteKeepsLargeIntegerIDsExact(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	sid := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	if _, err := app.DB.Exec(`INSERT INTO notes (id, user_id, title) VALUES (9007199254740992, 1, 'neighbour'), (9007199254740993, 1, 'target')`); err != nil {
		t.Fatal(err)
	}
	rec := crudScopeRequest(t, mux, http.MethodDelete, "/api/notes/batch", sid,
		map[string]any{"ids": []any{json.Number("9007199254740993")}})
	if rec.Code != http.StatusOK {
		t.Fatalf("batch delete = %d %s", rec.Code, rec.Body.String())
	}
	var left []string
	rows, err := app.DB.Query(`SELECT title FROM notes WHERE id >= 9007199254740992 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		left = append(left, s)
	}
	if len(left) != 1 || left[0] != "neighbour" {
		t.Fatalf("rows left = %v, want only the neighbour (the named id deleted)", left)
	}
}
