//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// TestQueryAggregateMissingColumnNamesTheKey: an aggregate written with
// `field:` (or no column at all) answered "unknown aggregate column: " with
// an empty name, which reads like a typo in a column name. The key /api/_query
// reads is `col`; the error now says so.
func TestQueryAggregateMissingColumnNamesTheKey(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Item {
  id Int @id @default(autoincrement())
  qty Int @default(0)
  user_id Int?
  @@map("items")
}
`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://audit.example.invalid")
	user := createCrudScopeSession(t, app, "u@example.com", "user", "", "")
	assertStatus(t, mux, http.MethodPost, "/api/items", user, map[string]any{"qty": 5}, http.StatusOK)

	cases := []struct {
		agg  map[string]any
		want []string
	}{
		{map[string]any{"fn": "sum", "field": "qty"}, []string{`"field"`, `col:'qty'`}},
		{map[string]any{"fn": "avg"}, []string{`avg needs "col"`}},
	}
	for _, tc := range cases {
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", user, map[string]any{"table": "items", "aggregates": []any{tc.agg}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: status %d %s", tc.agg, rec.Code, rec.Body.String())
		}
		var body struct {
			Error string `json:"error"`
		}
		mustDecodeBody(t, rec, &body)
		if strings.TrimSpace(body.Error) == "unknown aggregate column:" {
			t.Errorf("%v: error names no column: %q", tc.agg, body.Error)
		}
		for _, want := range tc.want {
			if !strings.Contains(body.Error, want) {
				t.Errorf("%v: error %q lacks %s", tc.agg, body.Error, want)
			}
		}
	}

	// The documented key keeps working, and count with no column is COUNT(*).
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", user, map[string]any{"table": "items", "aggregates": []any{map[string]any{"fn": "sum", "col": "qty", "as": "total"}, map[string]any{"fn": "count", "as": "n"}}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total":5`) || !strings.Contains(rec.Body.String(), `"n":1`) {
		t.Fatalf("documented aggregate spec: %d %s", rec.Code, rec.Body.String())
	}
}
