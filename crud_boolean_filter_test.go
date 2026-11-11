//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// booleanFilterFixture seeds items a (active), b (inactive) and c (active).
func booleanFilterFixture(t *testing.T, prisma bool) (*App, *http.ServeMux, string) {
	t.Helper()
	app, mux, sid := inventorySchemaFixture(t, prisma)
	RegisterQueryAPI(mux, app)
	for _, seed := range []struct {
		name   string
		active bool
	}{{"a", true}, {"b", false}, {"c", true}} {
		fields := inventoryValidFields()
		fields["name"], fields["active"] = seed.name, seed.active
		if w := inventorySchemaRequest(mux, sid, "single", fields); w.Code != http.StatusOK {
			t.Fatalf("seed %s: %d %s", seed.name, w.Code, w.Body.String())
		}
	}
	return app, mux, sid
}

func booleanFilterGet(t *testing.T, mux *http.ServeMux, sid, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com"+path, nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func booleanFilterNames(t *testing.T, rows []map[string]any) string {
	t.Helper()
	var names []string
	for _, row := range rows {
		name, _ := row["name"].(string)
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// Reads return a Boolean column as true/false and bm.d.ts types it boolean,
// so a filter written the same way must match: SQLite stores 0/1, and the
// raw text "true" used to match nothing (finding 4, round 2026-11-05).
func TestListBooleanFilterCoercion(t *testing.T) {
	_, mux, sid := booleanFilterFixture(t, true)
	cases := []struct{ query, want string }{
		{"where[active]=true", "a,c"},
		{"where[active]=false", "b"},
		{"active=true", "a,c"},
		{"active=TRUE", "a,c"},
		{"active=False", "b"},
		{"active=1", "a,c"},
		{"active=0", "b"},
		{"where[active__ne]=true", "b"},
		{"active__ne=false", "a,c"},
		{"active__in=true,false", "a,b,c"},
		{"where[active__in]=false", "b"},
		{"active__in=1", "a,c"},
		{"active__gt=false", "a,c"},
		{"active=true&name=a", "a"},
	}
	for _, tc := range cases {
		w := booleanFilterGet(t, mux, sid, "/api/items?"+tc.query)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v %s", tc.query, err, w.Body.String())
		}
		if got := booleanFilterNames(t, rows); got != tc.want {
			t.Errorf("%s matched %q, want %q", tc.query, got, tc.want)
		}
	}

	// count, the paged total and the cursor branch share the same filters.
	w := booleanFilterGet(t, mux, sid, "/api/items?count=true&where[active]=true")
	var count struct{ Count int }
	if err := json.Unmarshal(w.Body.Bytes(), &count); err != nil || w.Code != http.StatusOK || count.Count != 2 {
		t.Errorf("count where[active]=true: %d %s", w.Code, w.Body.String())
	}
	w = booleanFilterGet(t, mux, sid, "/api/items?count=true&active=false")
	if err := json.Unmarshal(w.Body.Bytes(), &count); err != nil || count.Count != 1 {
		t.Errorf("count active=false: %d %s", w.Code, w.Body.String())
	}
	w = booleanFilterGet(t, mux, sid, "/api/items?page=1&per_page=10&where[active]=false")
	var page struct {
		Data  []map[string]any
		Total int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || page.Total != 1 || booleanFilterNames(t, page.Data) != "b" {
		t.Errorf("paged where[active]=false: %d %s", w.Code, w.Body.String())
	}
	w = booleanFilterGet(t, mux, sid, "/api/items?cursor=0&active=true")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || booleanFilterNames(t, page.Data) != "a,c" {
		t.Errorf("cursor active=true: %d %s", w.Code, w.Body.String())
	}
}

// A value that is no boolean is refused, naming the column, instead of
// answering an empty list that reads as "no rows match".
func TestListBooleanFilterInvalidValue(t *testing.T) {
	_, mux, sid := booleanFilterFixture(t, true)
	for _, query := range []string{"active=maybe", "where[active]=yes", "active__in=true,maybe", "active__ne=2", "count=true&active=maybe", "cursor=0&active=maybe", "active="} {
		w := booleanFilterGet(t, mux, sid, "/api/items?"+query)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", query, w.Code, w.Body.String())
			continue
		}
		if body := w.Body.String(); !strings.Contains(body, "items.active") || !strings.Contains(body, "true/false or 1/0") {
			t.Errorf("%s: error does not name the column and accepted values: %s", query, body)
		}
	}
}

// A BOOLEAN column of a SQL-only app keeps SQLite's permissive storage (the
// write path accepts any text there), so true/false are coerced but other
// text still binds as written.
func TestListBooleanFilterSQLSchemaKeepsLegacyValues(t *testing.T) {
	app, mux, sid := booleanFilterFixture(t, false)
	mustExec(t, app.DB, `UPDATE items SET active = 'legacy-flag' WHERE name = 'c'`)
	for query, want := range map[string]string{"active=true": "a", "active=false": "b", "active=legacy-flag": "c"} {
		w := booleanFilterGet(t, mux, sid, "/api/items?"+query)
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
		}
		if got := booleanFilterNames(t, rows); got != want {
			t.Errorf("%s matched %q, want %q", query, got, want)
		}
	}
}

func TestQueryAPIBooleanFilterCoercion(t *testing.T) {
	_, mux, sid := booleanFilterFixture(t, true)
	query := func(where map[string]any) *httptest.ResponseRecorder {
		return crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "items", "select": []string{"name"}, "where": where})
	}
	cases := []struct {
		where map[string]any
		want  string
	}{
		{map[string]any{"active": true}, "a,c"},
		{map[string]any{"active": "true"}, "a,c"},
		{map[string]any{"active": "FALSE"}, "b"},
		{map[string]any{"active": 0}, "b"},
		{map[string]any{"active": map[string]any{"eq": "1"}}, "a,c"},
		{map[string]any{"active": map[string]any{"ne": "true"}}, "b"},
		{map[string]any{"active": map[string]any{"in": []any{"false", true}}}, "a,b,c"},
		{map[string]any{"active": map[string]any{"in": []any{"false"}}}, "b"},
	}
	for _, tc := range cases {
		w := query(tc.where)
		var body struct{ Rows []map[string]any }
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
			t.Fatalf("%v: %d %s", tc.where, w.Code, w.Body.String())
		}
		if got := booleanFilterNames(t, body.Rows); got != tc.want {
			t.Errorf("%v matched %q, want %q", tc.where, got, tc.want)
		}
	}
	for _, where := range []map[string]any{{"active": "maybe"}, {"active": 2}, {"active": map[string]any{"in": []any{true, "maybe"}}}} {
		w := query(where)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "true/false or 1/0") {
			t.Errorf("%v: %d %s, want 400 naming the accepted values", where, w.Code, w.Body.String())
		}
	}
}
