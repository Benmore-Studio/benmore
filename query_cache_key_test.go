//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestQueryCacheKeyIsUnambiguous(t *testing.T) {
	sql := "SELECT ? , ?"
	if queryCacheKey("/apps/a", sql, []any{"1", "23"}) == queryCacheKey("/apps/a", sql, []any{"12", "3"}) {
		t.Errorf("argument lists (1,23) and (12,3) share a cache key")
	}
	if queryCacheKey("/apps/a", sql, []any{int64(1)}) == queryCacheKey("/apps/a", sql, []any{"1"}) {
		t.Errorf("an integer and a string argument share a cache key")
	}
	if queryCacheKey("/apps/a", sql, nil) == queryCacheKey("/apps/b", sql, nil) {
		t.Errorf("two apps share a cache key for the same SQL")
	}
}

// In one process serving several apps, a cached <query> is per app.
func TestQueryCacheIsPerApp(t *testing.T) {
	a := ssrTestApp(t)
	b := ssrTestApp(t)
	crudScopeMustExec(t, a.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'app-a-row')`)
	crudScopeMustExec(t, b.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'app-b-row')`)
	tmpl := `<query sql="SELECT title FROM notes /*query_cache_per_app*/" cache="5m" as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}</query>`
	if out := ssrRender(t, a, &Page{Route: "/c", RawHTML: tmpl}, nil, nil); !strings.Contains(out, "app-a-row") {
		t.Fatalf("app A render: %s", out)
	}
	out := ssrRender(t, b, &Page{Route: "/c", RawHTML: tmpl}, nil, nil)
	if strings.Contains(out, "app-a-row") || !strings.Contains(out, "app-b-row") {
		t.Fatalf("app B rendered app A's cached rows: %s", out)
	}
	// Still cached within one app.
	crudScopeMustExec(t, b.DB, `UPDATE notes SET title = 'app-b-changed'`)
	if out := ssrRender(t, b, &Page{Route: "/c", RawHTML: tmpl}, nil, nil); !strings.Contains(out, "app-b-row") {
		t.Fatalf("cache not reused within the app: %s", out)
	}
}
