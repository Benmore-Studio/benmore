//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func newDocsAudienceApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, body TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE payroll (id INTEGER PRIMARY KEY, employee TEXT, salary_cents INTEGER)`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour,
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"posts": {OpRead: "anon"}, // writes fall back to the implicit admin default
		}},
		Tables: []Table{
			{Name: "posts", Columns: []Column{{Name: "id", PK: true}, {Name: "title"}}},
			{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "body"}}},
			{Name: "payroll", Columns: []Column{{Name: "id", PK: true}, {Name: "employee"}, {Name: "salary_cents"}}},
		},
		Pages: map[string]*Page{
			"/":             {Route: "/", File: "index.html"},
			"/admin/payrun": {Route: "/admin/payrun", File: "payrun.html", RawHTML: `<page role="admin"></page>`},
			"/dashboard":    {Route: "/dashboard", File: "dashboard.html", Auth: "required"},
		},
	}
	mux := http.NewServeMux()
	RegisterAPIDocsRoutes(mux, app)
	return app, mux
}

func docsGet(t *testing.T, mux *http.ServeMux, path, bearer string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status %d body=%s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// One anon-readable table made the docs public, and the docs then listed
// every table, column and route - the payroll schema included.
func TestAPIDocsListOnlyWhatTheCallerCanRead(t *testing.T) {
	app, mux := newDocsAudienceApp(t)
	user := createCrudScopeSession(t, app, "user@example.com", "user", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")

	docTables := func(bearer string) (string, map[string]any) {
		var doc struct {
			Endpoints map[string]any   `json:"endpoints"`
			Pages     []map[string]any `json:"pages"`
		}
		if err := json.Unmarshal([]byte(docsGet(t, mux, "/api/_docs", bearer)), &doc); err != nil {
			t.Fatal(err)
		}
		var names []string
		for k := range doc.Endpoints {
			names = append(names, k)
		}
		sort.Strings(names)
		var pages []string
		for _, p := range doc.Pages {
			pages = append(pages, p["route"].(string))
		}
		sort.Strings(pages)
		return strings.Join(names, ",") + " | " + strings.Join(pages, ","), doc.Endpoints
	}

	got, endpoints := docTables("")
	if got != "posts | /" {
		t.Fatalf("anonymous /api/_docs = %s, want only the public table and page", got)
	}
	for _, rt := range endpoints["posts"].(map[string]any)["routes"].([]any) {
		if m := rt.(map[string]any)["method"]; m != "GET" {
			t.Fatalf("anonymous docs advertise %v on posts, which only admins may write", m)
		}
	}
	if got, _ := docTables(user); got != "notes,posts | /,/dashboard" {
		t.Fatalf("user /api/_docs = %s", got)
	}
	if got, _ := docTables(admin); got != "notes,payroll,posts | /,/admin/payrun,/dashboard" {
		t.Fatalf("admin /api/_docs = %s", got)
	}

	for _, path := range []string{"/api/_openapi", "/openapi.json", "/docs", "/docs?format=md"} {
		anon := docsGet(t, mux, path, "")
		if strings.Contains(anon, "payroll") || strings.Contains(anon, "salary_cents") || strings.Contains(anon, "/api/notes") {
			t.Fatalf("anonymous %s exposes private tables", path)
		}
		if !strings.Contains(anon, "/api/posts") {
			t.Fatalf("anonymous %s dropped the public table", path)
		}
		if !strings.Contains(docsGet(t, mux, path, admin), "salary_cents") {
			t.Fatalf("admin %s lost the full schema", path)
		}
	}
	// The developer contract (benmore verify) stays complete.
	if paths := generateRuntimeOpenAPI(app)["paths"].(map[string]any); paths["/api/payroll"] == nil {
		t.Fatal("full OpenAPI contract dropped a table")
	}
}
