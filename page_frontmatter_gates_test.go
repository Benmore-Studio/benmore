//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ssrTestApp is a throwaway app with a `notes` table owned by user_id,
// users and sessions tables, and owner-scoped CRUD access on notes.
func ssrTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, body TEXT)`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"notes": {"all": "self"},
		}},
		Tables: []Table{{Name: "notes", Columns: []Column{
			{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}, {Name: "body"},
		}}},
	}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	return app
}

// ssrLoadPages writes page files into the app dir and loads them the way the
// app loader does, so <page> tags and frontmatter are parsed as in production.
func ssrLoadPages(t *testing.T, app *App, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(app.Dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pages, partials, err := LoadPages(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.Pages, app.Partials = pages, partials
	app.Paths = DiscoverAuthPaths(pages)
}

func ssrGet(mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "text/html")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func ssrRender(t *testing.T, app *App, page *Page, session *Session, data map[string]any) string {
	t.Helper()
	ctx := &RenderContext{Data: map[string]any{}, User: session, App: app, Page: page}
	for k, v := range data {
		ctx.Data[k] = v
	}
	out, err := RenderTemplate(app, page, ctx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// A frontmatter-only page's require: gate must survive route registration.
func TestFrontmatterRequireIsEnforced(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"pro.html": "---\nrequire: plan:pro\n---\n<h1>pro-only-content</h1>\n",
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")

	rec := ssrGet(mux, "/pro", "")
	if rec.Code == http.StatusOK {
		t.Fatalf("anonymous GET of a frontmatter require: page = 200; want a sign-in redirect")
	}
	free := createCrudScopeSession(t, app, "free@example.com", "user", "", "")
	if rec := ssrGet(mux, "/pro", free); rec.Code != http.StatusForbidden {
		t.Fatalf("user without plan=pro: status %d, want 403", rec.Code)
	}
	pro := createCrudScopeSession(t, app, "pro@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `UPDATE _benmore_users SET plan = 'pro' WHERE email = 'pro@example.com'`)
	if rec := ssrGet(mux, "/pro", pro); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pro-only-content") {
		t.Fatalf("plan=pro user: status %d, want the page", rec.Code)
	}
}

// A frontmatter role: gate applies exactly like <page role=...>.
func TestFrontmatterRoleIsEnforced(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"console.html": "---\nauth: required\nrole: admin\n---\n<h1>admin-only-content</h1>\n",
		"tagged.html":  "<page auth=\"required\" role=\"admin\"><h1>tag-admin-content</h1></page>\n",
	})
	if got := app.Pages["/console"].Role; got != "admin" {
		t.Fatalf("frontmatter role not loaded onto the page: %q", got)
	}
	mux := buildAppMux(app, false, "https://fixture.example.com")
	user := createCrudScopeSession(t, app, "plain@example.com", "user", "", "")
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	for _, path := range []string{"/console", "/tagged"} {
		if rec := ssrGet(mux, path, user); rec.Code != http.StatusForbidden {
			t.Errorf("%s as non-admin: status %d, want 403", path, rec.Code)
		}
		if rec := ssrGet(mux, path, admin); rec.Code != http.StatusOK {
			t.Errorf("%s as admin: status %d, want 200", path, rec.Code)
		}
	}
}

// The dev-mode re-read must keep frontmatter gates too.
func TestSetPageAttrsFromSourceKeepsFrontmatterGates(t *testing.T) {
	p := &Page{}
	setPageAttrsFromSource(p, "---\nauth: required\nrole: editor\nrequire: plan:pro\nscope: owner\n---\n<p>x</p>")
	if p.Auth != "required" || p.Role != "editor" || p.Require != "plan:pro" || p.Scope != "owner" {
		t.Fatalf("frontmatter gates lost: %+v", p)
	}
	setPageAttrsFromSource(p, `<page role="admin" require="verified:1"><p>x</p></page>`)
	if p.Role != "admin" || p.Require != "verified:1" || p.Auth != "" || p.Scope != "" {
		t.Fatalf("<page> tag attributes not re-read: %+v", p)
	}
}
