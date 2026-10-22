//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// Frontmatter `scope: owner` scopes gotmpl queries the way <page scope> scopes
// mustache <query> tags.
func TestGotmplScopeOwnerScopesFrontmatterQueries(t *testing.T) {
	app := ssrTestApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	_ = createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'alice-note'), (2, 'bob-note')`)
	ssrLoadPages(t, app, map[string]string{
		"mine.html": "---\nengine: gotmpl\nauth: required\nscope: owner\nqueries:\n  notes: SELECT title FROM notes ORDER BY id\n  total: SELECT COUNT(*) AS n FROM notes\n---\n<ul>{{range .notes}}<li>{{.title}}</li>{{end}}</ul><p>total={{.total.n}}</p>\n",
		"all.html":  "---\nengine: gotmpl\nauth: required\nqueries:\n  notes: SELECT title FROM notes ORDER BY id\n---\n<ul>{{range .notes}}<li>{{.title}}</li>{{end}}</ul>\n",
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")

	rec := ssrGet(mux, "/mine", alice)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "alice-note") {
		t.Fatalf("owner's own row missing: %d %s", rec.Code, body)
	}
	if strings.Contains(body, "bob-note") || !strings.Contains(body, "total=1") {
		t.Fatalf("scope: owner gotmpl page leaked another user's rows: %s", body)
	}
	// A page without scope: owner is unchanged.
	if rec := ssrGet(mux, "/all", alice); !strings.Contains(rec.Body.String(), "bob-note") {
		t.Fatalf("unscoped gotmpl page changed: %s", rec.Body.String())
	}
}
