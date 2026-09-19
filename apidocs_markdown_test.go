//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestRenderDocsMarkdownHasSectionsAndRoutes(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`CREATE TABLE _benmore_internal (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY, password_hash TEXT)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{DB: db, Pages: map[string]*Page{"/about": {File: "about.html", Title: "About"}}}

	md := renderDocsMarkdown(app)
	for _, want := range []string{
		"# API Documentation",
		"## Authentication",
		"## widgets",
		"| `name` | TEXT | required |",
		"`GET /api/widgets` - List all records",
		"`DELETE /api/widgets/batch`",
		"## Pages",
		"`/about` - About",
		"## Platform features",
		"**Idempotency:**",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown export missing %q\n---\n%s", want, md)
		}
	}
	// Internal tables and sensitive columns must never leak.
	if strings.Contains(md, "_benmore_") {
		t.Error("markdown export should skip _benmore_ internal tables")
	}
	if strings.Contains(md, "password_hash") {
		t.Error("markdown export should never expose password_hash")
	}
}
