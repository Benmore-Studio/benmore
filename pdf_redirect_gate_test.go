//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// GET /pdf/<page> renders the page's HTML for the caller, so it must answer
// the page's role-based redirect the way the page route does. A page taken
// offline with redirect="*:/" (or one that sends a role elsewhere) was still
// printed in full through /pdf.
func TestPDFRouteHonorsPageRedirect(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	page := &Page{File: "retired.html", Route: "/retired", Redirect: "*:/", RawHTML: `<page redirect="*:/">retired report</page>`}
	app := &App{Dir: dir, DB: db, Pages: map[string]*Page{"/retired": page}}
	mux := http.NewServeMux()
	RegisterPDFRoutes(mux, app)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/pdf/retired", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("/pdf of a redirected page: status %d location %q, want 303 to /", w.Code, w.Header().Get("Location"))
	}
}
