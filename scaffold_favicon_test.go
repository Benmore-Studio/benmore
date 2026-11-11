//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 2 B10: the scaffold shipped no icon, so a browser opening any page
// asked for /favicon.ico, got 404, and the starter journey failed `benmore
// verify --quick` on a fresh app. Every scaffolded page now links an icon the
// app serves, so the browser never asks for /favicon.ico.
func TestScaffoldPagesLinkAServedFavicon(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Icon fixture"); err != nil {
		t.Fatal(err)
	}
	head, err := os.ReadFile(filepath.Join(dir, "static", "partials", "head.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(head), `<link rel="icon" href="/static/favicon.svg"`) {
		t.Fatalf("head partial links no icon:\n%s", head)
	}
	pages, err := filepath.Glob(filepath.Join(dir, "static", "*.html"))
	if err != nil || len(pages) == 0 {
		t.Fatalf("no scaffold pages: %v", err)
	}
	for _, page := range pages {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `<include src="partials/head.html" />`) {
			t.Fatalf("%s does not include the head partial, so it links no icon", filepath.Base(page))
		}
	}

	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	mux := buildAppMux(app, false, "https://icon.example.com")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://icon.example.com/", nil))
	// The served link carries the static cache-busting ?v= hash.
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `rel="icon" href="/static/favicon.svg`) {
		t.Fatalf("home page %d does not link the icon: %.400s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://icon.example.com/static/favicon.svg", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "image/svg+xml") || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("icon answered %d %q: %.200s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}
