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

func TestAppMCPCapturedPagesRenderReviewedGeneration(t *testing.T) {
	app, _ := auditApp(t)
	sources := map[string]string{
		"gotmpl.html":                  "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n{{template \"nav\" .}}",
		"static/index.html":            `<html><head></head><body>approved-static<include src="fragments/detail.html"/></body></html>`,
		"static/fragments/detail.html": "approved-static-detail",
		"schema.sql":                   "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);",
		"index.html":                   `<page auth="none" layout="shell"><main>approved-root<include src="partials/nav.html"/><include src="fragments/detail.html"/><include src="fragments/late.html"/></main>`,
		"private.html":                 `<page auth="required" role="editor" layout="none">approved-private`,
		"layouts/shell.html":           `<section>approved-layout{{content}}</section><include src="partials/footer.html"/>`,
		"partials/nav.html":            "approved-nav",
		"partials/footer.html":         "approved-footer",
		"partials/kit.html":            "approved-kit",
		"fragments/detail.html":        "approved-detail",
		"head.html":                    `<meta name="generation" content="approved-head">`,
		"theme.css":                    ".approved-theme { color: red; }",
	}
	for name, source := range sources {
		writeTestFile(t, app.Dir, name, source)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for name := range sources {
		if name != "schema.sql" {
			writeTestFile(t, app.Dir, name, `<page auth="none">unreviewed`)
		}
	}
	if err := os.Remove(filepath.Join(app.Dir, "partials/footer.html")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"late.html", "partials/late.html", "fragments/late.html"} {
		writeTestFile(t, app.Dir, name, "unreviewed-late")
	}
	// Parse again after the disk mutation: membership and authority must come from capture.
	config.pages, config.partials, err = loadPagesFromSources(app.Dir, config.sourceFiles)
	if err != nil {
		t.Fatal(err)
	}
	if config.pages["/late"] != nil || config.partials["partials/late.html"] != "" {
		t.Fatal("late source joined captured generation")
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []bool{false, true} {
		mux := http.NewServeMux()
		registerAppPageRoutes(mux, app, dev)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		body := recorder.Body.String()
		if recorder.Code != http.StatusOK || strings.Contains(body, "unreviewed") {
			t.Fatalf("dev=%v render: %d %s", dev, recorder.Code, body)
		}
		for _, marker := range []string{"approved-root", "approved-layout", "approved-nav", "approved-footer", "approved-detail", "approved-head", "approved-theme"} {
			if !strings.Contains(body, marker) {
				t.Fatalf("dev=%v missing %s: %s", dev, marker, body)
			}
		}
		recorder = httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/gotmpl", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "approved-nav") || strings.Contains(recorder.Body.String(), "unreviewed") {
			t.Fatalf("captured gotmpl: %d %s", recorder.Code, recorder.Body.String())
		}
		recorder = httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/private", nil))
		if recorder.Code == http.StatusOK || strings.Contains(recorder.Body.String(), "approved-private") {
			t.Fatalf("dev=%v bypassed captured auth: %d %s", dev, recorder.Code, recorder.Body.String())
		}
	}
	if err := os.RemoveAll(filepath.Join(app.Dir, "static")); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if !serveStaticHTML(recorder, httptest.NewRequest(http.MethodGet, "/", nil), app) || !strings.Contains(recorder.Body.String(), "approved-static-detail") || strings.Contains(recorder.Body.String(), "unreviewed") {
		t.Fatalf("captured static: %s", recorder.Body.String())
	}
	writeTestFile(t, app.Dir, "static/late.html", "unreviewed-late")
	for _, dev := range []bool{false, true} {
		mux := buildAppMux(app, dev, "https://fixture.example.com")
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/index.html", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "approved-static") || strings.Contains(recorder.Body.String(), "unreviewed") {
			t.Fatalf("direct static capture dev=%v: %d %s", dev, recorder.Code, recorder.Body.String())
		}
		recorder = httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/late.html", nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("late direct static dev=%v: %d %s", dev, recorder.Code, recorder.Body.String())
		}
	}
	if tryServeHTMLFile(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/late.html", nil), app, filepath.Join(app.Dir, "static/late.html")) {
		t.Fatal("late static HTML joined capture")
	}
	if tryServeHTMLFile(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), app, filepath.Join(app.Dir, "index.html")) {
		t.Fatal("static capture escaped static root")
	}
}

func TestAppMCPCapturedSourceAbsenceNeverReadsDisk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "index.html", `<page auth="none">late`)
	writeTestFile(t, dir, "head.html", "late-head")
	pages, partials, err := loadPagesFromSources(dir, map[string][]byte{})
	if err != nil || len(pages) != 0 || len(partials) != 0 {
		t.Fatalf("captured absence: %v %v %v", pages, partials, err)
	}
	app := &App{Dir: dir, MCP: &AppMCPManifest{}, sourceFiles: map[string][]byte{}}
	if _, err := app.readSourceFile("head.html"); !os.IsNotExist(err) {
		t.Fatalf("late file read: %v", err)
	}
	app.sourceFiles = nil
	if _, err := app.readSourceFile("head.html"); err == nil {
		t.Fatal("missing capture read disk")
	}
	app.MCP = nil
	if data, err := app.readSourceFile("head.html"); err != nil || string(data) != "late-head" {
		t.Fatalf("ordinary source changed: %q %v", data, err)
	}
}
