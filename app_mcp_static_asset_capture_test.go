//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAppMCPCapturedStaticAssetsAndOverridesSurviveDiskChanges(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	sources := map[string]string{
		"static/image.bin":     "\x00\xffapproved-binary",
		"static/site.css":      ".approved { color: red; }",
		"static/site.js":       "window.assetGeneration = 'approved';",
		"static/favicon.ico":   "approved-ico",
		"static/favicon.png":   "approved-png",
		"static/llms.txt":      "# approved index\n",
		"static/llms-full.txt": "# approved full guide\n",
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
	if err := os.RemoveAll(filepath.Join(app.Dir, "static")); err != nil {
		t.Fatal(err)
	}
	for name := range sources {
		writeTestFile(t, app.Dir, name, "unreviewed replacement")
	}
	writeTestFile(t, app.Dir, "static/late.css", ".late {}")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	mux := buildAppMux(app, false, "https://fixture.example.com")
	for path, want := range map[string]string{
		"/static/image.bin":     sources["static/image.bin"],
		"/static/site.css":      sources["static/site.css"],
		"/static/site.js":       sources["static/site.js"],
		"/favicon.ico":          sources["static/favicon.ico"],
		"/llms.txt":             sources["static/llms.txt"],
		"/.well-known/llms.txt": sources["static/llms.txt"],
		"/llms-full.txt":        sources["static/llms-full.txt"],
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), []byte(want)) {
			t.Errorf("GET %s = %d %q, want captured %q", path, rec.Code, rec.Body.Bytes(), want)
		}
		if path == "/static/site.css" || path == "/static/site.js" || path == "/static/image.bin" {
			// Captured assets are revalidated on every use against a content
			// validator (never stored by a CDN), so a superseded generation
			// can't be served from a cache.
			etag := rec.Header().Get("ETag")
			if got := rec.Header().Get("Cache-Control"); got != "private, no-cache, must-revalidate" || etag == "" ||
				rec.Header().Get("CDN-Cache-Control") != "no-store" {
				t.Errorf("GET %s Cache-Control = %q ETag %q CDN %q, want revalidated private + CDN no-store", path, got, etag, rec.Header().Get("CDN-Cache-Control"))
			}
			cond := httptest.NewRequest(http.MethodGet, path, nil)
			cond.Header.Set("If-None-Match", etag)
			again := httptest.NewRecorder()
			mux.ServeHTTP(again, cond)
			if again.Code != http.StatusNotModified {
				t.Errorf("conditional GET %s = %d, want 304", path, again.Code)
			}
		}
		if path == "/favicon.ico" {
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("GET %s Cache-Control = %q, want no-store", path, got)
			}
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/late.css", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("late asset = %d, Cache-Control %q; want 404/no-store", rec.Code, rec.Header().Get("Cache-Control"))
	}

	// Ordinary apps still serve current files from disk through the existing paths.
	app.mu.Lock()
	app.MCP = nil
	app.mu.Unlock()
	writeTestFile(t, app.Dir, "static/site.css", ".ordinary { color: blue; }")
	writeTestFile(t, app.Dir, "static/favicon.ico", "ordinary-ico")
	writeTestFile(t, app.Dir, "static/llms.txt", "# ordinary index\n")
	mux = buildAppMux(app, false, "https://fixture.example.com")
	for path, want := range map[string]string{
		"/static/site.css": ".ordinary { color: blue; }",
		"/favicon.ico":     "ordinary-ico",
		"/llms.txt":        "# ordinary index\n",
	} {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Errorf("ordinary GET %s = %d %q, want %q", path, rec.Code, rec.Body.String(), want)
		}
	}
}

func TestAppMCPCapturedStaticAssetsDenyLateEmptyAndMetadataSources(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "static/empty.js", "")
	writeTestFile(t, app.Dir, "static/approved.css", ".approved {}")
	writeTestFile(t, app.Dir, "static/._hidden.css", "metadata")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(app.Dir, "static")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "static/late.js", "late")
	writeTestFile(t, app.Dir, "static/._late.css", "metadata")
	writeTestFile(t, app.Dir, "secret.css", "outside static")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	mux := buildAppMux(app, false, "https://fixture.example.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/empty.js", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("captured empty asset = %d %q, want empty 200", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/static/late.js", "/static/._late.css", "/static/._hidden.css"} {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s = %d, Cache-Control %q; want 404/no-store", path, rec.Code, rec.Header().Get("Cache-Control"))
		}
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/%2e%2e/secret.css", nil))
	if rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte("outside static")) {
		t.Fatalf("traversal served outside content: %d %q", rec.Code, rec.Body.String())
	}

	// An initialized empty capture and a missing capture both fail closed.
	writeTestFile(t, app.Dir, "static/late.js", "late")
	app.sourceFiles = map[string][]byte{}
	for _, sources := range []map[string][]byte{app.sourceFiles, nil} {
		app.mu.Lock()
		app.sourceFiles = sources
		app.mu.Unlock()
		mux = buildAppMux(app, false, "https://fixture.example.com")
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/late.js", nil))
		if rec.Code != http.StatusNotFound || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("empty capture late asset = %d, Cache-Control %q; want 404/no-store", rec.Code, rec.Header().Get("Cache-Control"))
		}
	}
}
