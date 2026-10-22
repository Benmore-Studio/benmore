//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// /sw.js is reserved, so an offline-first app's static/sw.js never ran and the
// app could not open with no connection. pwa.service_worker opts in to serving
// the app's own worker there. These tests pin that the opt-in works, that it
// cannot reach outside static/, and above all that apps which do not set it
// are served exactly what they were served before.

func swTestApp(t *testing.T, pwa map[string]string) *App {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "sw.js"), []byte("// app worker\nself.addEventListener('fetch', function(){});\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("site_name: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &App{Dir: dir, Design: &DesignConfig{PWA: pwa, SEO: map[string]string{"site_name": "X"}}}
}

func serveSW(t *testing.T, app *App) (string, http.Header) {
	t.Helper()
	mux := http.NewServeMux()
	RegisterPWARoutes(mux, app)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/sw.js status %d", rec.Code)
	}
	return rec.Body.String(), rec.Header()
}

func TestServiceWorkerUnchangedWithoutOptIn(t *testing.T) {
	// Even with a static/sw.js on disk, no key means the generated worker,
	// byte for byte: running apps must not change behaviour.
	for _, pwa := range []map[string]string{nil, {"offline": "true"}, {"name": "X"}} {
		app := swTestApp(t, pwa)
		body, hdr := serveSW(t, app)
		if body != GenerateServiceWorker(app) {
			t.Fatalf("pwa=%v: /sw.js differs from the generated worker:\n%s", pwa, body)
		}
		if hdr.Get("Cache-Control") != "no-cache" || hdr.Get("Content-Type") != "application/javascript" {
			t.Fatalf("headers changed: %v", hdr)
		}
	}
}

func TestServiceWorkerServesAppWorkerWhenOptedIn(t *testing.T) {
	for _, v := range []string{"/static/sw.js", "static/sw.js", "sw.js", " /static/sw.js "} {
		body, hdr := serveSW(t, swTestApp(t, map[string]string{"service_worker": v}))
		if body != "// app worker\nself.addEventListener('fetch', function(){});\n" {
			t.Fatalf("service_worker=%q: got %q", v, body)
		}
		if hdr.Get("Cache-Control") != "no-cache" || hdr.Get("Content-Type") != "application/javascript" {
			t.Fatalf("service_worker=%q: headers %v", v, hdr)
		}
	}
}

func TestServiceWorkerOptInCannotLeaveStatic(t *testing.T) {
	app := swTestApp(t, map[string]string{})
	outside := filepath.Join(t.TempDir(), "secret.js")
	if err := os.WriteFile(outside, []byte("// outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(app.Dir, "static", "link.js")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{
		"../app.yaml",         // not .js, and outside static/
		"/static/../app.yaml", // traversal
		"../../etc/passwd.js", // traversal with .js
		"/static/link.js",     // symlink escaping static/
		"/static/missing.js",  // does not exist
		"/static/",            // directory
		"/static/sw.txt",      // not a script
	} {
		app.Design.PWA["service_worker"] = v
		body, _ := serveSW(t, app)
		if body != GenerateServiceWorker(app) {
			t.Fatalf("service_worker=%q should fall back to the generated worker, got:\n%s", v, body)
		}
	}
}

func TestServiceWorkerReadsCurrentFile(t *testing.T) {
	// Read per request, so a push of static/sw.js takes effect without a reload.
	app := swTestApp(t, map[string]string{"service_worker": "/static/sw.js"})
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "sw.js"), []byte("// v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, _ := serveSW(t, app); body != "// v2" {
		t.Fatalf("stale worker served: %q", body)
	}
}

// A reviewed app (mcp.yaml with digests) serves only the source captured with
// its review: /static/*, favicon and llms.txt never read later disk bytes. The
// opted-in worker controls every page of the origin, so it must follow the
// same rule: an unreviewed static/sw.js left on disk by a refused reload, or a
// path that escapes static/ into another captured tree, must not be served.
func TestServiceWorkerOptInServesReviewedCapturedSource(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "app.yaml", "site_name: X\npwa:\n  service_worker: /static/sw.js\n")
	writeTestFile(t, app.Dir, "static/sw.js", "// reviewed worker\n")
	writeTestFile(t, app.Dir, "flows/helper.js", "// captured flow helper, not a worker\n")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "static/sw.js", "// unreviewed worker\n")
	writeTestFile(t, app.Dir, "static/late.js", "// unreviewed late worker\n")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if app.Design == nil || app.Design.PWA["service_worker"] != "/static/sw.js" {
		t.Fatalf("fixture did not load pwa.service_worker: %+v", app.Design)
	}
	get := func() string {
		mux := buildAppMux(app, false, "https://fixture.example.com")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("/sw.js status %d", rec.Code)
		}
		return rec.Body.String()
	}
	if body := get(); body != "// reviewed worker\n" {
		t.Fatalf("reviewed app served %q at /sw.js, want the captured reviewed worker", body)
	}
	for _, v := range []string{"/static/late.js", "/static/../flows/helper.js", "../flows/helper.js"} {
		app.Design.PWA["service_worker"] = v
		if body := get(); body != GenerateServiceWorker(app) {
			t.Fatalf("service_worker=%q on a reviewed app served %q, want the generated worker", v, body)
		}
	}
}
