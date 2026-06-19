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

// v2.7.139: an unmatched /api/* path must return a real JSON 404 with
// no-store - never SPA HTML (GET) or the HTML 404 page (other methods).
// HTML at an /api path makes client res.json() choke on '<' and, when a
// CDN caches the 200-HTML for a not-yet-deployed flow path, shadows the
// flow once it ships.
func TestNotFoundHandler_APIPathReturnsJSON404(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	h := notFoundHandler(app)

	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		req := httptest.NewRequest(method, "/api/not-a-real-flow", nil)
		req.Header.Set("Accept", "text/html") // even a browser-y Accept must NOT get HTML
		rec := httptest.NewRecorder()
		h(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /api/...: status = %d, want 404", method, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s /api/...: Content-Type = %q, want application/json", method, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s /api/...: Cache-Control = %q, want no-store", method, cc)
		}
		body := rec.Body.String()
		if strings.Contains(body, "<") {
			t.Errorf("%s /api/...: body contains HTML '<': %q", method, body)
		}
		if !strings.Contains(body, "not_found") {
			t.Errorf("%s /api/...: body missing not_found marker: %q", method, body)
		}
	}
}

// A non-/api unmatched path is NOT hijacked by the JSON-404 guard (it still
// goes through the SPA/HTML 404 path).
func TestNotFoundHandler_NonAPIPathNotJSON(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	h := notFoundHandler(app)

	req := httptest.NewRequest("GET", "/some-missing-page", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
		t.Errorf("non-/api path should not get the JSON-404 guard; Content-Type = %q", ct)
	}
}

func TestStaticHandlerBlocksSymlinkEscape(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("mkdir static: %v", err)
	}
	secret := "BENMORE_SECRET_SHOULD_NOT_LEAK"
	if err := os.WriteFile(filepath.Join(app.Dir, "env.yaml"), []byte(secret), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.Symlink("../env.yaml", filepath.Join(staticDir, "leak.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	req := httptest.NewRequest("GET", "/static/leak.txt", nil)
	rec := httptest.NewRecorder()
	serveStaticAsset(rec, req, app, false, "leak.txt")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("static symlink response leaked file outside static root")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestStaticHTMLBlocksSymlinkEscape(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("mkdir static: %v", err)
	}
	secret := "BENMORE_HTML_SECRET_SHOULD_NOT_LEAK"
	if err := os.WriteFile(filepath.Join(app.Dir, "env.yaml"), []byte(secret), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.Symlink("../env.yaml", filepath.Join(staticDir, "leak.html")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	req := httptest.NewRequest("GET", "/leak.html", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	if serveStaticHTML(rec, req, app) {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("clean HTML symlink response leaked file outside static root")
		}
	}
}

func TestStaticMissingAssetNoStore(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "static"), 0o755); err != nil {
		t.Fatalf("mkdir static: %v", err)
	}
	req := httptest.NewRequest("GET", "/static/missing.css", nil)
	rec := httptest.NewRecorder()
	serveStaticAsset(rec, req, app, false, "missing.css")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestUploadsMissingAssetNoStore(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads"), 0o755); err != nil {
		t.Fatalf("mkdir uploads: %v", err)
	}
	req := httptest.NewRequest("GET", "/uploads/missing.png", nil)
	rec := httptest.NewRecorder()
	serveUploadAsset(rec, req, app, false, "missing.png")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestUploadsHandlerBlocksSymlinkEscape(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	uploadsDir := filepath.Join(app.Dir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		t.Fatalf("mkdir uploads: %v", err)
	}
	secret := "BENMORE_UPLOAD_SECRET_SHOULD_NOT_LEAK"
	if err := os.WriteFile(filepath.Join(app.Dir, "env.yaml"), []byte(secret), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.Symlink("../env.yaml", filepath.Join(uploadsDir, "leak.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	req := httptest.NewRequest("GET", "/uploads/leak.txt", nil)
	rec := httptest.NewRecorder()
	serveUploadAsset(rec, req, app, false, "leak.txt")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("upload symlink response leaked file outside uploads root")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}
