//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.7.139: an unmatched /api/* path must return a real JSON 404 with
// no-store — never SPA HTML (GET) or the HTML 404 page (other methods).
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
