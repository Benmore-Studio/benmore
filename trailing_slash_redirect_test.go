package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A trailing-slash variant of a registered page redirects to the canonical
// route; everything else keeps its existing 404 behavior.
func TestTrailingSlashRedirectsToRegisteredPage(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Pages = map[string]*Page{
		"/":     {Route: "/", RawHTML: "<h1>Home</h1>"},
		"/docs": {Route: "/docs", RawHTML: "<h1>Docs</h1>"},
	}
	mux := buildAppMux(app, true, "https://fixture.example.com")

	cases := []struct {
		method   string
		path     string
		wantCode int
		wantLoc  string
	}{
		{http.MethodGet, "/docs/", http.StatusMovedPermanently, "/docs"},
		{http.MethodHead, "/docs/", http.StatusMovedPermanently, "/docs"},
		{http.MethodGet, "/docs/?utm_source=x&b=1", http.StatusMovedPermanently, "/docs?utm_source=x&b=1"},
		// ServeMux cleans repeated slashes itself (307 to /docs/), which then
		// lands on the 301 above - two hops, both permanent-safe.
		{http.MethodGet, "/docs///", http.StatusTemporaryRedirect, "/docs/"},
		{http.MethodGet, "/docs", http.StatusOK, ""},
		{http.MethodGet, "/", http.StatusOK, ""},
		{http.MethodGet, "/missing/", http.StatusNotFound, ""},
		{http.MethodPost, "/docs/", http.StatusNotFound, ""},
		{http.MethodGet, "/api/docs/", http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Accept", "text/html")
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.wantCode {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
		}
		if got := rec.Header().Get("Location"); got != tc.wantLoc {
			t.Errorf("%s %s: Location %q, want %q", tc.method, tc.path, got, tc.wantLoc)
		}
		if strings.HasPrefix(tc.path, "/api/") && !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s %s: API 404 must stay JSON, got %q", tc.method, tc.path, rec.Header().Get("Content-Type"))
		}
	}
}
