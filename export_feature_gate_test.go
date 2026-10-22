//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExportFeatureGateBeforeSessionOrRendering(t *testing.T) {
	// A known protected page avoids mistaking an unknown-page 404 for an export denial.
	app := &App{Design: &DesignConfig{Features: parseFeaturesConfig(map[string]any{"exports": false})}, Pages: map[string]*Page{"/refer": {Route: "/refer", Auth: "required"}}}
	mux := http.NewServeMux()
	RegisterPDFRoutes(mux, app)
	RegisterDSARRoute(mux, app)
	for _, path := range []string{"/pdf/refer", "/api/_my-data"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.AddCookie(&http.Cookie{Name: "session", Value: "synthetic-session"})
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound || w.Header().Get("Content-Disposition") != "" {
				t.Fatalf("status=%d, disposition=%q", w.Code, w.Header().Get("Content-Disposition"))
			}
		})
	}
}

func TestExportFeatureGateDefaultCompatible(t *testing.T) {
	for _, config := range []*FeaturesConfig{nil, {}, parseFeaturesConfig(map[string]any{"exports": true})} {
		if !config.IsEnabled("exports") {
			t.Fatal("HTTP exports must remain enabled by default")
		}
	}
	if message := ValidateOnWrite("app.yaml", "features:\n  exports: false\n"); message != "" {
		t.Fatal(message)
	}
}
