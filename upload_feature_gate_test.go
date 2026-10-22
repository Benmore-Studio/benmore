//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadFeatureGateRefusesBeforeReading(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Design = &DesignConfig{Features: parseFeaturesConfig(map[string]any{"uploads": false})}
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	RegisterFileUploadRoute(mux, app)
	for _, path := range []string{"/api/_upload", "/api/_files"} {
		t.Run(path, func(t *testing.T) {
			body := &uploadCountingReader{r: strings.NewReader("patient-content-canary")}
			request := httptest.NewRequest(http.MethodPost, path, body)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || body.n != 0 {
				t.Fatalf("status=%d, bytes read=%d", response.Code, body.n)
			}
		})
	}
}

func TestUploadFeatureGateDefaultCompatible(t *testing.T) {
	for _, config := range []*FeaturesConfig{nil, {}, parseFeaturesConfig(map[string]any{"uploads": true})} {
		if !config.IsEnabled("uploads") {
			t.Fatal("uploads must remain enabled by default")
		}
	}
	if message := ValidateOnWrite("app.yaml", "features:\n  uploads: false\n"); message != "" {
		t.Fatal(message)
	}
}
