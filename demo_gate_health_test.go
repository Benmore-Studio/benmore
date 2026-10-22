//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Release verification reads /health JSON and cannot present the visitor
// password, so the gate must pass exactly that path and nothing near it.
func TestDemoGateExemptsOnlyExactHealth(t *testing.T) {
	app, _ := auditApp(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler(app))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("app")) })
	gate := DemoGateMiddleware(app, "visitor-pass", mux)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	rec := get("/health")
	var body map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["version"] != version {
		t.Fatalf("/health behind the demo gate: code=%d body=%.120q", rec.Code, rec.Body.String())
	}
	if _, leaked := body["checks"]; leaked {
		t.Fatal("anonymous /health exposed admin-only checks")
	}

	for _, path := range []string{"/", "/healthz", "/health/x", "/health/"} {
		rec := get(path)
		if !strings.Contains(rec.Body.String(), "Demo Access") {
			t.Fatalf("%s was not gated: code=%d body=%.80q", path, rec.Code, rec.Body.String())
		}
	}
}
