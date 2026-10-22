//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The visitor password covers the API too. Only callers that can't present
// it and authenticate for themselves pass: a valid bearer credential, or a
// signed inbound webhook route.
func TestDemoGateCoversAPI(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "user@example.com", "user", "", "")
	token := auditToken(t, app, sid, "*")
	app.Flows = []Flow{{Name: "stripe_hook", Verify: "stripe", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/hooks/:provider"}}}
	reached := false
	gate := DemoGateMiddleware(app, "visitor-pass", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	try := func(method, path string, prep func(*http.Request)) (bool, int) {
		reached = false
		req := httptest.NewRequest(method, path, nil)
		if prep != nil {
			prep(req)
		}
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, req)
		return reached, rec.Code
	}
	if ok, code := try("GET", "/api/notes", nil); ok || code != http.StatusUnauthorized {
		t.Fatalf("anonymous API request passed the visitor gate: reached=%v code=%d", ok, code)
	}
	if ok, _ := try("GET", "/api/notes", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "demo_session", Value: demoSessionToken("visitor-pass")})
	}); !ok {
		t.Fatal("visitor with the demo cookie was blocked")
	}
	if ok, _ := try("GET", "/api/notes", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }); !ok {
		t.Fatal("valid bearer credential was blocked")
	}
	if ok, _ := try("GET", "/api/notes", func(r *http.Request) { r.Header.Set("Authorization", "Bearer bogus") }); ok {
		t.Fatal("a made-up bearer token passed the visitor gate")
	}
	if ok, _ := try("POST", "/api/hooks/stripe", nil); !ok {
		t.Fatal("signed inbound webhook route was blocked")
	}
	if ok, _ := try("GET", "/static/app.js", nil); !ok {
		t.Fatal("static asset was blocked")
	}
}
