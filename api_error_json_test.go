//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// api(at:"errors") tells a client to read `error` from a JSON body. These
// /api/ refusals answered Go's text/plain http.Error instead: some with a
// plain sentence, some with JSON text under the text content type, so
// `await res.json()` threw or a client that checks Content-Type saw no
// envelope (round 2026-11-09, docs F2).

const rateLimitedText = "Rate limit exceeded. Try again later."

// wantJSONRefusal requires the status, the JSON content type and an envelope
// whose `error` is exactly text. It reports and carries on, so one run lists
// every route that is still text.
func wantJSONRefusal(t *testing.T, name string, w *httptest.ResponseRecorder, status int, text string) {
	t.Helper()
	if w.Code != status {
		t.Errorf("%s: status %d, want %d (%s)", name, w.Code, status, strings.TrimSpace(w.Body.String()))
		return
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s: %d answered as %q, want application/json (%s)", name, w.Code, ct, strings.TrimSpace(w.Body.String()))
		return
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Errorf("%s: %d body is not one JSON object: %v (%s)", name, w.Code, err, strings.TrimSpace(w.Body.String()))
		return
	}
	if body["error"] != text {
		t.Errorf("%s: error %q, want %q", name, body["error"], text)
	}
}

// wantRetryAfter requires a Retry-After of 1..max whole seconds.
func wantRetryAfter(t *testing.T, name string, w *httptest.ResponseRecorder, max int) {
	t.Helper()
	got := w.Header().Get("Retry-After")
	if n, err := strconv.Atoi(got); err != nil || n < 1 || n > max {
		t.Errorf("%s: Retry-After %q, want 1..%d", name, got, max)
	}
}

// bearerCall sends one request through mux as the Bearer session sid ("" for
// an anonymous caller).
func bearerCall(mux http.Handler, method, path, body, sid string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if sid != "" {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func adminGateUser(t *testing.T, app *App, email string) string {
	t.Helper()
	uid, sid := gateUser(t, app, email)
	mustExec(t, app.DB, fmt.Sprintf("UPDATE _benmore_users SET role = 'admin' WHERE id = %d", uid))
	return sid
}

// The sixth NDJSON ingest in a minute answered 429 text/plain with no
// Retry-After. The limit here is one per minute so two requests show it.
func TestIngestRateLimitAnswersJSONWithRetryAfter(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	_, sid := gateUser(t, app, "writer@example.com")
	saved := ingestLimiter
	ingestLimiter = NewRateLimiter(1, time.Minute)
	t.Cleanup(func() { ingestLimiter = saved })

	ingest := func(row string) *httptest.ResponseRecorder {
		return gateCall(app, handleStreamingIngest, "notes", "POST", "/api/notes/ingest", "application/x-ndjson", row+"\n", sid)
	}
	if w := ingest(`{"title":"first"}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ingested":1`) {
		t.Fatalf("ingest within the limit: %d %s", w.Code, w.Body.String())
	}
	refused := ingest(`{"title":"second"}`)
	wantJSONRefusal(t, "ingest over the limit", refused, http.StatusTooManyRequests, rateLimitedText)
	wantRetryAfter(t, "ingest over the limit", refused, 60)
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM notes"); got != "1" {
		t.Fatalf("the refused ingest wrote rows: %s in notes, want 1", got)
	}
}

// The app-wide limiter wraps pages and the API alike. Under /api/ a refusal
// is the JSON envelope; a page or a form post keeps the text answer a browser
// shows as is. Both carry Retry-After.
func TestGeneralRateLimitAnswersJSONUnderAPIAndTextElsewhere(t *testing.T) {
	served := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served++ })
	second := func(method, path, accept string) *httptest.ResponseRecorder {
		t.Helper()
		h := RateLimitMiddleware(NewRateLimiter(1, time.Minute), next)
		var rec *httptest.ResponseRecorder
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest(method, "https://app.example.com"+path, nil)
			req.RemoteAddr = "198.51.100.9:1111"
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if i == 0 && rec.Code != http.StatusOK {
				t.Fatalf("%s %s within the limit: %d", method, path, rec.Code)
			}
		}
		return rec
	}

	const browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	for _, c := range []struct{ method, path, accept string }{
		{"GET", "/api/notes", "application/json"},
		{"POST", "/api/notes", ""},
		{"GET", "/api/_auth/profile", browser}, // the path decides, as for an unmatched /api/ route
	} {
		rec := second(c.method, c.path, c.accept)
		name := c.method + " " + c.path
		wantJSONRefusal(t, name, rec, http.StatusTooManyRequests, rateLimitedText)
		wantRetryAfter(t, name, rec, 60)
	}
	for _, c := range []struct{ method, path, accept string }{
		{"GET", "/dashboard", browser},
		{"GET", "/", browser},
		{"POST", "/login", browser},
		{"GET", "/apiary", browser}, // not under /api/
		{"GET", "/dashboard", "application/json"},
	} {
		rec := second(c.method, c.path, c.accept)
		name := c.method + " " + c.path
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s over the limit: %d, want 429", name, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("%s: a page refusal answered as %q, want the text answer it had", name, ct)
		}
		if got := rec.Body.String(); got != rateLimitedText+"\n" {
			t.Errorf("%s: page refusal body %q, want %q", name, got, rateLimitedText+"\n")
		}
		wantRetryAfter(t, name, rec, 60)
	}
	if served != 8 {
		t.Fatalf("the handler ran %d times, want once per case (8): a refused request must not reach it", served)
	}
}

// The same through the chain a served app runs (wrapMiddleware), with the
// app's own RATE_LIMIT_PER_MIN.
func TestAppRateLimitThroughTheServedChain(t *testing.T) {
	app := newGateApp(t)
	SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "1")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ping", func(w http.ResponseWriter, r *http.Request) { httpJSON(w, http.StatusOK, map[string]any{"ok": true}) })
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<h1>Dashboard</h1>"))
	})
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		req.RemoteAddr = "198.51.100.9:1111"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	api := wrapMiddleware(mux, app, false)
	if rec := get(api, "/api/ping"); rec.Code != http.StatusOK {
		t.Fatalf("first API request: %d %s", rec.Code, rec.Body.String())
	}
	rec := get(api, "/api/ping")
	wantJSONRefusal(t, "second API request", rec, http.StatusTooManyRequests, rateLimitedText)
	wantRetryAfter(t, "second API request", rec, 60)

	page := wrapMiddleware(mux, app, false) // its own limiter
	if rec := get(page, "/dashboard"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Dashboard") {
		t.Fatalf("first page request: %d %s", rec.Code, rec.Body.String())
	}
	rec = get(page, "/dashboard")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Body.String() != rateLimitedText+"\n" {
		t.Fatalf("second page request: %d %q %q, want the 429 text answer", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	wantRetryAfter(t, "second page request", rec, 60)
}

// Admin-only routes answered a signed-in non-admin 403 as text
// ("admin required"), or as JSON text under text/plain (/api/_audit).
func TestAdminOnlyAPIRefusalsAreJSON(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	_, member := gateUser(t, app, "member@example.com")
	admin := adminGateUser(t, app, "admin@example.com")
	mux := http.NewServeMux()
	RegisterAnalyticsRoutes(mux, app)
	RegisterAuditAPI(mux, app)
	RegisterCustomFieldRoutes(mux, app)
	mustExec(t, app.DB, `INSERT INTO _benmore_funnels (id, name, steps) VALUES (5, 'kept', '["/","/b"]')`)

	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/_analytics/summary", ""},
		{"GET", "/api/_analytics/funnels", ""},
		{"POST", "/api/_analytics/funnel", `{"name":"signup","steps":["/","/signup"]}`},
		{"DELETE", "/api/_analytics/funnel?id=5", ""},
		{"GET", "/api/_audit", ""},
		{"GET", "/api/_schema/notes/fields", ""},
		{"POST", "/api/_schema/notes/fields", `{"name":"extra","type":"TEXT"}`},
		{"DELETE", "/api/_schema/notes/fields/extra", ""},
	} {
		wantJSONRefusal(t, c.method+" "+c.path+" as a member", bearerCall(mux, c.method, c.path, c.body, member), http.StatusForbidden, "admin required")
		// No credential is unauthenticated (401), as on every other route.
		wantJSONRefusal(t, c.method+" "+c.path+" as an anonymous caller", bearerCall(mux, c.method, c.path, c.body, ""), http.StatusUnauthorized, "authentication required")
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_funnels"); got != "1" {
		t.Fatalf("a refused funnel request changed the funnels: %s rows, want 1", got)
	}

	// An admin's malformed requests are refused in the same shape.
	wantJSONRefusal(t, "a funnel with one step", bearerCall(mux, "POST", "/api/_analytics/funnel", `{"name":"short","steps":["/"]}`, admin),
		http.StatusBadRequest, "name and at least 2 steps required")
	for _, c := range []struct {
		method, path, body string
		status             int
		text               string
	}{
		{"GET", "/api/_schema/_benmore_users/fields", "", http.StatusForbidden, "cannot modify framework tables"},
		{"GET", "/api/_schema/no_such_table/fields", "", http.StatusNotFound, "table not found"},
		{"POST", "/api/_schema/notes/fields", `not json`, http.StatusBadRequest, "invalid request body"},
		{"POST", "/api/_schema/notes/fields", `{"name":"1bad","type":"TEXT"}`, http.StatusBadRequest, "invalid column name (must match [a-zA-Z_][a-zA-Z0-9_]*)"},
		{"POST", "/api/_schema/notes/fields", `{"name":"user_id","type":"TEXT"}`, http.StatusBadRequest, "column name 'user_id' is reserved"},
		{"POST", "/api/_schema/notes/fields", `{"name":"extra","type":"BLOB"}`, http.StatusBadRequest, "invalid column type (allowed: TEXT, INTEGER, REAL, DATETIME)"},
		{"POST", "/api/_schema/notes/fields", `{"name":"title","type":"TEXT"}`, http.StatusConflict, "column 'title' already exists"},
		{"DELETE", "/api/_schema/notes/fields/title", "", http.StatusNotFound, "field is not a custom field or does not exist"},
	} {
		wantJSONRefusal(t, c.method+" "+c.path+" "+c.body, bearerCall(mux, c.method, c.path, c.body, admin), c.status, c.text)
	}
}

// /api/_docs, the OpenAPI routes and /api/_schema answered an anonymous
// caller 401, and POST /api/_devices a body without token and platform 400,
// as JSON text under text/plain.
func TestDocsSchemaAndDeviceRefusalsAreJSON(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	app.Design = &DesignConfig{Features: &FeaturesConfig{DocsVisibility: "auth"}}
	_, sid := gateUser(t, app, "member@example.com")
	mux := http.NewServeMux()
	RegisterAPIDocsRoutes(mux, app)
	RegisterDeviceRoutes(mux, app)

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/_docs"},
		{"GET", "/api/_openapi"},
		{"GET", "/api/openapi.json"},
		{"GET", "/openapi.json"},
		{"GET", "/api/_schema"},
		{"POST", "/api/_devices"},
		{"DELETE", "/api/_devices"},
	} {
		wantJSONRefusal(t, "anonymous "+c.method+" "+c.path, bearerCall(mux, c.method, c.path, "", ""), http.StatusUnauthorized, "authentication required")
	}
	for _, body := range []string{`{}`, `{"token":"abc"}`, `{"platform":"ios"}`, `not json`} {
		wantJSONRefusal(t, "POST /api/_devices "+body, bearerCall(mux, "POST", "/api/_devices", body, sid), http.StatusBadRequest, "token and platform required")
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_devices"); got != "0" {
		t.Fatalf("a refused registration stored a device: %s rows", got)
	}
	// A signed-in caller still gets the documents.
	for _, path := range []string{"/api/_docs", "/api/_openapi", "/api/_schema"} {
		if w := bearerCall(mux, "GET", path, "", sid); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("signed-in GET %s: %d %q", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
}

// POST /api/_auth/token is what a native client calls before it has `bm`: its
// refusals were JSON text under text/plain too.
func TestTokenAuthRefusalsAreJSON(t *testing.T) {
	app := newGateApp(t)
	EnsureLoginAttemptsTable(app.DB)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://app.example.com/api/_auth/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "198.51.100.9:1111"
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		return w
	}
	wantJSONRefusal(t, "a body that is not JSON", post(`not json`), http.StatusBadRequest, "invalid request")
	wantJSONRefusal(t, "no password", post(`{"email":"a@example.com"}`), http.StatusBadRequest, "email and password required")
	wantJSONRefusal(t, "an over-long password", post(`{"email":"a@example.com","password":"`+strings.Repeat("p", maxPasswordLength+1)+`"}`),
		http.StatusBadRequest, "password too long")
	wantJSONRefusal(t, "an unknown account", post(`{"email":"nobody@example.com","password":"wrong-password-1"}`),
		http.StatusUnauthorized, "invalid credentials")

	saved := tokenAuthIPLimiter
	tokenAuthIPLimiter = NewRateLimiter(1, time.Minute)
	t.Cleanup(func() { tokenAuthIPLimiter = saved })
	post(`{}`)
	wantJSONRefusal(t, "over the per-address limit", post(`{}`), http.StatusTooManyRequests, "rate limited")

	app.Design = &DesignConfig{Auth: map[string]string{"oauth_only": "true"}}
	wantJSONRefusal(t, "a social-sign-in-only app", post(`{"email":"a@example.com","password":"x"}`),
		http.StatusForbidden, "password auth is disabled - this app uses social sign-in only")
}

// The 31st lock request in a minute answered 429 as JSON text under
// text/plain.
func TestLockRateLimitAnswersJSON(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	uid, sid := gateUser(t, app, "writer@example.com")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (1, %d, 'mine')", uid))
	mux := http.NewServeMux()
	registerLockTables(mux, app, []string{"notes"})

	for i := 0; i < 30; i++ {
		if w := bearerCall(mux, "POST", "/api/notes/1/lock", "", sid); w.Code != http.StatusOK {
			t.Fatalf("lock request %d within the limit: %d %s", i+1, w.Code, w.Body.String())
		}
	}
	wantJSONRefusal(t, "the 31st lock request", bearerCall(mux, "POST", "/api/notes/1/lock", "", sid), http.StatusTooManyRequests, "rate limit exceeded")
}

// GET /api/<table>/<id> with an id that is not the row's canonical spelling
// (01 for row 1) answered Go's text "404 page not found", while update,
// delete, restore and the workflow routes answer that id in JSON. It answers
// what a missing row does, so the spelling tells a caller nothing either.
func TestReadWithANonCanonicalIDAnswersLikeAMissingRow(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	uid, sid := gateUser(t, app, "reader@example.com")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (1, %d, 'mine')", uid))
	read := func(id string) *httptest.ResponseRecorder {
		return gateCall(app, handleRead, "notes", "GET", "/api/notes/"+id, "application/json", "", sid)
	}
	if w := read("1"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"title":"mine"`) {
		t.Fatalf("the row by its own id: %d %s", w.Code, w.Body.String())
	}
	missing := read("999")
	wantJSONRefusal(t, "a missing row", missing, http.StatusNotFound, "Not found")
	for _, id := range []string{"01", "1.0", "1e0"} {
		w := read(id)
		wantJSONRefusal(t, "id "+id, w, http.StatusNotFound, "Not found")
		if w.Body.String() != missing.Body.String() {
			t.Errorf("id %s answers %q, a missing row %q: they must not differ", id, w.Body.String(), missing.Body.String())
		}
	}
}

// http.Error always answers text/plain, so a JSON body written through it is
// the bug above. No source file may hand it one.
func TestNoJSONBodyIsWrittenThroughHTTPError(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	jsonThroughText := regexp.MustCompile("http\\.Error\\(\\s*\\w+,\\s*(?:fmt\\.Sprintf\\(\\s*)?[`\"]\\s*\\{")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if jsonThroughText.MatchString(line) {
				t.Errorf("%s:%d writes a JSON body as text/plain; use httpError or httpJSON: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
