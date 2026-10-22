//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func newTypesAccessApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour,
		Tables: []Table{{Name: "payroll_runs", Columns: []Column{{Name: "id", PK: true}, {Name: "salary_cents", Type: "INTEGER"}}}},
		Flows: []Flow{
			{Name: "public_ping", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/ping"}},
			{Name: "my_report", Auth: "required", Trigger: FlowTrigger{Type: "http", Path: "/api/my-report"}},
			{Name: "close_books", Role: "manager", Trigger: FlowTrigger{Type: "http", Path: "/api/admin/close-books"}},
			{Name: "stripe_hook", Verify: "stripe", Trigger: FlowTrigger{Type: "http", Path: "/api/hooks/stripe"}},
		},
	}
	mux := http.NewServeMux()
	RegisterBMTypesRoute(mux, app)
	return app, mux
}

func typesGet(mux *http.ServeMux, path, bearer, typesToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if typesToken != "" {
		req.Header.Set(typesTokenHeader, typesToken)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The generated .d.ts is the whole schema (every table, column and flow
// path). It was public even when /api/_docs was hidden.
func TestInternalTypesRequireAdminOrTypesToken(t *testing.T) {
	app, mux := newTypesAccessApp(t)
	user := createCrudScopeSession(t, app, "user@example.com", "user", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	exp := time.Now().Add(time.Minute)

	for _, path := range []string{"/_internal/types.d.ts", "/_internal/bm.d.ts"} {
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"anonymous":        typesGet(mux, path, "", ""),
			"ordinary user":    typesGet(mux, path, user, ""),
			"foreign audience": typesGet(mux, path, "", mintTypesTokenWithSecret(app.Dir+"-other", exp, serverSecret)),
			"wrong secret":     typesGet(mux, path, "", mintTypesTokenWithSecret(app.Dir, exp, "not-the-app-secret")),
			"expired":          typesGet(mux, path, "", mintTypesTokenWithSecret(app.Dir, time.Now().Add(-time.Second), serverSecret)),
			"import token":     typesGet(mux, path, "", mintImportOwnerToken(app, exp, "owner@example.com")),
		} {
			if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "salary_cents") {
				t.Fatalf("%s GET %s = %d, want 403 without the schema: %.200s", name, path, rec.Code, rec.Body.String())
			}
		}
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"admin session": typesGet(mux, path, admin, ""),
			"types token":   typesGet(mux, path, "", mintTypesTokenWithSecret(app.Dir, exp, serverSecret)),
		} {
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "salary_cents") {
				t.Fatalf("%s GET %s = %d, want the generated types", name, path, rec.Code)
			}
		}
	}
}

// flows.json stays reachable for the bm SDK but lists only what the caller
// may call.
func TestInternalFlowsRegistryListsCallableFlowsOnly(t *testing.T) {
	app, mux := newTypesAccessApp(t)
	user := createCrudScopeSession(t, app, "user@example.com", "user", "", "")
	manager := createCrudScopeSession(t, app, "manager@example.com", "manager", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")

	names := func(bearer string) string {
		t.Helper()
		rec := typesGet(mux, "/_internal/flows.json", bearer, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("flows.json status %d", rec.Code)
		}
		var reg map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
			t.Fatal(err)
		}
		var out []string
		for k := range reg {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	for who, want := range map[string]string{
		"":      "publicPing",
		user:    "myReport,publicPing",
		manager: "closeBooks,myReport,publicPing",
		admin:   "closeBooks,myReport,publicPing,stripeHook",
	} {
		if got := names(who); got != want {
			t.Fatalf("flows.json for %q = %s, want %s", who, got, want)
		}
	}
}
