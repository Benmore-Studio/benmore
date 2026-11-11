//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A create that names another user (or tenant) is written under the caller;
// the response now says so in X-Stripped-Fields. Sending your own id stays
// silent, and the rows land under the caller either way.
func TestCreateReportsReplacedOwnerAndTenant(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
	stripped := func(table string, body map[string]any) string {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/"+table, alice, body)
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("POST %s %v = %d %s", table, body, rec.Code, rec.Body.String())
		}
		return rec.Header().Get("X-Stripped-Fields")
	}
	var aliceID string
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'alice@example.com'").Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	if got := stripped("notes", map[string]any{"title": "x", "user_id": 999}); !strings.Contains(got, "user_id") {
		t.Fatalf("another user's id: X-Stripped-Fields = %q", got)
	}
	if got := stripped("notes", map[string]any{"title": "x", "user_id": aliceID}); got != "" {
		t.Fatalf("own id: X-Stripped-Fields = %q", got)
	}
	if got := stripped("records", map[string]any{"title": "x", "org_id": "org-b"}); !strings.Contains(got, "org_id") {
		t.Fatalf("another tenant: X-Stripped-Fields = %q", got)
	}
	if got := stripped("records", map[string]any{"title": "x", "org_id": "org-a"}); got != "" {
		t.Fatalf("own tenant: X-Stripped-Fields = %q", got)
	}
	var foreign int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM records WHERE org_id = 'org-b' AND title = 'x'").Scan(&foreign); err != nil || foreign != 0 {
		t.Fatalf("a row landed in the other tenant (%d, %v)", foreign, err)
	}
}
