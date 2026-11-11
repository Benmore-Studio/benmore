//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role grants and impersonation are admin-console actions (security rule
// 15b): they key off the CREDENTIAL being unscoped, not the role-derived
// session scopes. An app whose roles: block does not define admin gave a
// users.role='admin' account session scopes of _none_:read, and the gate
// used to read that as a scoped credential, so the app's own global admin
// on a plain login session got 403 "admin with a full-access session
// required" for every grant, revoke and impersonation. (That admin now holds
// every role scope; scoped credentials must still be refused here.)
func TestRoleGrantsAndImpersonationUseAdminConsoleGate(t *testing.T) {
	app := authzApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	authzTable(t, app, "tracker", `CREATE TABLE tracker (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)`)
	app.Roles = parseRolesConfig([]byte("roles:\n  member:\n    scopes: \"tracker:use\"\ntable_scopes: access\n"))
	if app.Roles == nil {
		t.Fatal("roles fixture did not parse")
	}
	bindRoleTableScopes(app.Roles, app.Tables)
	mux := http.NewServeMux()
	RegisterRoleRoutes(mux, app)
	RegisterAuthRoutes(mux, app)

	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('admin', 'admin@example.com', ?, 'admin', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := res.LastInsertId()
	res, err = app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('member', 'member@example.com', ?, 'user', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := res.LastInsertId()
	target := authzUser(t, app, "target@example.com", "user")

	full := authzSession(t, app, admin, "admin@example.com")
	// The bug's precondition was role-derived scopes narrowed to nothing on
	// an unscoped credential. Since the built-in admin role holds every scope
	// when roles: does not declare it (sessionRoleScopes), the admin's role
	// scopes are "*"; the gate below must still key off the credential.
	probe := httptest.NewRequest("GET", "https://app.example.com/", nil)
	probe.Header.Set("Authorization", "Bearer "+full)
	if s := getSession(app, probe); s == nil || s.Scopes != "*" || s.CredentialScopes != "" {
		t.Fatalf("fixture: want role scopes * on an unscoped credential, got %+v", s)
	}
	scopedSession := authzSession(t, app, admin, "admin@example.com", "tracker:use")
	scopedToken := auditToken(t, app, full, "tracker:use")
	starToken := auditToken(t, app, full, "*")
	nonAdmin := authzSession(t, app, member, "member@example.com")

	grant := func(cred string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq("POST", fmt.Sprintf("/api/_auth/users/%d/roles", target), cred, `{"role":"member"}`))
		return w
	}
	extend := func(cred string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"expires_at":%q}`, time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq("PATCH", fmt.Sprintf("/api/_auth/users/%d/roles/member", target), cred, body))
		return w
	}
	revoke := func(cred string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq("DELETE", fmt.Sprintf("/api/_auth/users/%d/roles/member", target), cred, ""))
		return w
	}
	impersonate := func(cred string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"user_id": target, "password": fixturePassword})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq("POST", "/api/_auth/impersonate", cred, string(body)))
		return w
	}
	grants := func() int {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ? AND role = 'member'", target).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Delegated or non-admin credentials are refused before any effect.
	type caller struct{ name, cred string }
	for _, c := range []caller{
		{"scoped admin session", scopedSession},
		{"scoped admin token", scopedToken},
		{"non-admin session", nonAdmin},
	} {
		for _, op := range []struct {
			name string
			call func(string) *httptest.ResponseRecorder
		}{{"grant", grant}, {"extend", extend}, {"revoke", revoke}, {"impersonate", impersonate}} {
			if w := op.call(c.cred); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
				t.Errorf("%s %s: %d %s, want 403", c.name, op.name, w.Code, w.Body.String())
			}
		}
	}
	if n := grants(); n != 0 {
		t.Fatalf("refused callers left %d grants", n)
	}

	// The global admin on an unscoped session (and on an explicit "*" token)
	// can grant, extend, revoke and impersonate.
	for _, c := range []caller{{"admin session", full}, {"admin * token", starToken}} {
		name, cred := c.name, c.cred
		if w := grant(cred); w.Code != http.StatusOK {
			t.Fatalf("%s grant: %d %s", name, w.Code, w.Body.String())
		}
		if n := grants(); n != 1 {
			t.Fatalf("%s grant: %d grants, want 1", name, n)
		}
		if w := extend(cred); w.Code != http.StatusOK {
			t.Fatalf("%s extend: %d %s", name, w.Code, w.Body.String())
		}
		if w := revoke(cred); w.Code != http.StatusOK {
			t.Fatalf("%s revoke: %d %s", name, w.Code, w.Body.String())
		}
		if n := grants(); n != 0 {
			t.Fatalf("%s revoke: %d grants left", name, n)
		}
		if w := impersonate(cred); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
			t.Fatalf("%s impersonate: %d %s", name, w.Code, w.Body.String())
		}
	}
}
