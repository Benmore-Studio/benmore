//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// POST /_admin/set-role rewrites a user's primary role. It had neither the
// last-admin guard the role-grant API applies (an admin could demote
// themselves out of the app's only admin seat) nor an audit record, so a role
// change made through the admin panel left no trail.
func TestAdminSetRoleGuardsLastAdminAndAudits(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAuditLogTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)

	mustExec(t, db, "INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'boss', 'boss@example.com', 'admin'), (2, 'member', 'member@example.com', 'user')")
	sid := CreateSession(db, 1, "boss@example.com", "", time.Hour)
	setRole := func(uid, role string) int {
		form := url.Values{"user_id": {uid}, "role": {role}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/_admin/set-role", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	role := func(id int) string {
		var r string
		db.QueryRow("SELECT role FROM _benmore_users WHERE id = ?", id).Scan(&r)
		return r
	}

	if code := setRole("1", "user"); code != http.StatusBadRequest || role(1) != "admin" {
		t.Fatalf("the only admin demoted themselves: %d, role now %q", code, role(1))
	}
	if code := setRole("2", "admin"); code != http.StatusSeeOther || role(2) != "admin" {
		t.Fatalf("promotion: %d, role %q", code, role(2))
	}
	var audited int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'role_changed' AND table_name = '_benmore_users' AND row_id = '2' AND user_id = 1").Scan(&audited)
	if audited != 1 {
		t.Fatal("the role change was not audited")
	}
	// With another admin in place, stepping down is allowed.
	if code := setRole("1", "user"); code != http.StatusSeeOther || role(1) != "user" {
		t.Fatalf("stepping down beside another admin: %d, role %q", code, role(1))
	}
}

// POST /_admin/set-role wrote any role string to the primary role column,
// while the grant API refuses a role app.yaml roles: does not declare. A typo
// (bogusrole) or a tenant role name (owner, the founding_role of a groups:
// app) became a GLOBAL role, and a global owner passes every role:owner gate
// on tables without the tenant key. Both doors now share one rule: user,
// admin, or a declared role. The user page's role form says the role is
// global.
func TestAdminSetRoleRefusesUndeclaredRoles(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAuditLogTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "*"}}}
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "orgs", FoundingRole: "owner"}}
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)
	RegisterRoleRoutes(mux, app)

	mustExec(t, db, "INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'boss', 'boss@example.com', 'admin'), (2, 'member', 'member@example.com', 'user')")
	sid := CreateSession(db, 1, "boss@example.com", "", time.Hour)
	setRole := func(role string) *httptest.ResponseRecorder {
		form := url.Values{"user_id": {"2"}, "role": {role}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/_admin/set-role", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	grant := func(role string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/users/2/roles", strings.NewReader(`{"role":"`+role+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	role := func() string {
		var r string
		db.QueryRow("SELECT role FROM _benmore_users WHERE id = 2").Scan(&r)
		return r
	}

	for _, undeclared := range []string{"bogusrole", "owner"} {
		w := setRole(undeclared)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not defined in app.yaml under roles:") || role() != "user" {
			t.Fatalf("set-role %q: %d %s, role now %q", undeclared, w.Code, w.Body.String(), role())
		}
		if w := grant(undeclared); w.Code != http.StatusBadRequest {
			t.Fatalf("grant API %q: %d %s", undeclared, w.Code, w.Body.String())
		}
	}
	var audited int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'role_changed'").Scan(&audited)
	if audited != 0 {
		t.Fatalf("refused role changes were audited as made: %d", audited)
	}
	// admin last: taking it away again is another admin's demotion, refused
	// (TestNoAdminDemotesAnotherAdmin).
	for _, declared := range []string{"editor", "user", "admin"} {
		if w := setRole(declared); w.Code != http.StatusSeeOther || role() != declared {
			t.Fatalf("set-role %q: %d %s, role now %q", declared, w.Code, w.Body.String(), role())
		}
	}

	// The user page offers user, admin and the declared roles in a form that
	// posts to /_admin/set-role and says the role is global.
	r := httptest.NewRequest(http.MethodGet, "/_admin/_benmore_users/2", nil)
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	page := w.Body.String()
	for _, want := range []string{`action="/_admin/set-role"`, `name="user_id" value="2"`, `<option value="editor"`, "Global role", "every tenant"} {
		if !strings.Contains(page, want) {
			t.Fatalf("user page lacks %q (status %d)", want, w.Code)
		}
	}
	if strings.Contains(page, `<option value="owner"`) {
		t.Fatal("user page offers the tenant role owner as a global role")
	}
}
