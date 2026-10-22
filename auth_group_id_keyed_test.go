//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func idKeyedGroupFixture(t *testing.T) *App {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	EnsureMFAColumns(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	// groups.user_field names members by user id, the shape
	// POST /api/_groups/create writes for a non-email column.
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id", RoleField: "member_role"}
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER, member_role TEXT)")
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'a', 'a@corp.example', ?, 'user', 1), (2, 'b', 'b@corp.example', ?, 'user', 1), (3, 'c', 'c@corp.example', ?, 'user', 1)", string(hash), string(hash), string(hash))
	mustExec(t, app.DB, "INSERT INTO members (org_id, user_id, member_role) VALUES ('tenant-a', 1, 'manager'), ('tenant-b', 2, 'viewer')")
	return app
}

// ResolveGroupID compared groups.user_field with the account's EMAIL whatever
// the column held, so a membership table keyed by user id never matched: the
// tenant was not resolved at sign-in or on later requests, and the tenant
// role (groups.role_field) was looked up the same way and never loaded.
func TestIDKeyedMembershipResolvesTenantAndRole(t *testing.T) {
	app := idKeyedGroupFixture(t)

	if got := ResolveGroupID(app.DB, app.Group, "a@corp.example"); got != "tenant-a" {
		t.Fatalf("ResolveGroupID for a member keyed by user id = %q, want tenant-a", got)
	}
	if got := ResolveGroupID(app.DB, app.Group, "b@corp.example"); got != "tenant-b" {
		t.Fatalf("ResolveGroupID = %q, want tenant-b", got)
	}
	for _, none := range []string{"c@corp.example", "nobody@corp.example", "", "1", "2"} {
		if got := ResolveGroupID(app.DB, app.Group, none); got != "" {
			t.Fatalf("ResolveGroupID(%q) = %q, want no tenant", none, got)
		}
	}

	// Through the sign-in form.
	form := url.Values{"email": {"a@corp.example"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	token := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatalf("sign-in failed: %d %q", w.Code, w.Header().Get("Location"))
	}
	var rowGroup string
	app.DB.QueryRow("SELECT COALESCE(group_id, '') FROM _benmore_sessions WHERE user_id = 1").Scan(&rowGroup)
	if rowGroup != "tenant-a" {
		t.Fatalf("session tenant at sign-in = %q, want tenant-a", rowGroup)
	}
	resolve := func(tok string) *Session {
		req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		return getSession(app, req)
	}
	s := resolve(token)
	if s == nil || s.GroupID != "tenant-a" {
		t.Fatalf("request session = %+v, want tenant-a", s)
	}
	if !HasAnyRole(s, []string{"manager"}) {
		t.Fatalf("the tenant role from groups.role_field was not loaded: roles = %v", s.Roles)
	}

	// A membership added to another tenant doesn't move the session; removing
	// the one it holds does, on the next request.
	mustExec(t, app.DB, "DELETE FROM members WHERE user_id = 1")
	if s := resolve(token); s == nil || s.GroupID != "" || HasAnyRole(s, []string{"manager"}) {
		t.Fatalf("a removed id-keyed member kept the tenant or its role: %+v", s)
	}

	// A session that started with no tenant picks one up on a later request
	// (a membership added after sign-in), by its own user id only.
	late := CreateSession(app.DB, 3, "c@corp.example", "", time.Hour)
	if s := resolve(late); s == nil || s.GroupID != "" {
		t.Fatalf("a non-member got a tenant: %+v", s)
	}
	mustExec(t, app.DB, "INSERT INTO members (org_id, user_id, member_role) VALUES ('tenant-b', 3, 'viewer')")
	if s := resolve(late); s == nil || s.GroupID != "tenant-b" || !HasAnyRole(s, []string{"viewer"}) || HasAnyRole(s, []string{"manager"}) {
		t.Fatalf("lazy resolution for an id-keyed member: %+v", s)
	}
}

// A user_field that is not named for email but holds addresses has always
// resolved by comparing it with the account's email. Matching ids first must
// not take that away.
func TestMembershipColumnHoldingAddressesStillResolves(t *testing.T) {
	app := idKeyedGroupFixture(t)
	app.Group = &GroupConfig{Table: "crew", Key: "org_id", UserField: "login", RoleField: "crew_role"}
	mustExec(t, app.DB, "CREATE TABLE crew (id INTEGER PRIMARY KEY, org_id TEXT, login TEXT, crew_role TEXT)")
	mustExec(t, app.DB, "INSERT INTO crew (org_id, login, crew_role) VALUES ('tenant-a', 'a@corp.example', 'lead')")
	if got := ResolveGroupID(app.DB, app.Group, "a@corp.example"); got != "tenant-a" {
		t.Fatalf("ResolveGroupID for a login column holding the address = %q, want tenant-a", got)
	}
	token := CreateSession(app.DB, 1, "a@corp.example", "", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	s := getSession(app, req)
	if s == nil || s.GroupID != "tenant-a" || !HasAnyRole(s, []string{"lead"}) {
		t.Fatalf("session for a login column holding the address: %+v", s)
	}
}

// A membership row that names an address is an invitation to that address.
// For a column called *email* it has resolved only for an account that
// proved the address since 2.7.237; a column holding addresses under another
// name skipped the rule, so anyone could sign up as an invited address and
// land in its tenant, with its tenant role.
func TestAddressMembershipUnderAnotherColumnNameNeedsProof(t *testing.T) {
	app := idKeyedGroupFixture(t)
	app.Group = &GroupConfig{Table: "crew", Key: "org_id", UserField: "login", RoleField: "crew_role"}
	mustExec(t, app.DB, "CREATE TABLE crew (id INTEGER PRIMARY KEY, org_id TEXT, login TEXT, crew_role TEXT)")
	// An invitation waiting for someone who has no account yet.
	mustExec(t, app.DB, "INSERT INTO crew (org_id, login, crew_role) VALUES ('tenant-a', 'invited@corp.example', 'lead')")
	// Someone else registers the address without proving it.
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, email_grandfathered) VALUES (9, 'squatter', 'invited@corp.example', 'x', 'user', 0, 0)")

	resolve := func() *Session {
		token := CreateSession(app.DB, 9, "invited@corp.example", ResolveGroupID(app.DB, app.Group, "invited@corp.example"), time.Hour)
		req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return getSession(app, req)
	}
	if got := ResolveGroupID(app.DB, app.Group, "invited@corp.example"); got != "" {
		t.Fatalf("an unproven address resolved tenant %q at sign-in", got)
	}
	if s := resolve(); s == nil || s.GroupID != "" || HasAnyRole(s, []string{"lead"}) {
		t.Fatalf("an account that never proved the invited address got its tenant or role: %+v", s)
	}

	// Once the address is proven (or for an account that predates the rule)
	// the membership applies.
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 1 WHERE id = 9")
	if s := resolve(); s == nil || s.GroupID != "tenant-a" || !HasAnyRole(s, []string{"lead"}) {
		t.Fatalf("a verified account did not get its membership: %+v", s)
	}
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 0, email_grandfathered = 1 WHERE id = 9")
	if s := resolve(); s == nil || s.GroupID != "tenant-a" {
		t.Fatalf("a grandfathered account lost its membership: %+v", s)
	}
}
