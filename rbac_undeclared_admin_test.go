//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A roles: block that does not declare `admin` used to leave the app's
// global admin (users.role = admin) with no scopes at all ("_none_:read"):
// the admin got 403 "scope denied" on every auto-CRUD table, admin-mode and
// self tables included, and on flows with permissions:, while the docs say
// admins bypass. The built-in admin role now holds every scope unless
// roles: declares admin; a credential's own scopes still narrow it.

const undeclaredAdminRoles = `roles:
  user:
    scopes: "shifts:write notes:write"
  manager:
    scopes: "shifts:write shifts:delete reports:read"
    inherits: user
`

const undeclaredAdminAccess = `access:
  shifts:
    read: "owner_or_role:manager"
    write: everyone
    update: "owner_or_role:manager"
    delete: "role:manager"
  audit_reports:
    read: "perm:reports.read"
    write: admin
    update: admin
    delete: admin
  notes: self
  pay_rates: everyone
`

func undeclaredAdminApp(t *testing.T, roles string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE shifts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE audit_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)`,
		`CREATE TABLE pay_rates (id INTEGER PRIMARY KEY AUTOINCREMENT, amount INTEGER)`,
	} {
		mustExec(t, db, stmt)
	}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	EnsureWebhooksTable(db)
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour}
	t.Cleanup(app.Shutdown)
	names, err := GetTableNames(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	appYAML := roles + undeclaredAdminAccess
	app.Roles = parseRolesConfig([]byte(appYAML))
	if app.Roles == nil {
		t.Fatal("roles fixture did not parse")
	}
	bindRoleTableScopes(app.Roles, app.Tables)
	app.Access = accessFromYAML(t, appYAML)
	writeTestFile(t, dir, "flows/report-feed.yaml", `on:
  request:
    method: GET
    path: /api/report-feed
    permissions: [reports:read]
jobs:
  read:
    steps:
      - run: respond
        with: {status: 200, body: {ok: true}}
`)
	flows, err := loadFlowsChecked(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	app.Flows = flows
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterFlows(mux, app, flows)
	return app, mux
}

func undeclaredAdminCall(t *testing.T, mux *http.ServeMux, method, path, bearer, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func undeclaredAdminSession(t *testing.T, app *App, bearer string) *Session {
	t.Helper()
	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	s := getSession(app, r)
	if s == nil {
		t.Fatal("session did not resolve")
	}
	return s
}

func TestUndeclaredAdminRoleHoldsEveryScope(t *testing.T) {
	app, mux := undeclaredAdminApp(t, undeclaredAdminRoles)
	boss := authzUser(t, app, "boss@example.com", "admin")
	staff := authzUser(t, app, "staff@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf(`INSERT INTO shifts (id, user_id, title) VALUES (1, %d, 'staff shift'), (2, %d, 'staff shift 2')`, staff, staff))
	mustExec(t, app.DB, fmt.Sprintf(`INSERT INTO notes (id, user_id, body) VALUES (1, %d, 'staff note')`, staff))
	bossSID := authzSession(t, app, boss, "boss@example.com")

	s := undeclaredAdminSession(t, app, bossSID)
	if s.Scopes != "*" || len(s.Permissions) != 1 || s.Permissions[0] != "*" {
		t.Fatalf("global admin scopes = %q permissions = %v, want every scope", s.Scopes, s.Permissions)
	}

	// Reads: an owner_or_role table and a self table, both through the admin
	// bypass (another user's rows), on the cookie and on a Bearer session.
	for _, c := range []struct{ name, bearer, cookie string }{{"bearer", bossSID, ""}, {"cookie", "", bossSID}} {
		if w := undeclaredAdminCall(t, mux, "GET", "/api/shifts", c.bearer, c.cookie, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "staff shift 2") {
			t.Fatalf("%s GET /api/shifts: %d %s", c.name, w.Code, w.Body.String())
		}
		if w := undeclaredAdminCall(t, mux, "GET", "/api/notes", c.bearer, c.cookie, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "staff note") {
			t.Fatalf("%s GET /api/notes (self, admins bypass): %d %s", c.name, w.Code, w.Body.String())
		}
	}
	// An admin-mode create lands.
	if w := undeclaredAdminCall(t, mux, "POST", "/api/audit_reports", bossSID, "", `{"title":"q3"}`); w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("POST /api/audit_reports (write: admin): %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM audit_reports WHERE title = 'q3'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("admin create left %d rows: %v", n, err)
	}
	// A role: delete of another user's row (admins bypass role: and rows).
	if w := undeclaredAdminCall(t, mux, "DELETE", "/api/shifts/2", bossSID, "", ""); w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("DELETE /api/shifts/2: %d %s", w.Code, w.Body.String())
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM shifts WHERE id = 2").Scan(&n); err != nil || n != 0 {
		t.Fatalf("admin delete left the row: %d %v", n, err)
	}
	// A perm: read and a flow's permissions: gate.
	if w := undeclaredAdminCall(t, mux, "GET", "/api/audit_reports", bossSID, "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "q3") {
		t.Fatalf("GET /api/audit_reports (perm:reports.read): %d %s", w.Code, w.Body.String())
	}
	if w := undeclaredAdminCall(t, mux, "GET", "/api/report-feed", bossSID, "", ""); w.Code != http.StatusOK {
		t.Fatalf("flow with permissions: [reports:read]: %d %s", w.Code, w.Body.String())
	}

	// A credential's own scopes still narrow the admin: a token and a scoped
	// Bearer session minted for shifts:read reach shifts and nothing else.
	token := auditToken(t, app, bossSID, "shifts:read")
	scopedSID := authzSession(t, app, boss, "boss@example.com", "shifts:read")
	for _, c := range []struct{ name, cred string }{{"API token", token}, {"scoped session", scopedSID}} {
		if s := undeclaredAdminSession(t, app, c.cred); s.Scopes != "shifts:read" {
			t.Fatalf("%s scopes widened to %q", c.name, s.Scopes)
		}
		if w := undeclaredAdminCall(t, mux, "GET", "/api/shifts", c.cred, "", ""); w.Code != http.StatusOK {
			t.Fatalf("%s GET /api/shifts: %d %s", c.name, w.Code, w.Body.String())
		}
		w := undeclaredAdminCall(t, mux, "POST", "/api/audit_reports", c.cred, "", `{"title":"via token"}`)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "scope denied: token does not have audit_reports:write permission") {
			t.Fatalf("%s POST /api/audit_reports: %d %s, want the token's scope refusal", c.name, w.Code, w.Body.String())
		}
		if w := undeclaredAdminCall(t, mux, "GET", "/api/report-feed", c.cred, "", ""); w.Code != http.StatusForbidden {
			t.Fatalf("%s flow with permissions: [reports:read]: %d, want 403", c.name, w.Code)
		}
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM audit_reports WHERE title = 'via token'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a narrowed token wrote %d rows: %v", n, err)
	}

	// Ordinary accounts are unchanged: staff hold exactly user's scopes, and
	// a cookie session refused by its roles is called a session.
	staffSID := authzSession(t, app, staff, "staff@example.com")
	if s := undeclaredAdminSession(t, app, staffSID); s.Scopes != "notes:write shifts:write" {
		t.Fatalf("staff scopes = %q", s.Scopes)
	}
	w := undeclaredAdminCall(t, mux, "GET", "/api/pay_rates", "", staffSID, "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "scope denied: session does not have pay_rates:read permission") || strings.Contains(w.Body.String(), "token") {
		t.Fatalf("staff cookie GET /api/pay_rates: %d %s, want a session scope refusal", w.Code, w.Body.String())
	}
	staffToken := auditToken(t, app, staffSID, "shifts:read")
	w = undeclaredAdminCall(t, mux, "GET", "/api/notes", staffToken, "", "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "scope denied: token does not have notes:read permission") {
		t.Fatalf("staff token GET /api/notes: %d %s, want the token's scope refusal", w.Code, w.Body.String())
	}
	if w := undeclaredAdminCall(t, mux, "GET", "/api/report-feed", staffSID, "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("staff flow with permissions: [reports:read]: %d, want 403", w.Code)
	}
}

// Declaring admin under roles: sets its scopes explicitly, as before.
func TestDeclaredAdminRoleKeepsItsScopes(t *testing.T) {
	app, mux := undeclaredAdminApp(t, undeclaredAdminRoles+"  admin:\n    scopes: \"shifts:read\"\n")
	boss := authzUser(t, app, "boss@example.com", "admin")
	bossSID := authzSession(t, app, boss, "boss@example.com")
	if s := undeclaredAdminSession(t, app, bossSID); s.Scopes != "shifts:read" {
		t.Fatalf("declared admin scopes = %q, want shifts:read", s.Scopes)
	}
	if w := undeclaredAdminCall(t, mux, "POST", "/api/audit_reports", bossSID, "", `{"title":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("declared admin without audit_reports scope: %d %s", w.Code, w.Body.String())
	}
}

// Only a global admin gains it: a tenant membership role or group-scoped
// grant named admin, and a delegated connector identity, keep what roles:
// grants.
func TestUndeclaredAdminScopesOnlyForGlobalAdmin(t *testing.T) {
	rc := parseRolesConfig([]byte(undeclaredAdminRoles))
	tenantAdmin := &Session{Role: "user", Roles: []string{"user", "admin"}}
	if got := rc.sessionRoleScopes(tenantAdmin, tenantAdmin.Roles); got != "notes:write shifts:write" {
		t.Fatalf("tenant admin role scopes = %q", got)
	}
	connector := &Session{Role: "admin", GlobalAdmin: true, Roles: []string{"admin"}, connectorGrant: true}
	if got := rc.sessionRoleScopes(connector, connector.Roles); got != "" {
		t.Fatalf("connector grant of an admin gained %q", got)
	}
	global := &Session{Role: "user", GlobalAdmin: true, Roles: []string{"user", "admin"}}
	if got := rc.sessionRoleScopes(global, global.Roles); got != "*" {
		t.Fatalf("global admin grant scopes = %q, want *", got)
	}
}
