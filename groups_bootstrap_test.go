//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newBootstrapTestApp(t *testing.T, userField string) (*App, int64, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	mustExec(t, app.DB, "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, user_id INTEGER)")
	mustExec(t, app.DB, "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, user_id INTEGER, member_role TEXT)")
	app.Group = &GroupConfig{
		Table: "company_members", Key: "company_id", UserField: userField, RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "company_admin"},
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('founder', 'founder@example.com', 'user', 1)")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	return app, uid, cleanup
}

func bootstrapAs(app *App, sid, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://app.example.com/api/_groups/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	handleGroupBootstrap(w, r, app)
	return w
}

func countRows(t *testing.T, app *App, table string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// A scoped credential must hold write scope on the org and membership
// tables, exactly as an auto-CRUD create would require.
func TestGroupBootstrapRequiresWriteScope(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "email")
	defer cleanup()

	readOnly := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour, "*:read")
	if w := bootstrapAs(app, readOnly, `{"name":"Acme"}`); w.Code != http.StatusForbidden {
		t.Fatalf("read-only token must be refused, got %d: %s", w.Code, w.Body.String())
	}
	orgOnly := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour, "companies:write")
	if w := bootstrapAs(app, orgOnly, `{"name":"Acme"}`); w.Code != http.StatusForbidden {
		t.Fatalf("token without membership write scope must be refused, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "companies"); n != 0 {
		t.Fatalf("refused bootstraps created %d orgs", n)
	}

	full := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	if w := bootstrapAs(app, full, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("full session bootstrap: %d %s", w.Code, w.Body.String())
	}
	var role string
	if err := app.DB.QueryRow("SELECT member_role FROM company_members WHERE email = 'founder@example.com'").Scan(&role); err != nil || role != "company_admin" {
		t.Fatalf("founding membership = %q, %v", role, err)
	}
}

// Before-hooks on the org table gate bootstrap like any other insert.
func TestGroupBootstrapRunsBeforeHooks(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "email")
	defer cleanup()
	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{
		"companies": {{SQL: "SELECT 'org names are reviewed' AS error WHERE {{name}} = 'Blocked'"}},
	}}

	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	if w := bootstrapAs(app, sid, `{"name":"Blocked"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("aborting before-hook must refuse bootstrap, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "companies") + countRows(t, app, "company_members"); n != 0 {
		t.Fatalf("aborted bootstrap left %d rows", n)
	}
	if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("passing before-hook: %d %s", w.Code, w.Body.String())
	}
}

// A session that never learns its group (API tokens are not updated in
// place) must not found a second tenant: the transaction re-checks.
func TestGroupBootstrapRefusesSecondTenant(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "user_id")
	defer cleanup()

	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("first bootstrap: %d %s", w.Code, w.Body.String())
	}
	mustExec(t, app.DB, "UPDATE _benmore_sessions SET group_id = NULL")
	if w := bootstrapAs(app, sid, `{"name":"Second"}`); w.Code != http.StatusConflict {
		t.Fatalf("second bootstrap must be 409, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "companies"); n != 1 {
		t.Fatalf("expected exactly one org, got %d", n)
	}
}
