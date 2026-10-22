//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// owner_or_role on an un-grouped table or the tenant root: a role held only
// inside a tenant never widens past the caller's own rows (round 12,
// globalRoleTier); a global holder sees every row.
func TestTenantRoleOwnerOrRoleOnUngroupedTables(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  brokers: owner_or_role:clinic_staff\n  companies: owner_or_role:clinic_staff\n")
	member, _ := tenantMember(t, app, "member@example.com", "user", 2, "clinic_staff")
	granted, grantedID := tenantMember(t, app, "granted@example.com", "user", 2, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (%d, 'clinic_staff', '2')", grantedID))
	for name, sid := range map[string]string{"membership role": member, "tenant-scoped grant": granted} {
		t.Run(name, func(t *testing.T) {
			for _, table := range []string{"brokers", "companies"} {
				assertListIDs(t, mux, sid, "/api/"+table, []float64{})
				assertStatus(t, mux, http.MethodGet, "/api/"+table+"/1", sid, nil, http.StatusNotFound)
				assertStatus(t, mux, http.MethodPatch, "/api/"+table+"/1", sid, map[string]any{"name": "overwritten"}, http.StatusNotFound)
				assertStatus(t, mux, http.MethodDelete, "/api/"+table+"/2", sid, nil, http.StatusNotFound)
			}
		})
	}
	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'clinic_staff')", globalID))
	assertListIDs(t, mux, global, "/api/brokers", []float64{2, 1})
	assertListIDs(t, mux, global, "/api/companies", []float64{2, 1})
}

// An owner_or_role create on a table with no user_id column has no owner tier
// to create into, so it takes a listed role, judged like role:. Every signed-in
// user, role or not, used to pass: on an un-grouped table or the tenant root
// that let any member of any tenant plant rows every role-holder reads. A
// table with user_id keeps the owner tier (anyone creates rows they own).
func TestOwnerOrRoleCreateWithoutOwnerColumnNeedsRole(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  brokers: owner_or_role:clinic_staff\n  companies: owner_or_role:clinic_staff\n  projects: owner_or_role:clinic_staff\n  notes: owner_or_role:clinic_staff\n")
	crudScopeMustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)`)
	cols, err := GetTableColumns(app.DB, "notes")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "notes", Columns: cols})
	mux = buildAppMux(app, true, "http://localhost")

	plain, _ := tenantMember(t, app, "plain@example.com", "user", 2, "viewer")
	member, _ := tenantMember(t, app, "member@example.com", "user", 2, "clinic_staff")
	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'clinic_staff')", globalID))

	for _, table := range []string{"brokers", "companies", "projects"} {
		assertStatus(t, mux, http.MethodPost, "/api/"+table, plain, map[string]any{"name": "planted"}, http.StatusNotFound)
		assertStatus(t, mux, http.MethodPost, "/api/"+table+"/batch", plain, []map[string]any{{"name": "planted"}}, http.StatusNotFound)
	}
	// A tenant role creates only where the row is bounded by its tenant.
	assertStatus(t, mux, http.MethodPost, "/api/brokers", member, map[string]any{"name": "planted"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPost, "/api/companies", member, map[string]any{"name": "planted"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPost, "/api/projects", member, map[string]any{"name": "member-p"}, http.StatusOK)
	var n int
	if err := app.DB.QueryRow("SELECT (SELECT COUNT(*) FROM brokers WHERE name = 'planted') + (SELECT COUNT(*) FROM companies WHERE name = 'planted') + (SELECT COUNT(*) FROM projects WHERE name = 'planted')").Scan(&n); err != nil || n != 0 {
		t.Fatalf("planted rows: n=%d err=%v", n, err)
	}
	for _, table := range []string{"brokers", "companies", "projects"} {
		assertStatus(t, mux, http.MethodPost, "/api/"+table, global, map[string]any{"name": "by-global"}, http.StatusOK)
	}
	// The owner tier still lets anyone create a row they own.
	assertStatus(t, mux, http.MethodPost, "/api/notes", plain, map[string]any{"name": "mine"}, http.StatusOK)
	// Apps without groups: a listed role is enough (the membership role is
	// gone with groups:, so the former member is an ordinary user).
	// Complete the successful creates' async audience checks before changing
	// the fixture's group configuration outside the normal reload lifecycle.
	realtimeFlush()
	app.Group = nil
	assertStatus(t, mux, http.MethodPost, "/api/brokers", plain, map[string]any{"name": "planted"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPost, "/api/brokers", member, map[string]any{"name": "planted"}, http.StatusNotFound)
	if s := getSession(app, authzReq("GET", "/", global, "")); !tableModeAllowed(app, "brokers", OpWrite, "owner_or_role:clinic_staff", s, 0) {
		t.Fatal("a role-holder must still create without groups:")
	}
}
