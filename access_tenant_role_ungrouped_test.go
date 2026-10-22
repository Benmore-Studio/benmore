//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// newTenantRoleFixture serves a multi-tenant app whose tenant roles come from
// company_members.member_role. companies is the tenant root (the bootstrap
// org table, no company_id column), brokers is an un-grouped shared table, and
// projects is group-keyed.
func newTenantRoleFixture(t *testing.T, access string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	for _, stmt := range []string{
		`CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`,
		`CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, member_role TEXT)`,
		`CREATE TABLE brokers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`,
		`CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, name TEXT)`,
		`INSERT INTO companies (id, name) VALUES (1, 'acme'), (2, 'globex')`,
		`INSERT INTO brokers (id, name) VALUES (1, 'broker-a'), (2, 'broker-b')`,
		`INSERT INTO projects (id, company_id, name) VALUES (1, 1, 'acme-p'), (2, 2, 'globex-p')`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group: &GroupConfig{Table: "company_members", Key: "company_id", UserField: "email", RoleField: "member_role",
			Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "company_admin"}},
		Access: accessFromYAML(t, access),
	}
	for _, name := range []string{"companies", "company_members", "brokers", "projects"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

// tenantMember creates a verified user with primary role `role`, a live
// membership in company with member_role, and a session in that tenant.
func tenantMember(t *testing.T, app *App, email, role string, company int, memberRole string) (string, int64) {
	t.Helper()
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO company_members (company_id, email, member_role) VALUES (%d, '%s', '%s')", company, email, memberRole))
	sid := createCrudScopeSession(t, app, email, role, fmt.Sprint(company), "")
	var uid int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	return sid, uid
}

// A role held only inside a tenant (the membership role, or a grant scoped
// to the tenant) must not pass a `role:` gate on a table without the tenant
// key: there is no tenant column to bound it, so it reached every tenant's
// rows. Global roles keep working, and grouped tables are unchanged.
func TestTenantRoleDoesNotPassRoleGateOnUngroupedTable(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  brokers: role:clinic_staff\n  projects: role:clinic_staff\n")

	member, _ := tenantMember(t, app, "member@example.com", "user", 2, "clinic_staff")
	granted, grantedID := tenantMember(t, app, "granted@example.com", "user", 2, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (%d, 'clinic_staff', '2')", grantedID))
	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'clinic_staff')", globalID))
	primary, _ := tenantMember(t, app, "primary@example.com", "clinic_staff", 1, "viewer")

	for name, sid := range map[string]string{"membership role": member, "tenant-scoped grant": granted} {
		t.Run(name, func(t *testing.T) {
			assertStatus(t, mux, http.MethodGet, "/api/brokers", sid, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/brokers/1", sid, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPost, "/api/brokers", sid, map[string]any{"name": "planted"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/brokers/1", sid, map[string]any{"name": "overwritten"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/brokers/2", sid, nil, http.StatusNotFound)
			s := getSession(app, authzReq("GET", "/", sid, ""))
			if s == nil {
				t.Fatal("session did not resolve")
			}
			if !HasAnyRole(s, []string{"clinic_staff"}) {
				t.Fatalf("fixture: session should hold the tenant role, roles=%v", s.Roles)
			}
			if SessionCanAccessTable(app, "brokers", OpRead, s) {
				t.Fatal("SessionCanAccessTable must refuse a tenant-only role on an un-grouped table")
			}
			// Grouped table: the tenant role still works, bounded by the tenant.
			assertListIDs(t, mux, sid, "/api/projects", []float64{2})
		})
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM brokers WHERE name IN ('planted', 'overwritten')").Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant-only role wrote to the un-grouped table: n=%d err=%v", n, err)
	}
	assertRowExists(t, app.DB, "brokers", 2, true)

	// A globally held role (global grant or the users.role column) still
	// reaches every row of the un-grouped table.
	for name, sid := range map[string]string{"global grant": global, "users.role": primary} {
		t.Run(name, func(t *testing.T) {
			assertListIDs(t, mux, sid, "/api/brokers", []float64{2, 1})
			assertStatus(t, mux, http.MethodGet, "/api/brokers/2", sid, nil, http.StatusOK)
			assertListIDs(t, mux, sid, "/api/projects", []float64{1})
		})
	}
	assertStatus(t, mux, http.MethodPost, "/api/brokers", global, map[string]any{"name": "by-global"}, http.StatusOK)
}

// The tenant-root table (groups.bootstrap.org_table) is un-grouped by nature:
// its id IS the tenant. A tenant role reaches exactly the caller's own tenant
// row there, so `companies: {update: role:company_admin}` keeps working for a
// company's own admin without reaching any other company.
func TestTenantRoleOnTenantRootReachesOnlyOwnTenantRow(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  companies: role:company_admin\n")

	admin, _ := tenantMember(t, app, "admin@example.com", "user", 1, "company_admin")
	assertListIDs(t, mux, admin, "/api/companies", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/companies/1", admin, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/companies/2", admin, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/companies/2", admin, map[string]any{"name": "pwned"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/companies/2", admin, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/companies/1", admin, map[string]any{"name": "acme-renamed"}, http.StatusOK)
	// Creating an org row is not an act on the caller's own tenant.
	assertStatus(t, mux, http.MethodPost, "/api/companies", admin, map[string]any{"name": "new-co"}, http.StatusNotFound)

	var name string
	if err := app.DB.QueryRow("SELECT name FROM companies WHERE id = 2").Scan(&name); err != nil || name != "globex" {
		t.Fatalf("other tenant's row changed: %q %v", name, err)
	}
	if err := app.DB.QueryRow("SELECT name FROM companies WHERE id = 1").Scan(&name); err != nil || name != "acme-renamed" {
		t.Fatalf("own tenant row not updated: %q %v", name, err)
	}
	assertRowExists(t, app.DB, "companies", 2, true)

	// A global holder of the role still reaches every org row.
	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'company_admin')", globalID))
	assertListIDs(t, mux, global, "/api/companies", []float64{2, 1})
	assertStatus(t, mux, http.MethodPost, "/api/companies", global, map[string]any{"name": "by-global"}, http.StatusOK)
}

// A table the app declares in groups.shared is a reference catalog every
// tenant reads (a broker catalog): a tenant role keeps passing its
// role: gate there, exactly as before the un-grouped rule, while every other
// un-grouped table still counts only global roles. The list also parses and
// validates from app.yaml.
func TestGroupsSharedTableKeepsTenantRoles(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  brokers: role:clinic_staff\n  projects: role:clinic_staff\n")
	app.Group.Shared = []string{"Brokers"}
	member, _ := tenantMember(t, app, "member@example.com", "user", 2, "clinic_staff")
	assertStatus(t, mux, http.MethodGet, "/api/brokers/1", member, nil, http.StatusOK)
	if s := getSession(app, authzReq("GET", "/", member, "")); !SessionCanAccessTable(app, "brokers", OpRead, s) {
		t.Fatal("a tenant role must pass the role: gate of a groups.shared table")
	}
	app.Group.Shared = nil
	assertStatus(t, mux, http.MethodGet, "/api/brokers/1", member, nil, http.StatusNotFound)

	gc := parseGroupConfig([]byte("groups:\n  table: m\n  key: k\n  user_field: email\n  shared: [brokers, \"bad name\"]\n"))
	if gc == nil || len(gc.Shared) != 1 || gc.Shared[0] != "brokers" {
		t.Fatalf("groups.shared parsed as %+v", gc)
	}
}
