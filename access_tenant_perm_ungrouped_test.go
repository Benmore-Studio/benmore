//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// tenantPermYAML maps a tenant role (clinic_staff, held as a membership role
// or a tenant-scoped grant) and a global role (catalog_editor) onto the same
// permission set.
const tenantPermYAML = `roles:
  user:
    scopes: "projects:read"
  viewer:
    scopes: "projects:read"
  clinic_staff:
    scopes: "brokers:write brokers:delete companies:write companies:delete projects:write"
  catalog_editor:
    scopes: "brokers:write brokers:delete companies:write companies:delete projects:write"
access:
  brokers:
    read: perm:brokers.read
    write: perm:brokers.write
    update: perm:brokers.write
    delete: perm:brokers.delete
  companies:
    read: perm:companies.read
    write: perm:companies.write
    update: perm:companies.write
    delete: perm:companies.delete
  projects:
    read: perm:projects.read
    write: perm:projects.write
    update: perm:projects.write
    delete: perm:projects.write
`

func newTenantPermFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app, mux := newTenantRoleFixture(t, tenantPermYAML)
	app.Roles = parseRolesConfig([]byte(tenantPermYAML))
	if app.Roles == nil {
		t.Fatal("fixture: roles did not parse")
	}
	return app, mux
}

// A permission granted only by a role held inside a tenant (the membership
// role, or a grant scoped to the tenant) must not pass a `perm:` gate on a
// table without the tenant key: the table has no tenant column to bound it,
// so it reached every tenant's rows. This is the role: rule (global roles
// only on un-grouped tables) applied to the permissions those roles grant.
func TestTenantRolePermissionDoesNotPassPermGateOnUngroupedTable(t *testing.T) {
	app, mux := newTenantPermFixture(t)

	member, _ := tenantMember(t, app, "member@example.com", "user", 2, "clinic_staff")
	granted, grantedID := tenantMember(t, app, "granted@example.com", "user", 2, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (%d, 'clinic_staff', '2')", grantedID))
	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'catalog_editor')", globalID))
	primary, _ := tenantMember(t, app, "primary@example.com", "catalog_editor", 1, "viewer")

	for name, sid := range map[string]string{"membership role": member, "tenant-scoped grant": granted} {
		t.Run(name, func(t *testing.T) {
			s := getSession(app, authzReq("GET", "/", sid, ""))
			if s == nil || !HasPermission(s, "brokers:write") {
				t.Fatalf("fixture: the tenant role should grant brokers:write, session=%+v", s)
			}
			assertStatus(t, mux, http.MethodGet, "/api/brokers", sid, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/brokers/1", sid, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPost, "/api/brokers", sid, map[string]any{"name": "planted"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/brokers/1", sid, map[string]any{"name": "overwritten"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/brokers/2", sid, nil, http.StatusNotFound)
			if SessionCanAccessTable(app, "brokers", OpRead, s) {
				t.Fatal("SessionCanAccessTable must refuse a tenant-only permission on an un-grouped table")
			}
			// Grouped table: the tenant permission still works, bounded by the tenant.
			assertListIDs(t, mux, sid, "/api/projects", []float64{2})
		})
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM brokers WHERE name IN ('planted', 'overwritten')").Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant-only permission wrote to the un-grouped table: n=%d err=%v", n, err)
	}
	assertRowExists(t, app.DB, "brokers", 2, true)

	// A permission from a globally held role (global grant or users.role)
	// still reaches every row of the un-grouped table.
	for name, sid := range map[string]string{"global grant": global, "users.role": primary} {
		t.Run(name, func(t *testing.T) {
			assertListIDs(t, mux, sid, "/api/brokers", []float64{2, 1})
			assertStatus(t, mux, http.MethodGet, "/api/brokers/2", sid, nil, http.StatusOK)
			assertListIDs(t, mux, sid, "/api/projects", []float64{1})
		})
	}
	assertStatus(t, mux, http.MethodPost, "/api/brokers", global, map[string]any{"name": "by-global"}, http.StatusOK)

	// groups.shared keeps counting tenant-held permissions, as for role:.
	app.Group.Shared = []string{"brokers"}
	assertStatus(t, mux, http.MethodGet, "/api/brokers/1", member, nil, http.StatusOK)
}

// On the tenant root a tenant-held permission reaches only the caller's own
// tenant row, and creating an org row needs a globally granted permission.
func TestTenantRolePermissionOnTenantRootReachesOnlyOwnTenantRow(t *testing.T) {
	app, mux := newTenantPermFixture(t)

	admin, _ := tenantMember(t, app, "admin@example.com", "user", 1, "clinic_staff")
	assertListIDs(t, mux, admin, "/api/companies", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/companies/1", admin, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/companies/2", admin, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/companies/2", admin, map[string]any{"name": "pwned"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/companies/2", admin, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/companies/1", admin, map[string]any{"name": "acme-renamed"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/companies", admin, map[string]any{"name": "new-co"}, http.StatusNotFound)
	var name string
	if err := app.DB.QueryRow("SELECT name FROM companies WHERE id = 2").Scan(&name); err != nil || name != "globex" {
		t.Fatalf("other tenant's row changed: %q %v", name, err)
	}
	assertRowExists(t, app.DB, "companies", 2, true)

	global, globalID := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'catalog_editor')", globalID))
	assertListIDs(t, mux, global, "/api/companies", []float64{2, 1})
	assertStatus(t, mux, http.MethodPost, "/api/companies", global, map[string]any{"name": "by-global"}, http.StatusOK)
}
