//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

const tenantRootOwnerRoleYAML = `access:
  companies:
    read: role:company_admin,viewer
    write: role:company_admin
    update: role:company_admin
    delete: role:company_admin
`

func tenantRootOwnerFixture(t *testing.T, config string) (*App, *http.ServeMux) {
	t.Helper()
	app, _ := newTenantRoleFixture(t, config)
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN user_id INTEGER")
	cols, err := GetTableColumns(app.DB, "companies")
	if err != nil {
		t.Fatal(err)
	}
	for i := range app.Tables {
		if app.Tables[i].Name == "companies" {
			app.Tables[i].Columns = cols
		}
	}
	app.Roles = parseRolesConfig([]byte(config))
	return app, buildAppMux(app, true, "http://localhost")
}

func setTenantRootOwner(t *testing.T, app *App, id, owner int64) {
	t.Helper()
	if _, err := app.DB.Exec("UPDATE companies SET user_id=? WHERE id=?", owner, id); err != nil {
		t.Fatal(err)
	}
}

// Bootstrap records the founder in user_id, but a role/permission policy on
// the tenant root addresses the tenant, not the founding account. Conversely,
// owning an old tenant must not substitute for the current tenant role.
func TestTenantRootOwnerColumnUsesRoleScope(t *testing.T) {
	for _, mode := range []string{"role", "permission"} {
		config, role := tenantRootOwnerRoleYAML, "company_admin"
		if mode == "permission" {
			config, role = tenantPermYAML, "clinic_staff"
		}
		for _, scenario := range []string{"nonfounder", "foreign_owned_root"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				app, mux := tenantRootOwnerFixture(t, config)
				_, founderID := tenantMember(t, app, "founder@example.com", "user", 1, role)
				manager, managerID := tenantMember(t, app, "manager@example.com", "user", 1, role)
				setTenantRootOwner(t, app, 1, founderID)
				setTenantRootOwner(t, app, 2, managerID)
				if scenario == "nonfounder" {
					assertListIDs(t, mux, manager, "/api/companies", []float64{1})
					assertStatus(t, mux, http.MethodGet, "/api/companies/1", manager, nil, http.StatusOK)
					assertStatus(t, mux, http.MethodPatch, "/api/companies/1", manager, map[string]any{"name": "managed"}, http.StatusOK)
					var name string
					if err := app.DB.QueryRow("SELECT name FROM companies WHERE id=1").Scan(&name); err != nil || name != "managed" {
						t.Fatalf("authorized update did not persist: name=%q err=%v", name, err)
					}
					assertStatus(t, mux, http.MethodPost, "/api/companies", manager, map[string]any{"name": "new-root"}, http.StatusNotFound)
					return
				}
				for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
					w := crudScopeRequest(t, mux, method, "/api/companies/2", manager, map[string]any{"name": "foreign-write"})
					if w.Code != http.StatusNotFound {
						t.Errorf("foreign owned root %s returned %d, want404", method, w.Code)
					}
				}
				var name string
				if err := app.DB.QueryRow("SELECT name FROM companies WHERE id=2").Scan(&name); err != nil || name != "globex" {
					t.Errorf("foreign root changed/deleted: name=%q err=%v", name, err)
				}
			})
		}
	}
}

func TestTenantRootOwnerColumnPreservesGlobalRoles(t *testing.T) {
	for _, primary := range []bool{false, true} {
		t.Run(fmt.Sprint("primary=", primary), func(t *testing.T) {
			app, mux := tenantRootOwnerFixture(t, tenantRootOwnerRoleYAML)
			role := "user"
			if primary {
				role = "company_admin"
			}
			global, uid := tenantMember(t, app, "global@example.com", role, 1, "viewer")
			if !primary {
				if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles(user_id,role) VALUES (?,'company_admin')", uid); err != nil {
					t.Fatal(err)
				}
			}
			assertListIDs(t, mux, global, "/api/companies", []float64{2, 1})
			assertStatus(t, mux, http.MethodPatch, "/api/companies/2", global, map[string]any{"name": "global-update"}, http.StatusOK)
			assertStatus(t, mux, http.MethodPost, "/api/companies", global, map[string]any{"name": "global-create"}, http.StatusOK)
		})
	}
}

func TestTenantRootOwnerColumnPreservesSelfAndViewer(t *testing.T) {
	app, mux := tenantRootOwnerFixture(t, tenantRootOwnerRoleYAML)
	viewer, uid := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	setTenantRootOwner(t, app, 2, uid)
	assertListIDs(t, mux, viewer, "/api/companies", []float64{1})
	assertStatus(t, mux, http.MethodPatch, "/api/companies/1", viewer, map[string]any{"name": "viewer-write"}, http.StatusNotFound)
	app.Access = accessFromYAML(t, "access:\n  companies: self\n")
	assertListIDs(t, mux, viewer, "/api/companies", []float64{2})
	assertStatus(t, mux, http.MethodGet, "/api/companies/1", viewer, nil, http.StatusNotFound)
}

func TestTenantRootOwnerColumnActAsRemainsTenantBounded(t *testing.T) {
	app, mux := tenantRootOwnerFixture(t, tenantRootOwnerRoleYAML)
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "1", "")
	stepped := createCrudScopeSession(t, app, "stepped@example.com", "admin", "1", "2")
	setTenantRootOwner(t, app, 1, GetSessionFromDB(app.DB, stepped).UserID)
	assertListIDs(t, mux, admin, "/api/companies", []float64{2, 1})
	assertListIDs(t, mux, stepped, "/api/companies", []float64{2})
	assertStatus(t, mux, http.MethodPatch, "/api/companies/1", stepped, map[string]any{"name": "wrong-tenant"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/companies/2", stepped, map[string]any{"name": "acted-tenant"}, http.StatusOK)
}
