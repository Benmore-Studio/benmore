//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// A member whose membership was deactivated (groups.active_field) has no
// tenant any more; owning the membership row (its user_id) must not let them
// switch it back on through CRUD.
func TestDeactivatedMemberCannotReactivateOwnMembership(t *testing.T) {
	// With no rule on the membership table only a tenant admin switches other
	// members; with a declared rule the app's own policy applies and the
	// activation gate is what stops the deactivated member.
	t.Run("implicit", func(t *testing.T) {
		testDeactivatedMemberCannotReactivate(t, "access:\n  projects: role:company_admin\n", "company_admin")
	})
	t.Run("declared", func(t *testing.T) {
		testDeactivatedMemberCannotReactivate(t, "access:\n  projects: role:company_admin\n  company_members:\n    update: everyone\n", "viewer")
	})
}

func testDeactivatedMemberCannotReactivate(t *testing.T, access, peerRole string) {
	app, mux := newTenantRoleFixture(t, access)
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN user_id INTEGER")
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
	app.Group.ActiveField = "active"
	for i := range app.Tables {
		if app.Tables[i].Name == "company_members" {
			cols, err := GetTableColumns(app.DB, "company_members")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	sid, uid := tenantMember(t, app, "lead@example.com", "user", 1, "company_admin")
	var row int64
	if err := app.DB.QueryRow("SELECT id FROM company_members WHERE email = 'lead@example.com'").Scan(&row); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE company_members SET user_id = %d WHERE id = %d", uid, row))
	assertStatus(t, mux, http.MethodGet, "/api/projects", sid, nil, http.StatusOK)

	// The tenant deactivates the membership.
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE company_members SET active = 0 WHERE id = %d", row))
	assertStatus(t, mux, http.MethodGet, "/api/projects", sid, nil, http.StatusNotFound)

	rec := crudScopeRequest(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", row), sid, map[string]any{"active": 1})
	var active int
	if err := app.DB.QueryRow("SELECT active FROM company_members WHERE id = ?", row).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("deactivated member switched its own membership back on (status %d, body %s)", rec.Code, rec.Body.String())
	}
	// Bulk paths and revert-style updates share the gate.
	crudScopeRequest(t, mux, http.MethodPatch, "/api/company_members/batch", sid, map[string]any{"ids": []any{row}, "fields": map[string]any{"active": "1"}})
	crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sid, map[string]any{"operations": []any{map[string]any{"table": "company_members", "action": "update", "id": row, "data": map[string]any{"active": 1}}}})
	if err := app.DB.QueryRow("SELECT active FROM company_members WHERE id = ?", row).Scan(&active); err != nil || active != 0 {
		t.Fatalf("bulk path reactivated the membership: active=%d err=%v", active, err)
	}
	assertStatus(t, mux, http.MethodGet, "/api/projects", sid, nil, http.StatusNotFound)

	// A member acting inside the row's tenant still switches memberships
	// on and off through CRUD.
	peer, _ := tenantMember(t, app, "peer@example.com", "user", 1, peerRole)
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", row), peer, map[string]any{"active": 1}, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/projects", sid, nil, http.StatusOK)
	// ...and a live member may switch their own membership off (leave).
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", row), sid, map[string]any{"active": 0}, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/projects", sid, nil, http.StatusNotFound)
}
