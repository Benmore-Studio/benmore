//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// A tenant member must not take over another member's membership row through
// generic CRUD. groups.user_field binds the in-tenant role (groups.role_field)
// to an identity, so re-pointing it moves that role to whoever the new value
// names. The role column itself is protected (H-10); the identity column is
// the other half of the same grant.
func TestMembershipIdentityNotRepointableThroughCRUD(t *testing.T) {
	// The membership table carries its own access rule here, so the app's
	// members reach the update pipeline (without one, managing members takes
	// a tenant admin: TestMembershipTableWritesNeedTenantAdmin).
	app, mux := newTenantRoleFixture(t, "access:\n  projects: role:company_admin\n  company_members:\n    write: everyone\n    update: everyone\n")

	adminSID, _ := tenantMember(t, app, "admin@example.com", "user", 1, "company_admin")
	memberSID, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	_ = adminSID
	var adminRow int64
	if err := app.DB.QueryRow("SELECT id FROM company_members WHERE email = 'admin@example.com'").Scan(&adminRow); err != nil {
		t.Fatal(err)
	}
	// Before: the plain member cannot reach the admin-only table.
	assertStatus(t, mux, http.MethodGet, "/api/projects", memberSID, nil, http.StatusNotFound)

	path := fmt.Sprintf("/api/company_members/%d", adminRow)
	rec := crudScopeRequest(t, mux, http.MethodPatch, path, memberSID, map[string]any{"email": "member@example.com"})
	var email string
	if err := app.DB.QueryRow("SELECT email FROM company_members WHERE id = ?", adminRow).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "admin@example.com" {
		t.Fatalf("member re-pointed the admin's membership row to itself (status %d, body %s): email now %q", rec.Code, rec.Body.String(), email)
	}
	// The batch and transaction paths share the same protected set.
	crudScopeRequest(t, mux, http.MethodPatch, "/api/company_members/batch", memberSID, map[string]any{"ids": []any{adminRow}, "fields": map[string]any{"email": "member@example.com"}})
	crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", memberSID, map[string]any{"operations": []any{map[string]any{"table": "company_members", "action": "update", "id": adminRow, "data": map[string]any{"email": "member@example.com"}}}})
	if err := app.DB.QueryRow("SELECT email FROM company_members WHERE id = ?", adminRow).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "admin@example.com" {
		t.Fatalf("bulk path re-pointed the admin's membership row: email now %q", email)
	}
	assertStatus(t, mux, http.MethodGet, "/api/projects", memberSID, nil, http.StatusNotFound)

	// Other membership columns stay editable, and a new membership row may
	// still name any identity (invite flows create rows through CRUD).
	assertStatus(t, mux, http.MethodPost, "/api/company_members", memberSID, map[string]any{"email": "invitee@example.com"}, http.StatusOK)

	// Without groups.role_field the identity column carries no role and
	// stays editable as before.
	app.Group.RoleField = ""
	assertStatus(t, mux, http.MethodPatch, path, memberSID, map[string]any{"email": "renamed@example.com"}, http.StatusOK)
	if err := app.DB.QueryRow("SELECT email FROM company_members WHERE id = ?", adminRow).Scan(&email); err != nil || email != "renamed@example.com" {
		t.Fatalf("without role_field the identity column should stay editable: email=%q err=%v", email, err)
	}
}
