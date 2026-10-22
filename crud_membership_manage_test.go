//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

func membershipRowID(t *testing.T, app *App, email string) int64 {
	t.Helper()
	var id int64
	if err := app.DB.QueryRow("SELECT id FROM company_members WHERE email = ?", email).Scan(&id); err != nil {
		t.Fatalf("membership row for %s: %v", email, err)
	}
	return id
}

func membershipCount(t *testing.T, app *App, where string, args ...any) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM company_members WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The groups membership table decides who is in a tenant. Under the implicit
// default access every tenant member could write it through generic CRUD:
// add an outsider (who then resolves into this tenant), delete the tenant
// admin's row, or switch another member off. Without an access rule on the
// table, managing memberships now takes a tenant admin; a member may still
// leave.
func TestMembershipTableWritesNeedTenantAdmin(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  projects: role:company_admin\n")
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
	adminSID, _ := tenantMember(t, app, "lead@example.com", "user", 1, "company_admin")
	memberSID, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	peerSID, _ := tenantMember(t, app, "peer@example.com", "user", 1, "viewer")
	otherAdminSID, _ := tenantMember(t, app, "other@example.com", "user", 2, "company_admin")
	adminRow := membershipRowID(t, app, "lead@example.com")
	memberRow := membershipRowID(t, app, "member@example.com")
	peerRow := membershipRowID(t, app, "peer@example.com")

	// A plain member cannot add anyone, on any create path.
	crudScopeRequest(t, mux, http.MethodPost, "/api/company_members", memberSID, map[string]any{"email": "outsider@example.com"})
	crudScopeRequest(t, mux, http.MethodPost, "/api/company_members/batch", memberSID, []any{map[string]any{"email": "outsider@example.com"}})
	crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", memberSID, map[string]any{"operations": []any{map[string]any{"table": "company_members", "action": "insert", "data": map[string]any{"email": "outsider@example.com"}}}})
	if n := membershipCount(t, app, "email = 'outsider@example.com'"); n != 0 {
		t.Fatalf("a plain member added %d membership row(s) for an outsider", n)
	}

	// ...nor remove the tenant admin or another member.
	for _, row := range []int64{adminRow, peerRow} {
		crudScopeRequest(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", row), memberSID, nil)
		crudScopeRequest(t, mux, http.MethodDelete, "/api/company_members/batch", memberSID, map[string]any{"ids": []any{row}})
		crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", memberSID, map[string]any{"operations": []any{map[string]any{"table": "company_members", "action": "delete", "id": row}}})
	}
	if n := membershipCount(t, app, "id IN (?, ?)", adminRow, peerRow); n != 2 {
		t.Fatalf("a plain member deleted another member's row (%d of 2 left)", n)
	}

	// ...nor switch another member off, or edit their row.
	crudScopeRequest(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", peerRow), memberSID, map[string]any{"active": 0})
	crudScopeRequest(t, mux, http.MethodPatch, "/api/company_members/batch", memberSID, map[string]any{"ids": []any{peerRow, adminRow}, "fields": map[string]any{"active": "0"}})
	crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", memberSID, map[string]any{"operations": []any{map[string]any{"table": "company_members", "action": "update", "id": adminRow, "data": map[string]any{"active": 0}}}})
	if n := membershipCount(t, app, "active = 1 AND id IN (?, ?)", adminRow, peerRow); n != 2 {
		t.Fatalf("a plain member deactivated another member (%d of 2 still active)", n)
	}
	// Reads stay tenant-scoped.
	assertStatus(t, mux, http.MethodGet, "/api/company_members", memberSID, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/company_members/%d", adminRow), memberSID, nil, http.StatusOK)

	// The tenant admin (groups.bootstrap.founding_role) manages memberships.
	assertStatus(t, mux, http.MethodPost, "/api/company_members", adminSID, map[string]any{"email": "invitee@example.com"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", peerRow), adminSID, map[string]any{"active": 0}, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", peerRow), adminSID, map[string]any{"active": 1}, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", membershipRowID(t, app, "invitee@example.com")), adminSID, nil, http.StatusOK)
	// ...of their own tenant only.
	crudScopeRequest(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", adminRow), otherAdminSID, nil)
	if n := membershipCount(t, app, "id = ?", adminRow); n != 1 {
		t.Fatal("another tenant's admin deleted this tenant's admin row")
	}

	// A member may leave: switch their own membership off, or delete it.
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", peerRow), peerSID, map[string]any{"active": 0}, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", memberRow), memberSID, nil, http.StatusOK)
	if n := membershipCount(t, app, "id = ?", memberRow); n != 0 {
		t.Fatal("a member could not delete their own membership row")
	}

	// A global admin is not restricted.
	globalSID := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	assertStatus(t, mux, http.MethodPost, "/api/company_members", globalSID, map[string]any{"email": "seeded@example.com", "company_id": 1}, http.StatusOK)
}

// A member's own row is still not theirs to edit: only leaving is open.
func TestMembershipOwnRowUpdateIsLeaveOnly(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  projects: role:company_admin\n")
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN can_approve INTEGER NOT NULL DEFAULT 0")
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
	memberSID, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	row := membershipRowID(t, app, "member@example.com")
	crudScopeRequest(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", row), memberSID, map[string]any{"can_approve": 1})
	crudScopeRequest(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", row), memberSID, map[string]any{"active": 0, "can_approve": 1})
	if n := membershipCount(t, app, "id = ? AND can_approve = 0 AND active = 1", row); n != 1 {
		t.Fatal("a plain member edited an app column on their own membership row")
	}
}

// An access rule the app declares on the membership table is the app's own
// policy and is applied as written.
func TestMembershipTableDeclaredRuleIsUntouched(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  company_members:\n    write: group\n    update: group\n    delete: group\n")
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN title TEXT")
	for i := range app.Tables {
		if app.Tables[i].Name == "company_members" {
			cols, err := GetTableColumns(app.DB, "company_members")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	memberSID, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	tenantMember(t, app, "peer@example.com", "user", 1, "viewer")
	peerRow := membershipRowID(t, app, "peer@example.com")
	assertStatus(t, mux, http.MethodPost, "/api/company_members", memberSID, map[string]any{"email": "invitee@example.com"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", peerRow), memberSID, map[string]any{"title": "renamed"}, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", peerRow), memberSID, nil, http.StatusOK)
}

// Without a tenant role to go by (no groups.role_field / founding_role), the
// tenant admin is whoever owns the tenant's org row.
func TestMembershipTableCreatorManagesWithoutTenantRoles(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  projects: group\n")
	app.Group.RoleField = ""
	app.Group.Bootstrap.FoundingRole = ""
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN user_id INTEGER")
	for i := range app.Tables {
		if app.Tables[i].Name == "companies" {
			cols, err := GetTableColumns(app.DB, "companies")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	founderSID, founderID := tenantMember(t, app, "founder@example.com", "user", 1, "")
	memberSID, _ := tenantMember(t, app, "member@example.com", "user", 1, "")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE companies SET user_id = %d WHERE id = 1", founderID))
	founderRow := membershipRowID(t, app, "founder@example.com")

	crudScopeRequest(t, mux, http.MethodPost, "/api/company_members", memberSID, map[string]any{"email": "outsider@example.com"})
	crudScopeRequest(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", founderRow), memberSID, nil)
	if membershipCount(t, app, "email = 'outsider@example.com'") != 0 || membershipCount(t, app, "id = ?", founderRow) != 1 {
		t.Fatal("a plain member managed memberships in a tenant they did not create")
	}
	assertStatus(t, mux, http.MethodPost, "/api/company_members", founderSID, map[string]any{"email": "invitee@example.com"}, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", membershipRowID(t, app, "member@example.com")), founderSID, nil, http.StatusOK)
}

// A lock blocks everyone else's edits and a share hands out access, so on the
// membership table both take the right to manage the row. A plain member
// could otherwise hold a rolling lock on their own (or the admin's) membership
// row and keep the tenant admin from changing or removing it.
func TestMembershipRowLockAndShareNeedTenantAdmin(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  projects: role:company_admin\n")
	crudScopeMustExec(t, app.DB, "ALTER TABLE company_members ADD COLUMN user_id INTEGER")
	for i := range app.Tables {
		if app.Tables[i].Name == "company_members" {
			cols, err := GetTableColumns(app.DB, "company_members")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	adminSID, _ := tenantMember(t, app, "lead@example.com", "user", 1, "company_admin")
	memberSID, memberID := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	memberRow := membershipRowID(t, app, "member@example.com")
	adminRow := membershipRowID(t, app, "lead@example.com")
	// The member even owns their row (user_id), as a flow or bootstrap sets it.
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE company_members SET user_id = %d WHERE id = %d", memberID, memberRow))

	for _, row := range []int64{memberRow, adminRow} {
		crudScopeRequest(t, mux, http.MethodPost, fmt.Sprintf("/api/company_members/%d/lock", row), memberSID, nil)
		crudScopeRequest(t, mux, http.MethodPost, fmt.Sprintf("/api/company_members/%d/share", row), memberSID, map[string]any{"email": "outsider@example.com", "permission": "admin"})
	}
	var locks, shares int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_locks WHERE table_name = 'company_members'").Scan(&locks); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_permissions WHERE resource_type = 'company_members'").Scan(&shares); err != nil {
		t.Fatal(err)
	}
	if locks != 0 || shares != 0 {
		t.Fatalf("a plain member took %d lock(s) and %d share(s) on membership rows", locks, shares)
	}
	// The admin's management is not blocked, and the admin may lock.
	assertStatus(t, mux, http.MethodPatch, fmt.Sprintf("/api/company_members/%d", memberRow), adminSID, map[string]any{"email": "member@example.com"}, http.StatusBadRequest)
	assertStatus(t, mux, http.MethodPost, fmt.Sprintf("/api/company_members/%d/lock", memberRow), adminSID, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, fmt.Sprintf("/api/company_members/%d", memberRow), adminSID, nil, http.StatusOK)
}
