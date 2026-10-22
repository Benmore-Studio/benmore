//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// A record-level ACL grant used to be OR'd next to the tenant clause
// (`org_id = ? OR <acl>`), so a row shared from tenant A reached a user who
// belongs to tenant B on every CRUD surface. Grants are now bounded by the
// caller's effective tenant.
func TestACLGrant_DoesNotCrossTenants(t *testing.T) {
	for _, mode := range []string{"group", "self", "owner_or_role:manager"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := newAccessScopeFixture(t,
				map[string]map[AccessOp]string{"records": {"all": mode}},
				`INSERT INTO records (org_id, user_id, title) VALUES
					('org-a', 1, 'tenant-a-secret'),
					('org-b', 2, 'tenant-b-own')`,
			)
			_ = createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
			bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-b", "")
			crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission)
				VALUES ('records', '1', 'user', 'bob@example.com', 'admin')`)

			assertListIDs(t, mux, bob, "/api/records", []float64{2})
			assertStatus(t, mux, http.MethodGet, "/api/records/1", bob, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/records/1", bob, map[string]any{"title": "crossed"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/records/1", bob, nil, http.StatusNotFound)
			assertRecordTitle(t, app.DB, 1, "tenant-a-secret")
			assertRowExists(t, app.DB, "records", 1, true)
		})
	}
}

// Inside the tenant a grant still works for the owner-scoped modes, and a
// caller with no tenant at all keeps reaching rows explicitly shared with
// them (there is no tenant clause to apply).
func TestACLGrant_StillWorksWithinTenant(t *testing.T) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (org_id, user_id, title) VALUES ('org-a', 1, 'alice-doc')`,
	)
	_ = createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
	coworker := createCrudScopeSession(t, app, "carol@example.com", "user", "org-a", "")
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission)
		VALUES ('records', '1', 'user', 'carol@example.com', 'view')`)
	assertListIDs(t, mux, coworker, "/api/records", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/records/1", coworker, nil, http.StatusOK)
}
