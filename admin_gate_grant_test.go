//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The /_admin gate read only _benmore_users.role, so an account made admin
// through a global grant in _benmore_user_roles - an admin everywhere else
// (row bypass, /api/_audit, role management) - got 403 on the panel. The
// gate is now the canonical one for admin-only management surfaces.
func TestAdminPanelGateCountsGlobalAdminGrant(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES
		(1, 'primary', 'primary@example.com', 'x', 'admin', 1),
		(2, 'granted', 'granted@example.com', 'x', 'user', 1),
		(3, 'tenantadmin', 'tenantadmin@example.com', 'x', 'user', 1),
		(4, 'member', 'member@example.com', 'x', 'user', 1),
		(5, 'expired', 'expired@example.com', 'x', 'user', 1)`)
	mustExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (2, 'admin')")
	mustExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (3, 'admin', 'tenant-a')")
	mustExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role, expires_at) VALUES (5, 'admin', '2020-01-01T00:00:00Z')")
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'tenantadmin@example.com')")

	get := func(userID int64, email, group, scopes string) int {
		token := CreateSession(app.DB, userID, email, group, time.Hour, scopes)
		r := httptest.NewRequest(http.MethodGet, "/_admin", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if code := get(1, "primary@example.com", "", ""); code != http.StatusOK {
		t.Fatalf("control: primary-role admin = %d", code)
	}
	if code := get(2, "granted@example.com", "", ""); code != http.StatusOK {
		t.Fatalf("an admin by global grant was refused the panel: %d", code)
	}
	for name, code := range map[string]int{
		"a grant scoped to one tenant":           get(3, "tenantadmin@example.com", "tenant-a", ""),
		"no admin role":                          get(4, "member@example.com", "", ""),
		"an expired grant":                       get(5, "expired@example.com", "", ""),
		"a scoped credential of an admin":        get(1, "primary@example.com", "", "notes:read"),
		"a scoped credential of a granted admin": get(2, "granted@example.com", "", "notes:read"),
	} {
		if code != http.StatusForbidden {
			t.Errorf("%s opened the admin panel: %d", name, code)
		}
	}
}
