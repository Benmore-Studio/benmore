//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A role grant with group_id was stored in an app with no groups: config,
// where no session ever has a group, so it could never apply while GET
// .../roles went on listing its permissions. It is now refused with 400; an
// app with groups: still takes it.
func TestRoleGrantWithGroupNeedsGroupsConfig(t *testing.T) {
	for _, withGroups := range []bool{false, true} {
		t.Run(fmt.Sprintf("groups_%t", withGroups), func(t *testing.T) {
			app := authzApp(t)
			app.Paths = DiscoverAuthPaths(nil)
			app.Roles = parseRolesConfig([]byte("roles:\n  auditor:\n    scopes: \"audit_reports:read\"\n"))
			if app.Roles == nil {
				t.Fatal("roles fixture did not parse")
			}
			if withGroups {
				app.Group = &GroupConfig{Table: "memberships", Key: "org_id", UserField: "email"}
			}
			mux := http.NewServeMux()
			RegisterRoleRoutes(mux, app)
			admin := authzUser(t, app, "admin@example.com", "admin")
			target := authzUser(t, app, "staff@example.com", "user")
			adminSession := authzSession(t, app, admin, "admin@example.com")

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, authzReq("POST", fmt.Sprintf("/api/_auth/users/%d/roles", target), adminSession, `{"role":"auditor","group_id":"1"}`))
			var grants int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ?", target).Scan(&grants); err != nil {
				t.Fatal(err)
			}
			if withGroups {
				if w.Code != http.StatusOK || grants != 1 {
					t.Fatalf("group grant with groups: = %d (%d rows) %s, want 200 and one grant", w.Code, grants, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "groups:") || grants != 0 {
				t.Fatalf("group grant without groups: = %d (%d rows) %s, want 400 naming groups: and no grant", w.Code, grants, w.Body.String())
			}
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, authzReq("GET", fmt.Sprintf("/api/_auth/users/%d/roles", target), adminSession, ""))
			if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "audit_reports:read") {
				t.Fatalf("roles listing after the refused grant = %d %s, want no auditor permissions", w.Code, w.Body.String())
			}
			// A global grant still works.
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, authzReq("POST", fmt.Sprintf("/api/_auth/users/%d/roles", target), adminSession, `{"role":"auditor"}`))
			if w.Code != http.StatusOK {
				t.Fatalf("global grant = %d %s", w.Code, w.Body.String())
			}
		})
	}
}
