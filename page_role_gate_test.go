//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A page's role gate read only _benmore_users.role, so an account holding
// the role through a global grant - an admin everywhere else, or a "manager"
// on every un-grouped table - got 403 on the page and its PDF. The gate now
// counts the same global sources as /_admin and a role: mode on an un-grouped
// table, and still nothing a tenant hands out.
func TestPageRoleGateCountsGloballyHeldRoles(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, role TEXT)")
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES
		(1, 'primaryadmin', 'primaryadmin@example.com', 'x', 'admin', 1),
		(2, 'grantadmin', 'grantadmin@example.com', 'x', 'user', 1),
		(3, 'primarymanager', 'primarymanager@example.com', 'x', 'manager', 1),
		(4, 'grantmanager', 'grantmanager@example.com', 'x', 'user', 1),
		(5, 'granteditor', 'granteditor@example.com', 'x', 'user', 1),
		(6, 'tenantgrant', 'tenantgrant@example.com', 'x', 'user', 1),
		(7, 'tenantmember', 'tenantmember@example.com', 'x', 'user', 1),
		(8, 'expired', 'expired@example.com', 'x', 'user', 1),
		(9, 'plain', 'plain@example.com', 'x', 'user', 1),
		(10, 'grantops', 'grantops@example.com', 'x', 'user', 1)`)
	mustExec(t, db, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (2, 'admin'), (4, 'manager'), (5, 'editor'), (10, 'ops')")
	mustExec(t, db, "INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (6, 'manager', 'tenant-a'), (6, 'admin', 'tenant-a'), (6, 'ops', 'tenant-a')")
	mustExec(t, db, "INSERT INTO _benmore_user_roles (user_id, role, expires_at) VALUES (8, 'manager', '2020-01-01T00:00:00Z'), (8, 'ops', '2020-01-01T00:00:00Z')")
	mustExec(t, db, "INSERT INTO members (org_id, email, role) VALUES ('tenant-a', 'tenantgrant@example.com', 'member'), ('tenant-a', 'tenantmember@example.com', 'manager')")

	pages := map[string]*Page{
		"/desk":     {File: "desk.html", Route: "/desk", Role: "manager"},
		"/ops":      {File: "ops.html", Route: "/ops", Role: "ops"},
		"/pdfdesk":  {File: "pdfdesk.html", Route: "/pdfdesk", Role: "manager", Redirect: "*:/"},
		"/pdfstaff": {File: "pdfstaff.html", Route: "/pdfstaff", Role: "admin, ops", Redirect: "*:/"},
	}
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour, Paths: DiscoverAuthPaths(nil), Pages: pages,
		Group: &GroupConfig{Table: "members", Key: "org_id", UserField: "email", RoleField: "role"}}
	mux := http.NewServeMux()
	shown := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	mux.HandleFunc("GET /desk", RoleMiddleware(app, pages["/desk"], shown))
	mux.HandleFunc("GET /ops", RoleMiddleware(app, pages["/ops"], shown))
	RegisterPDFRoutes(mux, app)

	type caller struct {
		id    int64
		email string
		group string
	}
	callers := map[string]caller{
		"primary admin":            {1, "primaryadmin@example.com", ""},
		"admin by global grant":    {2, "grantadmin@example.com", ""},
		"primary manager":          {3, "primarymanager@example.com", ""},
		"manager by global grant":  {4, "grantmanager@example.com", ""},
		"editor by global grant":   {5, "granteditor@example.com", ""},
		"grants in one tenant":     {6, "tenantgrant@example.com", "tenant-a"},
		"tenant membership role":   {7, "tenantmember@example.com", "tenant-a"},
		"expired global grants":    {8, "expired@example.com", ""},
		"no role":                  {9, "plain@example.com", ""},
		"custom role global grant": {10, "grantops@example.com", ""},
	}
	get := func(who, path string) int {
		t.Helper()
		c := callers[who]
		token := CreateSession(db, c.id, c.email, c.group, time.Hour, "")
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	// The PDF route answers the page's redirect once every gate has passed,
	// so 303 means "would be printed" without needing a browser.
	const shownPDF = http.StatusSeeOther
	for _, c := range []struct {
		who, path string
		want      int
	}{
		{"primary manager", "/desk", http.StatusOK},
		{"primary admin", "/desk", http.StatusOK},
		{"admin by global grant", "/desk", http.StatusOK},
		{"manager by global grant", "/desk", http.StatusOK},
		{"editor by global grant", "/desk", http.StatusForbidden},
		{"grants in one tenant", "/desk", http.StatusForbidden},
		{"tenant membership role", "/desk", http.StatusForbidden},
		{"expired global grants", "/desk", http.StatusForbidden},
		{"no role", "/desk", http.StatusForbidden},

		// A custom role is matched by name: an admin does not pass it, by
		// the primary column or by grant.
		{"custom role global grant", "/ops", http.StatusOK},
		{"primary admin", "/ops", http.StatusForbidden},
		{"admin by global grant", "/ops", http.StatusForbidden},
		{"grants in one tenant", "/ops", http.StatusForbidden},
		{"expired global grants", "/ops", http.StatusForbidden},

		{"primary manager", "/pdf/pdfdesk", shownPDF},
		{"manager by global grant", "/pdf/pdfdesk", shownPDF},
		{"admin by global grant", "/pdf/pdfdesk", shownPDF},
		{"grants in one tenant", "/pdf/pdfdesk", http.StatusForbidden},
		{"tenant membership role", "/pdf/pdfdesk", http.StatusForbidden},
		{"no role", "/pdf/pdfdesk", http.StatusForbidden},

		// role="admin, ops" is any-of on the PDF route as on the page.
		{"primary admin", "/pdf/pdfstaff", shownPDF},
		{"admin by global grant", "/pdf/pdfstaff", shownPDF},
		{"custom role global grant", "/pdf/pdfstaff", shownPDF},
		{"primary manager", "/pdf/pdfstaff", http.StatusForbidden},
		{"grants in one tenant", "/pdf/pdfstaff", http.StatusForbidden},
	} {
		if got := get(c.who, c.path); got != c.want {
			t.Errorf("%s on %s = %d, want %d", c.who, c.path, got, c.want)
		}
	}
}
