//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// POST /_admin/set-role rewrites a user's primary role. It had neither the
// last-admin guard the role-grant API applies (an admin could demote
// themselves out of the app's only admin seat) nor an audit record, so a role
// change made through the admin panel left no trail.
func TestAdminSetRoleGuardsLastAdminAndAudits(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAuditLogTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)

	mustExec(t, db, "INSERT INTO _benmore_users (id, username, email, role) VALUES (1, 'boss', 'boss@example.com', 'admin'), (2, 'member', 'member@example.com', 'user')")
	sid := CreateSession(db, 1, "boss@example.com", "", time.Hour)
	setRole := func(uid, role string) int {
		form := url.Values{"user_id": {uid}, "role": {role}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/_admin/set-role", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	role := func(id int) string {
		var r string
		db.QueryRow("SELECT role FROM _benmore_users WHERE id = ?", id).Scan(&r)
		return r
	}

	if code := setRole("1", "user"); code != http.StatusBadRequest || role(1) != "admin" {
		t.Fatalf("the only admin demoted themselves: %d, role now %q", code, role(1))
	}
	if code := setRole("2", "admin"); code != http.StatusSeeOther || role(2) != "admin" {
		t.Fatalf("promotion: %d, role %q", code, role(2))
	}
	var audited int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'role_changed' AND table_name = '_benmore_users' AND row_id = '2' AND user_id = 1").Scan(&audited)
	if audited != 1 {
		t.Fatal("the role change was not audited")
	}
	// With another admin in place, stepping down is allowed.
	if code := setRole("1", "user"); code != http.StatusSeeOther || role(1) != "user" {
		t.Fatalf("stepping down beside another admin: %d, role %q", code, role(1))
	}
}
