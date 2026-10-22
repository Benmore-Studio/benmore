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

// An email-keyed membership counts for a session only once THAT session's
// account has proven the address (groupMemberValue / sessionGrantEmail), and
// the per-request revalidation clears a tenant that fails the check. The
// lazy re-resolution right after it used ResolveGroupID, whose predicate is
// "some account with this email is verified". Where two accounts share an
// address case-insensitively - a database whose NOCASE email index could not
// be created because it already held case variants - an unverified signup
// of the lower-case variant was put back into the verified owner's tenant on
// every request, with that member's tenant role.
func TestUnverifiedSessionDoesNotInheritAnotherAccountsEmailTenant(t *testing.T) {
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
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	// A legacy database: case variants existed, so the NOCASE unique index
	// was never created.
	mustExec(t, db, "DROP INDEX IF EXISTS idx_benmore_users_email_nocase")
	mustExec(t, db, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, member_role TEXT)")
	mustExec(t, db, "INSERT INTO members (org_id, email, member_role) VALUES ('tenant-a', 'owner@example.com', 'org_admin')")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email", RoleField: "member_role"}
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour

	// The member, stored with the mixed case of an older signup, verified.
	mustExec(t, db, "INSERT INTO _benmore_users (username, email, verified) VALUES ('owner', 'Owner@Example.com', 1)")
	// A later, unverified signup of the normalized address.
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, verified, email_grandfathered) VALUES ('squatter', 'owner@example.com', 0, 0)")
	if err != nil {
		t.Fatalf("fixture: case-variant signup refused: %v", err)
	}
	squatter, _ := res.LastInsertId()
	sid := CreateSession(db, squatter, "owner@example.com", ResolveGroupID(db, app.Group, "owner@example.com"), time.Hour)

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
		s := getSession(app, r)
		if s == nil {
			t.Fatal("fixture: the unverified session should resolve")
		}
		if s.EffectiveGroupID() != "" {
			t.Fatalf("request %d: unverified account placed in tenant %q", i, s.EffectiveGroupID())
		}
		for _, role := range s.Roles {
			if role == "org_admin" {
				t.Fatalf("request %d: unverified account holds the member's tenant role", i)
			}
		}
	}
}
