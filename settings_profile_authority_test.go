//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// Public signup drops every auth.signup_fields column that carries authority
// (signupFieldRefusal): the account-state columns and the groups: tenant
// columns. The profile API made every signup_fields (and profile_fields)
// column self-editable after signup, so the same columns signup refused were
// writable one request later. email_grandfathered lets an unverified account
// keep email-keyed tenant memberships and shares; the tenant key column binds
// the account to a tenant.
func TestProfilePatchRefusesSignupRefusedColumns(t *testing.T) {
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
	mustExec(t, db, "ALTER TABLE _benmore_users ADD COLUMN org_id TEXT DEFAULT ''")
	mustExec(t, db, "ALTER TABLE _benmore_users ADD COLUMN company TEXT DEFAULT ''")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{
		"signup_fields":  "company,email_grandfathered,org_id",
		"profile_fields": "last_login_at",
	}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, email_grandfathered) VALUES ('m', 'm@example.com', 'x', 'user', 0)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(db, uid, "m@example.com", "", time.Hour)

	for _, body := range []map[string]any{
		{"email_grandfathered": 1},
		{"org_id": "tenant-b"},
		{"last_login_at": "2030-01-01 00:00:00"},
	} {
		if w := profilePatch(t, mux, sid, body); w.Code != http.StatusForbidden {
			t.Errorf("PATCH %v: %d %s", body, w.Code, w.Body.String())
		}
	}
	var grandfathered int
	var org string
	var lastLogin sql.NullString
	db.QueryRow("SELECT email_grandfathered, org_id, last_login_at FROM _benmore_users WHERE id = ?", uid).Scan(&grandfathered, &org, &lastLogin)
	if grandfathered != 0 || org != "" || lastLogin.Valid {
		t.Fatalf("authority columns written: grandfathered=%d org=%q last_login=%v", grandfathered, org, lastLogin)
	}

	// A plain profile column from signup_fields stays editable.
	if w := profilePatch(t, mux, sid, map[string]any{"company": "Acme"}); w.Code != http.StatusOK {
		t.Fatalf("plain signup field refused: %d %s", w.Code, w.Body.String())
	}
}
