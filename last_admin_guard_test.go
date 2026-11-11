//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The last-admin guard counted every unexpired admin grant and every admin
// row (round 1105 F3/F4). The only durable admin could demote or un-grant
// themselves while someone held a two-minute admin grant, and the app had no
// admin once it lapsed; the last admin could also delete or purge their own
// account. These tests drive each door with that setup.

type lastAdminFixture struct {
	t   *testing.T
	app *App
	db  *sql.DB
	mux *http.ServeMux
}

func newLastAdminFixture(t *testing.T) *lastAdminFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour}
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
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, app)
	RegisterRoleRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	// boss (1) is the only usable durable admin. The others look like admins
	// to the old count: a deactivated admin, an admin held at a temporary
	// password, and staff (6) who is about to get a short admin grant.
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, role, verified, deactivated_at, password_change_required) VALUES
		(1, 'boss', 'boss@example.com', 'admin', 1, NULL, 0),
		(2, 'gone', 'gone@example.com', 'admin', 1, '2026-01-01 00:00:00', 0),
		(3, 'pending', 'pending@example.com', 'admin', 1, NULL, 1),
		(6, 'staff', 'staff@example.com', 'user', 1, NULL, 0)`)
	return &lastAdminFixture{t: t, app: app, db: db, mux: mux}
}

func (f *lastAdminFixture) session(uid int64, email string) string {
	f.t.Helper()
	sid := CreateSession(f.db, uid, email, "", time.Hour)
	if sid == "" {
		f.t.Fatal("no session")
	}
	return sid
}

// form posts a form with the session cookie and its CSRF token.
func (f *lastAdminFixture) form(sid, path string, values url.Values, header ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	values.Set("_csrf", authMintCSRFToken(sid))
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

// api sends a JSON request with the session as a Bearer token.
func (f *lastAdminFixture) api(sid, method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func (f *lastAdminFixture) role(id int64) string {
	var r sql.NullString
	f.db.QueryRow("SELECT role FROM _benmore_users WHERE id = ?", id).Scan(&r)
	return r.String
}

// adminGrant describes user id's global admin grant: "" (none), "durable" or
// "expires".
func (f *lastAdminFixture) adminGrant(id int64) string {
	var exp sql.NullString
	err := f.db.QueryRow("SELECT expires_at FROM _benmore_user_roles WHERE user_id = ? AND role = 'admin' AND group_id IS NULL", id).Scan(&exp)
	switch {
	case err != nil:
		return ""
	case exp.Valid:
		return "expires"
	}
	return "durable"
}

func (f *lastAdminFixture) live(id int64) bool {
	var n int
	f.db.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND deactivated_at IS NULL AND email IS NOT NULL", id).Scan(&n)
	return n == 1
}

func soon(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

func TestLastAdminGuardSetRoleIgnoresTimeBoundedAndUnusableAdmins(t *testing.T) {
	f := newLastAdminFixture(t)
	boss := f.session(1, "boss@example.com")

	// F3 repro 1: boss gives staff a 2-minute admin grant, then demotes
	// himself. The old guard counted the grant (and the deactivated and
	// pending admins); the app had no admin two minutes later.
	if w := f.api(boss, http.MethodPost, "/api/_auth/users/6/roles", `{"role":"admin","expires_at":"`+soon(2*time.Minute)+`"}`); w.Code != http.StatusOK {
		t.Fatalf("short grant: %d %s", w.Code, w.Body.String())
	}
	w := f.form(boss, "/_admin/set-role", url.Values{"user_id": {"1"}, "role": {"user"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "last active admin") || f.role(1) != "admin" {
		t.Fatalf("the only durable admin demoted himself beside a 2-minute grant: %d %q, role now %q", w.Code, w.Body.String(), f.role(1))
	}

	// The time-bounded admin cannot demote the durable one either: the app
	// would be left with an admin that expires.
	temp := f.session(6, "staff@example.com")
	w = f.form(temp, "/_admin/set-role", url.Values{"user_id": {"1"}, "role": {"user"}})
	if w.Code != http.StatusBadRequest || f.role(1) != "admin" {
		t.Fatalf("a time-bounded admin demoted the last durable admin: %d %q, role now %q", w.Code, w.Body.String(), f.role(1))
	}
	var audited int
	f.db.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'role_changed'").Scan(&audited)
	if audited != 0 {
		t.Fatalf("refused role changes were audited as made: %d", audited)
	}

	// A durable grant for staff counts: now boss may step down.
	if w := f.api(boss, http.MethodPost, "/api/_auth/users/6/roles", `{"role":"admin"}`); w.Code != http.StatusOK || f.adminGrant(6) != "durable" {
		t.Fatalf("durable grant: %d %s (%s)", w.Code, w.Body.String(), f.adminGrant(6))
	}
	if w := f.form(boss, "/_admin/set-role", url.Values{"user_id": {"1"}, "role": {"user"}}); w.Code != http.StatusSeeOther || f.role(1) != "user" {
		t.Fatalf("stepping down beside a durable admin: %d %q, role %q", w.Code, w.Body.String(), f.role(1))
	}
}

func TestLastAdminGuardRoleAPIIgnoresTimeBoundedAdmins(t *testing.T) {
	f := newLastAdminFixture(t)
	// F3 repro 2: boss holds admin only through a durable global grant.
	mustExec(t, f.db, `UPDATE _benmore_users SET role = 'user' WHERE id = 1`)
	mustExec(t, f.db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (1, 'admin', NULL, NULL)`)
	boss := f.session(1, "boss@example.com")
	if w := f.api(boss, http.MethodPost, "/api/_auth/users/6/roles", `{"role":"admin","expires_at":"`+soon(75*time.Second)+`"}`); w.Code != http.StatusOK {
		t.Fatalf("short grant: %d %s", w.Code, w.Body.String())
	}

	refused := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "last active admin") || f.adminGrant(1) != "durable" {
			t.Fatalf("%s: %d %s, boss's grant now %q", what, w.Code, w.Body.String(), f.adminGrant(1))
		}
	}
	refused("revoke beside a 75-second grant", f.api(boss, http.MethodDelete, "/api/_auth/users/1/roles/admin", ""))
	// group_id=all deletes the global grant too; it used to skip the guard.
	refused("revoke with group_id=all", f.api(boss, http.MethodDelete, "/api/_auth/users/1/roles/admin?group_id=all", ""))
	// Putting the grant on a timer ends it later (or, with a past time, now).
	refused("expiry via PATCH", f.api(boss, http.MethodPatch, "/api/_auth/users/1/roles/admin", `{"expires_at":"`+soon(time.Hour)+`"}`))
	refused("past expiry via PATCH", f.api(boss, http.MethodPatch, "/api/_auth/users/1/roles/admin", `{"expires_at":"2020-01-01T00:00:00Z"}`))
	refused("expiry via re-grant", f.api(boss, http.MethodPost, "/api/_auth/users/1/roles", `{"role":"admin","expires_at":"`+soon(time.Hour)+`"}`))

	// A group-scoped admin grant never made anyone an app admin: revoking
	// one stays allowed.
	mustExec(t, f.db, `INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (1, 'admin', 'g1')`)
	if w := f.api(boss, http.MethodDelete, "/api/_auth/users/1/roles/admin?group_id=g1", ""); w.Code != http.StatusOK {
		t.Fatalf("group-scoped revoke: %d %s", w.Code, w.Body.String())
	}

	// A second durable admin (by the role column) lifts the guard.
	mustExec(t, f.db, `INSERT INTO _benmore_users (id, username, email, role, verified) VALUES (7, 'second', 'second@example.com', 'admin', 1)`)
	if w := f.api(boss, http.MethodDelete, "/api/_auth/users/1/roles/admin", ""); w.Code != http.StatusOK || f.adminGrant(1) != "" {
		t.Fatalf("revoke beside a durable admin: %d %s, grant %q", w.Code, w.Body.String(), f.adminGrant(1))
	}
}

func TestLastAdminGuardDeleteAccount(t *testing.T) {
	f := newLastAdminFixture(t)
	if w := f.api(f.session(1, "boss@example.com"), http.MethodPost, "/api/_auth/users/6/roles", `{"role":"admin","expires_at":"`+soon(2*time.Minute)+`"}`); w.Code != http.StatusOK {
		t.Fatalf("short grant: %d %s", w.Code, w.Body.String())
	}
	boss := f.session(1, "boss@example.com")

	// F4 repro 1: the form post gets the settings page with the reason.
	w := f.form(boss, "/settings/delete-account", url.Values{"confirm": {"DELETE"}})
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.Contains(loc, "error=") || !strings.Contains(loc, "last+admin") || !f.live(1) {
		t.Fatalf("the last admin deleted their account: %d %q, live=%v", w.Code, loc, f.live(1))
	}
	// A page that asks for JSON gets the reason as JSON.
	w = f.form(boss, "/settings/delete-account", url.Values{"confirm": {"DELETE"}}, "Accept", "application/json")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "last admin") || !f.live(1) {
		t.Fatalf("JSON delete: %d %s, live=%v", w.Code, w.Body.String(), f.live(1))
	}
	var sessions int
	f.db.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = 1").Scan(&sessions)
	if sessions == 0 {
		t.Fatal("the refused deletion still ended the admin's sessions")
	}

	// A plain user deletes their account as before.
	staff := f.session(6, "staff@example.com")
	if w := f.form(staff, "/settings/delete-account", url.Values{"confirm": {"DELETE"}}); w.Code != http.StatusSeeOther || f.live(6) {
		t.Fatalf("a member could not delete their account: %d, live=%v", w.Code, f.live(6))
	}

	// With another durable admin, the admin may go.
	mustExec(t, f.db, `INSERT INTO _benmore_users (id, username, email, role, verified) VALUES (7, 'second', 'second@example.com', 'admin', 1)`)
	if w := f.form(boss, "/settings/delete-account", url.Values{"confirm": {"DELETE"}}); w.Code != http.StatusSeeOther || f.live(1) {
		t.Fatalf("delete beside a durable admin: %d %q, live=%v", w.Code, w.Header().Get("Location"), f.live(1))
	}
}

func TestLastAdminGuardPurgeCurrentUser(t *testing.T) {
	f := newLastAdminFixture(t)
	mustExec(t, f.db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (6, 'admin', NULL, datetime('now', '+2 minutes'))`)
	boss := f.session(1, "boss@example.com")
	flow := &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	purge := func(sid string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		executeFlowHTTP(f.app, flow, w, r)
		return w
	}

	// F4 repro 2. The step refuses inside the flow's transaction; the
	// answer is a 409 naming the reason (a purge refusal, not a 500).
	w := purge(boss)
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusConflict || body.Error != "last_admin" || !f.live(1) || !strings.Contains(body.Message, "last active admin") {
		t.Fatalf("the last admin purged their account: %d %s, live=%v", w.Code, w.Body.String(), f.live(1))
	}
	var sessions int
	f.db.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = 1").Scan(&sessions)
	if sessions == 0 {
		t.Fatal("the refused purge still ended the admin's sessions")
	}

	// Once staff's grant has no expiry, boss may go.
	mustExec(t, f.db, `UPDATE _benmore_user_roles SET expires_at = NULL WHERE user_id = 6`)
	if w := purge(boss); w.Code != http.StatusOK || f.live(1) {
		t.Fatalf("purge beside a durable admin: %d %s, live=%v", w.Code, w.Body.String(), f.live(1))
	}
}

// The admin panel's inline editor writes deactivated_at (and verified) on a
// _benmore_users row, and its delete removes the row when the app declares
// the table: both would remove the last admin.
func TestLastAdminGuardAdminPanelDeactivateAndDelete(t *testing.T) {
	f := newLastAdminFixture(t)
	f.app.Design.Auth["require_verified"] = "true"
	cols, err := GetTableColumns(f.db, "_benmore_users")
	if err != nil {
		t.Fatal(err)
	}
	f.app.Tables = append(f.app.Tables, Table{Name: "_benmore_users", Columns: cols})
	boss := f.session(1, "boss@example.com")

	for _, change := range []url.Values{
		{"deactivated_at": {"2026-01-01 00:00:00"}},
		{"verified": {"0"}}, // require_verified: an unverified admin cannot sign in
	} {
		w := f.form(boss, "/_admin/api/_benmore_users/update/1", change)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "last active admin") || !f.live(1) {
			t.Fatalf("admin panel %v on the last admin: %d %s, live=%v", change, w.Code, w.Body.String(), f.live(1))
		}
	}
	var verified int
	f.db.QueryRow("SELECT verified FROM _benmore_users WHERE id = 1").Scan(&verified)
	if verified != 1 {
		t.Fatal("the refused edit unverified the last admin")
	}
	// Edits that keep the account an admin pass.
	if w := f.form(boss, "/_admin/api/_benmore_users/update/1", url.Values{"first_name": {"Boss"}}); w.Code != http.StatusOK {
		t.Fatalf("plain edit of the last admin: %d %s", w.Code, w.Body.String())
	}
	if w := f.form(boss, "/_admin/api/_benmore_users/delete/1", url.Values{}); w.Code != http.StatusConflict || !f.live(1) {
		t.Fatalf("admin panel deleted the last admin: %d %s, live=%v", w.Code, w.Body.String(), f.live(1))
	}

	// With a second durable admin the same deactivation goes through.
	mustExec(t, f.db, `INSERT INTO _benmore_users (id, username, email, role, verified) VALUES (7, 'second', 'second@example.com', 'admin', 1)`)
	if w := f.form(boss, "/_admin/api/_benmore_users/update/1", url.Values{"deactivated_at": {"2026-01-01 00:00:00"}}); w.Code != http.StatusOK || f.live(1) {
		t.Fatalf("deactivation beside a durable admin: %d %s, live=%v", w.Code, w.Body.String(), f.live(1))
	}
}

// Which accounts count. Only a usable account holding admin durably does.
func TestRefuseLastDurableAdminCounting(t *testing.T) {
	f := newLastAdminFixture(t)
	last := func() bool {
		t.Helper()
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		err = refuseLastDurableAdmin(f.app, tx, 1, dropsAccount)
		if err != nil && err != errLastDurableAdmin {
			t.Fatal(err)
		}
		return err == errLastDurableAdmin
	}
	if !last() {
		t.Fatal("boss beside a deactivated and a pending admin is not the last admin")
	}
	for _, other := range []string{
		`INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (6, 'admin', NULL, datetime('now', '+1 day'))`,
		`INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (6, 'admin', 'g1', NULL)`,
		`INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (2, 'admin', NULL, NULL)`,
		`INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (99, 'admin', NULL, NULL)`,
	} {
		mustExec(t, f.db, other)
		if !last() {
			t.Fatalf("counted as another admin: %s", other)
		}
	}
	// Under require_verified an unverified admin cannot sign in.
	f.app.Design.Auth["require_verified"] = "true"
	mustExec(t, f.db, `INSERT INTO _benmore_users (id, username, email, role, verified) VALUES (8, 'unverified', 'unverified@example.com', 'admin', 0)`)
	if !last() {
		t.Fatal("an unverified admin counted under require_verified")
	}
	f.app.Design.Auth["require_verified"] = ""
	if last() {
		t.Fatal("a verified-or-not admin did not count without require_verified")
	}
	mustExec(t, f.db, `DELETE FROM _benmore_users WHERE id = 8`)
	mustExec(t, f.db, `INSERT INTO _benmore_user_roles (user_id, role, group_id, expires_at) VALUES (6, 'admin', NULL, NULL) ON CONFLICT(user_id, role, IFNULL(group_id, '')) DO UPDATE SET expires_at = NULL`)
	if last() {
		t.Fatal("a durable global grant did not count")
	}
}
