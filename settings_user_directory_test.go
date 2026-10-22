//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func userDirectoryFixture(t *testing.T, mode string, group *GroupConfig) (*App, *http.ServeMux) {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	EnsureAuditLogTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.Group = group
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"_benmore_users": {OpRead: mode}}}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES
		(1, 'boss', 'boss@corp.example', 'x', 'admin', 1),
		(2, 'staff', 'staff@corp.example', 'x', 'staff', 1),
		(3, 'member', 'member@corp.example', 'x', 'user', 1),
		(4, 'granted', 'granted@corp.example', 'x', 'user', 1),
		(5, 'tenantstaff', 'tenantstaff@corp.example', 'x', 'user', 1),
		(6, 'other', 'other@corp.example', 'x', 'user', 1),
		(7, 'gone', 'gone@corp.example', 'x', 'user', 1)`)
	mustExec(t, app.DB, "UPDATE _benmore_users SET deactivated_at = '2026-01-01' WHERE id = 7")
	mux := http.NewServeMux()
	registerSettingsRoutes(mux, app)
	return app, mux
}

func directoryList(t *testing.T, app *App, mux *http.ServeMux, userID int64, email, groupID string) (int, []int) {
	t.Helper()
	token := CreateSession(app.DB, userID, email, groupID, time.Hour)
	r := httptest.NewRequest(http.MethodGet, "/api/_auth/users", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var out struct {
		Users []map[string]any `json:"users"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	var ids []int
	for _, u := range out.Users {
		if id, ok := u["id"].(float64); ok {
			ids = append(ids, int(id))
		}
	}
	sort.Ints(ids)
	return w.Code, ids
}

func directoryLookup(app *App, mux *http.ServeMux, userID int64, email, groupID string, target int) int {
	token := CreateSession(app.DB, userID, email, groupID, time.Hour)
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/_auth/users/%d", target), nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Code
}

// `access: _benmore_users: read: role:<x>` is an accepted directory mode, but
// neither endpoint implemented it: the list was empty for everyone, admins
// included, and every lookup but one's own answered 404.
func TestUserDirectoryRoleMode(t *testing.T) {
	group := &GroupConfig{Table: "members", Key: "org_id", UserField: "email", RoleField: "member_role"}
	app, mux := userDirectoryFixture(t, "role:staff,support", group)
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, member_role TEXT)")
	// A global grant of the role, and a tenant role of the same name.
	mustExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (4, 'support')")
	mustExec(t, app.DB, "INSERT INTO members (org_id, email, member_role) VALUES ('tenant-a', 'tenantstaff@corp.example', 'staff'), ('tenant-a', 'other@corp.example', 'viewer')")
	everyone := []int{1, 2, 3, 4, 5, 6}

	for _, c := range []struct {
		name  string
		id    int64
		email string
		gid   string
		want  []int
	}{
		{"admin", 1, "boss@corp.example", "", everyone},
		{"primary role", 2, "staff@corp.example", "", everyone},
		{"global grant", 4, "granted@corp.example", "", everyone},
		{"no listed role", 3, "member@corp.example", "", []int{3}},
		// A role held only inside one tenant doesn't open every tenant's users.
		{"tenant role of the same name", 5, "tenantstaff@corp.example", "tenant-a", []int{5}},
	} {
		code, ids := directoryList(t, app, mux, c.id, c.email, c.gid)
		if code != http.StatusOK || fmt.Sprint(ids) != fmt.Sprint(c.want) {
			t.Errorf("%s: list = %d %v, want %v", c.name, code, ids, c.want)
		}
	}
	if code := directoryLookup(app, mux, 2, "staff@corp.example", "", 3); code != http.StatusOK {
		t.Errorf("a role holder's lookup of another user = %d", code)
	}
	if code := directoryLookup(app, mux, 2, "staff@corp.example", "", 7); code != http.StatusNotFound {
		t.Errorf("a deactivated account was visible to a role holder: %d", code)
	}
	if code := directoryLookup(app, mux, 3, "member@corp.example", "", 2); code != http.StatusNotFound {
		t.Errorf("a user without the role looked up another user: %d", code)
	}
	if code := directoryLookup(app, mux, 5, "tenantstaff@corp.example", "tenant-a", 6); code != http.StatusNotFound {
		t.Errorf("a tenant-role holder looked up another user through a global role gate: %d", code)
	}
	if code := directoryLookup(app, mux, 3, "member@corp.example", "", 3); code != http.StatusOK {
		t.Errorf("own lookup = %d", code)
	}
}

// The group directory joined _benmore_users to the membership table on a
// column of the SAME NAME on both sides, which exists on the users table only
// when groups.user_field is literally `email`: a `member_email` column or a
// user-id column failed the query (500 on the list, 404 on every lookup).
func TestUserDirectoryGroupModeMatchesTheMembershipColumn(t *testing.T) {
	for _, c := range []struct {
		name  string
		field string
		ddl   string
		rows  string
	}{
		{"email column under another name", "member_email", "member_email TEXT",
			"('tenant-a', 'member@corp.example'), ('tenant-a', 'other@corp.example'), ('tenant-b', 'staff@corp.example'), ('tenant-a', 'gone@corp.example')"},
		{"user id column", "user_id", "user_id INTEGER",
			"('tenant-a', 3), ('tenant-a', 6), ('tenant-b', 2), ('tenant-a', 7)"},
	} {
		group := &GroupConfig{Table: "members", Key: "org_id", UserField: c.field}
		app, mux := userDirectoryFixture(t, "group", group)
		mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, "+c.ddl+")")
		mustExec(t, app.DB, "INSERT INTO members (org_id, "+c.field+") VALUES "+c.rows)

		code, ids := directoryList(t, app, mux, 3, "member@corp.example", "tenant-a")
		if code != http.StatusOK || fmt.Sprint(ids) != fmt.Sprint([]int{3, 6}) {
			t.Errorf("%s: a member's directory = %d %v, want their tenant's active members [3 6]", c.name, code, ids)
		}
		if code := directoryLookup(app, mux, 3, "member@corp.example", "tenant-a", 6); code != http.StatusOK {
			t.Errorf("%s: lookup of a fellow member = %d", c.name, code)
		}
		if code := directoryLookup(app, mux, 3, "member@corp.example", "tenant-a", 2); code != http.StatusNotFound {
			t.Errorf("%s: lookup of another tenant's member = %d", c.name, code)
		}
		code, ids = directoryList(t, app, mux, 2, "staff@corp.example", "tenant-b")
		if code != http.StatusOK || fmt.Sprint(ids) != fmt.Sprint([]int{2}) {
			t.Errorf("%s: the other tenant's directory = %d %v, want [2]", c.name, code, ids)
		}
	}
}

// The group directory pages by user. Its query is a top-level EXISTS over the
// membership table with LIMIT and OFFSET, and SQLite 3.51 counted OFFSET
// against the membership rows it joined: a member with two live rows (invited
// twice) pushed the next page one user early, and a page past the end still
// answered rows. The engine in go.mod (3.53) counts result rows.
func TestUserDirectoryGroupModePagesByUserNotByMembershipRow(t *testing.T) {
	for _, c := range []struct {
		name  string
		field string
		ddl   string
		rows  string
	}{
		{"email column", "member_email", "member_email TEXT",
			"('tenant-a', 'staff@corp.example'), ('tenant-a', 'staff@corp.example'), ('tenant-a', 'member@corp.example'), ('tenant-a', 'member@corp.example'), " +
				"('tenant-a', 'granted@corp.example'), ('tenant-a', 'tenantstaff@corp.example'), ('tenant-a', 'other@corp.example'), ('tenant-b', 'boss@corp.example')"},
		{"user id column", "user_id", "user_id INTEGER",
			"('tenant-a', 2), ('tenant-a', 2), ('tenant-a', 3), ('tenant-a', 3), ('tenant-a', 4), ('tenant-a', 5), ('tenant-a', 6), ('tenant-b', 1)"},
	} {
		group := &GroupConfig{Table: "members", Key: "org_id", UserField: c.field}
		app, mux := userDirectoryFixture(t, "group", group)
		mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, "+c.ddl+")")
		mustExec(t, app.DB, "CREATE INDEX idx_members_org_user ON members(org_id, "+c.field+")")
		mustExec(t, app.DB, "INSERT INTO members (org_id, "+c.field+") VALUES "+c.rows)
		token := CreateSession(app.DB, 3, "member@corp.example", "tenant-a", time.Hour)
		page := func(limit, offset int) []int {
			t.Helper()
			r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/_auth/users?limit=%d&offset=%d", limit, offset), nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("%s: limit %d offset %d = %d %s", c.name, limit, offset, w.Code, w.Body.String())
			}
			var out struct {
				Users []map[string]any `json:"users"`
			}
			json.Unmarshal(w.Body.Bytes(), &out)
			ids := []int{}
			for _, u := range out.Users {
				if id, ok := u["id"].(float64); ok {
					ids = append(ids, int(id))
				}
			}
			return ids
		}
		// tenant-a's members in id order: 2 3 4 5 6 (2 and 3 hold two rows each).
		for _, p := range []struct {
			limit, offset int
			want          []int
		}{
			{2, 0, []int{2, 3}},
			{2, 2, []int{4, 5}},
			{2, 4, []int{6}},
			{2, 5, []int{}},
			{50, 1, []int{3, 4, 5, 6}},
		} {
			if got := page(p.limit, p.offset); fmt.Sprint(got) != fmt.Sprint(p.want) {
				t.Errorf("%s: limit %d offset %d = %v, want %v", c.name, p.limit, p.offset, got, p.want)
			}
		}
	}
}

// password_change_required marks an account that still holds a temporary
// password (often a shared default handed out by provisioning). The directory
// returned it for every listed user, which told any caller who passed the
// mode exactly which accounts to try that password on.
func TestUserDirectoryHidesPendingPasswordFlagFromOtherUsers(t *testing.T) {
	app, mux := userDirectoryFixture(t, "everyone", nil)
	mustExec(t, app.DB, "UPDATE _benmore_users SET password_change_required = 1 WHERE id IN (3, 6)")
	fetch := func(userID int64, email, path string) string {
		token := CreateSession(app.DB, userID, email, "", time.Hour)
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s as user %d: %d %s", path, userID, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	// rows returns the user rows of a list or single-lookup response by id.
	rows := func(body string) map[int]map[string]any {
		var list struct {
			Users []map[string]any `json:"users"`
		}
		var one map[string]any
		json.Unmarshal([]byte(body), &list)
		json.Unmarshal([]byte(body), &one)
		if len(list.Users) == 0 && one["id"] != nil {
			list.Users = []map[string]any{one}
		}
		out := map[int]map[string]any{}
		for _, u := range list.Users {
			if id, ok := u["id"].(float64); ok {
				out[int(id)] = u
			}
		}
		return out
	}
	for _, path := range []string{"/api/_auth/users", "/api/_auth/users/6"} {
		asUser := rows(fetch(2, "staff@corp.example", path))
		if _, shown := asUser[6]["password_change_required"]; shown || asUser[6] == nil {
			t.Errorf("%s shows another account's pending-password flag to an ordinary user: %v", path, asUser[6])
		}
		// An admin manages accounts and keeps seeing it.
		if asAdmin := rows(fetch(1, "boss@corp.example", path)); asAdmin[6]["password_change_required"] != float64(1) {
			t.Errorf("%s no longer shows the flag to an admin: %v", path, asAdmin[6])
		}
	}
	// The caller's own row keeps it.
	if own := rows(fetch(2, "staff@corp.example", "/api/_auth/users")); own[2]["password_change_required"] == nil {
		t.Errorf("the caller's own row lost the flag: %v", own[2])
	}
}
