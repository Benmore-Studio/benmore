//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A membership row used to grant access for as long as it existed: removing
// someone meant deleting the row, a soft-deleted row still counted, there
// was no way to suspend a member, and a session kept its cached tenant even
// after the row was gone. Only live rows grant membership now - not
// soft-deleted, and active per groups.active_field - on every surface.
func TestMembershipRequiresLiveRow(t *testing.T) {
	app, mux := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	for _, stmt := range []string{
		`ALTER TABLE members ADD COLUMN active INTEGER DEFAULT 1`,
		`ALTER TABLE members ADD COLUMN deleted_at DATETIME`,
		`ALTER TABLE room_members ADD COLUMN deleted_at DATETIME`,
	} {
		mustExec(t, app.DB, stmt)
	}
	for i, tbl := range app.Tables {
		if tbl.Name == "members" || tbl.Name == "room_members" {
			cols, err := GetTableColumns(app.DB, tbl.Name)
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	app.Group.ActiveField = "active"
	app.WSRooms = []WSRoomRule{{Pattern: "room-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	sid := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	mustExec(t, app.DB, "INSERT INTO members (id, org_id, email, active) VALUES (1, 'tenant-a', 'alice@example.com', 1)")
	passwordChangeExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (1, ?)", uid)

	get := func(path string) string {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Body.String()
	}
	switchTo := func(group string) int {
		form := url.Values{"group_id": {group}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		handleSwitchGroup(w, r, app)
		return w.Code
	}
	joinRoom := func() bool {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		session := getSession(app, r)
		c := newWSTestClient(realtimeAppID(app.Dir), uid, session.EffectiveGroupID())
		c.principal = realtimePrincipal{app: app, request: r, session: session}
		return wsRoomAuthorized(app, c, "room-1")
	}

	// Control: a live membership resolves the tenant, the room and the rows.
	if !strings.Contains(get("/api/orgdocs"), "private-a") || !strings.Contains(get("/api/rooms"), "private-room") || !joinRoom() {
		t.Fatal("live membership did not grant access")
	}

	for _, change := range []string{
		"UPDATE members SET active = 0 WHERE id = 1",
		"UPDATE members SET active = 1, deleted_at = datetime('now') WHERE id = 1",
	} {
		mustExec(t, app.DB, change)
		if g := ResolveGroupID(app.DB, app.Group, "alice@example.com"); g != "" {
			t.Fatalf("%s: tenant still resolved (%q)", change, g)
		}
		// The session that already cached tenant-a loses it too.
		if body := get("/api/orgdocs"); strings.Contains(body, "private-a") {
			t.Fatalf("%s: cached session still reads the tenant: %s", change, body)
		}
		if code := switchTo("tenant-a"); code != http.StatusForbidden {
			t.Fatalf("%s: _switch_group into the tenant returned %d", change, code)
		}
	}

	// A soft-deleted member-of / ws_rooms membership grants nothing.
	mustExec(t, app.DB, "UPDATE room_members SET deleted_at = datetime('now')")
	if body := get("/api/rooms"); strings.Contains(body, "private-room") {
		t.Fatalf("soft-deleted room membership still reads the room: %s", body)
	}
	if joinRoom() {
		t.Fatal("soft-deleted room membership still joins the WS room")
	}

	// Restoring the row restores access.
	mustExec(t, app.DB, "UPDATE members SET deleted_at = NULL WHERE id = 1")
	mustExec(t, app.DB, "UPDATE room_members SET deleted_at = NULL")
	if code := switchTo("tenant-a"); code != http.StatusSeeOther {
		t.Fatalf("switch back into a live membership: %d", code)
	}
	if !strings.Contains(get("/api/orgdocs"), "private-a") || !strings.Contains(get("/api/rooms"), "private-room") {
		t.Fatal("restored membership did not grant access again")
	}

	// active_field naming a missing or malformed column fails closed.
	for _, bad := range []string{"is_enabled", "active; --"} {
		app.Group.ActiveField = bad
		if g := ResolveGroupID(app.DB, app.Group, "alice@example.com"); g != "" {
			t.Fatalf("active_field %q: membership resolved", bad)
		}
	}
	if _, _, err := parseAppConfigDocument([]byte("groups:\n  table: members\n  key: org_id\n  user_field: email\n  active_field: \"active; --\"\n")); err == nil {
		t.Fatal("malformed groups.active_field accepted at load")
	}
}
