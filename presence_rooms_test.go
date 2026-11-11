//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func presenceFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app, _ := auditApp(t)
	EnsurePresenceTable(app.DB)
	mux := http.NewServeMux()
	RegisterPresenceRoutes(mux, app)
	return app, mux
}

func presencePost(mux *http.ServeMux, sid, slug, action string) int {
	body, _ := json.Marshal(map[string]string{"slug": slug, "action": action})
	req := httptest.NewRequest("POST", "/api/_presence/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	req.Header.Set("X-CSRF-Token", generateCSRFToken())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

func presenceList(t *testing.T, mux *http.ServeMux, sid, slug string) (int, []any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/_presence?slug="+url.QueryEscape(slug), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out struct {
		Members []any `json:"members"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.Members
}

// A presence slug that matches a declared ws_rooms pattern is a membership
// room, as it is for bm.room and bm.broadcast: a non-member can't join it or
// read who is in it.
func TestPresenceHonoursWSRoomMembership(t *testing.T) {
	app, mux := presenceFixture(t)
	app.WSRooms = []WSRoomRule{{Pattern: "huddle-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	outsider := createCrudScopeSession(t, app, "outsider@example.com", "user", "", "")
	memberID := GetSessionFromDB(app.DB, member).UserID
	mustExec(t, app.DB, "INSERT INTO room_members (id, room_id, member_id) VALUES (1, 1, "+itoa64(memberID)+")")

	if code := presencePost(mux, member, "huddle-1", "join"); code != 200 {
		t.Fatalf("member join: %d", code)
	}
	if code := presencePost(mux, outsider, "huddle-1", "join"); code != http.StatusForbidden {
		t.Fatalf("non-member join of a membership room: %d", code)
	}
	if code := presencePost(mux, outsider, "huddle-1", "heartbeat"); code != http.StatusForbidden {
		t.Fatalf("non-member heartbeat in a membership room: %d", code)
	}
	if code, members := presenceList(t, mux, outsider, "huddle-1"); code != http.StatusForbidden || len(members) != 0 {
		t.Fatalf("non-member read of a membership room: %d %v", code, members)
	}
	if code, members := presenceList(t, mux, member, "huddle-1"); code != 200 || len(members) != 1 {
		t.Fatalf("member read: %d %v", code, members)
	}
	// Slugs that match no pattern stay open, and leaving is always allowed.
	if code := presencePost(mux, outsider, "lobby", "join"); code != 200 {
		t.Fatalf("open slug join: %d", code)
	}
	if code := presencePost(mux, outsider, "huddle-1", "leave"); code != 200 {
		t.Fatalf("leave: %d", code)
	}
}

// Presence is keyed by the caller's effective tenant, the one every other
// per-tenant surface uses: an admin stepped into a tenant sees that
// tenant's presence, not their home group's.
func TestPresenceUsesEffectiveTenant(t *testing.T) {
	app, mux := presenceFixture(t)
	mustExec(t, app.DB, `INSERT INTO members (org_id, email) VALUES ('tenant-a', 'peer@example.com'), ('tenant-z', 'ops@example.com')`)
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "tenant-a", "")
	admin := createCrudScopeSession(t, app, "ops@example.com", "admin", "tenant-z", "tenant-a")
	if s := GetSessionFromDB(app.DB, admin); s == nil || s.EffectiveGroupID() != "tenant-a" {
		t.Fatalf("fixture: admin not stepped into tenant-a: %+v", s)
	}
	if code := presencePost(mux, peer, "huddle:42", "join"); code != 200 {
		t.Fatalf("peer join: %d", code)
	}
	if code, members := presenceList(t, mux, admin, "huddle:42"); code != 200 || len(members) != 1 {
		t.Fatalf("stepped-in admin sees %d member(s) (status %d), want tenant-a's 1", len(members), code)
	}
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func presencePostBody(t *testing.T, mux *http.ServeMux, sid, slug, action string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"slug": slug, "action": action})
	req := httptest.NewRequest("POST", "/api/_presence/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	req.Header.Set("X-CSRF-Token", generateCSRFToken())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Leaving is always allowed, so a member removed mid-session can clear its
// row. Its answer carried the room's member count for everyone, though: a
// caller the room refuses (403 on join, heartbeat and list) could poll
// `leave` to watch how many people are in it. A caller who is not a member
// of the room now gets the same answer without the count; members, and
// anyone on a slug no ws_rooms pattern matches, still get it.
func TestPresenceLeaveTellsNonMemberNoCount(t *testing.T) {
	app, mux := presenceFixture(t)
	app.WSRooms = []WSRoomRule{{Pattern: "huddle-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	second := createCrudScopeSession(t, app, "second@example.com", "user", "", "")
	outsider := createCrudScopeSession(t, app, "outsider@example.com", "user", "", "")
	mustExec(t, app.DB, "INSERT INTO room_members (id, room_id, member_id) VALUES (1, 1, "+itoa64(GetSessionFromDB(app.DB, member).UserID)+"), (2, 1, "+itoa64(GetSessionFromDB(app.DB, second).UserID)+")")
	for _, sid := range []string{member, second} {
		if code := presencePost(mux, sid, "huddle-1", "join"); code != 200 {
			t.Fatalf("member join: %d", code)
		}
	}

	code, out := presencePostBody(t, mux, outsider, "huddle-1", "leave")
	if code != 200 || out["ok"] != true {
		t.Fatalf("non-member leave: %d %v, want 200 ok", code, out)
	}
	if n, has := out["members"]; has {
		t.Fatalf("non-member leave answered members=%v for a room it may not list", n)
	}
	if out["heartbeat_s"] == nil || out["expires_in_s"] == nil {
		t.Fatalf("non-member leave answer lost its other fields: %v", out)
	}
	// The members are still listed: the outsider's leave removed no one.
	if code, members := presenceList(t, mux, member, "huddle-1"); code != 200 || len(members) != 2 {
		t.Fatalf("after a non-member leave the room lists %d member(s) (status %d), want 2", len(members), code)
	}

	// A member who leaves is told how many remain.
	code, out = presencePostBody(t, mux, second, "huddle-1", "leave")
	if code != 200 || out["members"] != float64(1) {
		t.Fatalf("member leave: %d %v, want members=1", code, out)
	}
	// A member removed from the room mid-session can still clear its row,
	// and learns no count.
	mustExec(t, app.DB, "DELETE FROM room_members WHERE id = 1")
	code, out = presencePostBody(t, mux, member, "huddle-1", "leave")
	if _, has := out["members"]; code != 200 || has {
		t.Fatalf("removed member's leave: %d %v, want 200 without a count", code, out)
	}
	var left int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_presence").Scan(&left)
	if left != 0 {
		t.Fatalf("%d presence row(s) left after every member left", left)
	}

	// A slug no pattern matches is open: leave answers the count.
	if code := presencePost(mux, member, "lobby", "join"); code != 200 {
		t.Fatalf("open slug join: %d", code)
	}
	code, out = presencePostBody(t, mux, outsider, "lobby", "leave")
	if code != 200 || out["members"] != float64(1) {
		t.Fatalf("leave on an open slug: %d %v, want members=1", code, out)
	}
}
