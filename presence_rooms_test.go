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
