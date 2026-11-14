//go:build !cli

package main

import (
	"net/http"
	"reflect"
	"testing"
)

// bm.presence(slug).onChange listens for _benmore_presence events, but
// delivery required the table to be one of the app's own (canRead ->
// appHasTable), so no presence event ever reached a client and onChange
// never fired. Presence events now reach signed-in streams, within the
// joining caller's tenant in an app with groups:.
func TestPresenceEventsReachSignedInStreamsInTenant(t *testing.T) {
	app := realtimeTasksApp(t)
	EnsurePresenceTable(app.DB)
	mux := http.NewServeMux()
	RegisterPresenceRoutes(mux, app)
	joinerSID := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	colleague := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", ""))
	other := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))

	if code := presencePost(mux, joinerSID, "huddle:1", "join"); code != 200 {
		t.Fatalf("join: %d", code)
	}
	joined := []string{`{"table":"_benmore_presence","action":"insert"}`}
	if sse, _ := colleague.drain(); !reflect.DeepEqual(sse, joined) {
		t.Fatalf("same-tenant stream: %q", sse)
	}
	if sse, _ := admin.drain(); !reflect.DeepEqual(sse, joined) {
		t.Fatalf("admin stream: %q", sse)
	}
	if sse, ws := other.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("other tenant heard a presence change: sse=%q ws=%q", sse, ws)
	}

	if code := presencePost(mux, joinerSID, "huddle:1", "leave"); code != 200 {
		t.Fatalf("leave: %d", code)
	}
	if sse, _ := colleague.drain(); !reflect.DeepEqual(sse, []string{`{"table":"_benmore_presence","action":"delete"}`}) {
		t.Fatalf("leave event: %q", sse)
	}
	if sse, ws := other.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("other tenant heard a leave: sse=%q ws=%q", sse, ws)
	}
	admin.drain()

	// The sweeper has no session: its expiry event reaches every signed-in
	// stream (it names no slug, tenant or user).
	BroadcastUnscoped(app, presenceTable, "delete")
	for name, s := range map[string]*flowRealtimeSubscriber{"colleague": colleague, "other": other, "admin": admin} {
		if sse, _ := s.drain(); !reflect.DeepEqual(sse, []string{`{"table":"_benmore_presence","action":"delete"}`}) {
			t.Fatalf("%s: sweep event %q", name, sse)
		}
	}
}

// A leave that removes no row changed nothing, so it raises no event: a
// caller who was never in the room (one its ws_rooms rule refuses, or simply
// one who never joined) used to make every stream in its tenant re-fetch the
// room, as often as it liked. A leave that removes the caller's row still
// raises the delete event, once.
func TestPresenceLeaveByOneNeverPresentRaisesNoEvent(t *testing.T) {
	app := realtimeTasksApp(t)
	EnsurePresenceTable(app.DB)
	app.WSRooms = []WSRoomRule{{Pattern: "huddle-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	mux := http.NewServeMux()
	RegisterPresenceRoutes(mux, app)
	memberSID := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	outsiderSID := createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", "")
	mustExec(t, app.DB, "INSERT INTO room_members (id, room_id, member_id) VALUES (1, 1, "+itoa64(GetSessionFromDB(app.DB, memberSID).UserID)+")")
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a3@example.com')")
	watcher := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a3@example.com", "user", "tenant-a", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	deleted := []string{`{"table":"_benmore_presence","action":"delete"}`}

	for _, slug := range []string{"huddle-1", "lobby"} {
		if code := presencePost(mux, memberSID, slug, "join"); code != 200 {
			t.Fatalf("%s: member join: %d", slug, code)
		}
		watcher.drain()
		admin.drain()

		// The outsider never joined: huddle-1 refuses it, lobby is open.
		if code := presencePost(mux, outsiderSID, slug, "leave"); code != 200 {
			t.Fatalf("%s: leave by a caller who is not present: %d, want 200", slug, code)
		}
		for name, s := range map[string]*flowRealtimeSubscriber{"tenant stream": watcher, "admin stream": admin} {
			if sse, ws := s.drain(); len(sse)+len(ws) != 0 {
				t.Fatalf("%s: a leave that removed no row reached the %s: sse=%q ws=%q", slug, name, sse, ws)
			}
		}

		// The member's leave removes its row and is announced once; leaving
		// again removes nothing and is silent.
		if code := presencePost(mux, memberSID, slug, "leave"); code != 200 {
			t.Fatalf("%s: member leave: %d", slug, code)
		}
		if sse, _ := watcher.drain(); !reflect.DeepEqual(sse, deleted) {
			t.Fatalf("%s: a real leave reached the tenant stream as %q, want one delete event", slug, sse)
		}
		admin.drain()
		if code := presencePost(mux, memberSID, slug, "leave"); code != 200 {
			t.Fatalf("%s: second leave: %d", slug, code)
		}
		if sse, ws := watcher.drain(); len(sse)+len(ws) != 0 {
			t.Fatalf("%s: a second leave was announced: sse=%q ws=%q", slug, sse, ws)
		}
		admin.drain()
	}
}
