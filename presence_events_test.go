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
