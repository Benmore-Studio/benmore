//go:build !cli

package main

import (
	"reflect"
	"testing"
)

// BroadcastUnscoped(app, "", "refresh") is how an opaque SQL write, a SQL
// import and reset_and_seed tell open clients to refetch. Delivery checked
// canRead(""), which no table name passes, so the refresh never reached
// anyone and clients kept showing deleted rows.
func TestRealtimeTablelessRefreshReachesEveryLiveStream(t *testing.T) {
	app := realtimeTasksApp(t)
	a := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	revokedSID := createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", "")
	revoked := subscribeFlowRealtime(t, app, revokedSID)
	mustExec(t, app.DB, "DELETE FROM _benmore_sessions WHERE id = '"+sessionStorageKey(revokedSID)+"'")

	BroadcastUnscoped(app, "", "refresh")
	for name, s := range map[string]*flowRealtimeSubscriber{"tenant-a": a, "tenant-b": b, "admin": admin} {
		sse, ws := s.drain()
		if !reflect.DeepEqual(sse, []string{realtimeGenericSSE}) || !reflect.DeepEqual(ws, []string{string(realtimeWSGenericRefresh)}) {
			t.Fatalf("%s: table-less refresh not delivered: sse=%q ws=%q", name, sse, ws)
		}
	}
	if sse, ws := revoked.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("revoked stream got the refresh: sse=%q ws=%q", sse, ws)
	}
}
