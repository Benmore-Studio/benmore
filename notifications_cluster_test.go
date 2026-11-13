//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// clusterPeerApp is a second instance of app: its own process state (pool,
// stop channel, identity in the realtime hubs) on the same database file, as
// under BENMORE_CLUSTER=true. Streams connected to it hear only what its own
// event poller delivers.
func clusterPeerApp(t *testing.T, app *App) *App {
	t.Helper()
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// Another host's path for the same app: the hubs of this test process
	// tell instances apart by database handle and directory.
	return &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Group: app.Group, Access: app.Access, Tables: app.Tables}
}

// Under BENMORE_CLUSTER=true a notification's live event was handed to the
// creating instance's own streams only: a recipient connected to another
// instance got the row but no event, so its badge stayed stale until the
// next poll. The event takes the path table events take: published once,
// delivered by every instance's poller, to the recipient only.
func TestNotificationEventReachesEveryClusterInstance(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "true")
	app := realtimeTasksApp(t)
	EnsureEventsTable(app.DB)
	peer := clusterPeerApp(t, app)
	recipientSID := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	otherSID := createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", "")
	recipientID := GetSessionFromDB(app.DB, recipientSID).UserID

	here := subscribeFlowRealtime(t, app, recipientSID)
	there := subscribeFlowRealtime(t, peer, recipientSID)
	otherHere := subscribeFlowRealtime(t, app, otherSID)
	otherThere := subscribeFlowRealtime(t, peer, otherSID)
	pollers := []*eventPoller{{db: app.DB, app: app}, {db: peer.DB, app: peer}}

	if _, err := CreateNotification(app.DB, recipientID, "Approval needed", "", "info", ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range pollers {
		p.poll()
	}
	for name, s := range map[string]*flowRealtimeSubscriber{"creating instance": here, "other instance": there} {
		sse, ws := s.drain()
		if !reflect.DeepEqual(sse, []string{notifyEventSSE}) || !reflect.DeepEqual(ws, []string{notifyEventWS}) {
			t.Errorf("recipient's stream on the %s got sse=%q ws=%q, want the notification event once", name, sse, ws)
		}
	}
	for name, s := range map[string]*flowRealtimeSubscriber{"creating instance": otherHere, "other instance": otherThere} {
		if sse, ws := s.drain(); len(sse)+len(ws) != 0 {
			t.Errorf("another user's stream on the %s heard the notification: sse=%q ws=%q", name, sse, ws)
		}
	}

	// A flow's `run: notify` announces through the same function.
	flows := notifyFlows(t, "flows/ping-user.yaml", notifyRequestFlow)
	if status, out := postFlow(t, app, &flows[0], otherSID, map[string]any{"to": recipientID, "message": "from a flow"}); status != 200 {
		t.Fatalf("notify flow: %d %v", status, out)
	}
	for _, p := range pollers {
		p.poll()
	}
	if sse, _ := there.drain(); !reflect.DeepEqual(sse, []string{notifyEventSSE}) {
		t.Errorf("a flow's notification reached the other instance as %q, want the event once", sse)
	}
	if sse, _ := here.drain(); !reflect.DeepEqual(sse, []string{notifyEventSSE}) {
		t.Errorf("a flow's notification reached the creating instance as %q, want the event once", sse)
	}
}

// Without cluster mode nothing is published: the event is delivered to the
// process's own streams directly, as before.
func TestNotificationEventStaysLocalWithoutClusterMode(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "")
	app := realtimeTasksApp(t)
	EnsureEventsTable(app.DB)
	sid := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	sub := subscribeFlowRealtime(t, app, sid)
	if _, err := CreateNotification(app.DB, GetSessionFromDB(app.DB, sid).UserID, "Approval needed", "", "info", ""); err != nil {
		t.Fatal(err)
	}
	if sse, _ := sub.drain(); !reflect.DeepEqual(sse, []string{notifyEventSSE}) {
		t.Fatalf("single-instance notification event: %q", sse)
	}
	var published int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_events`).Scan(&published); err != nil || published != 0 {
		t.Fatalf("single-instance notification published %d cluster event(s) (%v)", published, err)
	}
}
