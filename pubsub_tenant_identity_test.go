//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

func pubsubIdentityFixture(t *testing.T) (*sql.DB, *App) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.db")
	open := func() *sql.DB {
		db, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		return db
	}
	writer := open()
	EnsureEventsTable(writer)
	// A separate connection models a cluster peer reading the committed event.
	app := &App{Dir: dir, DB: open(), Group: &GroupConfig{Key: "org_id"}, Access: &AccessConfig{},
		Tables: []Table{{Name: "documents", Columns: []Column{{Name: "id"}, {Name: "org_id"}}}}}
	return writer, app
}

func pubsubIdentitySubscriber(t *testing.T, app *App, group string, userID int64) *flowRealtimeSubscriber {
	t.Helper()
	principal := realtimePrincipal{app: app, session: &Session{UserID: userID, GroupID: group, Role: "user"}}
	s := &flowRealtimeSubscriber{
		sse: &sseClient{principal: principal, ch: make(chan string, 16), userID: userID, groupID: group, appDir: app.Dir},
		ws:  newWSTestClient(realtimeAppID(app.Dir), userID, group),
	}
	s.ws.principal = principal
	sseHub.mu.Lock()
	sseHub.clients[s.sse] = true
	sseHub.mu.Unlock()
	registerWSClient(s.ws)
	t.Cleanup(func() {
		sseHub.mu.Lock()
		delete(sseHub.clients, s.sse)
		sseHub.mu.Unlock()
		unregisterWSClient(s.ws)
	})
	return s
}

func TestPubsubPreservesOpaqueTenantIDsAcrossConnections(t *testing.T) {
	for _, tenant := range []string{"001", "+1", "1e2", "9223372036854775808", "tenant-a", "42", "", "0"} {
		t.Run(tenant, func(t *testing.T) {
			writer, app := pubsubIdentityFixture(t)
			PublishEvent(writer, "documents", "update", tenant, 0)
			var got string
			if err := app.DB.QueryRow(`SELECT group_id FROM _benmore_events`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tenant {
				t.Fatalf("published tenant %q was read by the cluster peer as %q", tenant, got)
			}
		})
	}
}

func TestPubsubRoutesOnlyToTheExactTextTenant(t *testing.T) {
	for _, pair := range [][2]string{{"001", "1"}, {"1e2", "100"}} {
		t.Run(pair[0], func(t *testing.T) {
			writer, app := pubsubIdentityFixture(t)
			intended := pubsubIdentitySubscriber(t, app, pair[0], 1)
			other := pubsubIdentitySubscriber(t, app, pair[1], 2)
			PublishEvent(writer, "documents", "update", pair[0], 1)
			poller := &eventPoller{db: app.DB, app: app}
			poller.poll()
			if sse, ws := other.drain(); len(sse) != 0 || len(ws) != 0 {
				t.Errorf("another text tenant received the event: SSE=%q WS=%q", sse, ws)
			}
			sse, ws := intended.drain()
			if !reflect.DeepEqual(sse, []string{`{"table":"documents","action":"update"}`}) ||
				!reflect.DeepEqual(ws, []string{`{"type":"change","table":"documents","action":"update"}`}) {
				t.Fatalf("intended tenant missed the event: SSE=%q WS=%q", sse, ws)
			}
		})
	}
}

func TestPubsubLegacyIntegerAndGlobalEventsRemainReadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group any
		wantA []string
		wantB []string
		wsA   []string
		wsB   []string
	}{
		{"integer", int64(7), []string{`{"table":"documents","action":"update"}`}, nil,
			[]string{`{"type":"change","table":"documents","action":"update"}`}, nil},
		{"zero", int64(0), []string{realtimeSSEGenericRefresh}, []string{realtimeSSEGenericRefresh},
			[]string{string(realtimeWSGenericRefresh)}, []string{string(realtimeWSGenericRefresh)}},
		{"empty", "", []string{realtimeSSEGenericRefresh}, []string{realtimeSSEGenericRefresh},
			[]string{string(realtimeWSGenericRefresh)}, []string{string(realtimeWSGenericRefresh)}},
		{"null", nil, nil, nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, app := pubsubIdentityFixture(t)
			a := pubsubIdentitySubscriber(t, app, "7", 1)
			b := pubsubIdentitySubscriber(t, app, "8", 2)
			mustExecArgs(t, writer, `INSERT INTO _benmore_events (table_name, action, group_id, user_id) VALUES ('documents', 'update', ?, 0)`, tc.group)
			poller := &eventPoller{db: app.DB, app: app}
			poller.poll()
			if sse, ws := a.drain(); !reflect.DeepEqual(sse, tc.wantA) || !reflect.DeepEqual(ws, tc.wsA) {
				t.Errorf("tenant 7 events = SSE %q WS %q, want SSE %q WS %q", sse, ws, tc.wantA, tc.wsA)
			}
			if sse, ws := b.drain(); !reflect.DeepEqual(sse, tc.wantB) || !reflect.DeepEqual(ws, tc.wsB) {
				t.Errorf("tenant 8 events = SSE %q WS %q, want SSE %q WS %q", sse, ws, tc.wantB, tc.wsB)
			}
		})
	}
}
