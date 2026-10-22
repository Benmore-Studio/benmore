//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// realtimeTasksApp adds a table that carries both the owner and tenant
// columns, the shape where explicit `self` and `member-of` used to widen to
// the whole tenant.
func realtimeTasksApp(t *testing.T) *App {
	t.Helper()
	app := flowRealtimeApp(t)
	mustExec(t, app.DB, `CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, org_id TEXT, title TEXT)`)
	cols, err := GetTableColumns(app.DB, "tasks")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "tasks", Columns: cols})
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a1@example.com'), ('tenant-a', 'a2@example.com'), ('tenant-b', 'b@example.com')")
	return app
}

const realtimeGenericSSE = `{"table":"","action":"refresh"}`

// A cascade (BroadcastUnscoped names no tenant or owner) on a tenant table
// no longer tells every tenant which table changed: admins get the event,
// other readers only the generic refresh. A publicly readable table still
// reaches everyone in full.
func TestRealtimeCascadeDoesNotNameTenantTableToOtherTenants(t *testing.T) {
	app := realtimeTasksApp(t)
	a := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))

	for _, table := range []string{"orgdocs", "notes"} {
		BroadcastUnscoped(app, table, "delete")
		event := fmt.Sprintf(`{"table":"%s","action":"delete"}`, table)
		if sse, ws := b.drain(); strings.Contains(strings.Join(sse, ""), table) || strings.Contains(strings.Join(ws, ""), table) {
			t.Fatalf("%s: tenant B learned of a cascade it cannot read: sse=%q ws=%q", table, sse, ws)
		}
		if sse, _ := a.drain(); !reflect.DeepEqual(sse, []string{realtimeGenericSSE}) {
			t.Fatalf("%s: tenant A reader should get only the generic refresh, got %q", table, sse)
		}
		if sse, _ := admin.drain(); !reflect.DeepEqual(sse, []string{event}) {
			t.Fatalf("%s: admin should get the full event, got %q", table, sse)
		}
	}

	app.Access.rules["orgdocs"] = map[AccessOp]string{"all": "anon"}
	BroadcastUnscoped(app, "orgdocs", "update")
	for _, s := range []*flowRealtimeSubscriber{a, b, admin} {
		if sse, _ := s.drain(); !reflect.DeepEqual(sse, []string{`{"table":"orgdocs","action":"update"}`}) {
			t.Fatalf("public table event should reach every reader, got %q", sse)
		}
	}
}

// Explicit `self` and `member-of` are owner/member scoped even inside one
// tenant: the actor sees the event, a tenant colleague only the generic
// refresh, another tenant nothing.
func TestRealtimeTenantBroadcastHonoursSelfAndMemberOf(t *testing.T) {
	app := realtimeTasksApp(t)
	sid1 := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	a1 := subscribeFlowRealtime(t, app, sid1)
	a2 := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	actor := GetSessionFromDB(app.DB, sid1)
	event := `{"table":"tasks","action":"update"}`

	for _, mode := range []string{"self", "member-of:room_members(room_id=id, member_id)"} {
		app.Access.rules["tasks"] = map[AccessOp]string{"all": mode}
		Broadcast(app, "tasks", "update", actor)
		if sse, _ := a1.drain(); !reflect.DeepEqual(sse, []string{event}) {
			t.Fatalf("%s: actor got %q", mode, sse)
		}
		if sse, _ := a2.drain(); !reflect.DeepEqual(sse, []string{realtimeGenericSSE}) {
			t.Fatalf("%s: tenant colleague should get only the generic refresh, got %q", mode, sse)
		}
		if sse, ws := b.drain(); len(sse) != 0 || len(ws) != 0 {
			t.Fatalf("%s: other tenant got sse=%q ws=%q", mode, sse, ws)
		}
	}

	// The implicit default stays tenant-wide.
	delete(app.Access.rules, "tasks")
	Broadcast(app, "tasks", "update", actor)
	if sse, _ := a2.drain(); !reflect.DeepEqual(sse, []string{event}) {
		t.Fatalf("implicit tenant-wide default: colleague got %q", sse)
	}
}

// Fan-out reads a cached credential check; a revoked session stops being
// trusted within realtimePrincipalTTL, and a heartbeat refresh notices at once.
func TestRealtimePrincipalRevalidationIsCachedAndBounded(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "live@example.com", "user", "", "")
	r := httptest.NewRequest("GET", "/sse/events", nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	p := realtimePrincipal{app: app, request: r, session: getSession(app, r)}.withCache()
	if p.session == nil {
		t.Fatal("fixture session did not resolve")
	}

	before := realtimeRevalidations.Load()
	for i := 0; i < 100; i++ {
		if !p.canRead("notes", 0) {
			t.Fatal("live principal refused")
		}
	}
	if n := realtimeRevalidations.Load() - before; n != 0 {
		t.Fatalf("fan-out revalidated %d times inside the TTL, want 0", n)
	}

	DeleteSessionFromDB(app.DB, sid)
	p.cache.mu.Lock()
	p.cache.checked = time.Now().Add(-realtimePrincipalTTL - time.Millisecond)
	p.cache.mu.Unlock()
	if _, valid := p.current(); valid {
		t.Fatal("revoked session still trusted after the TTL")
	}

	sid2 := createCrudScopeSession(t, app, "live2@example.com", "user", "", "")
	r2 := httptest.NewRequest("GET", "/ws", nil)
	r2.Header.Set("Authorization", "Bearer "+sid2)
	p2 := realtimePrincipal{app: app, request: r2, session: getSession(app, r2)}.withCache()
	DeleteSessionFromDB(app.DB, sid2)
	if _, valid := p2.refresh(); valid {
		t.Fatal("heartbeat refresh kept a revoked session")
	}
}

// The writer never waits on the hubs: a broadcast returns while another
// goroutine holds both hub locks, and is delivered once they are released.
func TestRealtimeBroadcastDoesNotBlockOnHubs(t *testing.T) {
	app := realtimeTasksApp(t)
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	sseHub.mu.Lock()
	wsHub.mu.Lock()
	done := make(chan struct{})
	go func() {
		BroadcastScopedDirect(app, "orgdocs", "update", "tenant-a", 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		wsHub.mu.Unlock()
		sseHub.mu.Unlock()
		t.Fatal("broadcast blocked on the hub locks")
	}
	wsHub.mu.Unlock()
	sseHub.mu.Unlock()
	if sse, _ := admin.drain(); !reflect.DeepEqual(sse, []string{`{"table":"orgdocs","action":"update"}`}) {
		t.Fatalf("queued event not delivered, got %q", sse)
	}
}

// One dispatcher per app keeps each connection's events in enqueue order.
func TestRealtimeDispatchPreservesOrder(t *testing.T) {
	app := realtimeTasksApp(t)
	c := &sseClient{ch: make(chan string, 512), isAdmin: true,
		principal: realtimePrincipal{app: app, session: &Session{UserID: 1, Role: "admin", GlobalAdmin: true}}}
	sseHub.mu.Lock()
	sseHub.clients[c] = true
	sseHub.mu.Unlock()
	t.Cleanup(func() { sseHub.mu.Lock(); delete(sseHub.clients, c); sseHub.mu.Unlock() })

	var want []string
	for i := 0; i < 300; i++ {
		action := fmt.Sprintf("a%d", i)
		want = append(want, fmt.Sprintf(`{"table":"orgdocs","action":"%s"}`, action))
		BroadcastScopedDirect(app, "orgdocs", action, "tenant-a", 0)
	}
	realtimeFlush()
	var got []string
	for len(c.ch) > 0 {
		got = append(got, <-c.ch)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events out of order or missing: got %d events, first mismatch in %v", len(got), got[:min(5, len(got))])
	}
}

// The dispatcher ends with app.Stop; a stopped app is delivered inline, and a
// reload's fresh Stop generation gets a fresh dispatcher.
func TestRealtimeDispatcherFollowsAppStop(t *testing.T) {
	app := realtimeTasksApp(t)
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	BroadcastScopedDirect(app, "orgdocs", "update", "tenant-a", 0)
	admin.drain()

	app.mu.Lock()
	close(app.Stop)
	app.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		realtimeDispatchers.mu.Lock()
		_, running := realtimeDispatchers.m[app]
		realtimeDispatchers.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dispatcher outlived app.Stop")
		}
		time.Sleep(5 * time.Millisecond)
	}
	BroadcastScopedDirect(app, "orgdocs", "delete", "tenant-a", 0)
	if len(admin.sse.ch) != 1 {
		t.Fatal("stopped app's event was not delivered inline")
	}
	admin.drain()

	app.mu.Lock()
	app.Stop = make(chan struct{})
	app.mu.Unlock()
	BroadcastScopedDirect(app, "orgdocs", "insert", "tenant-a", 0)
	realtimeDispatchers.mu.Lock()
	_, running := realtimeDispatchers.m[app]
	realtimeDispatchers.mu.Unlock()
	if !running {
		t.Fatal("reloaded app did not get a dispatcher")
	}
	if sse, _ := admin.drain(); !reflect.DeepEqual(sse, []string{`{"table":"orgdocs","action":"insert"}`}) {
		t.Fatalf("event after reload: got %q", sse)
	}
}

// realtimeBenchApp is a minimal app with an owner-scoped notes table and one
// signed-in user's session.
func realtimeBenchApp(b *testing.B) (*App, string) {
	b.Helper()
	dir := b.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`); err != nil {
		b.Fatal(err)
	}
	if err := EnsureUsersTable(db); err != nil {
		b.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('bench', 'bench@example.com', 'user', 1)")
	if err != nil {
		b.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"all": "self"}}}}
	cols, err := GetTableColumns(db, "notes")
	if err != nil {
		b.Fatal(err)
	}
	app.Tables = []Table{{Name: "notes", Columns: cols}}
	return app, CreateSession(db, uid, "bench@example.com", "", time.Hour)
}

// BenchmarkRealtimeFanOut measures one table event delivered to N connected
// SSE clients. "uncached" is the pre-fix behavior (a session lookup per
// client per event); "cached" is the current one. revalidations/op is the
// number of session lookups one broadcast costs.
func BenchmarkRealtimeFanOut(b *testing.B) {
	for _, n := range []int{100, 1000} {
		for _, cached := range []bool{false, true} {
			name := fmt.Sprintf("clients=%d/uncached", n)
			if cached {
				name = fmt.Sprintf("clients=%d/cached", n)
			}
			b.Run(name, func(b *testing.B) {
				app, sid := realtimeBenchApp(b)
				r := httptest.NewRequest("GET", "/sse/events", nil)
				r.Header.Set("Authorization", "Bearer "+sid)
				session := getSession(app, r)
				clients := make([]*sseClient, n)
				sseHub.mu.Lock()
				for i := range clients {
					p := realtimePrincipal{app: app, request: r, session: session}
					if cached {
						p = p.withCache()
					}
					clients[i] = &sseClient{ch: make(chan string, 1), userID: session.UserID, principal: p}
					sseHub.clients[clients[i]] = true
				}
				sseHub.mu.Unlock()
				defer func() {
					sseHub.mu.Lock()
					for _, c := range clients {
						delete(sseHub.clients, c)
					}
					sseHub.mu.Unlock()
					app.Shutdown()
				}()
				change := realtimeChange{table: "notes", action: "update", userID: session.UserID}
				before := realtimeRevalidations.Load()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					deliverRealtimeChange(app, change)
					for _, c := range clients {
						select {
						case <-c.ch:
						default:
						}
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(realtimeRevalidations.Load()-before)/float64(b.N), "revalidations/op")
			})
		}
	}
}
