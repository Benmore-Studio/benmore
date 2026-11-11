//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

func TestRealtimeDeliveryUsesOnePolicyGenerationDuringReload(t *testing.T) {
	app, _, _ := newCommandProviderTaskFixtureWithPolicies(t, commandTaskFlowFixture, "")
	schemaPath := filepath.Join(app.Dir, "schema.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaPath, append(schema, []byte("\nCREATE TABLE IF NOT EXISTS scope_probe (id INTEGER PRIMARY KEY, user_id INTEGER, org_id TEXT, title TEXT);\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	writePolicy := func(mode string) error {
		body := `groups: {table: members, key: org_id, user_field: email}
roles:
  editor: {scopes: [tasks:read, tasks:write, scope_probe:read]}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
  scope_probe: {all: ` + mode + `}
`
		if err := os.WriteFile(filepath.Join(app.Dir, "app.yaml"), []byte(body), 0600); err != nil {
			return err
		}
		reviewAppMCPFixture(t, app.Dir)
		return nil
	}
	if err := writePolicy("group"); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("initial realtime policy reload: %v", err)
	}

	clients := make([]*flowRealtimeSubscriber, 0, 3)
	for _, identity := range []struct{ email, group string }{
		{"owner@example.com", "17"},
		{"colleague@example.com", "17"},
		{"other-tenant@example.com", "18"},
	} {
		sid := createCrudScopeSession(t, app, identity.email, "editor", identity.group, "")
		var userID int64
		if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", identity.email).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec("INSERT INTO members(org_id, email, user_id) VALUES (?, ?, ?)", identity.group, identity.email, userID); err != nil {
			t.Fatal(err)
		}
		client := subscribeFlowRealtime(t, app, sid)
		client.sse.principal = client.sse.principal.withCache()
		client.ws.principal = client.ws.principal.withCache()
		client.sse.ch = make(chan string, 256)
		client.ws.send = make(chan []byte, 256)
		client.ws.subMu.Lock()
		client.ws.subscriptions["scope_probe"] = true
		client.ws.subMu.Unlock()
		clients = append(clients, client)
	}

	var reloadErr error
	var reloadMu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 12; i++ {
			mode := "self"
			if i%2 == 0 {
				mode = "group"
			}
			if err := writePolicy(mode); err != nil {
				reloadMu.Lock()
				reloadErr = err
				reloadMu.Unlock()
				return
			}
			if err := reloadAppConfig(app); err != nil {
				reloadMu.Lock()
				reloadErr = err
				reloadMu.Unlock()
				return
			}
		}
	}()
	ownerID := clients[0].sse.userID
	if policy := snapshotAppMCPGeneration(app).view; !clients[0].sse.principal.canReadWithPolicy(policy, "scope_probe", ownerID) {
		t.Fatalf("owner cannot read scope_probe before concurrent reload: tables=%v group=%#v access=%#v session=%#v", policy.Tables, policy.Group, policy.Access, clients[0].sse.principal.session)
	}
	close(start)
	for i := 0; i < 240; i++ {
		deliverRealtimeChange(app, realtimeChange{table: "scope_probe", action: fmt.Sprintf("e%d", i), groupID: "17", userID: ownerID})
	}
	wg.Wait()
	reloadMu.Lock()
	err = reloadErr
	reloadMu.Unlock()
	if err != nil {
		t.Fatalf("concurrent policy reload failed: %v", err)
	}
	if published := app.realtimePolicyView.Load(); published != snapshotAppMCPGeneration(app).view {
		t.Fatal("realtime policy publication did not advance with the latest app generation")
	}

	drain := func(client *flowRealtimeSubscriber) (sse, ws []string) {
		for {
			select {
			case message := <-client.sse.ch:
				sse = append(sse, message)
			case message := <-client.ws.send:
				ws = append(ws, string(message))
			default:
				return sse, ws
			}
		}
	}
	ownerSSE, ownerWS := drain(clients[0])
	if len(ownerSSE) != 240 || len(ownerWS) != 240 {
		t.Fatalf("owner missed full events across reloads: SSE=%d WS=%d", len(ownerSSE), len(ownerWS))
	}
	for i := range ownerSSE {
		want := fmt.Sprintf(`{"table":"scope_probe","action":"e%d"}`, i)
		if ownerSSE[i] != want {
			t.Fatalf("owner SSE event %d = %s, want %s", i, ownerSSE[i], want)
		}
	}
	for i := range ownerWS {
		want := fmt.Sprintf(`{"type":"change","table":"scope_probe","action":"e%d"}`, i)
		if ownerWS[i] != want {
			t.Fatalf("owner WS event %d = %s, want %s", i, ownerWS[i], want)
		}
	}
	colleagueSSE, colleagueWS := drain(clients[1])
	if len(colleagueSSE) != 240 || len(colleagueWS) != 240 {
		t.Fatalf("same-tenant colleague missed policy notifications: SSE=%d WS=%d", len(colleagueSSE), len(colleagueWS))
	}
	for i := 0; i < 240; i++ {
		fullSSE := fmt.Sprintf(`{"table":"scope_probe","action":"e%d"}`, i)
		fullWS := fmt.Sprintf(`{"type":"change","table":"scope_probe","action":"e%d"}`, i)
		if colleagueSSE[i] != realtimeGenericSSE && colleagueSSE[i] != fullSSE {
			t.Fatalf("same-tenant SSE event %d leaked unexpected payload: %s", i, colleagueSSE[i])
		}
		if colleagueWS[i] != string(realtimeWSGenericRefresh) && colleagueWS[i] != fullWS {
			t.Fatalf("same-tenant WS event %d leaked unexpected payload: %s", i, colleagueWS[i])
		}
		if (colleagueSSE[i] == fullSSE) != (colleagueWS[i] == fullWS) {
			t.Fatalf("SSE/WS event %d used different policy generations: SSE=%s WS=%s", i, colleagueSSE[i], colleagueWS[i])
		}
	}
	foreignSSE, foreignWS := drain(clients[2])
	if len(foreignSSE) != 0 || len(foreignWS) != 0 {
		t.Fatalf("other tenant received table events across policy reloads: SSE=%q WS=%q", foreignSSE, foreignWS)
	}
}

func TestRealtimePolicySnapshotPublishedForLoadedAppWithoutMCP(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "frontend:\n  stack: html\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP != nil {
		t.Fatal("fixture unexpectedly loaded an MCP manifest")
	}
	if view := realtimePolicySnapshot(app); view == nil || len(view.Tables) == 0 {
		t.Fatal("cold-loaded non-MCP app did not publish a realtime policy view")
	}

	client := &sseClient{ch: make(chan string, 1), userID: 7, isAdmin: true,
		principal: realtimePrincipal{app: app, session: &Session{UserID: 7, Role: "admin", GlobalAdmin: true, Scopes: "notes:read"}}}
	sseHub.mu.Lock()
	sseHub.clients[client] = true
	sseHub.mu.Unlock()
	t.Cleanup(func() { sseHub.mu.Lock(); delete(sseHub.clients, client); sseHub.mu.Unlock() })

	// A loaded app with no Stop channel still takes the inline delivery path.
	// Holding app.mu exercises the same path used when a caller broadcasts
	// during a reload: delivery must use the already-published snapshot.
	app.mu.Lock()
	app.Stop = nil
	dispatchRealtimeChange(app, realtimeChange{table: "notes", action: "update", userID: 7})
	app.mu.Unlock()
	select {
	case got := <-client.ch:
		if got != `{"table":"notes","action":"update"}` {
			t.Fatalf("inline event = %s", got)
		}
	default:
		t.Fatal("loaded no-MCP app did not deliver its inline event")
	}
}

func TestRealtimePolicySnapshotFallbackForNoStopSyntheticApp(t *testing.T) {
	app := realtimeTasksApp(t)
	app.Stop = nil
	app.JoinMap = JoinMap{"artifact_members": {"artifact_ref": {Table: "tasks", Column: "id"}}}
	app.Access.rules["tasks"] = map[AccessOp]string{"all": "member-of:artifact_members(artifact_ref, member_id)"}
	app.Access.rolesDeclared = true
	app.Access.rules["rooms"] = map[AccessOp]string{"all": "role:lead"}
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{
		"reader": {Scopes: "tasks:read"},
		"editor": {Inherits: []string{"reader"}},
	}}
	view := realtimePolicySnapshot(app)
	if view == nil || memberOfMisdeclared(view, "tasks", "member-of:artifact_members(artifact_ref, member_id)") {
		t.Fatal("synthetic policy snapshot did not preserve nonconventional membership foreign keys")
	}
	if !view.Access.rolesDeclared || !reflect.DeepEqual(permGrantingRoles(view, "tasks:read"), []string{"editor", "reader"}) {
		t.Fatal("synthetic policy snapshot lost roles: declarations or inherited permission scopes")
	}
	if tableModeAllowed(view, "rooms", OpRead, "role:lead", &Session{UserID: 7, Role: "user", Roles: []string{"user", "lead"}, GroupID: "tenant-a"}, 0) {
		t.Fatal("synthetic policy snapshot treated a tenant-only role as a global grant")
	}
	if !tableModeAllowed(view, "rooms", OpRead, "role:lead", &Session{UserID: 7, Role: "lead", Roles: []string{"lead"}, GroupID: "tenant-a"}, 0) {
		t.Fatal("synthetic policy snapshot refused a global primary role")
	}
	client := &sseClient{ch: make(chan string, 1), userID: 7, groupID: "tenant-a", isAdmin: true,
		principal: realtimePrincipal{app: app, session: &Session{UserID: 7, Role: "admin", GlobalAdmin: true, Scopes: "orgdocs:read"}}}
	sseHub.mu.Lock()
	sseHub.clients[client] = true
	sseHub.mu.Unlock()
	t.Cleanup(func() { sseHub.mu.Lock(); delete(sseHub.clients, client); sseHub.mu.Unlock() })
	dispatchRealtimeChange(app, realtimeChange{table: "orgdocs", action: "update", groupID: "tenant-a"})
	select {
	case got := <-client.ch:
		if got != `{"table":"orgdocs","action":"update"}` {
			t.Fatalf("synthetic app event = %s", got)
		}
	default:
		t.Fatal("directly assembled app did not use the nonblocking policy fallback")
	}

	// Synthetic fixtures sometimes replace unrelated runtime configuration
	// directly rather than under app.mu. The realtime policy fallback must not
	// inspect those unrelated values while capturing its security snapshot.
	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for i := 0; i < 500; i++ {
			app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"tasks": {{SQL: fmt.Sprintf("SELECT %d", i)}}}}
			app.Flows = []Flow{{Name: fmt.Sprintf("flow-%d", i)}}
		}
	}()
	close(start)
	for i := 0; i < 500; i++ {
		if view := realtimePolicySnapshot(app); view == nil || memberOfMisdeclared(view, "tasks", "member-of:artifact_members(artifact_ref, member_id)") {
			t.Fatal("synthetic policy snapshot lost its membership policy during unrelated config updates")
		}
	}
	<-done
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
