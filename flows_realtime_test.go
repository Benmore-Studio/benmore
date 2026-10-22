//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- flow SQL writes → realtime table events ---

// flowRealtimeSubscriber is one signed-in user's SSE + WebSocket connection,
// registered in the process hubs the way the /sse/events and /ws handlers do.
type flowRealtimeSubscriber struct {
	sse *sseClient
	ws  *wsClient
}

func subscribeFlowRealtime(t *testing.T, app *App, sid string) *flowRealtimeSubscriber {
	t.Helper()
	req := httptest.NewRequest("GET", "/sse/events", nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	session := getSession(app, req)
	if session == nil {
		t.Fatal("subscriber session did not resolve")
	}
	principal := realtimePrincipal{app: app, request: req, session: session}
	s := &flowRealtimeSubscriber{
		sse: &sseClient{principal: principal, ch: make(chan string, 16), userID: session.UserID, groupID: session.EffectiveGroupID(), appDir: app.Dir},
		ws:  newWSTestClient(realtimeAppID(app.Dir), session.UserID, session.EffectiveGroupID()),
	}
	s.ws.principal = principal
	s.ws.send = make(chan []byte, 16)
	// As the /sse/events and /ws handlers set it.
	s.sse.isAdmin, s.ws.isAdmin = session.IsAdminBypass(), session.IsAdminBypass()
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

// drain returns every SSE data payload and WebSocket frame queued so far.
func (s *flowRealtimeSubscriber) drain() (sse, ws []string) {
	realtimeFlush() // table events are delivered by the per-app dispatcher
	for {
		select {
		case m := <-s.sse.ch:
			sse = append(sse, m)
		case m := <-s.ws.send:
			ws = append(ws, string(m))
		default:
			return sse, ws
		}
	}
}

func flowRealtimeApp(t *testing.T) *App {
	t.Helper()
	app, _ := auditApp(t)
	mustExec(t, app.DB, `CREATE TABLE staff_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE _benmore_flowprobe (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE notes_fts (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`)
	// Deliberately put framework and full-text shadow names in app.Tables so
	// only announceFlowWrites' own filter, not table discovery, keeps them out.
	for _, name := range []string{"staff_notes", "_benmore_flowprobe", "notes_fts"} {
		cols, err := GetTableColumns(app.DB, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.Access.rules["staff_notes"] = map[AccessOp]string{"all": "admin"}
	return app
}

func runFlowAs(t *testing.T, app *App, flow *Flow, sid string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set("Authorization", "Bearer "+sid)
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	return rr
}

func respondOK() FlowStep {
	return FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}}
}

// A flow's committed `run: sql` INSERT reaches a subscriber of that table
// over SSE and WebSocket with exactly the auto-CRUD event shape: {table,
// action} and nothing else - no row values. Delivery keeps every existing
// per-subscriber gate: the non-owner gets the same generic refresh auto-CRUD
// sends for an owner-scoped table, and nobody who cannot read a table
// (staff_notes is admin-only) hears about writes to it.
func TestFlowSQLWriteEmitsTableEvent(t *testing.T) {
	app := flowRealtimeApp(t)
	owner := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	other := createCrudScopeSession(t, app, "other@example.com", "user", "", "")
	ownerSub := subscribeFlowRealtime(t, app, owner)
	otherSub := subscribeFlowRealtime(t, app, other)

	flow := &Flow{
		Name:    "add-note",
		Auth:    "required",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/add-note"},
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO notes (user_id, title) VALUES (:user_id, 'row-secret-title')"},
			{Type: "sql", SQL: "INSERT INTO staff_notes (title) VALUES ('staff-only')"},
			respondOK(),
		},
	}
	if rr := runFlowAs(t, app, flow, owner); rr.Code != http.StatusOK {
		t.Fatalf("flow status=%d body=%s", rr.Code, rr.Body.String())
	}

	sse, ws := ownerSub.drain()
	if !reflect.DeepEqual(sse, []string{`{"table":"notes","action":"insert"}`}) {
		t.Fatalf("owner SSE events = %q, want exactly the notes insert event", sse)
	}
	if !reflect.DeepEqual(ws, []string{`{"type":"change","table":"notes","action":"insert"}`}) {
		t.Fatalf("owner WS frames = %q, want exactly the notes change frame", ws)
	}
	for _, frame := range append(sse, ws...) {
		if strings.Contains(frame, "row-secret-title") || strings.Contains(frame, "staff") {
			t.Fatalf("event leaked row data or an unreadable table: %s", frame)
		}
	}
	sse, ws = otherSub.drain()
	if !reflect.DeepEqual(sse, []string{`{"table":"","action":"refresh"}`}) || len(ws) != 1 || !strings.Contains(ws[0], `"action":"refresh"`) || strings.Contains(ws[0], "notes") {
		t.Fatalf("non-owner must get only the generic refresh auto-CRUD sends: sse=%q ws=%q", sse, ws)
	}
}

// A transactional flow announces its writes only after COMMIT. A rollback
// announces nothing (and leaves no row). A write in a non-transactional flow
// is durable when its statement returns, so it is announced even though a
// later step failed.
func TestFlowSQLWriteEventsFollowDurability(t *testing.T) {
	app := flowRealtimeApp(t)
	sid := createCrudScopeSession(t, app, "tx@example.com", "user", "", "")
	sub := subscribeFlowRealtime(t, app, sid)
	flow := func(tx bool, steps ...FlowStep) *Flow {
		return &Flow{Name: "tx", Auth: "required", Transaction: tx,
			Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/tx"}, Steps: steps}
	}
	insert := func(title string) FlowStep {
		return FlowStep{Type: "sql", SQL: "INSERT INTO notes (user_id, title) VALUES (:user_id, '" + title + "')"}
	}
	boom := FlowStep{Type: "sql", SQL: "INSERT INTO missing_table (x) VALUES (1)"}
	count := func(title string) int {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE title = ?", title).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	runFlowAs(t, app, flow(true, insert("committed"), respondOK()), sid)
	if sse, _ := sub.drain(); !reflect.DeepEqual(sse, []string{`{"table":"notes","action":"insert"}`}) || count("committed") != 1 {
		t.Fatalf("committed transaction: events=%q rows=%d", sse, count("committed"))
	}

	if rr := runFlowAs(t, app, flow(true, insert("rolled-back"), boom, respondOK()), sid); rr.Code == http.StatusOK {
		t.Fatalf("failing transactional flow returned 200: %s", rr.Body.String())
	}
	if sse, ws := sub.drain(); len(sse)+len(ws) != 0 || count("rolled-back") != 0 {
		t.Fatalf("rolled-back transaction announced a write: sse=%q ws=%q rows=%d", sse, ws, count("rolled-back"))
	}

	runFlowAs(t, app, flow(false, insert("autocommit"), boom, respondOK()), sid)
	if sse, _ := sub.drain(); !reflect.DeepEqual(sse, []string{`{"table":"notes","action":"insert"}`}) || count("autocommit") != 1 {
		t.Fatalf("durable write before a failed step: events=%q rows=%d", sse, count("autocommit"))
	}
}

// Writes made by nested steps (if / for_each bodies and on_error handlers)
// emit too, deduplicated to one event per (table, action) per run. Writes to
// framework and full-text shadow tables never emit, even when those names
// appear in app.Tables and the subscriber is an admin who could read them.
func TestFlowNestedWritesEmitAndFrameworkTablesDoNot(t *testing.T) {
	app := flowRealtimeApp(t)
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	sub := subscribeFlowRealtime(t, app, admin)
	mustExec(t, app.DB, "INSERT INTO notes (user_id, title) VALUES (1, 'seed'), (1, 'seed-2')")
	flows, err := parseGHAFlowFile("flows/nested.yaml", []byte(`on:
  request:
    method: POST
    path: /api/nested
    auth: required
jobs:
  nested:
    steps:
      - id: seed
        query: "SELECT id FROM notes WHERE title LIKE 'seed%'"
      - if: ${{ steps.seed.outputs.rows }}
        steps:
          - for_each: ${{ steps.seed.outputs.rows }}
            as: row
            steps:
              - run: sql
                with:
                  query: "UPDATE notes SET title = title || '!' WHERE id = :id"
                  params: { id: "${{ row.id }}" }
      - id: fails
        query: "INSERT INTO missing_table (x) VALUES (1)"
        on_error:
          - run: sql
            with:
              query: "DELETE FROM staff_notes WHERE id > 0"
          - run: sql
            with:
              query: "INSERT INTO _benmore_flowprobe (v) VALUES ('framework')"
          - run: sql
            with:
              query: "INSERT INTO notes_fts (v) VALUES ('shadow')"
`))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "INSERT INTO staff_notes (title) VALUES ('to-delete')")
	runFlowAs(t, app, &flows[0], admin)

	sse, _ := sub.drain()
	want := []string{`{"table":"notes","action":"update"}`, `{"table":"staff_notes","action":"delete"}`}
	if !reflect.DeepEqual(sse, want) {
		t.Fatalf("nested writes: events=%q want %q", sse, want)
	}
	var probe int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_flowprobe").Scan(&probe); err != nil || probe != 1 {
		t.Fatalf("framework-table write should have run (count=%d err=%v)", probe, err)
	}
}

// Async flows run through executeFlowJob with no session: their writes, a
// `run: sql_dynamic` write included, still reach every subscriber allowed to
// read the table, unscoped (as imports and hook jobs broadcast).
func TestFlowJobWritesEmitTableEvents(t *testing.T) {
	app := flowRealtimeApp(t)
	sid := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	sub := subscribeFlowRealtime(t, app, sid)
	mustExec(t, app.DB, "INSERT INTO notes (user_id, title) VALUES (999, 'someone else')")
	app.Flows = []Flow{{Name: "nightly", Transaction: true, Steps: []FlowStep{
		{Type: "sql_dynamic", SQL: "UPDATE notes SET title = 'renamed' WHERE user_id = 999"},
		{Type: "sql", SQL: "INSERT INTO staff_notes (title) VALUES ('job')"},
	}}}
	if err := executeFlowJob(app, "nightly", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	// A job knows no owner, so a reader of an owner-scoped table gets the
	// generic refresh auto-CRUD sends non-owners, never the table name.
	if sse, ws := sub.drain(); !reflect.DeepEqual(sse, []string{`{"table":"","action":"refresh"}`}) ||
		!reflect.DeepEqual(ws, []string{`{"type":"change","action":"refresh"}`}) {
		t.Fatalf("job writes: sse=%q ws=%q", sse, ws)
	}
}

// A run without a session (job, cron, data event, webhook) announces a write
// to a tenant's table only to that tenant, when trusted trigger data names it
// (a data event's row, job data that didn't come from a request), and
// otherwise only to admins, who see every tenant anyway.
func TestSessionlessFlowWritesStayInTheirTenant(t *testing.T) {
	app := flowRealtimeApp(t)
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a@example.com'), ('tenant-b', 'b@example.com')")
	subA := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a@example.com", "user", "tenant-a", ""))
	subB := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	app.Flows = []Flow{{Name: "recount", Steps: []FlowStep{
		{Type: "sql", SQL: "UPDATE orgdocs SET title = title || '!' WHERE org_id = 'tenant-a'"},
	}}}
	event := `{"table":"orgdocs","action":"update"}`
	for _, c := range []struct {
		name       string
		data       map[string]any
		toA, toB   bool
		fromClient bool
	}{
		{name: "no tenant", data: map[string]any{}},
		{name: "trusted tenant", data: map[string]any{"org_id": "tenant-a"}, toA: true},
		{name: "async caller's tenant", data: map[string]any{"_group_id": "tenant-b", "org_id": "tenant-a"}, toB: true},
		{name: "tenant from the request", data: map[string]any{"org_id": "tenant-b", flowRequestKeysPayloadField: []any{"org_id"}}, fromClient: true},
	} {
		if err := executeFlowJob(app, "recount", c.data); err != nil {
			t.Fatal(err)
		}
		for _, s := range []struct {
			sub  *flowRealtimeSubscriber
			want bool
		}{{subA, c.toA}, {subB, c.toB}, {admin, true}} {
			sse, _ := s.sub.drain()
			if got := reflect.DeepEqual(sse, []string{event}); got != s.want {
				t.Errorf("%s: subscriber %q got %q, want event=%v", c.name, s.sub.sse.groupID, sse, s.want)
			}
		}
	}
	// A data-event flow carries the triggering row, so its tenant is known.
	runFlowEvent(app, Flow{Name: "on-doc", Steps: []FlowStep{
		{Type: "sql", SQL: "UPDATE orgdocs SET title = 'seen' WHERE id = 2"},
	}}, map[string]any{"id": 2, "org_id": "tenant-b"})
	if sse, _ := subB.drain(); !reflect.DeepEqual(sse, []string{event}) {
		t.Errorf("data event: tenant-b got %q", sse)
	}
	if sse, _ := subA.drain(); len(sse) != 0 {
		t.Errorf("data event: tenant-a got %q", sse)
	}
}

func TestSQLWriteTargets(t *testing.T) {
	cases := []struct {
		sql   string
		want  []sqlWrite
		stmts int
	}{
		{"SELECT * FROM notes", nil, 1},
		{"INSERT INTO notes (title) VALUES ('x')", []sqlWrite{{"notes", "insert"}}, 1},
		{"insert or replace into Notes values (1)", []sqlWrite{{"Notes", "insert"}}, 1},
		{"REPLACE INTO notes VALUES (1)", []sqlWrite{{"notes", "insert"}}, 1},
		{"UPDATE OR IGNORE \"my notes\" SET a = 1", []sqlWrite{{"my notes", "update"}}, 1},
		{"DELETE FROM [notes] WHERE id = ?", []sqlWrite{{"notes", "delete"}}, 1},
		{"DELETE FROM main.`notes`", []sqlWrite{{"notes", "delete"}}, 1},
		{"INSERT INTO temp.scratch VALUES (1)", nil, 1},
		{"WITH x(a) AS (SELECT 1), y AS MATERIALIZED (SELECT (2)) INSERT INTO notes SELECT a FROM x", []sqlWrite{{"notes", "insert"}}, 1},
		{"WITH x AS (SELECT 'INSERT INTO notes') SELECT * FROM x", nil, 1},
		{"-- INSERT INTO notes\n/* UPDATE notes */ SELECT ';INSERT INTO notes'", nil, 1},
		{"INSERT INTO notes (t) VALUES ('a;b'); UPDATE deals SET x = 1; SELECT 1;", []sqlWrite{{"notes", "insert"}, {"deals", "update"}}, 3},
		{"INSERT INTO notes (id) VALUES (1) ON CONFLICT(id) DO UPDATE SET id = 2 RETURNING id", []sqlWrite{{"notes", "insert"}}, 1},
		{"CREATE TABLE t (id INTEGER); DROP TABLE t", nil, 2},
	}
	for _, c := range cases {
		got, n := sqlWriteTargets(c.sql)
		if !reflect.DeepEqual(got, c.want) || n != c.stmts {
			t.Errorf("sqlWriteTargets(%q) = %v, %d; want %v, %d", c.sql, got, n, c.want, c.stmts)
		}
	}
}

// --- run: broadcast ---

func broadcastRoomApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, "CREATE TABLE room_members (id INTEGER PRIMARY KEY, room_id INTEGER, member_id INTEGER)")
	mustExec(t, db, "INSERT INTO room_members (room_id, member_id) VALUES (7, 1)")
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour,
		WSRooms: []WSRoomRule{{Pattern: "room-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}}
	return app
}

func roomClient(app *App, appID string, userID int64, group string, rooms ...string) *wsClient {
	c := newWSTestClient(appID, userID, group)
	c.principal = realtimePrincipal{app: app, session: &Session{UserID: userID, GroupID: group}}
	for _, r := range rooms {
		wsJoinAs(c, r)
	}
	return c
}

func broadcastFlow(t *testing.T, room, payload string) *Flow {
	t.Helper()
	flows, err := parseGHAFlowFile("flows/notify.yaml", []byte(`on:
  request: { method: POST, path: /api/notify }
jobs:
  notify:
    steps:
      - id: b
        run: broadcast
        with:
          room: "`+room+`"
          payload: `+payload+`
      - run: respond
        with: { status: 200, body: { recipients: "${{ steps.b.outputs.recipients }}" } }
`))
	if err != nil {
		t.Fatal(err)
	}
	return &flows[0]
}

// `run: broadcast` reaches a joined member of the room in this app with the
// same frame bm.room() already handles ({type:'message', room, from,
// payload}, from = "server"), and nobody else: not a same-app connection that
// did not join, not a joined connection that fails the room's ws_rooms
// membership rule, and not another app's member of a room with the same name.
func TestFlowBroadcastStepDeliversToRoomMembersOnly(t *testing.T) {
	resetWSHub(t)
	app := broadcastRoomApp(t)
	other := &App{Dir: t.TempDir()}
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "room-7")
	outsider := roomClient(app, realtimeAppID(app.Dir), 2, "", "room-7") // joined, but no membership row
	idle := roomClient(app, realtimeAppID(app.Dir), 1, "")
	foreign := roomClient(other, realtimeAppID(other.Dir), 1, "", "room-7")
	for _, c := range []*wsClient{member, outsider, idle, foreign} {
		registerWSClient(c)
		defer unregisterWSClient(c)
	}

	flow := broadcastFlow(t, "room-${{ room_id }}", `{ kind: note, text: "${{ text }}", n: 3, tags: [a, b] }`)
	req := httptest.NewRequest("POST", "/api/notify", strings.NewReader(`{"room_id": 7, "text": "hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"recipients":1`) {
		t.Fatalf("flow status=%d body=%s", rr.Code, rr.Body.String())
	}

	select {
	case frame := <-member.send:
		var got map[string]any
		if err := json.Unmarshal(frame, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"type": "message", "room": "room-7", "from": "server",
			"payload": map[string]any{"kind": "note", "text": "hello", "n": float64(3), "tags": []any{"a", "b"}}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("frame = %s", frame)
		}
	default:
		t.Fatal("joined member did not receive the server broadcast")
	}
	for name, c := range map[string]*wsClient{"non-member": outsider, "not joined": idle, "other app": foreign} {
		if wsReceivedAny(c) {
			t.Errorf("%s received the broadcast", name)
		}
	}
}

// In an app with groups:, the message stays in the caller's tenant, and a
// run with no tenant (no session) fails instead of reaching every tenant.
func TestFlowBroadcastStepStaysInTenant(t *testing.T) {
	resetWSHub(t)
	app := broadcastRoomApp(t)
	app.WSRooms = nil
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	a := roomClient(app, realtimeAppID(app.Dir), 1, "tenant-a", "lobby")
	b := roomClient(app, realtimeAppID(app.Dir), 2, "tenant-b", "lobby")
	for _, c := range []*wsClient{a, b} {
		registerWSClient(c)
		defer unregisterWSClient(c)
	}
	step := &FlowStep{Name: "b", Type: "broadcast", Broadcast: &FlowBroadcast{Room: "lobby", Payload: map[string]any{"ok": true}, HasPayload: true}}
	ctx := &FlowContext{App: app, Session: &Session{UserID: 1, GroupID: "tenant-a"}, Data: map[string]any{}, Params: map[string]string{}}
	if err := executeStep(ctx, step); err != nil {
		t.Fatal(err)
	}
	if !wsReceivedAny(a) || wsReceivedAny(b) {
		t.Fatal("server broadcast crossed tenants or missed its tenant")
	}
	anon := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if err := executeStep(anon, step); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("tenant-less broadcast in a grouped app: err=%v", err)
	}
	if wsReceivedAny(a) || wsReceivedAny(b) {
		t.Fatal("tenant-less broadcast was delivered")
	}
}

// A payload over 64 KiB (or an invalid room) fails the step before anything
// is sent.
func TestFlowBroadcastStepRejectsOversizedPayloadAndBadRoom(t *testing.T) {
	resetWSHub(t)
	app := broadcastRoomApp(t)
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "room-7")
	registerWSClient(member)
	defer unregisterWSClient(member)

	ctx := &FlowContext{App: app, Data: map[string]any{"big": strings.Repeat("x", flowBroadcastMaxPayload)}, Params: map[string]string{}}
	step := &FlowStep{Type: "broadcast", Broadcast: &FlowBroadcast{Room: "room-7", Payload: map[string]any{"body": "{{big}}"}, HasPayload: true}}
	if err := executeStep(ctx, step); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized payload: err=%v", err)
	}
	bad := &FlowStep{Type: "broadcast", Broadcast: &FlowBroadcast{Room: "room 7", Payload: "hi", HasPayload: true}}
	if err := executeStep(ctx, bad); err == nil || !strings.Contains(err.Error(), "room name") {
		t.Fatalf("invalid room: err=%v", err)
	}
	unresolved := &FlowStep{Type: "broadcast", Broadcast: &FlowBroadcast{Room: "room-7", Payload: "{{nope.value}}", HasPayload: true}}
	if err := executeStep(ctx, unresolved); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("unresolved payload ref: err=%v", err)
	}
	if wsReceivedAny(member) {
		t.Fatal("a failed broadcast step still sent a message")
	}
}

// The write gate and `benmore check` accept a valid `run: broadcast` step (at
// the top level and nested, in flows.yaml and flows/*.yaml) and reject one
// without a room, without a payload, or with a room outside the room alphabet.
func TestFlowBroadcastStepValidation(t *testing.T) {
	const head = "on:\n  request: { method: POST, path: /api/notify, auth: required }\njobs:\n  notify:\n    steps:\n"
	const tail = "      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
	good := head +
		"      - id: b\n        run: broadcast\n        with:\n          room: \"order-${{ params.id }}\"\n          payload: { kind: shipped, id: \"${{ params.id }}\" }\n" +
		"      - if: ${{ params.id }}\n        steps:\n          - run: broadcast\n            with: { room: lobby, payload: \"ping\" }\n" + tail
	if msg := ValidateOnWrite("flows.yaml", good); msg != "" {
		t.Fatalf("write gate rejected a valid broadcast step: %s", msg)
	}
	bad := map[string]string{
		"missing room":    head + "      - run: broadcast\n        with: { payload: { ok: true } }\n" + tail,
		"missing payload": head + "      - run: broadcast\n        with: { room: lobby }\n" + tail,
		"bad room":        head + "      - run: broadcast\n        with: { room: \"my room\", payload: 1 }\n" + tail,
		"typo key":        head + "      - run: broadcast\n        with: { room: lobby, payload: 1, paylod: 2 }\n" + tail,
		"nested missing":  head + "      - if: ${{ params.id }}\n        steps:\n          - run: broadcast\n            with: { payload: 1 }\n" + tail,
	}
	wants := map[string]string{
		"missing room": "requires `with.room`", "missing payload": "requires `with.payload`",
		"bad room": "room name", "typo key": "`with.paylod`", "nested missing": "step 0 > if steps[0]",
	}
	for name, content := range bad {
		if msg := ValidateOnWrite("flows.yaml", content); !strings.Contains(msg, wants[name]) {
			t.Errorf("%s: write gate message %q does not contain %q", name, msg, wants[name])
		}
	}

	files := func(flow string) map[string]string {
		return map[string]string{
			"app.yaml":          "seo:\n  site_name: T\n",
			"schema.prisma":     "model Note {\n  id   Int    @id @default(autoincrement())\n  body String\n}\n",
			"flows/notify.yaml": flow,
		}
	}
	for _, f := range RunCompleteCheck(writeApp(t, files(good)), "").Findings {
		if f.Severity == "error" {
			t.Errorf("benmore check rejected a valid broadcast step: %s: %s", f.File, f.Message)
		}
	}
	rpt := RunCompleteCheck(writeApp(t, files(bad["missing room"])), "")
	found := false
	for _, f := range rpt.Findings {
		if f.Severity == "error" && f.File == filepath.Join("flows", "notify.yaml") && strings.Contains(f.Message, "requires `with.room`") {
			found = true
		}
	}
	if !found {
		t.Errorf("benmore check must flag a broadcast step without a room in flows/notify.yaml:\n%s", FormatReport(rpt))
	}
}
