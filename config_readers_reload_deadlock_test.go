//go:build !cli && !race

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is about deadlock only, so it is not built with the race
// detector: auto-CRUD handlers still read some configuration fields directly,
// which the detector reports under a real reload.
//
// The shared helpers (hasColumn, the hook and workflow lookups, the hidden
// and encrypted column checks, session role scopes, ...) take app.mu for
// reading, and a reload takes it for writing to publish. A caller that held
// the read lock and reached one of them would wait behind the reload for good,
// and so would the reload. Every auto-CRUD path that reaches those helpers
// runs here, concurrently, while the served app reloads in a loop.

func reloadDeadlockFixture(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: \"Reload deadlock\"\nauth:\n  identifier: email\naccess:\n  rooms: member-of:room_members(room_id, member_id)\n")
	writeTestFile(t, dir, "env.yaml", "RATE_LIMIT_PER_MIN: \"0\"\n")
	writeTestFile(t, dir, "schema.prisma", `model Project {
  id      Int      @id @default(autoincrement())
  name    String
  userId  Int?     @map("user_id")
  tickets Ticket[]

  @@map("projects")
}

model Ticket {
  id          Int       @id @default(autoincrement())
  title       String
  status      String    @default("open")
  note        String?
  secretToken String?   @map("secret_token")
  projectId   Int?      @map("project_id")
  project     Project?  @relation(fields: [projectId], references: [id])
  userId      Int?      @map("user_id")
  createdAt   DateTime  @default(now()) @map("created_at")
  updatedAt   DateTime  @default(now()) @updatedAt @map("updated_at")
  deletedAt   DateTime? @map("deleted_at")

  @@map("tickets")
}

model TicketLog {
  id   Int    @id @default(autoincrement())
  note String

  @@map("ticket_logs")
}

model Room {
  id    Int    @id @default(autoincrement())
  title String @default("")

  @@map("rooms")
}

model RoomMember {
  id       Int @id @default(autoincrement())
  roomId   Int @map("room_id")
  memberId Int @map("member_id")

  @@unique([roomId, memberId])
  @@map("room_members")
}
`)
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  tickets:\n    fields: [note]\n    unmask_roles: [self, manager, admin]\n")
	writeTestFile(t, dir, "workflows.yaml", `tickets:
  table: tickets
  field: status
  initial: open
  transitions:
    open:
      stale: { role: manager }
    stale:
      open: {}
  on_transition:
    stale:
      - sql: "INSERT INTO ticket_logs (note) VALUES ('transition {{id}}')"
  timeout:
    open: { after: 1h, to: stale }
`)
	writeTestFile(t, dir, "hooks.yaml", `before_update:
  tickets:
    - sql: "SELECT CASE WHEN '{{title}}' = 'refuse' THEN RAISE(ABORT, 'refused by hook') END"
on_insert:
  tickets:
    - sql: "INSERT INTO ticket_logs (note) VALUES ('created {{id}}')"
on_update:
  tickets:
    - sql: "INSERT INTO ticket_logs (note) VALUES ('updated {{id}}')"
on_delete:
  tickets:
    - sql: "INSERT INTO ticket_logs (note) VALUES ('deleted {{id}}')"
`)
	writeTestFile(t, dir, "flows/sweep.yaml", "on:\n  request: { method: POST, path: /api/sweep, auth: required }\njobs:\n  go:\n    steps:\n      - run: sql\n        query: \"INSERT INTO ticket_logs (note) VALUES ('scheduled')\"\n      - run: respond\n        with: { json: { ok: true } }\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

// reloadDeadlockTally counts, per traffic path, the requests that succeeded
// and the statuses of those that did not.
type reloadDeadlockTally struct {
	mu      sync.Mutex
	ok      map[string]int
	refused map[string]map[int]int
	sample  map[string]string
}

func (c *reloadDeadlockTally) record(path string, rec *httptest.ResponseRecorder) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec.Code >= 200 && rec.Code < 300 {
		c.ok[path]++
		return true
	}
	if c.refused[path] == nil {
		c.refused[path] = map[int]int{}
	}
	c.refused[path][rec.Code]++
	if c.sample[path] == "" {
		c.sample[path] = fmt.Sprintf("%d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	return false
}

func TestAutoCRUDFinishesWhileAppReloads(t *testing.T) {
	app := reloadDeadlockFixture(t)
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })

	manager := createCrudScopeSession(t, app, "manager@example.com", "manager", "", "")
	subscribers := []*flowRealtimeSubscriber{
		subscribeFlowRealtime(t, app, manager),
		subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "watcher@example.com", "user", "", "")),
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+manager)
	session := getSession(app, sessionRequest)
	if session == nil {
		t.Fatal("session did not resolve")
	}
	authority := marshalScheduledAuthority(session)

	tally := &reloadDeadlockTally{ok: map[string]int{}, refused: map[string]map[int]int{}, sample: map[string]string{}}
	call := func(path, method, url string, body any) (map[string]any, bool) {
		var reader *strings.Reader
		if body != nil {
			encoded, _ := json.Marshal(body)
			reader = strings.NewReader(string(encoded))
		} else {
			reader = strings.NewReader("")
		}
		req := httptest.NewRequest(method, "https://fixture.example.com"+url, reader)
		req.Header.Set("Authorization", "Bearer "+manager)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		ok := tally.record(path, rec)
		var decoded map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
		return decoded, ok
	}
	// newTicket creates a row for a path to work on and returns its id.
	newTicket := func(path, title string, projectID any) (string, bool) {
		created, ok := call(path, http.MethodPost, "/api/tickets", map[string]any{"title": title, "note": "private note", "secret_token": "tok-" + title, "project_id": projectID})
		if !ok || created["id"] == nil {
			return "", false
		}
		return valueText(created["id"]), true
	}

	project, ok := call("setup", http.MethodPost, "/api/projects", map[string]any{"name": "Apollo"})
	if !ok || project["id"] == nil {
		t.Fatalf("create project: %v", tally.sample["setup"])
	}
	projectID := project["id"]
	seeded, ok := newTicket("setup", "seeded", projectID)
	if !ok {
		t.Fatalf("create ticket: %v", tally.sample["setup"])
	}

	const reloadWindow = 8 * time.Second
	stop := make(chan struct{})
	var background sync.WaitGroup
	loop := func(step func(i int)) {
		background.Add(1)
		go func() {
			defer background.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					step(i)
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	loop(func(int) {
		call("list", http.MethodGet, "/api/tickets", nil)
		call("list include", http.MethodGet, "/api/tickets?include=project", nil)
		call("read include", http.MethodGet, "/api/tickets/"+seeded+"?include=project", nil)
	})
	loop(func(i int) { newTicket("create", fmt.Sprintf("create-%d", i), projectID) })
	loop(func(i int) {
		// before_update and on_update hooks, the encrypted and hidden columns.
		call("update", http.MethodPatch, "/api/tickets/"+seeded, map[string]any{"title": fmt.Sprintf("seeded-%d", i), "note": fmt.Sprintf("note %d", i)})
	})
	loop(func(i int) {
		if id, ok := newTicket("delete (create)", fmt.Sprintf("delete-%d", i), nil); ok {
			call("delete", http.MethodDelete, "/api/tickets/"+id, nil)
		}
	})
	loop(func(i int) {
		created, ok := call("batch create", http.MethodPost, "/api/tickets/batch", []map[string]any{{"title": fmt.Sprintf("batch-a-%d", i)}, {"title": fmt.Sprintf("batch-b-%d", i), "note": "n"}})
		if ids, _ := created["ids"].([]any); ok && len(ids) > 0 {
			call("batch update", http.MethodPatch, "/api/tickets/batch", map[string]any{"ids": ids, "fields": map[string]any{"title": fmt.Sprintf("batched-%d", i)}})
		}
	})
	loop(func(i int) {
		call("transaction", http.MethodPost, "/api/_transaction", map[string]any{"operations": []map[string]any{
			{"table": "tickets", "action": "insert", "data": map[string]any{"title": fmt.Sprintf("tx-%d", i), "note": "n"}},
			{"table": "tickets", "action": "update", "id": seeded, "data": map[string]any{"note": fmt.Sprintf("tx note %d", i)}},
		}})
	})
	loop(func(i int) {
		if id, ok := newTicket("transition (create)", fmt.Sprintf("transition-%d", i), nil); ok {
			call("transition", http.MethodPost, "/api/tickets/"+id+"/transition", map[string]any{"to": "stale"})
			call("transitions", http.MethodGet, "/api/tickets/"+id+"/transitions", nil)
		}
	})
	loop(func(i int) {
		// The lock routes allow 30 a minute; a refusal past that is counted,
		// not a failure.
		if i >= 12 {
			time.Sleep(50 * time.Millisecond)
			return
		}
		if id, ok := newTicket("lock (create)", fmt.Sprintf("lock-%d", i), nil); ok {
			if _, locked := call("lock", http.MethodPost, "/api/tickets/"+id+"/lock", nil); locked {
				call("locked update", http.MethodPatch, "/api/tickets/"+id, map[string]any{"title": fmt.Sprintf("locked-%d", i)})
				call("unlock", http.MethodDelete, "/api/tickets/"+id+"/lock", nil)
			}
		}
	})
	loop(func(i int) {
		if room, ok := call("member-of create", http.MethodPost, "/api/rooms", map[string]any{"title": fmt.Sprintf("room-%d", i)}); ok && room["id"] != nil {
			call("member-of read", http.MethodGet, "/api/rooms/"+valueText(room["id"]), nil)
		}
		call("member-of list", http.MethodGet, "/api/rooms", nil)
	})
	// The timeout checker's and the scheduled-task sweeper's sweeps; the job
	// worker buildAppMux started runs the hook jobs all of the above queue.
	loop(func(i int) {
		if _, err := app.DB.Exec("INSERT INTO tickets (title, status, updated_at) VALUES (?, 'open', datetime('now', '-2 hours'))", fmt.Sprintf("due-%d", i)); err == nil {
			if wf := GetWorkflowForTable(app, "tickets"); wf != nil {
				checkWorkflowTimeoutsAt(app, wf, time.Now())
			}
		}
		time.Sleep(20 * time.Millisecond)
	})
	loop(func(int) {
		if _, err := app.DB.Exec("INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, flow, body, run_at, authorization) VALUES (?, 'flow', 'Sweep', 'sweep', '{}', '2000-01-01T00:00:00Z', ?)", session.UserID, authority); err == nil {
			sweepScheduledTasks(app)
		}
		time.Sleep(20 * time.Millisecond)
	})
	var heardMu sync.Mutex
	heard := 0
	loop(func(int) {
		for _, subscriber := range subscribers {
			sse, ws := subscriber.drain()
			heardMu.Lock()
			heard += len(sse) + len(ws)
			heardMu.Unlock()
		}
	})

	keepWriterWaiting(app, stop, &background)

	reloaded := 0
	finished := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(reloadWindow)
		for time.Now().Before(deadline) {
			if err := hotReloadApp(app, false); err != nil {
				close(stop)
				finished <- fmt.Errorf("reload %d: %w", reloaded+1, err)
				return
			}
			reloaded++
			time.Sleep(5 * time.Millisecond)
		}
		close(stop)
		background.Wait()
		finished <- nil
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(reloadWindow + 60*time.Second):
		failDeadlocked("a request, a worker or a reload")
	}

	if reloaded < 3 {
		t.Fatalf("only %d reloads ran in %s", reloaded, reloadWindow)
	}
	tally.mu.Lock()
	defer tally.mu.Unlock()
	for _, path := range []string{"list", "list include", "read include", "create", "update", "delete", "batch create", "batch update", "transaction",
		"transition", "transitions", "lock", "locked update", "unlock", "member-of create", "member-of read", "member-of list"} {
		if tally.ok[path] == 0 {
			t.Errorf("%s never succeeded while the app reloaded (refusals %v, first: %s)", path, tally.refused[path], tally.sample[path])
		}
	}
	heardMu.Lock()
	defer heardMu.Unlock()
	if heard == 0 {
		t.Error("the realtime subscribers heard no table event")
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM tickets WHERE status = 'stale'"); got == 0 {
		t.Error("no ticket timed out or was transitioned")
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE status = 'done'"); got == 0 {
		t.Error("no scheduled flow ran")
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note LIKE 'updated %'"); got == 0 {
		t.Error("the job worker ran no on_update hook")
	}
	t.Logf("%d reloads; requests that succeeded: %v; refused: %v", reloaded, tally.ok, tally.refused)
}
