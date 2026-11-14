//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A reload publishes new configuration under app.mu and replaces each object
// whole. The workers that run app code in the background (the workflow
// timeout checker, the job worker, the scheduled-task sweeper) and the page
// path must read that configuration the way a reload publishes it. These tests
// republish an equal configuration in a tight loop while each of them runs:
// an unlocked read of a published field is a data race the detector reports.

func configReadersFixture(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: \"Config readers\"\nauth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", `model Ticket {
  id        Int       @id @default(autoincrement())
  title     String
  status    String    @default("open")
  userId    Int?      @map("user_id")
  createdAt DateTime  @default(now()) @map("created_at")
  updatedAt DateTime  @default(now()) @updatedAt @map("updated_at")
  deletedAt DateTime? @map("deleted_at")

  @@map("tickets")
}

model TicketLog {
  id   Int    @id @default(autoincrement())
  note String

  @@map("ticket_logs")
}
`)
	writeTestFile(t, dir, "workflows.yaml", `tickets:
  table: tickets
  field: status
  initial: open
  transitions:
    open:
      stale: {}
    stale:
      open: {}
  on_transition:
    stale:
      - sql: "INSERT INTO ticket_logs (note) VALUES ('transition {{id}}')"
  timeout:
    open: { after: 1h, to: stale }
`)
	writeTestFile(t, dir, "hooks.yaml", "on_update:\n  tickets:\n    - sql: \"INSERT INTO ticket_logs (note) VALUES ('hook {{id}}')\"\n")
	writeTestFile(t, dir, "flows/ticket_event.yaml", "on:\n  event: { table: tickets, op: update }\njobs:\n  go:\n    steps:\n      - run: sql\n        query: \"INSERT INTO ticket_logs (note) VALUES ('event')\"\n")
	writeTestFile(t, dir, "flows/sweep.yaml", "on:\n  request: { method: POST, path: /api/sweep, auth: required }\njobs:\n  go:\n    steps:\n      - run: sql\n        query: \"INSERT INTO ticket_logs (note) VALUES ('scheduled')\"\n      - run: respond\n        with: { json: { ok: true } }\n")
	writeTestFile(t, dir, "flows/queued.yaml", "on:\n  request: { method: POST, path: /api/queued, mode: async }\nidempotent: true\njobs:\n  go:\n    steps:\n      - run: sql\n        query: \"UPDATE tickets SET title = title WHERE id = -1\"\n      - run: sql\n        query: \"INSERT INTO ticket_logs (note) VALUES ('queued')\"\n")
	writeTestFile(t, dir, "report.html", "<page title=\"Report\" auth=\"none\" layout=\"none\">\n<include src=\"partials/nav.html\" />\n<query sql=\"SELECT title FROM tickets ORDER BY id LIMIT 3\" as=\"rows\">{{#rows}}<p>{{title}}</p>{{/rows}}</query>\n</page>")
	writeTestFile(t, dir, "board.html", "<page title=\"Board\" auth=\"none\" layout=\"shell\">\n<p>board</p>\n</page>")
	writeTestFile(t, dir, "layouts/shell.html", "<!doctype html><html><body><include src=\"partials/nav.html\" /><main>{{content}}</main></body></html>")
	writeTestFile(t, dir, "partials/nav.html", "<nav>navigation</nav>")
	writeTestFile(t, dir, "partials/kit.html", "<include src=\"partials/tokens.html\" />")
	writeTestFile(t, dir, "partials/tokens.html", "<style>:root{--kit:1}</style>")
	writeTestFile(t, dir, "static/plain.html", "<!doctype html><html><body><include src=\"partials/foot.html\" /><p>plain</p></body></html>")
	writeTestFile(t, dir, "static/partials/foot.html", "<footer>footer</footer>")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	EnsureJobsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	return app
}

// republishEqualConfiguration replaces every object a reload publishes with an
// equal copy, under the lock a reload publishes with. A field that is nil is
// written too: a reload assigns every field, whatever the app configures.
func republishEqualConfiguration(app *App) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.Tables = append([]Table(nil), app.Tables...)
	uuidTables := make(map[string]bool, len(app.UUIDTables))
	for k, v := range app.UUIDTables {
		uuidTables[k] = v
	}
	app.UUIDTables = uuidTables
	joins := make(JoinMap, len(app.JoinMap))
	for k, v := range app.JoinMap {
		joins[k] = v
	}
	app.JoinMap = joins
	app.Flows = append([]Flow(nil), app.Flows...)
	app.Hooks = cloneHookConfig(app.Hooks)
	app.Workflows = cloneWorkflowConfig(app.Workflows)
	app.Validators = cloneValidatorConfig(app.Validators)
	app.Computed = cloneComputedConfig(app.Computed)
	app.Pages = clonePages(app.Pages)
	republishPartials(app)
	app.Design = shallowCopy(app.Design)
	app.Group = shallowCopy(app.Group)
	app.Roles = shallowCopy(app.Roles)
	app.Access = shallowCopy(app.Access)
	app.Encrypted = shallowCopy(app.Encrypted)
	app.Admin = shallowCopy(app.Admin)
	app.I18n = shallowCopy(app.I18n)
	app.Cron = shallowCopy(app.Cron)
	scopes := make(map[string]ScopeConfig, len(app.Scopes))
	for k, v := range app.Scopes {
		scopes[k] = v
	}
	app.Scopes = scopes
	app.WSRooms = append([]WSRoomRule(nil), app.WSRooms...)
	publishAppMCPRuntimeGeneration(app, appMCPGenerationFromAppLocked(app))
}

// republishPartials replaces app.Partials with an equal map. The caller holds
// app.mu.
func republishPartials(app *App) {
	partials := make(map[string]string, len(app.Partials))
	for k, v := range app.Partials {
		partials[k] = v
	}
	app.Partials = partials
}

func shallowCopy[T any](in *T) *T {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

// whileRepublishing runs work while another goroutine republishes app's
// configuration without pause.
func whileRepublishing(t *testing.T, app *App, work func()) {
	t.Helper()
	whilePublishing(t, func() { republishEqualConfiguration(app) }, work)
}

// whilePublishing runs work while another goroutine calls publish without
// pause.
func whilePublishing(t *testing.T, publish func(), work func()) {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				publish()
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	work()
}

func configReadersWorkflow(t *testing.T, app *App) *Workflow {
	t.Helper()
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.Workflows == nil || app.Workflows.Workflows["tickets"] == nil {
		t.Fatal("fixture workflow did not load")
	}
	return app.Workflows.Workflows["tickets"]
}

func configReadersCount(t *testing.T, app *App, query string, args ...any) (n int) {
	t.Helper()
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// drainConfigReaderJobs runs the job worker's step until the queue is empty.
func drainConfigReaderJobs(t *testing.T, app *App) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for processNextJob(app) {
		}
		if configReadersCount(t, app, "SELECT COUNT(*) FROM _benmore_jobs WHERE status IN ('pending','running')") == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("jobs did not drain")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWorkflowTimeoutCheckerReadsPublishedConfiguration(t *testing.T) {
	app := configReadersFixture(t)
	const rows = 40
	for i := 0; i < rows; i++ {
		mustExecArgs(t, app.DB, "INSERT INTO tickets (title, status, updated_at) VALUES (?, 'open', datetime('now', '-2 hours'))", fmt.Sprintf("due-%d", i))
	}
	wf := configReadersWorkflow(t, app)
	whileRepublishing(t, app, func() {
		checkWorkflowTimeoutsAt(app, wf, time.Now())
		// The transition's hook and event-flow work, as the job worker runs it.
		drainConfigReaderJobs(t, app)
	})
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM tickets WHERE status = 'stale'"); got != rows {
		t.Fatalf("%d of %d due rows timed out", got, rows)
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note LIKE 'transition %'"); got != rows {
		t.Fatalf("on_transition hook ran for %d of %d rows", got, rows)
	}
}

func TestJobWorkerReadsPublishedConfiguration(t *testing.T) {
	app := configReadersFixture(t)
	const jobs = 40
	app.mu.RLock()
	hook := app.Hooks.OnUpdate["tickets"][0]
	app.mu.RUnlock()
	for i := 0; i < jobs; i++ {
		mustExecArgs(t, app.DB, "INSERT INTO tickets (title) VALUES (?)", fmt.Sprintf("job-%d", i))
		EnqueueHookJob(app, hook, "tickets", map[string]any{"id": int64(i + 1), "title": fmt.Sprintf("job-%d", i), "status": "open"})
		if _, _, err := EnqueueJob(app.DB, "queued", map[string]any{"n": i}, nil); err != nil {
			t.Fatal(err)
		}
	}
	whileRepublishing(t, app, func() {
		jobsRecoverOrphanedJobs(app)
		drainConfigReaderJobs(t, app)
	})
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'completed'"); got != 2*jobs {
		t.Fatalf("%d of %d jobs finished", got, 2*jobs)
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note LIKE 'hook %'"); got != jobs {
		t.Fatalf("hook SQL ran for %d of %d jobs", got, jobs)
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note = 'queued'"); got != jobs {
		t.Fatalf("queued flow ran for %d of %d jobs", got, jobs)
	}
}

func TestScheduledTaskSweeperReadsPublishedConfiguration(t *testing.T) {
	app := configReadersFixture(t)
	sid := createCrudScopeSession(t, app, "scheduler@example.com", "user", "", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	session := getSession(app, req)
	if session == nil {
		t.Fatal("scheduler session did not resolve")
	}
	const tasks = 30
	for i := 0; i < tasks; i++ {
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, flow, body, run_at, authorization) VALUES (?, 'flow', 'Sweep', 'sweep', '{}', '2000-01-01T00:00:00Z', ?)",
			session.UserID, marshalScheduledAuthority(session))
	}
	whileRepublishing(t, app, func() {
		sweepScheduledTasks(app)
	})
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE status = 'done'"); got != tasks {
		var lastError string
		app.DB.QueryRow("SELECT COALESCE(last_error,'') FROM _benmore_scheduled_tasks WHERE status != 'done' LIMIT 1").Scan(&lastError)
		t.Fatalf("%d of %d scheduled flows ran (%s)", got, tasks, lastError)
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note = 'scheduled'"); got != tasks {
		t.Fatalf("scheduled flow wrote %d of %d rows", got, tasks)
	}
}

func TestPagesReadPublishedPartials(t *testing.T) {
	app := configReadersFixture(t)
	mux := buildAppMux(app, false, "http://localhost")
	get := func(path, want string) {
		t.Helper()
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), want) {
			t.Errorf("GET %s = %d, want %q in: %s", path, rr.Code, want, rr.Body.String())
		}
	}
	// Partials only: the page path's other configuration reads are not what
	// this test is about.
	whilePublishing(t, func() {
		app.mu.Lock()
		republishPartials(app)
		app.mu.Unlock()
	}, func() {
		var wg sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 25; i++ {
					get("/report", "<nav>navigation</nav>")
					get("/report", "--kit:1")
					get("/board", "<nav>navigation</nav><main>")
					get("/plain", "<footer>footer</footer>")
				}
			}()
		}
		wg.Wait()
	})
}

// The accessors take app.mu for reading, and a reload waits for it to publish.
// A helper that took it again while its caller held it would stop behind that
// waiting reload for good. This reloads the served app for real while the
// started job worker, timeout sweeps, scheduled-task sweeps, page requests
// and realtime delivery to a subscriber all run, and fails if the whole does
// not finish.
func TestReloadsFinishWhileWorkersRequestsAndRealtimeRun(t *testing.T) {
	app := configReadersFixture(t)
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })

	sid := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	subscriber := subscribeFlowRealtime(t, app, sid)
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+sid)
	session := getSession(app, sessionRequest)
	if session == nil {
		t.Fatal("session did not resolve")
	}
	authority := marshalScheduledAuthority(session)
	serve := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "https://fixture.example.com"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+sid)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	const reloads = 6
	stop := make(chan struct{})
	var background sync.WaitGroup
	var served, swept atomic.Int64
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
					time.Sleep(2 * time.Millisecond)
				}
			}
		}()
	}
	// Requests: a page that expands an include. Auto-CRUD requests are left
	// out on purpose: their handlers still read configuration fields
	// directly, which the race detector reports under a real reload.
	loop(func(int) {
		if rec := serve(http.MethodGet, "/plain", ""); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "<footer>footer</footer>") {
			served.Add(1)
		} else {
			t.Errorf("GET /plain = %d", rec.Code)
		}
	})
	// The timeout checker's sweep, on rows already past their deadline.
	loop(func(i int) {
		if _, err := app.DB.Exec("INSERT INTO tickets (title, status, updated_at) VALUES (?, 'open', datetime('now', '-2 hours'))", fmt.Sprintf("due-%d", i)); err != nil {
			t.Errorf("seed due ticket: %v", err)
			return
		}
		if wf := GetWorkflowForTable(app, "tickets"); wf != nil {
			checkWorkflowTimeoutsAt(app, wf, time.Now())
		}
	})
	// The scheduled-task sweeper's sweep.
	loop(func(int) {
		if _, err := app.DB.Exec("INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, flow, body, run_at, authorization) VALUES (?, 'flow', 'Sweep', 'sweep', '{}', '2000-01-01T00:00:00Z', ?)", session.UserID, authority); err != nil {
			t.Errorf("seed scheduled task: %v", err)
			return
		}
		sweepScheduledTasks(app)
		swept.Add(1)
	})
	// Realtime: the timeouts and scheduled flows above announce their writes;
	// delivery checks the subscriber's session against the live app.
	var heard atomic.Int64
	loop(func(int) {
		sse, ws := subscriber.drain()
		heard.Add(int64(len(sse) + len(ws)))
	})

	keepWriterWaiting(app, stop, &background)

	finished := make(chan error, 1)
	go func() {
		for reload := 1; reload <= reloads; reload++ {
			if err := hotReloadApp(app, false); err != nil {
				finished <- fmt.Errorf("reload %d: %w", reload, err)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		close(stop)
		background.Wait()
		finished <- nil
	}()
	select {
	case err := <-finished:
		if err != nil {
			close(stop)
			t.Fatal(err)
		}
	case <-time.After(2 * time.Minute):
		failDeadlocked("the reloads, workers or requests")
	}

	if served.Load() == 0 || swept.Load() == 0 {
		t.Fatalf("background work did not run: %d pages, %d sweeps", served.Load(), swept.Load())
	}
	if heard.Load() == 0 {
		t.Fatal("the subscriber heard no table event while reloads ran")
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM tickets WHERE status = 'stale'"); got == 0 {
		t.Fatal("no ticket timed out while reloads ran")
	}
	if got := configReadersCount(t, app, "SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE status = 'done'"); got == 0 {
		t.Fatal("no scheduled flow ran while reloads ran")
	}
	// The started job worker ran the timeouts' hook jobs under the reloads.
	deadline := time.Now().Add(30 * time.Second)
	for configReadersCount(t, app, "SELECT COUNT(*) FROM ticket_logs WHERE note LIKE 'transition %'") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the job worker ran no transition hook")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// keepWriterWaiting asks for app.mu's write lock without pause until stop
// closes, the way a reload about to publish does. A real reload asks a few
// times a second, and a read lock taken inside another is fatal only while a
// writer is waiting: with this running, a nested read lock anywhere in the
// work under test meets a waiting writer at once instead of once in a great
// many runs.
func keepWriterWaiting(app *App, stop <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				app.mu.Lock()
				app.mu.Unlock() //nolint:staticcheck // the empty critical section is the point
				time.Sleep(20 * time.Microsecond)
			}
		}
	}()
}

// failDeadlocked reports work that did not finish and ends the test binary. A
// deadlocked app cannot be shut down, so the usual cleanup would hang until
// the go test timeout and the report would be lost.
func failDeadlocked(what string) {
	stacks := make([]byte, 4<<20)
	os.Stderr.Write(stacks[:runtime.Stack(stacks, true)])
	panic(what + " did not finish (deadlock): every goroutine's stack is printed above")
}
