//go:build !cli

package main

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func taintTestFlow(steps ...FlowStep) Flow {
	return Flow{Name: "t", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/t"}, Steps: steps}
}

func runTaintFlow(app *App, flow Flow, body string) error {
	req := httptest.NewRequest("POST", "/api/t", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return executeFlowHTTP(app, &flow, httptest.NewRecorder(), req)
}

// A `run: sql` step whose query binds a request value returns request-derived
// data; sql_dynamic must refuse it as raw text just like the request itself.
func TestSQLDynamicRefusesTaintThroughSQLOutput(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('a'), ('b')`)

	flow := taintTestFlow(
		FlowStep{Name: "pick", Type: "sql", SQL: "SELECT :q AS c"},
		FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT * FROM notes WHERE body = '{{pick.c}}'"},
	)
	err := runTaintFlow(app, flow, `{"q":"zzz' OR '1'='1"}`)
	if err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("sql output derived from request input reached sql_dynamic: err=%v", err)
	}
	if !strings.Contains(err.Error(), "`run: sql`") || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("error must tell the author to bind a parameter with :name: %v", err)
	}
}

// An identifier read by a lookup keyed only by literals is not
// request-derived and keeps working.
func TestSQLDynamicAllowsUntaintedSQLOutput(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('a')`)
	mustExec(t, app.DB, `CREATE TABLE cfg (k TEXT, v TEXT)`)
	mustExec(t, app.DB, `INSERT INTO cfg VALUES ('col', 'body')`)

	flow := taintTestFlow(
		FlowStep{Name: "cfg", Type: "sql", SQL: "SELECT v FROM cfg WHERE k = 'col'"},
		FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT {{cfg.v}} AS x FROM notes"},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
	)
	if err := runTaintFlow(app, flow, `{"q":"whatever"}`); err != nil {
		t.Fatalf("untainted lookup must still reach sql_dynamic: %v", err)
	}
}

func TestSQLDynamicRefusesTaintThroughComputeOutput(t *testing.T) {
	app := writeComputeFixture(t, "echo.ts", `export function f(x: string): string { return x; }`)
	db, err := sql.Open("sqlite3", filepath.Join(app.Dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	defer app.Shutdown()

	run := func(args string) error {
		return runTaintFlow(app, taintTestFlow(
			FlowStep{Name: "c", Type: "compute", Compute: &FlowCompute{Module: "echo", Function: "f", Args: args}},
			FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT '{{c}}' AS v"},
			FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		), `{"q":"x' OR '1'='1"}`)
	}
	if err := run("{{q}}"); err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("compute output derived from request input reached sql_dynamic: %v", err)
	}
	if err := run("literal"); err != nil {
		t.Fatalf("compute over literals must stay untainted: %v", err)
	}
}

// api steps cannot reach a public host in tests, so this checks the marking
// helper directly, including nested JSON bodies and headers.
func TestAPIStepOutputTaintFromTemplates(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{}, Params: map[string]string{}, RequestKeys: map[string]bool{"q": true}}

	ctx.taintStepOutputs(&FlowStep{Name: "fetch", Type: "api", API: &FlowAPICall{URL: "https://x.test/{{q}}"}})
	if !ctx.isTainted("fetch") {
		t.Fatal("api step templated from a request field must taint its output")
	}
	ctx.taintStepOutputs(&FlowStep{Name: "ok", Type: "api", API: &FlowAPICall{
		URL: "https://x.test/y", Headers: map[string]string{"A": "b"}, JSON: map[string]any{"a": []any{"lit", "{{other}}"}},
	}})
	if ctx.isTainted("ok") {
		t.Fatal("api step with no tainted reference must stay clean")
	}
	ctx.taintStepOutputs(&FlowStep{Name: "j", Type: "api", API: &FlowAPICall{URL: "https://x.test/y", JSON: map[string]any{"a": []any{"{{q}}"}}}})
	if !ctx.isTainted("j") {
		t.Fatal("nested JSON body reference must taint the output")
	}
	ctx.taintStepOutputs(&FlowStep{Name: "h", Type: "api", API: &FlowAPICall{URL: "https://x.test/y", Headers: map[string]string{"X": "{{q}}"}}})
	if !ctx.isTainted("h") {
		t.Fatal("header reference must taint the output")
	}
}

// Taint carried by a step output reaches a job flow through an enqueue
// payload and taints a for_each loop variable.
func TestSQLOutputTaintCrossesEnqueueAndForEach(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	worker := Flow{Name: "worker", Trigger: FlowTrigger{Type: "job"}, Steps: []FlowStep{
		{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{v}}' AS x"},
	}}
	app.mu.Lock()
	app.Flows = []Flow{worker}
	app.mu.Unlock()

	flow := taintTestFlow(
		FlowStep{Name: "pick", Type: "sql", SQL: "SELECT :q AS c"},
		FlowStep{Name: "e", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{"v": "{{pick.c}}"}}},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: 202, Body: "queued"}},
	)
	if err := runTaintFlow(app, flow, `{"q":"x"}`); err != nil {
		t.Fatalf("flow: %v", err)
	}
	FlushJobs(app)
	var status, jobErr string
	if err := app.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE flow_name='worker'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status == "completed" || !strings.Contains(jobErr, "request-sourced") {
		t.Fatalf("tainted sql output enqueued into a job must stay tainted: status=%q err=%q", status, jobErr)
	}

	loop := taintTestFlow(
		FlowStep{Name: "rows", Type: "sql", SQL: "SELECT :q AS c"},
		FlowStep{Type: "for_each", ForEach: "rows", ForAs: "r", Steps: []FlowStep{
			{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT '{{r.c}}' AS v"},
		}},
	)
	if err := runTaintFlow(app, loop, `{"q":"x"}`); err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("for_each over tainted sql rows must taint the loop variable: %v", err)
	}
}

func TestEnqueueRefusesTaintedFlowName(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	flow := taintTestFlow(
		FlowStep{Name: "queue_it", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "{{target}}"}},
	)
	err := runTaintFlow(app, flow, `{"target":"admin_only_flow"}`)
	if err == nil || !strings.Contains(err.Error(), "queue_it") || !strings.Contains(err.Error(), "flow name") {
		t.Fatalf("request-controlled enqueue flow name must be refused naming the step: %v", err)
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs`).Scan(&n)
	if n != 0 {
		t.Fatalf("no job may be queued, got %d", n)
	}
}
