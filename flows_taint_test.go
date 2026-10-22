//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSQLDynamicTaintSurvivesCopies pins item 22: a request value copied into
// another key used to reach sql_dynamic untainted. Each case launders `term`
// (a query-string value) through a different copy and must still be refused.
func TestSQLDynamicTaintSurvivesCopies(t *testing.T) {
	app, done := newTestApp(t)
	defer done()

	dyn := func(sql string) FlowStep { return FlowStep{Name: "q", Type: "sql_dynamic", SQL: sql} }
	cases := map[string][]FlowStep{
		"set output via steps.<id>": {
			{Name: "s", Type: "set", Set: map[string]string{"copy": "{{term}}"}},
			dyn("SELECT '{{s.copy}}' AS v"),
		},
		"set output via bare key": {
			{Name: "s", Type: "set", Set: map[string]string{"copy": "prefix-{{ term | upper }}"}},
			dyn("SELECT '{{copy}}' AS v"),
		},
		"chained set": {
			{Name: "a", Type: "set", Set: map[string]string{"one": "{{term}}"}},
			{Name: "b", Type: "set", Set: map[string]string{"two": "{{a.one}}"}},
			dyn("SELECT '{{b.two}}' AS v"),
		},
		"whole set map": {
			{Name: "s", Type: "set", Set: map[string]string{"copy": "{{term}}"}},
			dyn("SELECT '{{s}}' AS v"),
		},
		"|| fallback operand": {
			dyn("SELECT '{{ missing || term }}' AS v"),
		},
	}
	for name, steps := range cases {
		flow := Flow{Name: "t", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/t"}, Steps: steps}
		err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/t?term=x", nil))
		if err == nil || !strings.Contains(err.Error(), "request-sourced") {
			t.Errorf("%s: sql_dynamic ran on laundered request input, err=%v", name, err)
		}
	}

	// Control: a set value built only from literals stays usable.
	flow := Flow{Name: "t", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/t"}, Steps: []FlowStep{
		{Name: "s", Type: "set", Set: map[string]string{"copy": "literal"}},
		dyn("SELECT '{{s.copy}}' AS v"),
		{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
	}}
	if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/t?term=x", nil)); err != nil {
		t.Fatalf("untainted set output must still reach sql_dynamic: %v", err)
	}
}

// TestSQLDynamicTaintSurvivesForEachParseAndOnError covers the other copies of
// request input: a for_each loop variable over a JSON-body array, a parsed
// request body, and an on_error handler (which used to run with no taint set).
func TestSQLDynamicTaintSurvivesForEachParseAndOnError(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	mustExec(t, app.DB, `CREATE TABLE audit (v TEXT)`)

	post := func(steps []FlowStep, body string) error {
		flow := Flow{Name: "t", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/t"}, Steps: steps}
		req := httptest.NewRequest("POST", "/api/t", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return executeFlowHTTP(app, &flow, httptest.NewRecorder(), req)
	}

	err := post([]FlowStep{{Type: "for_each", ForEach: "items", ForAs: "it", Steps: []FlowStep{
		{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{it.x}}' AS v"},
	}}}, `{"items":[{"x":"a"}]}`)
	if err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Errorf("for_each over request input: want taint refusal, got %v", err)
	}

	err = post([]FlowStep{
		{Name: "b", Type: "parse", Parse: "body"},
		{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{b.note}}' AS v"},
	}, `{"note":"a"}`)
	if err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Errorf("parsed request body: want taint refusal, got %v", err)
	}

	_ = post([]FlowStep{{Name: "boom", Type: "sql", SQL: "SELECT * FROM no_such_table", OnError: []FlowStep{
		{Name: "log", Type: "sql_dynamic", SQL: "INSERT INTO audit (v) VALUES ('{{note}}')"},
	}}}, `{"note":"x'); DROP TABLE audit; --"}`)
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n); err != nil {
		t.Fatalf("audit table must survive: %v", err)
	}
	if n != 0 {
		t.Fatalf("on_error sql_dynamic ran on request input (%d rows written)", n)
	}
}

// TestEnqueueCarriesRequestTaintToJobFlow: a request value handed to a job
// through `enqueue: with:` is still request input when the job flow runs.
func TestEnqueueCarriesRequestTaintToJobFlow(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)

	worker := Flow{Name: "worker", Trigger: FlowTrigger{Type: "job"}, Steps: []FlowStep{
		{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{q}}' AS v, '{{fixed}}' AS w"},
	}}
	app.mu.Lock()
	app.Flows = []Flow{worker}
	app.mu.Unlock()

	enqueue := func(with map[string]string) (status, jobErr string) {
		t.Helper()
		app.DB.Exec(`DELETE FROM _benmore_jobs`)
		flow := Flow{Name: "front", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/front"}, Steps: []FlowStep{
			{Name: "e", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", With: with}},
			{Type: "respond", Respond: &FlowRespond{Status: 202, Body: "queued"}},
		}}
		if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/front?term=x", nil)); err != nil {
			t.Fatalf("enqueue flow: %v", err)
		}
		FlushJobs(app)
		if err := app.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE flow_name = 'worker'`).Scan(&status, &jobErr); err != nil {
			t.Fatalf("read job: %v", err)
		}
		return status, jobErr
	}

	if status, jobErr := enqueue(map[string]string{"q": "{{term}}", "fixed": "literal"}); status == "completed" || !strings.Contains(jobErr, "request-sourced") {
		t.Fatalf("job flow ran sql_dynamic on enqueued request input: status=%q error=%q", status, jobErr)
	}
	if status, jobErr := enqueue(map[string]string{"q": "server", "fixed": "literal"}); status != "completed" {
		t.Fatalf("an enqueue payload with no request input must run: status=%q error=%q", status, jobErr)
	}
}
