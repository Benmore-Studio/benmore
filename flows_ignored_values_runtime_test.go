//go:build !cli

package main

// What a deployed flow file does with a value the write gate now refuses: it
// keeps loading, the loader names the value in its log, and the runtime no
// longer skips a step, replaces the caller's identity or sends a message
// without its file.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// loadDeployedFlow loads a flow file the way a running app does and returns
// its one flow with what the loader logged.
func loadDeployedFlow(t *testing.T, app *App, yaml string) (Flow, string) {
	t.Helper()
	var flows []Flow
	var err error
	logged := captureLog(t, func() {
		flows, err = parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(yaml))
	})
	if err != nil || len(flows) != 1 {
		t.Fatalf("a deployed file must keep loading: %v (%d flows)\n%s", err, len(flows), logged)
	}
	return flows[0], logged
}

func runDeployedFlow(t *testing.T, app *App, flow Flow, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(flow.Trigger.Method, "https://app.example.com"+flow.Trigger.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flow, rr, req)
	return rr
}

// A negative `retry` ran its step zero times: the INSERT never happened and
// the flow answered 200.
func TestNegativeRetryRunsTheStepOnce(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE probes (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT)`)
	flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/retry-neg
jobs:
  j:
    steps:
      - id: w
        run: sql
        retry: -2
        with: { query: "INSERT INTO probes (k) VALUES ('ran') RETURNING id" }
      - run: respond
        with: { status: 200, json: { id: "${{ steps.w.outputs.id | default:'STEP DID NOT RUN' }}" } }
`)
	if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, "`retry: -2` is not a number of attempts") {
		t.Errorf("the loader does not name the value:\n%s", logged)
	}
	rr := runDeployedFlow(t, app, flow, `{}`)
	if rr.Code != 200 || strings.Contains(rr.Body.String(), "STEP DID NOT RUN") {
		t.Fatalf("the step did not run: %d %s", rr.Code, rr.Body.String())
	}
	var rows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM probes WHERE k = 'ran'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("the step ran %d times, want once", rows)
	}
}

// A failing step with a negative `retry` fails the flow once; it is not
// retried and not skipped.
func TestNegativeRetryStillFailsAFailingStep(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow, _ := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/retry-neg-fail
jobs:
  j:
    steps:
      - id: w
        run: sql
        retry: -1
        with: { query: "INSERT INTO no_such_table (k) VALUES (1)" }
      - run: respond
        with: { status: 200, json: { ok: true } }
`)
	started := time.Now()
	rr := runDeployedFlow(t, app, flow, `{}`)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"failed_step":"w"`) {
		t.Fatalf("a failing step with retry -1 answered %d %s", rr.Code, rr.Body.String())
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("the step waited %s as if it were retried", waited)
	}
}

func TestRetryDelayWholeSecondsAreReadAndOtherTextIsLogged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	load := func(delay string) (FlowStep, string) {
		flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/retry-delay
jobs:
  j:
    steps:
      - id: w
        run: sql
        retry: 2
        retry_delay: `+delay+`
        with: { query: "SELECT 1 AS n" }
`)
		return flow.Steps[0], logged
	}
	for text, want := range map[string]time.Duration{"5": 5 * time.Second, `"5"`: 5 * time.Second, "5s": 5 * time.Second, "650ms": 650 * time.Millisecond} {
		step, logged := load(text)
		if step.RetryDelay != want {
			t.Errorf("retry_delay: %s loads as %s, want %s", text, step.RetryDelay, want)
		}
		if strings.Contains(logged, "retry_delay") {
			t.Errorf("retry_delay: %s is logged as a problem:\n%s", text, logged)
		}
	}
	// What cannot be read keeps the default wait, and the log says so.
	for _, text := range []string{"1 second", "-5s", "0"} {
		step, logged := load(text)
		if step.RetryDelay != 0 {
			t.Errorf("retry_delay: %s loads as %s, want unset (the default wait)", text, step.RetryDelay)
		}
		if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, "`retry_delay: "+text+"`") || !strings.Contains(logged, "default 2s") {
			t.Errorf("retry_delay: %s is not named in the log:\n%s", text, logged)
		}
	}
}

// paginateProbe runs one paginated api step against a stand-in upstream and
// returns the query strings it was asked for.
type paginateProbe struct {
	mu       sync.Mutex
	requests []string
	answer   func(n int, r *http.Request) string
}

func (p *paginateProbe) client() *http.Client {
	return &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		p.mu.Lock()
		p.requests = append(p.requests, r.URL.RawQuery)
		n := len(p.requests)
		p.mu.Unlock()
		header := http.Header{"Content-Type": {"application/json"}}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(p.answer(n, r))), Request: r}, nil
	})}
}

func runPaginateStep(t *testing.T, app *App, paginate string, probe *paginateProbe) (*FlowContext, string) {
	t.Helper()
	flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/sync
jobs:
  j:
    steps:
      - id: c
        run: api
        with:
          method: GET
          url: https://8.8.8.8/v1/contacts
          paginate: `+paginate+`
`)
	ctx := &FlowContext{App: app, Request: httptest.NewRequest("POST", "https://app.example.com/api/sync", nil), Writer: httptest.NewRecorder(),
		Data: map[string]any{}, Params: map[string]string{}, apiClient: probe.client()}
	executeSteps(ctx, flow.Steps)
	return ctx, logged
}

// `page_start: 0` was read as unset, so a zero-based upstream lost its first
// page.
func TestPaginatePageStartZeroAsksForPageZeroFirst(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	twoPages := func(n int, r *http.Request) string {
		if n <= 2 {
			return fmt.Sprintf(`{"data":[{"n":%d}]}`, n)
		}
		return `{"data":[]}`
	}
	for paginate, want := range map[string][]string{
		`{ strategy: page, page_param: p, page_start: 0, items_field: $.data }`: {"p=0", "p=1", "p=2"},
		`{ strategy: page, page_param: p, page_start: 1, items_field: $.data }`: {"p=1", "p=2", "p=3"},
		`{ strategy: page, page_param: p, page_start: 4, items_field: $.data }`: {"p=4", "p=5", "p=6"},
		`{ strategy: page, page_param: p, items_field: $.data }`:                {"p=1", "p=2", "p=3"},
	} {
		probe := &paginateProbe{answer: twoPages}
		ctx, logged := runPaginateStep(t, app, paginate, probe)
		if ctx.Error != nil {
			t.Fatalf("%s: %v", paginate, ctx.Error)
		}
		if strings.Join(probe.requests, " ") != strings.Join(want, " ") {
			t.Errorf("%s asked for %v, want %v", paginate, probe.requests, want)
		}
		if got, _ := ctx.Data["c"].(map[string]any); got["item_count"] != 2 || got["pages_fetched"] != 3 {
			t.Errorf("%s: outputs %v, want 2 items from 3 answers", paginate, got)
		}
		if strings.Contains(logged, "paginate") {
			t.Errorf("%s is logged as a problem:\n%s", paginate, logged)
		}
	}
}

// A cursor strategy with no cursor_field read one page and reported success.
func TestPaginateCursorWithoutItsFieldFailsTheStep(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	answer := func(n int, r *http.Request) string { return `{"items":[{"n":1}],"next_cursor":"abc"}` }
	for _, paginate := range []string{`{ strategy: cursor, items_field: $.items }`, `{ items_field: $.items }`, `{}`} {
		probe := &paginateProbe{answer: answer}
		ctx, logged := runPaginateStep(t, app, paginate, probe)
		if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "the cursor strategy needs `cursor_field`") {
			t.Errorf("%s: the step reported %v, want a failure naming cursor_field", paginate, ctx.Error)
		}
		if reason := flowFailureReason("api", ctx.Error); reason != "the step's paginate block cannot be run as written" {
			t.Errorf("%s: the failure's reason is %q", paginate, reason)
		}
		if hint := stepFailureHint("c", "api", fmt.Sprint(ctx.Error)); !strings.Contains(hint, "`with.paginate` block cannot be run as written") {
			t.Errorf("%s: the failure's hint is %q", paginate, hint)
		}
		if len(probe.requests) != 0 {
			t.Errorf("%s: %d request(s) went out before the step failed", paginate, len(probe.requests))
		}
		if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, "has no `cursor_field`") {
			t.Errorf("%s: the loader does not name the missing key:\n%s", paginate, logged)
		}
	}
	// With its field the cursor is followed until an answer carries none.
	probe := &paginateProbe{answer: func(n int, r *http.Request) string {
		if n == 1 {
			return `{"items":[{"n":1}],"next":"abc"}`
		}
		return `{"items":[{"n":2}]}`
	}}
	ctx, _ := runPaginateStep(t, app, `{ cursor_field: $.next, cursor_param: after }`, probe)
	if ctx.Error != nil || strings.Join(probe.requests, " ") != " after=abc" {
		t.Fatalf("cursor paging asked for %q (%v), want the first page and then after=abc", probe.requests, ctx.Error)
	}
}

// Deployed files with a paginate value the gate refuses keep the reading they
// had, and the loader names each value.
func TestDeployedPaginateValuesKeepTheirReadingAndAreLogged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	endless := func(n int, r *http.Request) string { return `{"items":[{"n":1}]}` }
	for _, c := range []struct {
		paginate string
		requests int
		log      string
	}{
		{`{ strategy: page, max_pages: "2" }`, 50, "`with.paginate.max_pages` must be a whole number written without quotes"},
		{`{ strategy: page, max_pages: 1000 }`, 500, "`with.paginate.max_pages: 1000` is outside 1 to 500"},
		{`{ strategy: page, max_pages: 3, limit: 100 }`, 3, "`with.paginate.limit` is not read"},
		{`{ strategy: page, max_pages: 2, page_start: -5 }`, 2, "`with.paginate.page_start: -5` is not a page number"},
	} {
		probe := &paginateProbe{answer: endless}
		ctx, logged := runPaginateStep(t, app, c.paginate, probe)
		if ctx.Error != nil {
			t.Errorf("%s: %v", c.paginate, ctx.Error)
		}
		if len(probe.requests) != c.requests {
			t.Errorf("%s made %d requests, want %d", c.paginate, len(probe.requests), c.requests)
		}
		if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, c.log) {
			t.Errorf("%s: the log does not say %q:\n%s", c.paginate, c.log, logged)
		}
	}
	probe := &paginateProbe{answer: endless}
	if ctx, _ := runPaginateStep(t, app, `{ strategy: page, max_pages: 2, page_start: -5 }`, probe); ctx.Error != nil || probe.requests[0] != "page=1" {
		t.Errorf("a negative page_start asked for %v first, want page=1", probe.requests)
	}
	// `paginate: true` is not a block: one request, as before, and a log line.
	probe = &paginateProbe{answer: endless}
	ctx, logged := runPaginateStep(t, app, `true`, probe)
	if ctx.Error != nil || len(probe.requests) != 1 {
		t.Errorf("paginate: true made %d requests (%v), want one unpaginated call", len(probe.requests), ctx.Error)
	}
	if !strings.Contains(logged, "`with.paginate` must be a map") {
		t.Errorf("paginate: true is not named in the log:\n%s", logged)
	}
	// An unknown strategy fails when the step runs, as it did.
	probe = &paginateProbe{answer: endless}
	if ctx, _ := runPaginateStep(t, app, `{ strategy: offset }`, probe); ctx.Error == nil || !strings.Contains(ctx.Error.Error(), `unknown strategy "offset"`) {
		t.Errorf("an unknown strategy: %v", ctx.Error)
	}
}

// `for_each` with `as: user` put each element where the signed-in caller's
// row is read from, for the loop and for every step after it. The elements
// can come from the request.
func TestLoopVariableNeverReplacesTheCallersIdentity(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT, user_id INTEGER)`)
	uid, sid := gateUser(t, app, "ann@example.com")
	for _, as := range []string{"user", "user_id", "user_email", "user_role", "user_group_id", "_group_id", "env"} {
		flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/as-user
    auth: required
jobs:
  j:
    steps:
      - for_each: ${{ params.items }}
        as: `+as+`
        steps:
          - run: sql
            with:
              query: "INSERT INTO notes (body, user_id) VALUES ('in the loop', :uid)"
              params: { uid: "${{ user.id }}" }
      - run: respond
        with: { status: 200, json: { id: "${{ user.id }}", email: "${{ user.email }}" } }
`)
		if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, "`as: "+as+"`") {
			t.Errorf("as: %s: the loader does not name the loop variable:\n%s", as, logged)
		}
		// The element's id is long on purpose: the answer carries a random
		// hexadecimal request id, which contains any three digits now and then.
		rr := runDeployedFlow(t, app, flow, `{"items":[{"id":987654321,"email":"attacker@example.com"}]}`, "Authorization", "Bearer "+sid)
		if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"failed_type":"for_each"`) {
			t.Errorf("as: %s: the loop ran: %d %s", as, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"reason":"the loop variable's name is one the runtime owns, so the loop was not run"`) {
			t.Errorf("as: %s: the answer does not say why: %s", as, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "attacker@example.com") || strings.Contains(rr.Body.String(), "987654321") {
			t.Errorf("as: %s: the answer carries the element as the caller: %s", as, rr.Body.String())
		}
	}
	var rows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("%d row(s) were written by a loop that must not run", rows)
	}

	// A loop variable with a name of its own leaves the caller's values alone.
	flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/as-member
    auth: required
jobs:
  j:
    steps:
      - for_each: ${{ params.items }}
        as: member
        steps:
          - run: sql
            with:
              query: "INSERT INTO notes (body, user_id) VALUES (:email, :uid)"
              params: { email: "${{ member.email }}", uid: "${{ user.id }}" }
      - run: respond
        with: { status: 200, json: { id: "${{ user.id }}", email: "${{ user.email }}" } }
`)
	if strings.Contains(logged, "`as:") {
		t.Errorf("as: member is logged as a problem:\n%s", logged)
	}
	rr := runDeployedFlow(t, app, flow, `{"items":[{"id":999,"email":"attacker@example.com"}]}`, "Authorization", "Bearer "+sid)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"email":"ann@example.com"`) || !strings.Contains(rr.Body.String(), fmt.Sprintf(`"id":%d`, uid)) {
		t.Fatalf("as: member: %d %s", rr.Code, rr.Body.String())
	}
	if got := gateScalar(t, app, `SELECT body || '/' || user_id FROM notes`); got != fmt.Sprintf("attacker@example.com/%d", uid) {
		t.Fatalf("the loop wrote %q, want the element's email under the caller's id", got)
	}
}

const attachmentFlow = `on:
  request: { method: POST, path: /api/report }
jobs:
  send:
    steps:
      - run: email
        with:
          to: "ann@fixturemail.net"
          subject: "Report"
          text: "The report is attached."
          attachments: %s
      - run: respond
        with: { status: 200, body: { ok: true } }
`

// A malformed `attachments:` sent the message without the file.
func TestEmailWithAnAttachmentItCannotBuildIsNotSent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for _, c := range []struct {
		name, attachments, body, want, log string
	}{
		{"a map, not a list", `{ filename: a.txt, content: "aGk=" }`, `{}`, "with.attachments must be a list", "`with.attachments` must be a list"},
		{"a text entry", `["aGk="]`, `{}`, "with.attachments[0] must be a map", "`with.attachments[0]` must be a map"},
		{"path instead of content", `[{ filename: report.csv, path: uploads/private/x.csv }]`, `{}`, "with.attachments[0] has no content", "`with.attachments[0]` has no `content`"},
		{"content that renders empty", `[{ filename: report.csv, content: "${{ params.file | default:'' }}" }]`, `{}`, `attachment 0 ("report.csv") has no content`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			receipt := captureSMTP(t, app)
			flow, logged := loadDeployedFlow(t, app, fmt.Sprintf(attachmentFlow, c.attachments))
			if c.log != "" && (!strings.Contains(logged, "WARNING") || !strings.Contains(logged, c.log)) {
				t.Errorf("the loader does not name the value:\n%s", logged)
			}
			var rr *httptest.ResponseRecorder
			flowLog := captureLog(t, func() { rr = runDeployedFlow(t, app, flow, c.body) })
			if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"failed_type":"email"`) {
				t.Fatalf("the step did not fail: %d %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), `"reason":"an attachment could not be built, so nothing was sent"`) {
				t.Errorf("the answer does not say why: %s", rr.Body.String())
			}
			if !strings.Contains(flowLog, c.want) || !strings.Contains(flowLog, "nothing was sent") {
				t.Errorf("the failure does not say %q:\n%s", c.want, flowLog)
			}
			select {
			case got := <-receipt:
				if got.err == nil {
					t.Fatalf("a message went out without its file (%d bytes to %v)", len(got.message), got.recipients)
				}
			case <-time.After(300 * time.Millisecond):
			}
		})
	}

	t.Run("a well-formed attachment is sent", func(t *testing.T) {
		receipt := captureSMTP(t, app)
		flow, logged := loadDeployedFlow(t, app, fmt.Sprintf(attachmentFlow, `[{ filename: report.csv, content: "${{ params.file }}", content_type: text/csv }]`))
		if strings.Contains(logged, "attachments") {
			t.Errorf("a well-formed attachment is logged as a problem:\n%s", logged)
		}
		rr := runDeployedFlow(t, app, flow, `{"file":"YSxiCjEsMg=="}`)
		if rr.Code != 200 {
			t.Fatalf("%d %s", rr.Code, rr.Body.String())
		}
		got := <-receipt
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !strings.Contains(string(got.message), `filename="report.csv"`) || !strings.Contains(string(got.message), "YSxiCjEsMg==") {
			t.Fatalf("the message does not carry the file:\n%s", got.message)
		}
	})
}

// An event flow on a name the app serves no table under never starts: the
// file keeps loading and registration says so.
func TestEventFlowOnANameThatIsNoTableIsLoggedAtRegistration(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, user_id INTEGER)`)
	load := func(table, source string) Flow {
		flow, _ := loadDeployedFlow(t, app, "on:\n  event:\n    table: "+table+"\n    op: insert\njobs:\n  log:\n    steps:\n      - run: sql\n        with: { query: \"SELECT 1 AS n\" }\n")
		flow.Source = source
		return flow
	}
	flows := []Flow{load("Tasks", "flows/case.yaml"), load("Task", "flows/model.yaml"), load("invoices", "flows/other.yaml"), load("tasks", "flows/ok.yaml")}
	logged := captureLog(t, func() { RegisterFlows(http.NewServeMux(), app, flows) })
	for _, want := range []string{
		`WARNING: flows/case.yaml: on.event.table "Tasks" differs from the table "tasks" only in letter case`,
		`WARNING: flows/model.yaml: on.event.table "Task" is not a table of this app, so the flow would never run. Did you mean ` + "`table: tasks`?",
		`WARNING: flows/other.yaml: on.event.table "invoices" is not a table of this app, so the flow would never run. An event flow starts`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("registration does not log %q:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, "flows/ok.yaml") {
		t.Errorf("an event flow on a real table is logged as a problem:\n%s", logged)
	}
}

// `min`/`max` on a text input are not checked; the file loads and the loader
// says so.
func TestInputBoundsOnANonNumberAreLoggedAtLoad(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow, logged := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/bounded
    inputs:
      title: { type: text, min: 3, max: 10 }
      hours: { type: number, min: 1, max: 24 }
jobs:
  j:
    steps:
      - run: respond
        with: { status: 200, json: { title: "${{ params.title }}" } }
`)
	if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, "on.request.inputs.title sets `min` and `max`") || strings.Contains(logged, "inputs.hours") {
		t.Errorf("the loader log:\n%s", logged)
	}
	if rr := runDeployedFlow(t, app, flow, `{"title":"a","hours":2}`); rr.Code != 200 {
		t.Errorf("a short title is refused although text bounds are not checked: %d %s", rr.Code, rr.Body.String())
	}
	if rr := runDeployedFlow(t, app, flow, `{"title":"abc","hours":25}`); rr.Code != 422 {
		t.Errorf("a number over its max answered %d %s, want 422", rr.Code, rr.Body.String())
	}
}

// SQL in a parallel block of a transactional flow: a deployed file still
// loads, and the app still leaves the flow unregistered (its route answers
// 404) and says why at load. Only the write gate changed.
func TestDeployedParallelSQLInATransactionIsStillLeftUnregistered(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE probes (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT)`)
	flow, _ := loadDeployedFlow(t, app, `on:
  request:
    method: POST
    path: /api/par-sql-tx
    transaction: true
jobs:
  j:
    steps:
      - run: parallel
        steps:
          - id: a
            run: sql
            with: { query: "INSERT INTO probes (k) VALUES ('a')" }
          - id: b
            run: sql
            with: { query: "INSERT INTO probes (k) VALUES ('b')" }
      - run: respond
        with: { status: 200, json: { ok: true } }
`)
	mux := http.NewServeMux()
	logged := captureLog(t, func() { RegisterFlows(mux, app, []Flow{flow}) })
	if !strings.Contains(logged, "ERROR") || !strings.Contains(logged, "parallel block contains SQL steps") || !strings.Contains(logged, "skipping flow registration") {
		t.Errorf("registration does not say why the flow is left out:\n%s", logged)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "https://app.example.com/api/par-sql-tx", strings.NewReader(`{}`)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("the flow's route answered %d, want 404 (not registered)", rr.Code)
	}
	if got := gateScalar(t, app, `SELECT COUNT(*) FROM probes`); got != "0" {
		t.Fatalf("%s row(s) written by a flow that is not registered", got)
	}
}

// Every loop variable name the gate accepts is read wherever a flow reads a
// value: a template, an `if:` condition in both forms and a SQL bind. A name
// the gate refuses for its characters is not: a condition on it is false
// without a word, which is why it is refused.
func TestLoopNamesTheGateAcceptsAreReadEverywhere(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	run := func(as string) string {
		flow, _ := loadDeployedFlow(t, app, fmt.Sprintf(`on:
  request:
    method: POST
    path: /api/names
jobs:
  j:
    steps:
      - for_each: ${{ params.items }}
        as: "%[1]s"
        steps:
          - run: set
            with: { value: "${{ %[1]s.n | default:'(unread)' }}" }
          - if: ${{ %[1]s.n }} == 'one'
            run: set
            with: { compared: "held" }
          - if: ${{ %[1]s.n == 'one' }}
            run: set
            with: { expression: "held" }
          - id: bound
            run: sql
            with:
              query: "SELECT :v AS v"
              params: { v: "${{ %[1]s.n }}" }
      - run: respond
        with: { status: 200, json: { value: "${{ value | default:'-' }}", compared: "${{ compared | default:'-' }}", expression: "${{ expression | default:'-' }}", bound: "${{ steps.bound.outputs.v | default:'-' }}" } }
`, as))
		rr := runDeployedFlow(t, app, flow, `{"items":[{"n":"one"}]}`)
		return fmt.Sprintf("%d %s", rr.Code, strings.TrimSpace(rr.Body.String()))
	}
	const everywhere = `200 {"bound":"one","compared":"held","expression":"held","value":"one"}`
	for _, as := range []string{"row", "item", "deep_project", "line-item", "order.line", "w2", "9lives", "_"} {
		if flowLoopNameProblem(as) != "" {
			t.Errorf("as: %s is refused by the gate", as)
		}
		if got := run(as); got != everywhere {
			t.Errorf("as: %s is not read everywhere: %s", as, got)
		}
	}
	for _, as := range []string{"my item", "x:y", "a$"} {
		if flowLoopNameProblem(as) == "" {
			t.Errorf("as: %q is accepted by the gate", as)
		}
		if got := run(as); got == everywhere {
			t.Errorf("as: %q is read everywhere; the gate need not refuse it", as)
		}
	}
}

// What the two warnings of ghaMissingRequestValueWarnings describe: a request
// field the caller left out, read with no fallback, has no value on the
// right-hand side of an `if:` (it equals nothing, the reference's own text
// included) and is the text `{{params.<name>}}` in a redirect target. With
// the fallback the warning names, it is empty (or the fallback).
func TestMissingRequestFieldOnTheRightOfIfEqualsNothingAndARedirectSendsItsText(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	branch := func(cond, body string) string {
		flow, _ := loadDeployedFlow(t, app, "on:\n  request:\n    method: POST\n    path: /api/cond\njobs:\n  j:\n    steps:\n      - if: "+cond+"\n        steps:\n          - run: respond\n            with: { status: 200, json: { branch: taken } }\n        else:\n          - run: respond\n            with: { status: 200, json: { branch: otherwise } }\n")
		rr := runDeployedFlow(t, app, flow, body)
		return fmt.Sprintf("%d %s", rr.Code, strings.TrimSpace(rr.Body.String()))
	}
	const taken, otherwise = `200 {"branch":"taken"}`, `200 {"branch":"otherwise"}`
	for _, c := range []struct{ cond, body, want string }{
		// No fallback: the right side has no value, so only `!=` holds, also
		// for a caller who sends the reference's own text.
		{"${{ params.a }} != ${{ params.b }}", `{"a":"x"}`, taken},
		{"${{ params.a }} == ${{ params.b }}", `{"a":"x"}`, otherwise},
		{"${{ params.a }} == ${{ params.b }}", `{"a":"{{params.b}}"}`, otherwise},
		{"${{ params.a }} != ${{ params.b }}", `{"a":"{{params.b}}"}`, taken},
		{"${{ params.a != params.b }}", `{"a":"x"}`, taken},
		// The fallback forms the warning names: the right side is empty.
		{"${{ params.a }} == ${{ params.b || '' }}", `{"a":""}`, taken},
		{"${{ params.a }} == ${{ params.b | default:'' }}", `{"a":""}`, taken},
		{"${{ params.a }} == ${{ params.b || '' }}", `{"a":"{{params.b}}"}`, otherwise},
		{"${{ params.a }} != ${{ params.b || '' }}", `{"a":"x","b":"x"}`, otherwise},
		// Sent, it is compared as sent either way.
		{"${{ params.a }} != ${{ params.b }}", `{"a":"x","b":"x"}`, otherwise},
	} {
		if got := branch(c.cond, c.body); got != c.want {
			t.Errorf("`if: %s` with %s -> %s, want %s", c.cond, c.body, got, c.want)
		}
	}
	for to, want := range map[string]string{
		"/done?tab=${{ params.tab }}":                 "/done?tab={{params.tab}}",
		"/done?tab=${{ params.tab || 'all' }}":        "/done?tab=all",
		"/done?tab=${{ params.tab | default:'all' }}": "/done?tab=all",
	} {
		flow, _ := loadDeployedFlow(t, app, "on:\n  request:\n    method: POST\n    path: /api/redir\njobs:\n  j:\n    steps:\n      - run: redirect\n        with: { to: \""+to+"\" }\n")
		rr := runDeployedFlow(t, app, flow, `{}`)
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != want {
			t.Errorf("`to: %s` answered %d to %q, want a 303 to %q", to, rr.Code, rr.Header().Get("Location"), want)
		}
	}
}
