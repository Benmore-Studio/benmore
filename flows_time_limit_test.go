//go:build !cli

package main

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// timeLimitApp is one app on the served driver with a single pooled
// connection, on which test_sleep(ms) is registered: a statement that takes
// real time without depending on how fast this machine counts.
func timeLimitApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	mustExec(t, db, `CREATE TABLE items (id INTEGER PRIMARY KEY, n INTEGER); INSERT INTO items VALUES (1,0),(2,0),(3,0); CREATE TABLE marks (name TEXT)`)
	registerTestSleep(t, app)
	return app
}

// registerTestSleep adds test_sleep to the pool's one connection. A rollback
// at a context's end can discard the connection, so a test that runs a second
// slow flow registers again.
func registerTestSleep(t *testing.T, app *App) {
	t.Helper()
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		return mustSQLiteConn(raw).RegisterFunc("test_sleep", func(ms int64) int64 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
			return ms
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
}

func timeLimitFlow(t *testing.T, source string) *Flow {
	t.Helper()
	flows, err := parseGHAFlowFile("flows/slow.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("parsed %d flows", len(flows))
	}
	return &flows[0]
}

type flowTimeLimitAnswer struct {
	Error      string  `json:"error"`
	Outcome    string  `json:"outcome"`
	RolledBack bool    `json:"rolled_back"`
	Timeout    float64 `json:"timeout_seconds"`
	RequestID  string  `json:"request_id"`
	Message    string  `json:"message"`
}

func decodeTimeLimitAnswer(t *testing.T, rec *httptest.ResponseRecorder) flowTimeLimitAnswer {
	t.Helper()
	var out flowTimeLimitAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer is not JSON: %d %q (%v)", rec.Code, rec.Body.String(), err)
	}
	return out
}

const slowTransactionFlow = `on:
  request:
    method: POST
    path: /api/slow
    transaction: true
    timeout: 150ms
jobs:
  run:
    steps:
      - run: sql
        with:
          query: UPDATE items SET n = 1
      - run: sql
        with:
          query: SELECT test_sleep(400)
      - run: sql
        with:
          query: INSERT INTO marks VALUES ('after')
      - run: respond
        with:
          status: 200
          body: { ok: true }
`

// Observed 2026-10-29: a 40 s transaction flow committed all 5,000 updates
// while its caller got an error page. Past its limit it now rolls back and
// says so. 503, not 504: Cloudflare replaces a 502 or 504 body.
func TestFlowTransactionRollsBackAtItsTimeLimit(t *testing.T) {
	app := timeLimitApp(t)
	flow := timeLimitFlow(t, slowTransactionFlow)

	rec := httptest.NewRecorder()
	err := executeFlowHTTP(app, flow, rec, httptest.NewRequest(http.MethodPost, "/api/slow", nil))
	if err == nil {
		t.Fatalf("a flow past its limit reported success: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeTimeLimitAnswer(t, rec)
	if rec.Code != http.StatusServiceUnavailable || out.Error != "flow_timeout" || out.Outcome != "rolled_back" || !out.RolledBack || out.RequestID == "" {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Benmore-Outcome"); got != "rolled_back" {
		t.Fatalf("X-Benmore-Outcome = %q", got)
	}
	if !strings.Contains(out.Message, "rolled back") || !strings.Contains(out.Message, "150ms") {
		t.Fatalf("message does not state the outcome and limit: %q", out.Message)
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "0" {
		t.Fatalf("updates kept after the rollback: SUM(n)=%s", got)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM marks"); got != "0" {
		t.Fatalf("a step after the deadline ran and was kept: %s", got)
	}
	// The write lock is free: the rollback released the connection.
	mustExec(t, app.DB, "UPDATE items SET n = 2")
}

// A flow with no transaction stops: what ran stays committed, the rest does
// not run, and the answer says so rather than claiming a rollback.
func TestFlowWithoutTransactionStopsAtItsTimeLimit(t *testing.T) {
	app := timeLimitApp(t)
	flow := timeLimitFlow(t, strings.Replace(slowTransactionFlow, "    transaction: true\n", "", 1))

	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, httptest.NewRequest(http.MethodPost, "/api/slow", nil))
	out := decodeTimeLimitAnswer(t, rec)
	if rec.Code != http.StatusInternalServerError || out.Error != "flow_timeout" || out.Outcome != "stopped" || out.RolledBack {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(out.Message, "committed") {
		t.Fatalf("message does not say earlier writes are kept: %q", out.Message)
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "3" {
		t.Fatalf("the statement before the deadline was not kept: SUM(n)=%s", got)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM marks"); got != "0" {
		t.Fatalf("a step after the deadline ran: %s", got)
	}
}

// Steps check the deadline before they start, inside nested blocks too, and
// an on_error handler does not run with no time left.
func TestFlowTimeLimitStopsBeforeTheNextStep(t *testing.T) {
	app := timeLimitApp(t)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog(), execCtx: expired, timeLimit: time.Second}
	executeSteps(ctx, []FlowStep{{Type: "sql", SQL: "INSERT INTO marks VALUES ('step')", OnError: []FlowStep{{Type: "sql", SQL: "INSERT INTO marks VALUES ('handler')"}}}})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "time limit") {
		t.Fatalf("ctx.Error = %v", ctx.Error)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM marks"); got != "0" {
		t.Fatalf("a step or handler ran past the deadline: %s", got)
	}
}

// A declared limit moves this request's write deadline, through the full
// production middleware chain with gzip on (Go's client asks for it): the
// server's own WriteTimeout used to cut the answer of a flow that finished.
func TestFlowAnswerOutlivesServerWriteTimeout(t *testing.T) {
	app := timeLimitApp(t)
	SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "0")
	flow := timeLimitFlow(t, `on:
  request:
    method: POST
    path: /api/slow
    transaction: true
    timeout: 5s
jobs:
  run:
    steps:
      - run: sql
        with:
          query: SELECT test_sleep(600)
      - run: sql
        with:
          query: UPDATE items SET n = 1
      - run: respond
        with:
          status: 200
          body: { ok: true }
`)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/slow", func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(app, flow, w, r) })
	srv := httptest.NewUnstartedServer(wrapMiddleware(mux, app, false))
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	// Accept-Encoding set by hand: the transport then leaves the body alone
	// and the request is known to have taken the gzip writer's path.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/slow", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("answer lost past the server's WriteTimeout: %v (SUM(n)=%s)", err, gateScalar(t, app, "SELECT SUM(n) FROM items"))
	}
	defer resp.Body.Close()
	var body io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if body, err = gzip.NewReader(resp.Body); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := io.ReadAll(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), `"ok"`) {
		t.Fatalf("slow flow: %d %s", resp.StatusCode, data)
	}
}

// The time-limit error reaches the caller too: the answer at the deadline is
// written after the server's own WriteTimeout would have closed the connection.
func TestFlowTimeLimitAnswerIsDeliveredPastServerWriteTimeout(t *testing.T) {
	app := timeLimitApp(t)
	SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "0")
	flow := timeLimitFlow(t, slowTransactionFlow)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/slow", func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(app, flow, w, r) })
	srv := httptest.NewUnstartedServer(wrapMiddleware(mux, app, false))
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/slow", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("time-limit answer lost: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(data), "flow_timeout") {
		t.Fatalf("time-limit answer: %d %s", resp.StatusCode, data)
	}
	if got := resp.Header.Get("X-Benmore-Outcome"); got != "rolled_back" {
		t.Fatalf("X-Benmore-Outcome = %q", got)
	}
}

// A flow declaring nothing has the 30 s default (shortened here).
func TestFlowDefaultTimeLimitApplies(t *testing.T) {
	old := flowTimeoutDefault
	flowTimeoutDefault = 120 * time.Millisecond
	defer func() { flowTimeoutDefault = old }()

	app := timeLimitApp(t)
	flow := timeLimitFlow(t, strings.Replace(slowTransactionFlow, "    timeout: 150ms\n", "", 1))
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, httptest.NewRequest(http.MethodPost, "/api/slow", nil))
	if out := decodeTimeLimitAnswer(t, rec); rec.Code != http.StatusServiceUnavailable || out.Outcome != "rolled_back" {
		t.Fatalf("default limit: %d %s", rec.Code, rec.Body.String())
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "0" {
		t.Fatalf("SUM(n)=%s", got)
	}
}

// A limit that is not reached changes nothing, and a client that disconnects
// does not roll the flow back (it never did).
func TestFlowInsideItsTimeLimitCommits(t *testing.T) {
	app := timeLimitApp(t)
	flow := timeLimitFlow(t, strings.Replace(strings.Replace(slowTransactionFlow, "timeout: 150ms", "timeout: 5s", 1), "test_sleep(400)", "test_sleep(50)", 1))
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/slow", nil).WithContext(gone)
	if err := executeFlowHTTP(app, flow, rec, r); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("flow inside its limit: %v %d %s", err, rec.Code, rec.Body.String())
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "3" {
		t.Fatalf("SUM(n)=%s", got)
	}
}

// The write-lock limit also ends a transaction with a known outcome, and it
// stays authoritative when the flow's own limit is longer.
func TestFlowWriteLockLimitAnswersRolledBack(t *testing.T) {
	t.Setenv("BENMORE_DB_WRITE_TX_LIMIT", "150ms")
	app := timeLimitApp(t)
	flow := timeLimitFlow(t, strings.Replace(slowTransactionFlow, "timeout: 150ms", "timeout: 10s", 1))
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, httptest.NewRequest(http.MethodPost, "/api/slow", nil))
	out := decodeTimeLimitAnswer(t, rec)
	if rec.Code != http.StatusServiceUnavailable || out.Outcome != "rolled_back" || !strings.Contains(out.Message, "BENMORE_DB_WRITE_TX_LIMIT") {
		t.Fatalf("answer: %d %s", rec.Code, rec.Body.String())
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "0" {
		t.Fatalf("SUM(n)=%s", got)
	}
}

// Data-event flows are not synchronous requests: no deadline reaches them.
func TestEventFlowHasNoRequestTimeLimit(t *testing.T) {
	old := flowTimeoutDefault
	flowTimeoutDefault = 50 * time.Millisecond
	defer func() { flowTimeoutDefault = old }()

	app := timeLimitApp(t)
	flow := Flow{Name: "event", Transaction: true, Trigger: FlowTrigger{Type: "on_insert", Table: "items"}, Steps: []FlowStep{
		{Type: "sql", SQL: "SELECT test_sleep(200)"},
		{Type: "sql", SQL: "UPDATE items SET n = 1"},
	}}
	var finished *FlowContext
	runFlowEventWith(app, flow, map[string]any{"id": int64(1)}, func(c *FlowContext) { finished = c })
	if finished == nil || finished.Error != nil {
		t.Fatalf("event flow: %+v", finished)
	}
	if got := gateScalar(t, app, "SELECT SUM(n) FROM items"); got != "3" {
		t.Fatalf("SUM(n)=%s", got)
	}
}

func TestFlowRequestTimeoutWriteGate(t *testing.T) {
	file := func(lines string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/thing\n" + lines + "jobs:\n  run:\n    steps:\n      - run: respond\n        with:\n          status: 200\n          body: { ok: true }\n"
	}
	for _, tc := range []struct {
		name, lines, refused string
	}{
		{"seconds", "    timeout: 45\n", ""},
		{"duration", "    timeout: 90s\n", ""},
		{"hosted maximum", "    timeout: 95s\n", ""},
		{"over the maximum", "    timeout: 96s\n", "over the maximum"},
		{"minutes over", "    timeout: 2m\n", "over the maximum"},
		{"under the minimum", "    timeout: 200ms\n", "is under"},
		{"zero", "    timeout: 0\n", "must be positive"},
		{"negative", "    timeout: -5s\n", "must be positive"},
		{"unreadable", "    timeout: soon\n", "not a Go duration"},
		{"fraction of a second count", "    timeout: 1.5\n", "not a Go duration"},
		{"async", "    mode: async\n    timeout: 45s\n", "mode: async"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateOnWrite(filepath.Join(t.TempDir(), "flows", "thing.yaml"), file(tc.lines))
			if tc.refused == "" && got != "" {
				t.Fatalf("refused: %s", got)
			}
			if tc.refused != "" && !strings.Contains(got, tc.refused) {
				t.Fatalf("got %q, want a refusal naming %q", got, tc.refused)
			}
		})
	}
}

func TestFlowRequestTimeoutMaximum(t *testing.T) {
	if got := flowRequestTimeoutMax(); got != flowTimeoutHostedMax {
		t.Fatalf("default maximum %s", got)
	}
	t.Setenv(flowTimeoutMaxEnv, "10m")
	want := 10 * time.Minute
	if editionName == "platform" {
		want = flowTimeoutHostedMax // the platform edition is hosted
	}
	if got := flowRequestTimeoutMax(); got != want {
		t.Fatalf("self-hosted override: %s, want %s", got, want)
	}
	// A hosted app's env reaches its process environment, so it cannot raise it.
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	if got := flowRequestTimeoutMax(); got != flowTimeoutHostedMax {
		t.Fatalf("hosted process honored the override: %s", got)
	}
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	t.Setenv(flowTimeoutMaxEnv, "nonsense")
	if got := flowRequestTimeoutMax(); got != flowTimeoutHostedMax {
		t.Fatalf("unreadable override: %s", got)
	}
	// A deployed file over the maximum still loads and runs at the maximum.
	if got := flowRequestTimeout(&Flow{Timeout: time.Hour}); got != flowTimeoutHostedMax {
		t.Fatalf("clamped limit %s", got)
	}
}

// deadlineRecorder records the deadline a handler sets on its connection.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.deadline = t; return nil }

// The answer deadline only ever grows what the server gives: it leaves a
// server with no WriteTimeout alone (the deadline would outlive the request
// on the connection) and a long enough one (the host front door's 300 s).
func TestFlowAnswerDeadlineNeverShortensTheServers(t *testing.T) {
	for _, tc := range []struct {
		name        string
		write, read time.Duration
		limit       time.Duration
		set         bool
		atLeast     time.Duration
	}{
		{"no write timeout", 0, 15 * time.Second, 30 * time.Second, false, 0},
		{"host front door", 300 * time.Second, 15 * time.Second, 95 * time.Second, false, 0},
		{"app server, short limit", 30 * time.Second, 15 * time.Second, 5 * time.Second, false, 0},
		{"app server, default limit", 30 * time.Second, 15 * time.Second, 30 * time.Second, true, 40 * time.Second},
		{"app server, hosted maximum", 30 * time.Second, 15 * time.Second, 95 * time.Second, true, 105 * time.Second},
		{"limit near the write timeout", 30 * time.Second, 15 * time.Second, 15 * time.Second, true, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			r := httptest.NewRequest(http.MethodPost, "/api/slow", nil)
			r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, &http.Server{WriteTimeout: tc.write, ReadTimeout: tc.read}))
			before := time.Now()
			extendFlowAnswerDeadline(rec, r, tc.limit)
			if !tc.set {
				if !rec.deadline.IsZero() {
					t.Fatalf("set a deadline %s out", rec.deadline.Sub(before))
				}
				return
			}
			if rec.deadline.Before(before.Add(tc.atLeast)) {
				t.Fatalf("deadline %s out, want at least %s", rec.deadline.Sub(before), tc.atLeast)
			}
		})
	}
}
