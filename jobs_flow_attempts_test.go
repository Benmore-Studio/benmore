//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubFlowUpstream points the strict outbound transport (run: api, run:
// webhook, subscription deliveries) at a local server for one test. Call n
// is answered with statuses[n-1]; the last status repeats.
func stubFlowUpstream(t *testing.T, statuses ...int) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statuses[min(n, len(statuses))-1])
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })
	return &calls
}

// newFlowAttemptsApp is an app with a charges table (one row per run that
// got past its first step) and a flow_failures table (one row per on_error
// run), loaded with the given flow files.
func newFlowAttemptsApp(t *testing.T, files map[string]string) *App {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, `CREATE TABLE charges (id INTEGER PRIMARY KEY, note TEXT NOT NULL)`)
	mustExec(t, app.DB, `CREATE TABLE flow_failures (id INTEGER PRIMARY KEY, note TEXT)`)
	dir := filepath.Join(t.TempDir(), "flows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	flows := LoadFlowsGHA(filepath.Dir(dir))
	if len(flows) != len(files) {
		t.Fatalf("loaded %d flows, want %d: %+v", len(flows), len(files), flows)
	}
	app.mu.Lock()
	app.Flows = flows
	app.mu.Unlock()
	return app
}

func flowByName(t *testing.T, app *App, name string) *Flow {
	t.Helper()
	for i := range app.Flows {
		if app.Flows[i].Name == name {
			return &app.Flows[i]
		}
	}
	t.Fatalf("flow %q not loaded", name)
	return nil
}

// postAsyncFlow sends one request to an async flow and returns its job id
// and the status_url the caller was handed.
func postAsyncFlow(t *testing.T, app *App, flow *Flow, body string) (int64, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, flow.Trigger.Path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, flow, rec, r); err != nil {
		t.Fatalf("run: %v", err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enqueue status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	var answer struct {
		JobID     int64  `json:"job_id"`
		StatusURL string `json:"status_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil || answer.JobID == 0 {
		t.Fatalf("202 body %s: %v", rec.Body.String(), err)
	}
	return answer.JobID, answer.StatusURL
}

type flowJobRow struct {
	status      string
	attempts    int
	maxAttempts int
	err         string
}

func readFlowJob(t *testing.T, app *App, id int64) flowJobRow {
	t.Helper()
	var row flowJobRow
	if err := app.DB.QueryRow("SELECT status, attempts, max_attempts, COALESCE(error,'') FROM _benmore_jobs WHERE id = ?", id).
		Scan(&row.status, &row.attempts, &row.maxAttempts, &row.err); err != nil {
		t.Fatalf("read job %d: %v", id, err)
	}
	return row
}

// payFlow charges (a committed INSERT), then calls the payment provider,
// whose failure the step's on_error handler journals. maxAttempts is the
// `on.request.max_attempts:` line, or "" for none.
func payFlow(maxAttempts string) string {
	return `on:
  request:
    method: POST
    path: /api/pay
    mode: async
` + maxAttempts + `jobs:
  pay:
    steps:
      - run: sql
        query: INSERT INTO charges (note) VALUES ('charged')
      - id: provider
        run: api
        with:
          method: POST
          url: http://93.184.216.34/charge
        on_error:
          - run: sql
            query: INSERT INTO flow_failures (note) VALUES ('provider failed')
`
}

// Finding r1104-hooks #3: a failed async flow job was re-run from step 1 up to
// max_attempts (3) times, so one request charged three times, called the
// provider three times and journaled three failures. A flow job now runs once
// unless its flow opts in, so one request is one run and one on_error, even
// for a failure (503) that a retry could have changed.
func TestAsyncFlowJobFailureRunsOnceWithOneErrorHandler(t *testing.T) {
	calls := stubFlowUpstream(t, http.StatusServiceUnavailable)
	app := newFlowAttemptsApp(t, map[string]string{"pay": payFlow("")})
	id, _ := postAsyncFlow(t, app, flowByName(t, app, "pay"), `{}`)

	FlushJobs(app) // fast-forwards any retry backoff, so every retry would run here

	job := readFlowJob(t, app, id)
	if job.status != "failed" || job.attempts != 1 || job.maxAttempts != 1 {
		t.Fatalf("job = %+v, want failed after its one attempt (max_attempts 1)", job)
	}
	if !strings.Contains(job.err, "returned 503") {
		t.Fatalf("job error = %q, want the provider's 503", job.err)
	}
	if got := countRows(t, app, "charges"); got != 1 {
		t.Fatalf("one request charged %d times, want 1", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("one request called the provider %d times, want 1", got)
	}
	if got := countRows(t, app, "flow_failures"); got != 1 {
		t.Fatalf("on_error ran %d times for one failed request, want 1", got)
	}
}

// With `max_attempts: 3` a failure a retry can change (the provider answered
// 503) re-runs the whole flow from step 1, at most three runs in all. Each run
// is a full run: its committed INSERT and its on_error handler repeat, which is
// what the opt-in documents. While a retry waits, the job reads pending with
// the failed attempt's error, and the status_url says how many attempts ran.
func TestAsyncFlowJobOptInRetriesRerunWholeFlow(t *testing.T) {
	t.Run("exhausted", func(t *testing.T) {
		calls := stubFlowUpstream(t, http.StatusServiceUnavailable)
		app := newFlowAttemptsApp(t, map[string]string{"pay": payFlow("    max_attempts: 3\n")})
		id, statusURL := postAsyncFlow(t, app, flowByName(t, app, "pay"), `{}`)
		if job := readFlowJob(t, app, id); job.maxAttempts != 3 {
			t.Fatalf("queued job max_attempts = %d, want the flow's 3", job.maxAttempts)
		}

		// One attempt through the production claim path: the job waits for
		// its retry as pending, carrying the attempt's error.
		if !processNextJob(app) {
			t.Fatal("worker claimed nothing")
		}
		job := readFlowJob(t, app, id)
		if job.status != "pending" || job.attempts != 1 || !strings.Contains(job.err, "returned 503") {
			t.Fatalf("after one failed attempt job = %+v, want pending with the 503 error", job)
		}
		var inFuture int
		app.DB.QueryRow("SELECT not_before > datetime('now') FROM _benmore_jobs WHERE id = ?", id).Scan(&inFuture)
		if inFuture != 1 {
			t.Fatal("retry is not held back by a backoff")
		}
		mux := http.NewServeMux()
		RegisterJobsAPI(mux, app)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, statusURL, nil))
		var status map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("status_url = %d %s", rec.Code, rec.Body.String())
		}
		if status["status"] != "pending" || status["attempts"] != float64(1) || status["max_attempts"] != float64(3) || !strings.Contains(fmt.Sprint(status["error"]), "503") {
			t.Fatalf("status_url while a retry waits = %v, want pending, attempts 1 of 3 and the attempt's error", status)
		}

		FlushJobs(app)
		job = readFlowJob(t, app, id)
		if job.status != "failed" || job.attempts != 3 {
			t.Fatalf("job = %+v, want failed after 3 attempts", job)
		}
		if got := calls.Load(); got != 3 {
			t.Fatalf("provider called %d times, want 3 (one per attempt)", got)
		}
		if got := countRows(t, app, "charges"); got != 3 {
			t.Fatalf("charges = %d, want 3: each attempt re-runs the committed INSERT", got)
		}
		if got := countRows(t, app, "flow_failures"); got != 3 {
			t.Fatalf("on_error ran %d times, want once per failed attempt (3)", got)
		}
	})
	t.Run("recovers", func(t *testing.T) {
		calls := stubFlowUpstream(t, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusOK)
		app := newFlowAttemptsApp(t, map[string]string{"pay": payFlow("    max_attempts: 3\n")})
		id, _ := postAsyncFlow(t, app, flowByName(t, app, "pay"), `{}`)
		FlushJobs(app)
		if job := readFlowJob(t, app, id); job.status != "completed" || job.attempts != 3 {
			t.Fatalf("job = %+v, want completed on its third attempt", job)
		}
		if got := calls.Load(); got != 3 {
			t.Fatalf("provider called %d times, want 3", got)
		}
		if got := countRows(t, app, "flow_failures"); got != 2 {
			t.Fatalf("on_error ran %d times, want 2 (the two failed attempts)", got)
		}
	})
}

// A failure no retry can change fails the job on its first attempt even when
// the flow opts into retries: a body that is not JSON, a value missing from
// scope, a refused SQL statement, an upstream 4xx, and a parallel block where
// one branch failed for good while another failed transiently.
func TestAsyncFlowJobDeterministicFailureNotRetried(t *testing.T) {
	head := `on:
  request:
    method: POST
    path: /api/pay
    mode: async
    max_attempts: 3
jobs:
  pay:
    steps:
      - run: sql
        query: INSERT INTO charges (note) VALUES ('charged')
`
	for _, tc := range []struct {
		name, steps, body string
		statuses          []int
		wantErr           string
	}{
		{name: "invalid JSON body", body: `{"amount": `, wantErr: "", steps: `
      - id: evt
        run: parse
`},
		{name: "value missing from scope", body: `{}`, wantErr: "no value in scope", steps: `
      - run: api
        with:
          method: POST
          url: http://93.184.216.34/charge
          json:
            account: "${{ steps.lookup.outputs.account }}"
`},
		{name: "refused SQL", body: `{}`, wantErr: "NOT NULL", steps: `
      - run: sql
        query: INSERT INTO charges (note) VALUES (NULL)
`},
		{name: "upstream 4xx", body: `{}`, statuses: []int{http.StatusBadRequest}, wantErr: "returned 400", steps: `
      - run: api
        with:
          method: POST
          url: http://93.184.216.34/charge
`},
		{name: "parallel with one permanent failure", body: `{}`, statuses: []int{http.StatusServiceUnavailable}, wantErr: "returned 503", steps: `
      - run: parallel
        steps:
          - id: provider
            run: api
            with:
              method: POST
              url: http://93.184.216.34/charge
          - id: ledger
            run: sql
            query: INSERT INTO charges (note) VALUES (NULL)
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statuses := tc.statuses
			if statuses == nil {
				statuses = []int{http.StatusServiceUnavailable}
			}
			calls := stubFlowUpstream(t, statuses...)
			app := newFlowAttemptsApp(t, map[string]string{"pay": head + strings.TrimPrefix(tc.steps, "\n")})
			id, _ := postAsyncFlow(t, app, flowByName(t, app, "pay"), tc.body)
			FlushJobs(app)
			job := readFlowJob(t, app, id)
			if job.status != "failed" || job.attempts != 1 {
				t.Fatalf("job = %+v, want failed after one attempt", job)
			}
			if tc.wantErr != "" && !strings.Contains(job.err, tc.wantErr) {
				t.Fatalf("job error = %q, want it to mention %q", job.err, tc.wantErr)
			}
			if got := countRows(t, app, "charges"); got != 1 {
				t.Fatalf("flow ran %d times, want once", got)
			}
			if tc.statuses != nil && calls.Load() > 1 {
				t.Fatalf("upstream called %d times, want at most once", calls.Load())
			}
		})
	}
}

// `run: enqueue` queues a job that takes the target flow's max_attempts, and
// one run when the target declares none.
func TestEnqueueStepJobTakesTargetMaxAttempts(t *testing.T) {
	worker := func(name, attempts string) string {
		return `on:
  request:
    method: POST
    path: /api/` + name + `
` + attempts + `jobs:
  run:
    steps:
      - run: sql
        query: INSERT INTO charges (note) VALUES ('` + name + `')
`
	}
	app := newFlowAttemptsApp(t, map[string]string{
		"producer": `on:
  request:
    method: POST
    path: /api/produce
jobs:
  run:
    steps:
      - id: retried
        run: enqueue
        with:
          flow: retried_worker
      - id: once
        run: enqueue
        with:
          flow: plain_worker
      - run: respond
        with:
          json:
            retried: "${{ steps.retried.outputs.job_id }}"
            once: "${{ steps.once.outputs.job_id }}"
`,
		"retried_worker": worker("retried_worker", "    max_attempts: 2\n"),
		"plain_worker":   worker("plain_worker", ""),
	})
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, flowByName(t, app, "producer"), rec, httptest.NewRequest(http.MethodPost, "/api/produce", nil)); err != nil {
		t.Fatalf("producer: %v", err)
	}
	got := map[string]int{}
	rows, err := app.DB.Query("SELECT flow_name, max_attempts FROM _benmore_jobs")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int
		rows.Scan(&name, &n)
		got[name] = n
	}
	if got["retried_worker"] != 2 || got["plain_worker"] != 1 {
		t.Fatalf("queued max_attempts = %v, want retried_worker 2 and plain_worker 1", got)
	}
}

// A job queued before this change carries the column default of 3 attempts.
// The flow it runs decides: without max_attempts it runs once.
func TestLegacyQueuedFlowJobRunsOnce(t *testing.T) {
	calls := stubFlowUpstream(t, http.StatusServiceUnavailable)
	app := newFlowAttemptsApp(t, map[string]string{"pay": payFlow("")})
	res, err := app.DB.Exec("INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('flow', 'pay', '{}', datetime('now'))")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if job := readFlowJob(t, app, id); job.maxAttempts != 3 {
		t.Fatalf("legacy row max_attempts = %d, want the column default 3", job.maxAttempts)
	}
	FlushJobs(app)
	if job := readFlowJob(t, app, id); job.status != "failed" || job.attempts != 1 {
		t.Fatalf("legacy job = %+v, want failed after one attempt", job)
	}
	if calls.Load() != 1 || countRows(t, app, "charges") != 1 {
		t.Fatalf("legacy job ran %d provider calls / %d charges, want 1 / 1", calls.Load(), countRows(t, app, "charges"))
	}
}

// Webhook subscription deliveries keep their own retry budget: a receiver
// answering 503 gets the delivery again after a backoff.
func TestWebhookSubscriptionDeliveryStillRetries(t *testing.T) {
	calls := stubFlowUpstream(t, http.StatusServiceUnavailable)
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	_, _, adminID := loginTestUser(app, "owner@example.com", "admin")
	app.Tables = []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER"}, {Name: "title", Type: "TEXT"}}}}
	if _, err := app.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, 'http://93.184.216.34/hook', 'whsec-signing-secret', 'notes', '')", adminID); err != nil {
		t.Fatal(err)
	}
	_ = enqueueWebhookSubscriptionsTx(app.DB, app, "insert", "notes", map[string]any{"id": 1, "title": "hello"}, nil)
	if !processNextJob(app) {
		t.Fatal("worker claimed nothing")
	}
	var status string
	var attempts, maxAttempts int
	if err := app.DB.QueryRow("SELECT status, attempts, max_attempts FROM _benmore_jobs WHERE job_type = 'webhook_subscription'").Scan(&status, &attempts, &maxAttempts); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 1 || maxAttempts != 3 || calls.Load() != 1 {
		t.Fatalf("delivery after a 503 = %s, attempt %d of %d, %d sends; want pending for a retry (1 of 3, 1 send)", status, attempts, maxAttempts, calls.Load())
	}
	FlushJobs(app)
	if err := app.DB.QueryRow("SELECT status, attempts FROM _benmore_jobs WHERE job_type = 'webhook_subscription'").Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 3 || calls.Load() != 3 {
		t.Fatalf("delivery = %s after %d attempts and %d sends, want failed after 3 of each", status, attempts, calls.Load())
	}
}

// A flow declaring `idempotent: true` is still requeued after a worker crash
// although its job now carries max_attempts 1: the crash budget for such
// flows stays three claims.
func TestIdempotentFlowJobStillRequeuedAfterCrash(t *testing.T) {
	app := newJobsTestApp(t)
	app.Flows = []Flow{{Name: "safe_flow", Idempotent: true}, {Name: "unsafe_flow"}}
	expired := time.Now().Add(-2 * jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
	for _, row := range []struct {
		flow     string
		attempts int
	}{{"safe_flow", 1}, {"unsafe_flow", 1}} {
		if _, err := app.DB.Exec("INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at, run_at) VALUES ('flow', ?, '{}', 'running', ?, 1, ?, datetime('now'))", row.flow, row.attempts, expired); err != nil {
			t.Fatal(err)
		}
	}
	jobsRecoverOrphanedJobs(app)
	for flow, want := range map[string]string{"safe_flow": "pending", "unsafe_flow": "failed"} {
		var status string
		app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE flow_name = ?", flow).Scan(&status)
		if status != want {
			t.Fatalf("%s after a crash = %q, want %q", flow, status, want)
		}
	}
	// A job that already took three claims is not requeued again.
	mustExec(t, app.DB, "UPDATE _benmore_jobs SET status = 'running', attempts = 3, lease_expires_at = '"+expired+"' WHERE flow_name = 'safe_flow'")
	jobsRecoverOrphanedJobs(app)
	var status string
	app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE flow_name = 'safe_flow'").Scan(&status)
	if status != "failed" {
		t.Fatalf("idempotent job after 3 crashed claims = %q, want failed", status)
	}
}

// The write gate refuses a max_attempts the runtime would not honor.
func TestFlowMaxAttemptsWriteGate(t *testing.T) {
	src := func(v string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/pay\n    mode: async\n    max_attempts: " + v + "\njobs:\n  pay:\n    steps:\n      - run: sql\n        query: SELECT 1\n"
	}
	if msg := ValidateOnWrite("flows/pay.yaml", src("3")); msg != "" {
		t.Fatalf("max_attempts: 3 refused: %s", msg)
	}
	for _, bad := range []string{"0", "-1", fmt.Sprint(flowJobMaxAttemptsCap + 1)} {
		if msg := ValidateOnWrite("flows/pay.yaml", src(bad)); !strings.Contains(msg, "max_attempts") {
			t.Fatalf("max_attempts: %s accepted (%q), want a refusal naming max_attempts", bad, msg)
		}
	}
	// A misplaced retry count points at the key.
	wrong := "on:\n  request:\n    method: POST\n    path: /api/pay\n    mode: async\n    retries: 2\njobs:\n  pay:\n    steps:\n      - run: sql\n        query: SELECT 1\n"
	if msg := ValidateOnWrite("flows/pay.yaml", wrong); !strings.Contains(msg, "max_attempts") {
		t.Fatalf("on.request.retries refusal = %q, want a hint naming max_attempts", msg)
	}
}
