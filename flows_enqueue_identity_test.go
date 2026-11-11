//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// In a flow `user_id`, `user_email`, `user_role`, `user`, `user_group_id`,
// `_group_id` and `_group_key` are the runtime's: a request can never set
// them. A job binds every payload key as `:name`, so a `run: enqueue` payload
// key with one of those names was read by the queued flow as who it runs for,
// also when the producer filled it from request input. An enqueue step now
// never queues such a key, and an async flow's job keeps the identity the
// runtime wrote when the request was queued.

func jobIdentityFlow(t *testing.T, app *App, name, text string) Flow {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", name+".yaml"), []byte(text))
	if err != nil || len(flows) != 1 || flows[0].Name != name {
		t.Fatalf("parse %s: %v (%d flows)", name, err, len(flows))
	}
	return flows[0]
}

func jobIdentityCall(t *testing.T, app *App, flow *Flow, sid, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com"+flow.Trigger.Path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	rr := httptest.NewRecorder()
	_ = executeFlowHTTP(app, flow, rr, r)
	return rr
}

func jobIdentityPayloads(t *testing.T, app *App) []map[string]any {
	t.Helper()
	rows, err := app.DB.Query("SELECT payload FROM _benmore_jobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, payload)
	}
	return out
}

const jobIdentityWorkerFlow = `on:
  request: { method: POST, path: /api/worker, auth: required }
jobs:
  go:
    steps:
      - run: sql
        with:
          query: "INSERT INTO notes (title, user_id) VALUES (:label, :user_id)"
      - run: respond
        with: { status: 200, json: { ok: true } }
`

func TestEnqueueNeverQueuesAnIdentityNamedPayloadKey(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, user_id INTEGER)")
	EnsureJobsTable(app.DB)
	_, sid := gateUser(t, app, "caller@example.com")
	worker := jobIdentityFlow(t, app, "worker", jobIdentityWorkerFlow)
	// The producer is a deployed file: the write gate refuses it (below), the
	// loader still loads it.
	producer := jobIdentityFlow(t, app, "producer", `on:
  request: { method: POST, path: /api/producer, auth: required }
jobs:
  go:
    steps:
      - id: q
        run: enqueue
        with:
          flow: worker
          run_at: "2031-01-01T00:00:00Z"
          with:
            label: "enq"
            target_user_id: "${{ params.victim }}"
            user_id: "${{ params.victim }}"
            user_email: "victim@example.com"
            user_role: "admin"
            user_group_id: "tenant-b"
            _group_id: "tenant-b"
            _group_key: "org_id"
            user: "victim"
            user.id: "${{ params.victim }}"
      - run: respond
        with: { status: 200, json: { job: "${{ steps.q.outputs.job_id }}" } }
`)
	app.mu.Lock()
	app.Flows = []Flow{worker, producer}
	app.mu.Unlock()

	if rr := jobIdentityCall(t, app, &producer, sid, `{"victim":"99999"}`); rr.Code != http.StatusOK {
		t.Fatalf("producer answered %d %s", rr.Code, rr.Body.String())
	}
	payloads := jobIdentityPayloads(t, app)
	if len(payloads) != 1 {
		t.Fatalf("queued %d jobs, want 1", len(payloads))
	}
	for key := range payloads[0] {
		if flowJobIdentityKey(key) {
			t.Errorf("the job payload carries the identity name %q = %v", key, payloads[0][key])
		}
	}
	// Any other name is queued as before, with its request taint.
	if payloads[0]["label"] != "enq" || payloads[0]["target_user_id"] != "99999" {
		t.Fatalf("payload lost its own keys: %v", payloads[0])
	}
	if tainted, _ := payloads[0][flowRequestKeysPayloadField].([]any); !slices.Contains(tainted, any("target_user_id")) || slices.Contains(tainted, any("user_id")) {
		t.Fatalf("request taint of the payload: %v", payloads[0][flowRequestKeysPayloadField])
	}

	// The delayed job, when it runs (and when it is run again), has no
	// identity: `:user_id` is not the request's value, so the worker's write
	// does not happen under it.
	for attempt := 1; attempt <= 2; attempt++ {
		mustExec(t, app.DB, "UPDATE _benmore_jobs SET status = 'pending', attempts = 0, run_at = datetime('now', '-1 minute'), not_before = NULL, error = NULL")
		FlushJobs(app)
		var status, jobErr string
		if err := app.DB.QueryRow("SELECT status, COALESCE(error, '') FROM _benmore_jobs").Scan(&status, &jobErr); err != nil {
			t.Fatal(err)
		}
		if status != "failed" || !strings.Contains(jobErr, ":user_id is not set") {
			t.Fatalf("run %d: job status %q error %q, want it failed on the unset :user_id", attempt, status, jobErr)
		}
		if n := gateScalar(t, app, "SELECT COUNT(*) FROM notes"); n != "0" {
			t.Fatalf("run %d: the job wrote %s row(s) as user %s", attempt, n, gateScalar(t, app, "SELECT user_id FROM notes LIMIT 1"))
		}
	}
}

// An async flow's job runs for the caller who queued it, whatever the
// request sends under an identity name, on every run of the job.
func TestAsyncJobKeepsTheQueuingCallersIdentity(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, user_id INTEGER)")
	EnsureJobsTable(app.DB)
	uid, sid := gateUser(t, app, "caller@example.com")
	flow := jobIdentityFlow(t, app, "record", `on:
  request: { method: POST, path: /api/record, auth: required, mode: async }
jobs:
  go:
    steps:
      - run: sql
        with:
          query: "INSERT INTO notes (title, user_id) VALUES (:user_email || '/' || :user_role || '/' || COALESCE(:_group_id, ''), :user_id)"
`)
	app.mu.Lock()
	app.Flows = []Flow{flow}
	app.mu.Unlock()

	body := `{"user_id":99999,"user_email":"victim@example.com","user_role":"admin","user_group_id":"tenant-b","_group_id":"tenant-b","_group_key":"org_id","user":{"id":99999,"email":"victim@example.com"}}`
	if rr := jobIdentityCall(t, app, &flow, sid, body); rr.Code != http.StatusAccepted {
		t.Fatalf("async flow answered %d %s", rr.Code, rr.Body.String())
	}
	payloads := jobIdentityPayloads(t, app)
	if len(payloads) != 1 || valueText(payloads[0]["user_id"]) != valueText(uid) || payloads[0]["user_email"] != "caller@example.com" {
		t.Fatalf("queued identity is not the caller's: %v", payloads)
	}
	for run := 1; run <= 2; run++ {
		mustExec(t, app.DB, "UPDATE _benmore_jobs SET status = 'pending', attempts = 0, run_at = datetime('now', '-1 minute'), not_before = NULL, error = NULL")
		FlushJobs(app)
		if got := gateScalar(t, app, "SELECT COUNT(*) FROM notes WHERE user_id = ? AND title = 'caller@example.com/user/'", uid); got != valueText(run) {
			t.Fatalf("run %d: %s row(s) written as the caller; rows: %s", run, got, gateScalar(t, app, "SELECT group_concat(title || '#' || user_id) FROM notes"))
		}
	}
}

// The write gate and `benmore check` refuse the key where it is written; a
// deployed file still loads (the tests above run one).
func TestEnqueueIdentityPayloadKeyIsRefusedWhenWritten(t *testing.T) {
	flow := func(key string) string {
		return "on:\n  request: { method: POST, path: /api/producer, auth: required }\njobs:\n  go:\n    steps:\n" +
			"      - id: q\n        run: enqueue\n        with:\n          flow: worker\n          with:\n            label: \"x\"\n            " + key + ": \"${{ user.id }}\"\n" +
			"      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
	}
	for _, key := range []string{"user_id", "user_email", "user_role", "user", "user_group_id", "_group_id", "_group_key", "user.id"} {
		msg := ValidateOnWrite("flows/producer.yaml", flow(key))
		if !strings.Contains(msg, "`with.with."+key+"` is a reserved identity name") || !strings.Contains(msg, "target_user_id") {
			t.Errorf("%s: the write gate did not refuse the key: %q", key, msg)
		}
	}
	for _, key := range []string{"target_user_id", "queued_by", "org_id", "user_ids", "userid"} {
		if msg := ValidateOnWrite("flows/producer.yaml", flow(key)); msg != "" {
			t.Errorf("%s: the write gate refused an ordinary payload key: %s", key, msg)
		}
	}

	// cron.yaml's inline enqueue step.
	cron := "jobs:\n  - id: fanout\n    schedule: \"every 1h\"\n    steps:\n      - enqueue:\n          flow: worker\n          with:\n            user_id: \"7\"\n"
	if msg := ValidateOnWrite("cron.yaml", cron); !strings.Contains(msg, "`with.user_id` is a reserved identity name") {
		t.Errorf("cron.yaml: the write gate did not refuse the key: %q", msg)
	}
	if msg := ValidateOnWrite("cron.yaml", strings.Replace(cron, "user_id:", "target_user_id:", 1)); msg != "" {
		t.Errorf("cron.yaml: the write gate refused an ordinary payload key: %s", msg)
	}

	// `benmore check` reports the same refusal for a file already on disk.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"app.yaml":            "site_name: \"Identity\"\n",
		"flows/producer.yaml": flow("user_id"),
		"flows/worker.yaml":   jobIdentityWorkerFlow,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report := RunSourceCheck(dir, "")
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" && f.File == "flows/producer.yaml" && strings.Contains(f.Message, "`with.with.user_id` is a reserved identity name") {
			found = true
		}
	}
	if !found {
		t.Errorf("benmore check did not report the key as an error: %+v", report.Findings)
	}
}
