//go:build !cli

package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// asyncParseFlow loads one async flow from YAML the way an app writes it
// (the api(at:"parse") example plus `mode: async`) and registers it.
func asyncParseFlow(t *testing.T, app *App, steps string) Flow {
	t.Helper()
	dir := t.TempDir()
	source := "on:\n  request:\n    method: POST\n    path: /api/hooks/evt\n    mode: async\njobs:\n  evt:\n    steps:\n" + steps
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || !flows[0].Async {
		t.Fatalf("loaded flows = %+v, want one async flow", flows)
	}
	app.mu.Lock()
	app.Flows = flows
	app.mu.Unlock()
	return flows[0]
}

func runAsyncParseJob(t *testing.T, app *App, flow Flow, contentType, body string) (status, jobErr string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/hooks/evt", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, rec, r); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if rec.Code != 202 {
		t.Fatalf("enqueue status = %d, want 202 (body %s)", rec.Code, rec.Body.String())
	}
	FlushJobs(app)
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs ORDER BY id DESC LIMIT 1").Scan(&status, &jobErr); err != nil {
		t.Fatalf("read job: %v", err)
	}
	return status, jobErr
}

// A `run: parse` step in an async flow reads the body the request carried.
// It used to be skipped in the worker (no live request), so the flow answered
// 202 and the job failed every attempt on unresolved step references.
func TestAsyncFlowParseReadsQueuedJSONBody(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE charges (event_id TEXT, kind TEXT, amount INTEGER)")
	flow := asyncParseFlow(t, app, `      - id: evt
        run: parse
      - run: sql
        with:
          query: "INSERT INTO charges (event_id, kind, amount) VALUES (:id, :kind, :amount)"
          params:
            id: "${{ steps.evt.outputs.id }}"
            kind: "${{ steps.evt.outputs.type }}"
            amount: "${{ steps.evt.outputs.data.object.amount }}"
`)
	status, jobErr := runAsyncParseJob(t, app, flow, "application/json",
		`{"id":"evt_1","type":"charge.succeeded","data":{"object":{"amount":1250}}}`)
	if status != "completed" {
		t.Fatalf("job status = %q error = %q, want completed", status, jobErr)
	}
	var id, kind string
	var amount int
	if err := app.DB.QueryRow("SELECT event_id, kind, amount FROM charges").Scan(&id, &kind, &amount); err != nil {
		t.Fatalf("parsed body produced no row: %v", err)
	}
	if id != "evt_1" || kind != "charge.succeeded" || amount != 1250 {
		t.Fatalf("row = (%q, %q, %d), want (evt_1, charge.succeeded, 1250)", id, kind, amount)
	}
}

// A form body parses in the worker under `form` like it does inline.
func TestAsyncFlowParseReadsQueuedFormBody(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE notes (body TEXT)")
	flow := asyncParseFlow(t, app, `      - run: parse
      - run: sql
        with:
          query: "INSERT INTO notes (body) VALUES (:body)"
          params:
            body: "${{ form.note }}"
`)
	status, jobErr := runAsyncParseJob(t, app, flow, "application/x-www-form-urlencoded", "note=hello+there")
	if status != "completed" {
		t.Fatalf("job status = %q error = %q, want completed", status, jobErr)
	}
	var got string
	if err := app.DB.QueryRow("SELECT body FROM notes").Scan(&got); err != nil || got != "hello there" {
		t.Fatalf("note = %q (%v), want %q", got, err, "hello there")
	}
}

// Invalid JSON fails the parse step in the worker, as it fails the step inline;
// the job never completes with nothing parsed.
func TestAsyncFlowParseInvalidJSONFailsTheJob(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE charges (event_id TEXT)")
	flow := asyncParseFlow(t, app, `      - id: evt
        run: parse
      - run: sql
        with:
          query: "INSERT INTO charges (event_id) VALUES (:id)"
          params:
            id: "${{ steps.evt.outputs.id }}"
`)
	status, jobErr := runAsyncParseJob(t, app, flow, "text/plain", `{"id":`)
	if status == "completed" || !strings.Contains(jobErr, "parse body") {
		t.Fatalf("job status = %q error = %q, want a parse body failure", status, jobErr)
	}
}

// The carrier field is server-owned: a request field of the same name neither
// replaces the parsed body nor reaches the worker as a value.
func TestAsyncFlowQueuedBodyCannotBeForged(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE charges (event_id TEXT)")
	flow := asyncParseFlow(t, app, `      - id: evt
        run: parse
      - run: sql
        with:
          query: "INSERT INTO charges (event_id) VALUES (:id)"
          params:
            id: "${{ steps.evt.outputs.id }}"
`)
	body := `{"id":"real","` + flowRequestBodyPayloadField + `":{"value":{"id":"forged"}}}`
	status, jobErr := runAsyncParseJob(t, app, flow, "application/json", body)
	if status != "completed" {
		t.Fatalf("job status = %q error = %q, want completed", status, jobErr)
	}
	var id string
	if err := app.DB.QueryRow("SELECT event_id FROM charges").Scan(&id); err != nil || id != "real" {
		t.Fatalf("event_id = %q (%v), want the real body's id", id, err)
	}
}

// A queued body is not read back by job status surfaces: values named like
// hidden columns stay redacted inside it, as everywhere in a payload.
func TestAsyncFlowQueuedBodyRedactedOnRead(t *testing.T) {
	payload := `{"` + flowRequestBodyPayloadField + `":{"value":{"id":"evt_1","password":"hunter2"}}}`
	got, _ := redactJobPayloadForRead(nil, payload).(string)
	if strings.Contains(got, "hunter2") || !strings.Contains(got, "evt_1") {
		t.Fatalf("redacted payload = %s", got)
	}
}

// Flows without a body parse step queue no body copy.
func TestAsyncFlowWithoutParseQueuesNoBody(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	flow := asyncParseFlow(t, app, `      - run: sql
        with:
          query: "SELECT 1"
`)
	r := httptest.NewRequest("POST", "/api/hooks/evt", strings.NewReader(`{"id":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, rec, r); err != nil || rec.Code != 202 {
		t.Fatalf("enqueue: %v status %d", err, rec.Code)
	}
	var payload string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, flowRequestBodyPayloadField) {
		t.Fatalf("payload carries a body copy without a parse step: %s", payload)
	}
}
