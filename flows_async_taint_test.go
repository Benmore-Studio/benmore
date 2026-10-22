//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAsyncFlowKeepsSQLDynamicRequestTaint pins the M-1 guard across the
// async boundary: a request-sourced value must not reach sql_dynamic raw text
// just because the flow runs in the job worker instead of inline.
func TestAsyncFlowKeepsSQLDynamicRequestTaint(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)

	newFlow := func(async bool) Flow {
		return Flow{
			Name:    "echo",
			Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/echo"},
			Async:   async,
			Steps: []FlowStep{{
				Type: "if", Condition: "true",
				Steps: []FlowStep{{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{term}}' AS v"}},
			}},
		}
	}

	// Sync baseline: the guard rejects the request-sourced ref.
	syncFlow := newFlow(false)
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &syncFlow, rec, httptest.NewRequest("POST", "/api/echo?term=hello", nil)); err == nil || !strings.Contains(err.Error(), "request-sourced") {
		t.Fatalf("sync flow: want sql_dynamic request-taint error, got %v", err)
	}

	// Async: the same flow must fail the same way in the worker.
	asyncFlow := newFlow(true)
	app.mu.Lock()
	app.Flows = []Flow{asyncFlow}
	app.mu.Unlock()
	rec = httptest.NewRecorder()
	if err := executeFlowHTTP(app, &asyncFlow, rec, httptest.NewRequest("POST", "/api/echo?term=hello", nil)); err != nil {
		t.Fatalf("async enqueue: %v", err)
	}
	if rec.Code != 202 {
		t.Fatalf("async enqueue status = %d, want 202", rec.Code)
	}
	FlushJobs(app)

	var status, jobErr string
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE flow_name = 'echo'").Scan(&status, &jobErr); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status == "completed" || !strings.Contains(jobErr, "request-sourced") {
		t.Fatalf("async flow ran sql_dynamic on request input: status=%q error=%q", status, jobErr)
	}
}

// TestTakeFlowRequestKeysStripsReservedField keeps the carrier field out of
// the worker's data so it never surfaces as a flow value or SQL param.
func TestTakeFlowRequestKeysStripsReservedField(t *testing.T) {
	data := map[string]any{"term": "x", flowRequestKeysPayloadField: []any{"term"}}
	keys := takeFlowRequestKeys(data)
	if !keys["term"] || len(keys) != 1 {
		t.Fatalf("taint set = %v, want {term}", keys)
	}
	if _, ok := data[flowRequestKeysPayloadField]; ok {
		t.Fatal("reserved taint field left in job data")
	}
	if takeFlowRequestKeys(map[string]any{"a": 1}) != nil {
		t.Fatal("payload without the field must yield no taint set")
	}
}
