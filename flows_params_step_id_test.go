//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `${{ params.<id> }}` is the request field of that name, never the step's
// output. When the request omitted the field it used to fall back to the
// step's output (flows/lab-shadow.yaml: `{"flag":"go"}` gave params_approved
// the step's rows instead of the default 'absent').
func TestParamsStepIDNeverReadsTheStepOutput(t *testing.T) {
	app, mux := auditApp(t)
	file := filepath.Join(t.TempDir(), "lab-shadow.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/lab-shadow
    auth: none
jobs:
  main:
    steps:
      - id: flag2
        run: sql
        with:
          query: "SELECT 'step-row' AS v"
      - if: ${{ params.flag2 }}
        run: respond
        with:
          json: { gated: true }
      - run: respond
        with:
          json:
            params_approved: "${{ params.flag2 | default:'absent' }}"
            nested: "${{ params.flag2.v | default:'absent' }}"
            step: "${{ steps.flag2.outputs.v }}"
            flag: "${{ params.flag | default:'none' }}"
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := loadOneGHAFile(file)
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	RegisterFlows(mux, app, flows)
	call := func(body string) map[string]any {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/flows/lab-shadow", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: status %d body %s", body, rec.Code, rec.Body.String())
		}
		return out
	}
	out := call(`{"flag":"go"}`)
	if out["gated"] == true {
		t.Fatalf("`if: ${{ params.flag2 }}` read the step's output: %v", out)
	}
	if out["params_approved"] != "absent" || out["nested"] != "absent" {
		t.Fatalf("params.flag2 read the step's output when the request omitted it: %v", out)
	}
	if out["step"] != "step-row" || out["flag"] != "go" {
		t.Fatalf("step output or an unrelated request field changed: %v", out)
	}
	if out := call(`{"flag2":"yes"}`); out["gated"] != true {
		t.Fatalf("the request's flag2 is no longer readable as params.flag2: %v", out)
	}
}

// A queued flow keeps the rule in the worker.
func TestParamsStepIDInAsyncWorker(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE seen (approved TEXT)")
	flow := Flow{
		Name: "lab-shadow-async", Async: true,
		Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/lab-shadow-async"},
		Steps: []FlowStep{
			{Name: "flag2", Type: "sql", SQL: "SELECT 'step-row' AS v"},
			{Type: "sql", SQL: "INSERT INTO seen (approved) VALUES (:a)", SQLParams: map[string]string{"a": "{{params.flag2 | default:'absent'}}"}},
		},
	}
	app.mu.Lock()
	app.Flows = []Flow{flow}
	app.mu.Unlock()
	for _, tc := range []struct{ body, want string }{{`{"flag":"go"}`, "absent"}, {`{"flag2":"yes"}`, "yes"}} {
		mustExec(t, app.DB, "DELETE FROM seen")
		r := httptest.NewRequest("POST", "/api/lab-shadow-async", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := executeFlowHTTP(app, &flow, rec, r); err != nil || rec.Code != 202 {
			t.Fatalf("enqueue: %v %d", err, rec.Code)
		}
		FlushJobs(app)
		var got string
		if err := app.DB.QueryRow("SELECT approved FROM seen").Scan(&got); err != nil || got != tc.want {
			t.Fatalf("%s: approved = %q (%v), want %q", tc.body, got, err, tc.want)
		}
	}
}

// The flattened lookup (conditions, pipes, SQL params) and the direct one
// agree.
func TestParamsStepIDLookupIsRequestOnly(t *testing.T) {
	ctx := &FlowContext{
		Data:        map[string]any{"flag2": []map[string]any{{"v": "row"}}, "other": "o", "plain": "p"},
		Params:      map[string]string{},
		RequestKeys: map[string]bool{"plain": true},
	}
	shadowStepNamedRequestKeys(ctx, []FlowStep{{Name: "flag2", Type: "sql"}})
	if v, ok := flowDataValue(ctx, "params.flag2"); ok {
		t.Fatalf("flowDataValue(params.flag2) = %v, want missing", v)
	}
	flat := flatDataForCtx(ctx)
	for _, key := range []string{"params.flag2", "params.flag2.v", "params.flag2.0.v"} {
		if v, ok := flowLookup(flat, key); ok {
			t.Fatalf("flowLookup(%s) = %v, want missing", key, v)
		}
	}
	if v, ok := flowLookup(flat, "params.plain"); !ok || v != "p" {
		t.Fatalf("params.plain = %v %v, want the request value", v, ok)
	}
	if v, ok := flowLookup(flat, "flag2.v"); !ok || v != "row" {
		t.Fatalf("the step output is no longer readable by its own name: %v %v", v, ok)
	}
}
