//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// `${{ params.<set key> }}` and `${{ params.<loop variable> }}` are the
// request fields of those names. When the request omitted the field they
// used to fall back to what the set step or the loop wrote: after
// `set: { page: "${{ params.page | default:'1' }}" }` a later
// `params.page | default:'absent'` was '1', and inside a loop `params.row`
// was the current row.
func TestParamsSetKeyAndLoopVarAreRequestOnly(t *testing.T) {
	app, mux := auditApp(t)
	mustExec(t, app.DB, "CREATE TABLE seen (v TEXT)")
	file := filepath.Join(t.TempDir(), "lab-set.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/lab-set
    auth: none
jobs:
  main:
    steps:
      - id: norm
        run: set
        with:
          page: "${{ params.page | default:'1' }}"
      - id: rows
        run: sql
        with:
          query: "SELECT 'a' AS v UNION ALL SELECT 'b' AS v"
      - for_each: ${{ steps.rows.outputs.rows }}
        as: row
        steps:
          - run: sql
            with:
              query: "INSERT INTO seen (v) VALUES (:v)"
              params: { v: "${{ params.row | default:'absent' }}" }
      - run: respond
        with:
          json:
            page_param: "${{ params.page | default:'absent' }}"
            page: "${{ page }}"
            set_output: "${{ steps.norm.outputs.page }}"
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := loadOneGHAFile(file)
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	RegisterFlows(mux, app, flows)
	call := func(body string) (map[string]any, []string) {
		t.Helper()
		mustExec(t, app.DB, "DELETE FROM seen")
		req := httptest.NewRequest("POST", "/api/flows/lab-set", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: status %d body %s", body, rec.Code, rec.Body.String())
		}
		rows, err := QueryRows(app.DB, "SELECT v FROM seen ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		var seen []string
		for _, r := range rows {
			seen = append(seen, valueText(r["v"]))
		}
		return out, seen
	}

	out, seen := call(`{}`)
	if out["page_param"] != "absent" {
		t.Errorf("params.page read the set step's value when the request omitted it: %v", out)
	}
	if out["page"] != "1" || out["set_output"] != "1" {
		t.Errorf("the set step's own value changed: %v", out)
	}
	if !slices.Equal(seen, []string{"absent", "absent"}) {
		t.Errorf("params.row inside the loop = %v, want absent twice (the request sent no row)", seen)
	}

	out, seen = call(`{"page":"3","row":"r"}`)
	if out["page_param"] != "3" || out["page"] != "3" {
		t.Errorf("the request's page is no longer readable as params.page: %v", out)
	}
	if !slices.Equal(seen, []string{"r", "r"}) {
		t.Errorf("params.row inside the loop = %v, want the request's r twice", seen)
	}
}

// A queued HTTP flow keeps the rule in the worker. A value an enqueue step
// passes under a set key's name is not a request field that was shadowed, so
// it keeps reading as before.
func TestParamsSetKeyInAsyncWorker(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE seen (page TEXT)")
	flow := Flow{
		Name: "lab-set-async", Async: true,
		Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/lab-set-async"},
		Steps: []FlowStep{
			{Name: "norm", Type: "set", Set: map[string]string{"page": "{{params.page | default:'1'}}"}},
			{Type: "sql", SQL: "INSERT INTO seen (page) VALUES (:p)", SQLParams: map[string]string{"p": "{{params.page | default:'absent'}}"}},
		},
	}
	app.mu.Lock()
	app.Flows = []Flow{flow}
	app.mu.Unlock()
	read := func() string {
		t.Helper()
		var got string
		if err := app.DB.QueryRow("SELECT page FROM seen").Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, tc := range []struct{ body, want string }{{`{}`, "absent"}, {`{"page":"3"}`, "3"}} {
		mustExec(t, app.DB, "DELETE FROM seen")
		r := httptest.NewRequest("POST", "/api/lab-set-async", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := executeFlowHTTP(app, &flow, rec, r); err != nil || rec.Code != 202 {
			t.Fatalf("enqueue: %v %d", err, rec.Code)
		}
		FlushJobs(app)
		if got := read(); got != tc.want {
			t.Fatalf("%s: page = %q, want %q", tc.body, got, tc.want)
		}
	}
	mustExec(t, app.DB, "DELETE FROM seen")
	if _, _, err := EnqueueJob(app.DB, flow.Name, map[string]any{"page": "9"}, nil); err != nil {
		t.Fatal(err)
	}
	FlushJobs(app)
	if got := read(); got != "9" {
		t.Fatalf("an enqueued page = %q, want 9", got)
	}
}

// Identity values keep today's reading: `params.user_id` and friends are
// never request fields (the request's are stripped), and a set key or loop
// variable named like one does not make them missing.
func TestParamsIdentityKeysUnchanged(t *testing.T) {
	ctx := &FlowContext{
		Data:        map[string]any{"user_id": int64(7), "user_role": "admin", "user": map[string]any{"id": int64(7)}, "page": "2"},
		Params:      map[string]string{},
		RequestKeys: map[string]bool{"page": true},
	}
	shadowStepNamedRequestKeys(ctx, []FlowStep{
		{Type: "set", Set: map[string]string{"user_role": "x", "page": "y"}},
		{Type: "for_each", ForEach: "items", ForAs: "user", Steps: []FlowStep{{Type: "sql"}}},
	})
	flat := flatDataForCtx(ctx)
	for key, want := range map[string]any{"params.user_id": int64(7), "params.user_role": "admin", "params.user.id": int64(7), "params.page": "2"} {
		if v, ok := flowLookup(flat, key); !ok || v != want {
			t.Errorf("flowLookup(%s) = %v %v, want %v", key, v, ok, want)
		}
		if !strings.Contains(key, ".id") {
			if v, ok := flowDataValue(ctx, key); !ok || v != want {
				t.Errorf("flowDataValue(%s) = %v %v, want %v", key, v, ok, want)
			}
		}
	}
	// The set writes its value at the top level; params.page stays the
	// request's.
	ctx.Data["page"] = "y"
	if v, ok := flowLookup(flatDataForCtx(ctx), "params.page"); !ok || v != "2" {
		t.Errorf("after the set, params.page = %v %v, want the request's 2", v, ok)
	}
}
