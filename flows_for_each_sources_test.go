//go:build !cli

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// for_each over a json_group_array() column ran zero times and the flow
// answered 200, while respond showed the same reference as an array. JSON text
// of an array is now iterated, decoded the way respond decodes it.
func TestForEachIteratesJSONTextArray(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE line_items (id INTEGER PRIMARY KEY, description TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE loop_log (detail TEXT)`)
	mustExec(t, app.DB, `INSERT INTO line_items (description) VALUES ('Widget'), ('Gadget')`)
	flow := `on:
  request:
    method: POST
    path: /api/loop
jobs:
  loop:
    steps:
      - id: agg
        run: sql
        with:
          query: "SELECT json_group_array(json_object('id', id, 'd', description)) AS items FROM line_items"
      - id: walk
        for_each: ${{ steps.agg.outputs.first.items }}
        as: it
        steps:
          - run: sql
            with:
              query: "INSERT INTO loop_log (detail) VALUES (:d)"
              params: { d: "${{ it.d }}" }
      - id: n
        run: sql
        with:
          query: "SELECT COUNT(*) AS n FROM loop_log"
      - run: respond
        with:
          status: 200
          json: { items: "${{ steps.agg.outputs.first.items }}", inserted: "${{ steps.n.outputs.first.n }}" }
`
	rr := runProbeGHAFlow(t, app, flow, `{}`)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var got []string
	rows, err := app.DB.Query(`SELECT detail FROM loop_log ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		got = append(got, d)
	}
	if strings.Join(got, ",") != "Widget,Gadget" {
		t.Fatalf("loop inserted %q, want Widget,Gadget; answer %s", got, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"inserted":2`) {
		t.Fatalf("answer = %s", rr.Body.String())
	}
}

// A non-empty source that is not a list fails the step with an error naming
// the source and what it holds. Each of these ran zero times and answered 200.
func TestForEachRefusesSourceThatIsNotAList(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE loop_log (detail TEXT)`)
	flow := `on:
  request:
    method: POST
    path: /api/add-lines
jobs:
  add:
    steps:
      - for_each: ${{ params.lines }}
        as: line
        steps:
          - run: sql
            with:
              query: "INSERT INTO loop_log (detail) VALUES (:d)"
              params: { d: "${{ line.d }}" }
      - run: respond
        with:
          status: 200
          json: { ok: true }
`
	for _, tc := range []struct{ body, kind string }{
		{`{"lines":"hello"}`, "is text the caller sent, not a list"},
		{`{"lines":"[{\"d\":\"x\"}]"}`, "never decoded into a list"},
		{`{"lines":{"d":"x"}}`, "is an object, not a list"},
		{`{"lines":7}`, "is a number, not a list"},
		{`{"lines":true}`, "is a boolean, not a list"},
	} {
		logged := flowFailureLogFor(t, app, flow, tc.body)
		if !strings.Contains(logged, "${{ params.lines }}") || !strings.Contains(logged, tc.kind) {
			t.Fatalf("%s: error %q does not name the source and %q", tc.body, logged, tc.kind)
		}
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM loop_log`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows = %d (%v), want 0", n, err)
	}

	// A step output that is a number or JSON text of an object fails too.
	computed := `on:
  request:
    method: POST
    path: /api/walk
jobs:
  walk:
    steps:
      - id: one
        run: sql
        with:
          query: "SELECT 3 AS n, json_object('results', json_array(1, 2)) AS envelope"
      - for_each: ${{ steps.one.outputs.first.n }}
        steps:
          - run: sql
            with: { query: "INSERT INTO loop_log (detail) VALUES ('n')" }
      - run: respond
        with: { status: 200, json: { ok: true } }
`
	if logged := flowFailureLogFor(t, app, computed, `{}`); !strings.Contains(logged, "${{ steps.one.outputs.first.n }} is a number, not a list") {
		t.Fatalf("number source: %q", logged)
	}
	envelope := strings.Replace(computed, "steps.one.outputs.first.n }}", "steps.one.outputs.first.envelope }}", 1)
	if logged := flowFailureLogFor(t, app, envelope, `{}`); !strings.Contains(logged, "is an object, not a list") || !strings.Contains(logged, "name the list") {
		t.Fatalf("object source: %q", logged)
	}
}

// flowFailureLogFor runs flow with body in a dev-mode app (whose failure
// answer carries the step's error) and returns that error, failing the test
// when the flow answers 200 or gives another reason.
func flowFailureLogFor(t *testing.T, app *App, flow, body string) string {
	t.Helper()
	app.DevMode = true
	rr := runProbeGHAFlow(t, app, flow, body)
	var full map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &full); err != nil {
		t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
	}
	if rr.Code != 500 || full["reason"] != "the loop's source is not a list" || full["failed_type"] != "for_each" {
		t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
	}
	msg, _ := full["message"].(string)
	return msg
}

// Empty, null and missing sources keep running zero times, and so does an
// empty JSON array from SQL.
func TestForEachEmptySourcesStillRunZeroTimes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE loop_log (detail TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE line_items (id INTEGER PRIMARY KEY, description TEXT)`)
	flow := `on:
  request:
    method: POST
    path: /api/add-lines
jobs:
  add:
    steps:
      - id: agg
        run: sql
        with:
          query: "SELECT json_group_array(description) AS items FROM line_items"
      - for_each: ${{ params.lines }}
        steps:
          - run: sql
            with: { query: "INSERT INTO loop_log (detail) VALUES ('request')" }
      - for_each: ${{ steps.agg.outputs.first.items }}
        steps:
          - run: sql
            with: { query: "INSERT INTO loop_log (detail) VALUES ('sql')" }
      - run: respond
        with:
          status: 200
          json: { ok: true }
`
	for _, body := range []string{`{"lines":[]}`, `{"lines":null}`, `{}`, `{"lines":""}`, `{"lines":{}}`} {
		rr := runProbeGHAFlow(t, app, flow, body)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM loop_log`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows = %d (%v), want 0", n, err)
	}
}

// Queued flows (run: enqueue, mode: async) and cron run the same loop: a job
// iterates a JSON-text list and fails on a source that is not a list.
func TestForEachSourcesInQueuedFlow(t *testing.T) {
	app := newJobsTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE loop_log (detail TEXT)`)
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "worker.yaml"), []byte(`on:
  request:
    method: POST
    path: /api/worker
jobs:
  worker:
    steps:
      - for_each: ${{ items }}
        as: it
        steps:
          - run: sql
            with:
              query: "INSERT INTO loop_log (detail) VALUES (:d)"
              params: { d: "${{ it.d }}" }
`))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse: %v", err)
	}
	app.Flows = flows
	if err := executeFlowJob(app, "worker", map[string]any{"items": `[{"d":"a"},{"d":"b"}]`}); err != nil {
		t.Fatalf("JSON-text list: %v", err)
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM loop_log`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows = %d (%v), want 2", n, err)
	}
	err = executeFlowJob(app, "worker", map[string]any{"items": map[string]any{"results": []any{1}}})
	if err == nil || !strings.Contains(err.Error(), "is an object, not a list") {
		t.Fatalf("object source: %v", err)
	}
}
