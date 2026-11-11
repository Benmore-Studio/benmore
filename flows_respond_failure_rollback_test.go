//go:build !cli

package main

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A `transaction: true` request flow whose respond step cannot produce its
// answer (a `${{ }}` reference with no value) answered 500 template_unresolved
// and still committed every write of the run: the order, its lines, the queued
// job and the notification. The caller saw a failure, sent the request again
// and the order existed twice. The answer is part of the transaction: when it
// cannot be produced, nothing is kept, queued or announced.

const respondFailureOrderFlow = `on:
  request:
    method: POST
    path: /api/place-order
    auth: required
    transaction: true

jobs:
  place:
    steps:
      - id: order
        run: sql
        with:
          query: "INSERT INTO notes (user_id, title) VALUES (:user_id, 'order') RETURNING id"
      - run: sql
        with:
          query: "INSERT INTO order_lines (note_id, qty) VALUES (:note_id, 2)"
          params: { note_id: "${{ steps.order.outputs.id }}" }
      - run: enqueue
        with:
          flow: send-confirmation
          with: { order_id: "${{ steps.order.outputs.id }}" }
      - run: notify
        with:
          user_id: ${{ user.id }}
          title: "Order placed"
      - if: ${{ params.shape || '' }} == 'nested'
        steps:
          - for_each: ${{ params.items }}
            as: item
            steps:
              - run: respond
                with:
                  status: 201
                  json: { order_id: "${{ steps.order.outputs.id }}", x: "${{ params.value_that_is_not_sent }}" }
      - if: ${{ params.shape || '' }} == 'bare_body'
        run: respond
        with:
          status: 201
          body: ${{ steps.order.outputs.missing_column }}
      - if: ${{ params.shape || '' }} == 'text_body'
        run: respond
        with:
          status: 201
          body: "order ${{ params.value_that_is_not_sent }}"
      - if: ${{ params.shape || '' }} == 'header'
        run: respond
        with:
          status: 201
          headers: { X-Order: "${{ params.value_that_is_not_sent }}" }
          json: { ok: true }
      - if: ${{ params.shape || '' }} == 'status'
        run: respond
        with:
          status: ${{ params.value_that_is_not_sent }}
          json: { ok: true }
      - if: ${{ params.shape || '' }} == 'json_array'
        run: respond
        with:
          status: 201
          json: [ "${{ params.value_that_is_not_sent }}" ]
      - if: ${{ params.shape || '' }} == 'redirect'
        run: redirect
        with: { to: "/orders/${{ params.value_that_is_not_sent }}" }
      - run: respond
        with:
          status: 201
          json: { order_id: "${{ steps.order.outputs.id }}", x: "${{ params.x }}" }
`

func respondFailureApp(t *testing.T) (*App, *Flow, string) {
	t.Helper()
	app, _ := auditApp(t)
	mustExec(t, app.DB, `CREATE TABLE order_lines (id INTEGER PRIMARY KEY AUTOINCREMENT, note_id INTEGER, qty INTEGER)`)
	cols, err := GetTableColumns(app.DB, "order_lines")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "order_lines", Columns: cols})
	app.Access.rules["order_lines"] = map[AccessOp]string{"all": "everyone"}
	EnsureJobsTable(app.DB)
	flows := notifyFlows(t, "flows/place-order.yaml", respondFailureOrderFlow)
	app.Flows = append(flows, Flow{Name: "send-confirmation", Steps: []FlowStep{{Type: "set"}}})
	sid := createCrudScopeSession(t, app, "buyer@example.com", "user", "", "")
	return app, &app.Flows[0], sid
}

// respondFailureCounts is everything the order flow leaves behind.
func respondFailureCounts(t *testing.T, app *App) [4]int {
	t.Helper()
	var out [4]int
	for i, table := range []string{"notes", "order_lines", "_benmore_jobs", "_benmore_notifications"} {
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&out[i]); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
	}
	return out
}

func TestTransactionalFlowFailedRespondRollsBack(t *testing.T) {
	for _, tc := range []struct {
		shape string
		body  map[string]any
		// wantError is the answer's "error" value.
		wantError string
		// missing is text the template_unresolved answer names.
		missing string
	}{
		{shape: "final", body: map[string]any{}, wantError: "template_unresolved", missing: "params.x"},
		{shape: "nested", body: map[string]any{"shape": "nested", "items": []any{1, 2}}, wantError: "template_unresolved", missing: "params.value_that_is_not_sent"},
		{shape: "bare_body", body: map[string]any{"shape": "bare_body"}, wantError: "template_unresolved", missing: "order.missing_column"},
		{shape: "text_body", body: map[string]any{"shape": "text_body"}, wantError: "template_unresolved", missing: "params.value_that_is_not_sent"},
		{shape: "header", body: map[string]any{"shape": "header"}, wantError: "template_unresolved", missing: "params.value_that_is_not_sent"},
		{shape: "status", body: map[string]any{"shape": "status"}, wantError: "template_unresolved", missing: "params.value_that_is_not_sent"},
		{shape: "json_array", body: map[string]any{"shape": "json_array"}, wantError: "template_unresolved", missing: "params.value_that_is_not_sent"},
		// A redirect whose target has no value is a failed step.
		{shape: "redirect", body: map[string]any{"shape": "redirect"}, wantError: "flow_no_response"},
	} {
		t.Run(tc.shape, func(t *testing.T) {
			app, flow, sid := respondFailureApp(t)
			sub := subscribeFlowRealtime(t, app, sid)
			before := respondFailureCounts(t, app)

			status, out := postFlow(t, app, flow, sid, tc.body)
			if status != http.StatusInternalServerError || out["error"] != tc.wantError {
				t.Fatalf("answer = %d %v, want 500 %s", status, out, tc.wantError)
			}
			if tc.missing != "" {
				named, _ := out["unresolved_key"].(string)
				if refs, ok := out["unresolved_refs"].([]any); ok {
					for _, ref := range refs {
						named += " " + ref.(string)
					}
				}
				if !strings.Contains(named, tc.missing) {
					t.Errorf("answer does not name the missing reference %q: %v", tc.missing, out)
				}
				if id, _ := out["request_id"].(string); id == "" {
					t.Errorf("answer carries no request_id: %v", out)
				}
			}
			if after := respondFailureCounts(t, app); after != before {
				t.Fatalf("a flow that could not answer kept its writes: notes, order_lines, jobs, notifications before=%v after=%v", before, after)
			}
			if sse, ws := sub.drain(); len(sse)+len(ws) != 0 {
				t.Fatalf("rolled-back writes were announced: sse=%q ws=%q", sse, ws)
			}

			// The failed attempt left nothing, so sending it again with the
			// value places the order exactly once.
			body := map[string]any{"x": "1"}
			status, out = postFlow(t, app, flow, sid, body)
			if status != http.StatusCreated || out["x"] != "1" {
				t.Fatalf("complete request = %d %v, want 201", status, out)
			}
			want := [4]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1}
			if after := respondFailureCounts(t, app); after != want {
				t.Fatalf("a successful order: notes, order_lines, jobs, notifications = %v, want %v", after, want)
			}
			if sse, _ := sub.drain(); len(sse) == 0 {
				t.Fatal("the committed order was not announced")
			}
		})
	}
}

// Without `transaction: true` every step's write is already durable when the
// respond step runs: the unresolved answer changes nothing about them.
func TestNonTransactionalFlowFailedRespondKeepsStepWrites(t *testing.T) {
	app, flow, sid := respondFailureApp(t)
	plain := *flow
	plain.Transaction = false
	before := respondFailureCounts(t, app)
	status, out := postFlow(t, app, &plain, sid, map[string]any{})
	if status != http.StatusInternalServerError || out["error"] != "template_unresolved" {
		t.Fatalf("answer = %d %v, want 500 template_unresolved", status, out)
	}
	want := [4]int{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1}
	if after := respondFailureCounts(t, app); after != want {
		t.Fatalf("non-transactional writes: notes, order_lines, jobs, notifications = %v, want %v", after, want)
	}
}

// A respond the author wrote with an error status is an answer, not a failure
// to answer: the transaction commits, as it does for any other status.
func TestTransactionalFlowAuthoredErrorStatusCommits(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusBadGateway, JSON: map[string]any{"recorded": true}}},
	)
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusBadGateway || strings.TrimSpace(rr.Body.String()) != `{"recorded":true}` {
		t.Fatalf("response = %d %q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("an authored 502 did not commit: rows=%d err=%v", count, err)
	}
}

// An on_error handler runs after the rollback. When its own respond cannot be
// produced the caller gets that template_unresolved answer, and the failed
// transaction stays rolled back.
func TestTransactionalFlowHandlerFailedRespondStaysRolledBack(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "sql", SQL: `INSERT INTO missing_table VALUES(1)`, OnError: []FlowStep{
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusConflict, JSON: map[string]any{"why": "{{not_in_scope}}"}}},
		}},
		respondOK(),
	)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, httptest.NewRequest(http.MethodPost, flow.Trigger.Path, nil))
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"template_unresolved"`) {
		t.Fatalf("handler answer = %d %q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rows after a failed handler answer = %d err=%v, want 0", count, err)
	}
}

// A respond step that fails as a step (a status that is no HTTP status, a
// body that cannot be encoded) rolls back too, with the step failure answer.
func TestTransactionalFlowRespondStepErrorRollsBack(t *testing.T) {
	for name, respond := range map[string]*FlowRespond{
		"status that is not a status": {StatusTemplate: "{{code}}", JSON: map[string]any{"ok": true}},
		"body that cannot be encoded": {Status: http.StatusOK, JSON: map[string]any{"n": math.NaN()}},
		"header with a line break":    {Status: http.StatusOK, Headers: []FlowRespondHeader{{Name: "X-Note", Value: "{{note}}"}}, JSON: map[string]any{"ok": true}},
	} {
		t.Run(name, func(t *testing.T) {
			app, cleanup := transactionalResponseApp(t)
			defer cleanup()
			flow := transactionalResponseFlow(
				FlowStep{Type: "set", Set: map[string]string{"code": "created", "note": "a\nb"}},
				FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
				FlowStep{Type: "respond", Respond: respond},
			)
			rr := runTransactionalResponse(app, flow)
			if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"failed_type":"respond"`) {
				t.Fatalf("answer = %d %q, want the 500 step failure of the respond step", rr.Code, rr.Body.String())
			}
			var count int
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("a failed respond step committed rows=%d err=%v", count, err)
			}
		})
	}
}

// A scheduled run of the same flow has no caller to answer, but the rule is
// the same: the run is reported failed and its writes are rolled back.
func TestScheduledTransactionalFlowFailedRespondRollsBack(t *testing.T) {
	app, flow, sid := respondFailureApp(t)
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil {
		t.Fatal("missing session")
	}
	before := respondFailureCounts(t, app)
	req := httptest.NewRequest(http.MethodPost, flow.Trigger.Path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := &scheduledFlowResponse{header: make(http.Header)}
	err := executeFlowHTTPAs(app, flow, w, req, actor)
	if err == nil || !strings.Contains(err.Error(), "template_unresolved: params.x") {
		t.Fatalf("scheduled run error = %v, want the unresolved reference", err)
	}
	if after := respondFailureCounts(t, app); after != before {
		t.Fatalf("a scheduled run that could not answer kept its writes: before=%v after=%v", before, after)
	}
}
