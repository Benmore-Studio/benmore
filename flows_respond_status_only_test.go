//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A `run: respond` that is taken is the flow's answer, with or without a
// body: the caller gets the status the author wrote, the run ends there, and
// a `transaction: true` flow commits once. A respond with a status and no
// body (`with: { status: 204 }`, a 403 guard) used to write nothing and let
// the run continue: the steps after a refusal ran, and a flow that ended on
// one committed and answered 500 flow_no_response.

// respondShapeFlow is a request flow with one respond under test, in three
// places: gated by an inline `if:`, inside an `if:` block, and as the last
// step. `mark` tags the rows of one request.
func respondShapeFlow(place, with string, transaction bool) string {
	head := `on:
  request:
    method: POST
    path: /api/respond-shape
    auth: required
    transaction: ` + map[bool]string{true: "true", false: "false"}[transaction] + `

jobs:
  run:
    steps:
      - run: sql
        with:
          query: "INSERT INTO notes (user_id, title) VALUES (:user_id, :title)"
          params: { title: "before ${{ params.mark }}" }
`
	late := `      - run: sql
        with:
          query: "INSERT INTO notes (user_id, title) VALUES (:user_id, :title)"
          params: { title: "after ${{ params.mark }}" }
      - run: respond
        with: { status: 200, json: { reached_end: true } }
`
	switch place {
	case "inline_if":
		return head + `      - if: ${{ params.take || '' }} == 'yes'
        run: respond
        with: ` + with + "\n" + late
	case "if_block":
		return head + `      - if: ${{ params.take || '' }} == 'yes'
        steps:
          - run: respond
            with: ` + with + "\n" + late
	default: // last step
		return head + `      - run: respond
        with: ` + with + "\n"
	}
}

// respondShapeRun posts body to the flow and returns the recorded answer.
func respondShapeRun(t *testing.T, app *App, flow *Flow, sid string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sid)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	return rr
}

func respondShapeNotes(t *testing.T, app *App, title string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes WHERE title = ?`, title).Scan(&n); err != nil {
		t.Fatalf("count notes %q: %v", title, err)
	}
	return n
}

var respondShapes = []struct {
	name string
	with string
	// request fields the shape reads
	fields     map[string]any
	wantStatus int
	// wantBody is the exact body (trimmed); wantHeader a header the answer carries.
	wantBody   string
	wantHeader [2]string
}{
	{name: "status 200 only", with: `{ status: 200 }`, wantStatus: 200},
	{name: "status 201 only", with: `{ status: 201 }`, wantStatus: 201},
	{name: "status 204 only", with: `{ status: 204 }`, wantStatus: 204},
	{name: "status 403 only", with: `{ status: 403 }`, wantStatus: 403},
	{name: "quoted status only", with: `{ status: "202" }`, wantStatus: 202},
	{name: "templated status only", with: `{ status: "${{ params.code }}" }`, fields: map[string]any{"code": 409}, wantStatus: 409},
	{name: "status and empty json object", with: `{ status: 201, json: {} }`, wantStatus: 201, wantBody: `{}`},
	{name: "status and empty body object", with: `{ status: 201, body: {} }`, wantStatus: 201, wantBody: `{}`},
	{name: "status and empty json list", with: `{ status: 200, json: [] }`, wantStatus: 200, wantBody: `[]`},
	{name: "status and empty string body", with: `{ status: 201, body: "" }`, wantStatus: 201},
	{name: "status and empty string json", with: `{ status: 202, json: "" }`, wantStatus: 202},
	{name: "status and headers only", with: `{ status: 204, headers: { X-Order-State: "kept" } }`, wantStatus: 204, wantHeader: [2]string{"X-Order-State", "kept"}},
	{name: "status and content type only", with: `{ status: 200, content_type: "text/plain" }`, wantStatus: 200},
	{name: "status and a number body", with: `{ status: 200, body: 0 }`, wantStatus: 200, wantBody: `0`, wantHeader: [2]string{"Content-Type", "application/json"}},
	{name: "status and a boolean json", with: `{ status: 200, json: false }`, wantStatus: 200, wantBody: `false`, wantHeader: [2]string{"Content-Type", "application/json"}},
	{name: "status and a number body as text", with: `{ status: 200, body: 1.5, content_type: "text/plain" }`, wantStatus: 200, wantBody: `1.5`, wantHeader: [2]string{"Content-Type", "text/plain"}},
	{name: "status and a body", with: `{ status: 201, json: { ok: true } }`, wantStatus: 201, wantBody: `{"ok":true}`},
}

// Every shape, in every place, with and without a transaction: the authored
// status, the authored body (none when none was written), the write before
// the respond kept exactly once and the steps after it not run.
func TestTakenRespondAnswersItsStatusWithOrWithoutBody(t *testing.T) {
	for _, transaction := range []bool{true, false} {
		for _, place := range []string{"last_step", "inline_if", "if_block"} {
			for _, shape := range respondShapes {
				name := map[bool]string{true: "transaction", false: "no transaction"}[transaction] + "/" + place + "/" + shape.name
				t.Run(name, func(t *testing.T) {
					app, _ := auditApp(t)
					sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
					flows := notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow(place, shape.with, transaction))
					flow := &flows[0]
					if flow.Transaction != transaction {
						t.Fatalf("flow.Transaction = %v, want %v", flow.Transaction, transaction)
					}

					body := map[string]any{"mark": "taken", "take": "yes"}
					for k, v := range shape.fields {
						body[k] = v
					}
					rr := respondShapeRun(t, app, flow, sid, body)
					if rr.Code != shape.wantStatus {
						t.Errorf("answer = %d %q, want the authored status %d", rr.Code, rr.Body.String(), shape.wantStatus)
					}
					if got := strings.TrimSpace(rr.Body.String()); got != shape.wantBody {
						t.Errorf("body = %q, want %q", got, shape.wantBody)
					}
					if shape.wantHeader[0] != "" && rr.Header().Get(shape.wantHeader[0]) != shape.wantHeader[1] {
						t.Errorf("header %s = %q, want %q", shape.wantHeader[0], rr.Header().Get(shape.wantHeader[0]), shape.wantHeader[1])
					}
					if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
						t.Errorf("Cache-Control = %q on a signed-in caller's answer, want private, no-store", got)
					}
					if n := respondShapeNotes(t, app, "before taken"); n != 1 {
						t.Errorf("the write before the respond was kept %d times, want once", n)
					}
					if n := respondShapeNotes(t, app, "after taken"); n != 0 {
						t.Errorf("a step after the taken respond ran (%d rows): the respond did not end the run", n)
					}

					if place == "last_step" {
						return
					}
					// The same flow when the respond is not taken runs to its end.
					rr = respondShapeRun(t, app, flow, sid, map[string]any{"mark": "skipped"})
					if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"reached_end":true}` {
						t.Errorf("respond not taken: answer = %d %q, want 200 reached_end", rr.Code, rr.Body.String())
					}
					if before, after := respondShapeNotes(t, app, "before skipped"), respondShapeNotes(t, app, "after skipped"); before != 1 || after != 1 {
						t.Errorf("respond not taken: before=%d after=%d rows, want 1 and 1", before, after)
					}
				})
			}
		}
	}
}

// The rollback rule for a respond that cannot answer holds for a respond
// with no body: a status that reads a value the request did not send answers
// template_unresolved, and a transactional flow keeps nothing.
func TestStatusOnlyRespondThatCannotAnswerRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name, with, wantError string
		fields                map[string]any
	}{
		{name: "status with no value", with: `{ status: "${{ params.code }}" }`, wantError: "template_unresolved"},
		{name: "status that is no status", with: `{ status: "${{ params.code }}" }`, fields: map[string]any{"code": "created"}, wantError: "flow_no_response"},
		{name: "header with no value", with: `{ status: 204, headers: { X-Order-State: "${{ params.state }}" } }`, wantError: "template_unresolved"},
	} {
		for _, transaction := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: "/transaction", false: "/no transaction"}[transaction], func(t *testing.T) {
				app, _ := auditApp(t)
				sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
				flows := notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow("last_step", tc.with, transaction))
				body := map[string]any{"mark": "failed"}
				for k, v := range tc.fields {
					body[k] = v
				}
				rr := respondShapeRun(t, app, &flows[0], sid, body)
				var out map[string]any
				_ = json.Unmarshal(rr.Body.Bytes(), &out)
				if rr.Code != http.StatusInternalServerError || out["error"] != tc.wantError {
					t.Fatalf("answer = %d %q, want 500 %s", rr.Code, rr.Body.String(), tc.wantError)
				}
				// Without a transaction the earlier step's write is already durable.
				want := map[bool]int{true: 0, false: 1}[transaction]
				if n := respondShapeNotes(t, app, "before failed"); n != want {
					t.Errorf("rows kept = %d, want %d", n, want)
				}
			})
		}
	}
}

// A flow file in the older step form (`respond: { status: 204 }`) and a flow
// built in code reach the same step: the status is the answer there too.
func TestStatusOnlyRespondOnDirectSteps(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	for i, respond := range []*FlowRespond{
		{Status: http.StatusNoContent},
		{}, // no status reads as 200
		{Status: http.StatusAccepted, JSON: map[string]any{}},
	} {
		want := respond.Status
		if want == 0 {
			want = http.StatusOK
		}
		mustExec(t, app.DB, `DELETE FROM tx_response_rows`)
		flow := transactionalResponseFlow(
			FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
			FlowStep{Type: "if", Condition: "true", Steps: []FlowStep{{Type: "respond", Respond: respond}}},
			FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(2)`},
			respondOK(),
		)
		rr := runTransactionalResponse(app, flow)
		if rr.Code != want {
			t.Errorf("case %d: answer = %d %q, want %d", i, rr.Code, rr.Body.String(), want)
		}
		var count int
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 1 {
			t.Errorf("case %d: rows = %d err=%v, want the one row written before the respond", i, count, err)
		}
	}
}

// An on_error handler that answers with a status alone: the failed
// transaction stays rolled back and the caller gets the handler's status,
// not the step failure diagnostic.
func TestStatusOnlyRespondFromErrorHandler(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "sql", SQL: `INSERT INTO missing_table VALUES(1)`, OnError: []FlowStep{
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusConflict}},
		}},
		respondOK(),
	)
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusConflict || rr.Body.Len() != 0 {
		t.Fatalf("handler answer = %d %q, want 409 with no body", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rows after the handler answered = %d err=%v, want 0", count, err)
	}
}

// A scheduled run has no caller, but a respond ends it the same way: the
// steps after a taken status-only respond do not run, and an error status
// records the run as failed, as a respond with a body does.
func TestScheduledRunStopsAtStatusOnlyRespond(t *testing.T) {
	for _, tc := range []struct {
		with      string
		wantError string
	}{
		{with: `{ status: 204 }`},
		{with: `{ status: 403 }`, wantError: "scheduled flow returned HTTP 403"},
		{with: `{ status: 403, json: { error: forbidden } }`, wantError: "scheduled flow returned HTTP 403"},
	} {
		t.Run(tc.with, func(t *testing.T) {
			app, _ := auditApp(t)
			sid := createCrudScopeSession(t, app, "caller@example.com", "user", "", "")
			actor := GetSessionFromDB(app.DB, sid)
			if actor == nil {
				t.Fatal("missing session")
			}
			flows := notifyFlows(t, "flows/respond-shape.yaml", respondShapeFlow("inline_if", tc.with, true))
			flow := &flows[0]
			req := httptest.NewRequest(http.MethodPost, flow.Trigger.Path, strings.NewReader(`{"mark":"scheduled","take":"yes"}`))
			req.Header.Set("Content-Type", "application/json")
			w := &scheduledFlowResponse{header: make(http.Header)}
			err := executeFlowHTTPAs(app, flow, w, req, actor)
			if err == nil && w.status >= 400 {
				// executeScheduledFlow's own rule for the task's outcome.
				err = fmt.Errorf("scheduled flow returned HTTP %d", w.status)
			}
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || err.Error() != tc.wantError) {
				t.Fatalf("scheduled run error = %v, want %q", err, tc.wantError)
			}
			if before, after := respondShapeNotes(t, app, "before scheduled"), respondShapeNotes(t, app, "after scheduled"); before != 1 || after != 0 {
				t.Errorf("before=%d after=%d rows, want the write before the respond once and no step after it", before, after)
			}
		})
	}
}
