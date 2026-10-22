//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type flowPanicRoundTripper struct{}

func (flowPanicRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("transport panic")
}

func transactionalResponseApp(t *testing.T) (*App, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE tx_response_rows(id INTEGER PRIMARY KEY)`)
	return app, cleanup
}

func transactionalResponseFlow(steps ...FlowStep) *Flow {
	return &Flow{Name: "tx-response", Transaction: true,
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/tx-response"}, Steps: steps}
}

func runTransactionalResponse(app *App, flow *Flow) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, httptest.NewRequest(http.MethodPost, flow.Trigger.Path, nil))
	return rr
}

func TestTransactionalFlowResponseWaitsForCommitAndPreservesOutput(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()

	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusCreated, JSON: map[string]any{"created": true}}},
	)
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusCreated || rr.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(rr.Body.String()) != `{"created":true}` {
		t.Fatalf("response = %d %v %q", rr.Code, rr.Header(), rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed rows=%d err=%v", count, err)
	}

	redirect := transactionalResponseFlow(
		FlowStep{Type: "redirect", Redirect: "/account"},
	)
	rr = runTransactionalResponse(app, redirect)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/account" {
		t.Fatalf("redirect response = %d %v", rr.Code, rr.Header())
	}
}

func TestTransactionalFlowCommitFailureDiscardsResponseAndRollsBack(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	mustExec(t, app.DB, `PRAGMA foreign_keys=ON`)
	mustExec(t, app.DB, `CREATE TABLE tx_parent(id INTEGER PRIMARY KEY)`)
	mustExec(t, app.DB, `CREATE TABLE tx_child(parent_id INTEGER REFERENCES tx_parent(id) DEFERRABLE INITIALLY DEFERRED)`)

	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_child VALUES(999)`},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"success": true}}},
	)
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("commit failure leaked response: %d %q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback rows=%d err=%v", count, err)
	}
}

func TestTransactionalFlowPanicRollsBackWithoutAnnouncement(t *testing.T) {
	app := flowRealtimeApp(t)
	sid := createCrudScopeSession(t, app, "panic@example.com", "user", "", "")
	sub := subscribeFlowRealtime(t, app, sid)
	flow := &Flow{
		Name: "tx-panic", Auth: "required", Transaction: true,
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/tx-panic"},
		Steps: []FlowStep{
			{Type: "sql", SQL: `INSERT INTO notes (user_id, title) VALUES (:user_id, 'panic-rolled-back')`},
			{Type: "api", API: &FlowAPICall{URL: "https://8.8.8.8/"}},
			respondOK(),
		},
	}
	req := httptest.NewRequest(http.MethodPost, flow.Trigger.Path, nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	rr := httptest.NewRecorder()
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		_ = executeFlowHTTPAsWithAPIClient(app, flow, rr, req, nil, &http.Client{Transport: flowPanicRoundTripper{}})
	}()
	if !panicked {
		t.Fatal("API transport did not panic")
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes WHERE title='panic-rolled-back'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("panic left rows=%d err=%v", count, err)
	}
	if sse, ws := sub.drain(); len(sse) != 0 || len(ws) != 0 {
		t.Fatalf("panic announced uncommitted writes: sse=%v ws=%v", sse, ws)
	}
}

func TestTransactionalFlowOversizedResponseRollsBackEvenWhenWriteErrorIsIgnored(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, Body: strings.Repeat("x", flowResponseBufferLimit+1)}},
	)
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "xxxx") {
		t.Fatalf("oversized response = %d %q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("oversized response committed rows=%d err=%v", count, err)
	}
}

func TestTransactionalFlowBeginFailureSetsHTTPError(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	flow := transactionalResponseFlow(respondOK())
	rr := httptest.NewRecorder()
	err := executeFlowHTTP(app, flow, rr, httptest.NewRequest(http.MethodPost, flow.Trigger.Path, nil))
	if err == nil || rr.Code != http.StatusInternalServerError {
		t.Fatalf("begin failure err=%v response=%d %q", err, rr.Code, rr.Body.String())
	}
}

func TestTransactionalFlowWithoutRespondKeepsDiagnostic500(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`})
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"error":"flow_no_response"`) {
		t.Fatalf("missing-response diagnostic = %d %q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("missing-response committed rows=%d err=%v", count, err)
	}
}

func TestTransactionalFlowRejectsNestedStreamingBeforeEffects(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	flow := transactionalResponseFlow(
		FlowStep{Type: "sql", SQL: `INSERT INTO tx_response_rows VALUES(1)`},
		FlowStep{Type: "if", Steps: []FlowStep{{Type: "for_each", Steps: []FlowStep{{Type: "serve_file"}}}}},
	)
	if err := flowValidateTransactionalResponse(flow); err == nil || !strings.Contains(err.Error(), "serve_file") {
		t.Fatalf("nested serve_file validation error = %v", err)
	}
	rr := runTransactionalResponse(app, flow)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("invalid flow status = %d body=%q", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM tx_response_rows`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid flow caused effects: rows=%d err=%v", count, err)
	}
}

func TestFlowWriteValidationRejectsNestedStreamingInTransactionalGHA(t *testing.T) {
	source := `on:
  request:
    method: POST
    path: /api/streaming-transaction
    transaction: true
jobs:
  run:
    steps:
      - if: true
        steps:
          - run: serve_file
            with: { path: uploads/report.pdf }
`
	if msg := validateFlowsYAML(source); !strings.Contains(msg, "serve_file") {
		t.Fatalf("transactional GHA validation error = %q", msg)
	}
}

func TestFlowResponseBufferPreservesMultipleCookies(t *testing.T) {
	b := newFlowResponseBuffer()
	b.Header().Add("Set-Cookie", "first=1")
	b.Header().Add("Set-Cookie", "second=2")
	if _, err := b.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	b.flushTo(rr)
	if got := rr.Header().Values("Set-Cookie"); len(got) != 2 || got[0] != "first=1" || got[1] != "second=2" || rr.Body.String() != "body" {
		t.Fatalf("flushed cookies=%v body=%q", got, rr.Body.String())
	}
}
