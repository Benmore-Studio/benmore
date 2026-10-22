//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlowOnErrorHandlerCanRespond(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE handled (id INTEGER PRIMARY KEY)`)
	flow := `on:
  request:
    method: POST
    path: /api/error-response
jobs:
  main:
    steps:
      - id: boom
        run: sql
        with:
          query: "SELECT * FROM no_such_table"
        on_error:
          - run: sql
            with:
              query: "INSERT INTO handled (id) VALUES (1)"
          - run: respond
            with:
              status: 202
              body: { handled: true }
      - run: sql
        with:
          query: "INSERT INTO handled (id) VALUES (2)"
`
	rr := runProbeGHAFlow(t, app, flow, `{}`)
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM handled`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("handler must persist its write and stop the parent (rows=%d err=%v)", n, err)
	}
	if rr.Code != http.StatusAccepted || strings.TrimSpace(rr.Body.String()) != `{"handled":true}` {
		t.Fatalf("handler response = %d %s", rr.Code, rr.Body.String())
	}
}

func TestFlowOnErrorNestedResponseStopsOuterHandlersAndRetries(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for _, kind := range []string{"if", "for_each", "handler"} {
		t.Run(kind, func(t *testing.T) {
			response := FlowStep{Type: "respond", Respond: &FlowRespond{Status: 202, Body: "handled"}}
			inner := errorResponseStep(response)
			var step FlowStep
			if kind == "handler" {
				step = errorResponseStep(inner)
			} else {
				step = FlowStep{Type: kind, Condition: "true", ForEach: "items", Retry: 2,
					Steps: []FlowStep{inner}, OnError: []FlowStep{{Type: "set", Set: map[string]string{"outer_ran": "yes"}}}}
			}
			rr := httptest.NewRecorder()
			ctx := &FlowContext{App: app, Writer: rr, Request: httptest.NewRequest("GET", "/", nil),
				Data: map[string]any{"items": []map[string]any{{"id": 1}, {"id": 2}}}, Params: map[string]string{}}
			executeSteps(ctx, []FlowStep{step, {Type: "set", Set: map[string]string{"after_ran": "yes"}}})
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "original_failure") || !ctx.Stopped ||
				rr.Code != 202 || strings.TrimSpace(rr.Body.String()) != "handled" || ctx.Data["outer_ran"] != nil || ctx.Data["after_ran"] != nil {
				t.Fatalf("nested response did not stop execution: ctx=%+v response=%d %s", ctx, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestFlowOnErrorKeepsHTTPAndSecurityContext(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads", "private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "private", "handler.txt"), []byte("handler file"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, handler := range map[string][]FlowStep{
		"private response":         {{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "private", Headers: []FlowRespondHeader{{Name: "Cache-Control", Value: "public, max-age=3600"}}}}},
		"same-origin redirect":     {{Type: "redirect", Redirect: "{{next}}"}},
		"local file response":      {{Type: "serve_file", ServeFile: &FlowServeFile{Path: "uploads/private/handler.txt"}}},
		"null parameter":           {{Name: "read", Type: "sql", SQL: "SELECT :value IS NULL AS is_null"}, {Type: "respond", Respond: &FlowRespond{Body: "{{read.is_null}}"}}},
		"request taint":            {{Type: "sql_dynamic", SQL: "SELECT '{{request_sql}}'"}, respondOK()},
		"secret host guard":        {{Type: "api", API: &FlowAPICall{URL: "{{url}}", Method: "POST", JSON: map[string]any{"token": "{{secret}}"}}}, respondOK()},
		"authored host provenance": {{Type: "api", API: &FlowAPICall{URL: "{{url}}", Method: "POST", JSON: map[string]any{"token": "{{secret}}"}}}, respondOK()},
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			requests := 0
			ctx := &FlowContext{App: app, Request: httptest.NewRequest("GET", "https://example.com/failure", nil), Writer: rr,
				privateResponse: true, Data: map[string]any{"next": "/complete", "request_sql": "synthetic", "secret": "fixture", "url": "https://8.8.8.8/"},
				Params: map[string]string{"value": ""}, NullParams: map[string]bool{"value": true},
				RequestKeys: map[string]bool{"request_sql": true, "url": true}, SecretKeys: map[string]bool{"secret": true},
				apiClient: &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
					requests++
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
				})},
			}
			if name == "authored host provenance" {
				ctx.requestStepSources = map[string][]string{"url": {"SELECT 'https://8.8.8.8/' AS url"}}
			}
			executeSteps(ctx, []FlowStep{errorResponseStep(handler...)})
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "original_failure") {
				t.Fatalf("lost original failure: %v", ctx.Error)
			}
			switch name {
			case "private response":
				if rr.Code != 200 || !ctx.Stopped || rr.Header().Get("Cache-Control") != "private, no-store" {
					t.Fatalf("private response = %d %v", rr.Code, rr.Header())
				}
			case "same-origin redirect":
				if rr.Code != 303 || !ctx.Stopped || rr.Header().Get("Location") != "/complete" {
					t.Fatalf("redirect = %d %v", rr.Code, rr.Header())
				}
			case "local file response":
				if rr.Code != 200 || !ctx.Stopped || rr.Body.String() != "handler file" {
					t.Fatalf("file response = %d %s", rr.Code, rr.Body.String())
				}
			case "null parameter":
				if !ctx.Stopped || strings.TrimSpace(rr.Body.String()) != "1" {
					t.Fatalf("null SQL binding = %s", rr.Body.String())
				}
			case "authored host provenance":
				if !ctx.Stopped || rr.Code != 200 || requests != 1 {
					t.Fatalf("authored host rejected: stopped=%t requests=%d response=%d %s", ctx.Stopped, requests, rr.Code, rr.Body.String())
				}
			default:
				if ctx.Stopped || rr.Body.Len() != 0 || requests != 0 {
					t.Fatalf("handler escaped its security guard: stopped=%t requests=%d body=%s", ctx.Stopped, requests, rr.Body.String())
				}
			}
		})
	}
}

func TestFlowOnErrorParallelJoinCanRespond(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE parallel_handled (id INTEGER)")
	flow := &Flow{Name: "parallel-handler", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/parallel-handler"}, Steps: []FlowStep{{
		Type: "parallel", Steps: []FlowStep{errorResponseStep(), {Type: "sql", SQL: "INSERT INTO parallel_handled VALUES(1)"}},
		OnError: []FlowStep{{Type: "respond", Respond: &FlowRespond{Status: 202, Body: "joined"}}},
	}}}
	rr := httptest.NewRecorder()
	err := executeFlowHTTP(app, flow, rr, httptest.NewRequest("GET", flow.Trigger.Path, nil))
	if err == nil || !strings.Contains(err.Error(), "original_failure") || rr.Code != 202 || strings.TrimSpace(rr.Body.String()) != "joined" {
		t.Fatalf("parallel handler = %v %d %s", err, rr.Code, rr.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM parallel_handled").Scan(&n); err != nil || n != 1 {
		t.Fatalf("sibling did not finish: n=%d err=%v", n, err)
	}
}

func errorResponseStep(handler ...FlowStep) FlowStep {
	return FlowStep{Name: "original", Type: "sql", SQL: "SELECT * FROM original_failure", OnError: handler}
}

func TestFlowOnErrorPreservesOriginalFailureWithoutResponse(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for name, handler := range map[string][]FlowStep{
		"no handler":                nil,
		"handler only writes state": {{Type: "set", Set: map[string]string{"handled": "yes"}}},
		"handler fails":             {{Type: "sql", SQL: "SELECT * FROM handler_failure"}, respondOK()},
		"invalid response":          {{Type: "respond", Respond: &FlowRespond{Status: 99, Body: "unexpected"}}},
	} {
		t.Run(name, func(t *testing.T) {
			flow := &Flow{Name: "error-response", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/error-response"}, Steps: []FlowStep{errorResponseStep(handler...), respondOK()}}
			rr := httptest.NewRecorder()
			err := executeFlowHTTP(app, flow, rr, httptest.NewRequest("GET", flow.Trigger.Path, nil))
			if err == nil || !strings.Contains(err.Error(), "original_failure") || rr.Code != 500 || strings.Contains(rr.Body.String(), "unexpected") {
				t.Fatalf("original failure lost: err=%v response=%d %s", err, rr.Code, rr.Body.String())
			}
		})
	}
}

type errorResponseRollbackWriter struct {
	*httptest.ResponseRecorder
	check func()
}

func (w *errorResponseRollbackWriter) WriteHeader(status int) {
	w.check()
	w.ResponseRecorder.WriteHeader(status)
}

func TestFlowOnErrorTransactionalResponseFollowsRollback(t *testing.T) {
	app, cleanup := transactionalResponseApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	for _, large := range []bool{false, true} {
		t.Run(map[bool]string{false: "response", true: "oversized response"}[large], func(t *testing.T) {
			body := "handled"
			if large {
				body = strings.Repeat("x", flowResponseBufferLimit+1)
			}
			flow := transactionalResponseFlow(
				FlowStep{Type: "sql", SQL: "INSERT INTO tx_response_rows VALUES(1)"},
				errorResponseStep(FlowStep{Type: "respond", Respond: &FlowRespond{Status: 409, Body: body}}),
			)
			rr := httptest.NewRecorder()
			writes := 0
			writer := &errorResponseRollbackWriter{rr, func() {
				writes++
				// A live transaction consumes the only connection; check the
				// pool first so an early response fails instead of deadlocking.
				if app.DB.Stats().InUse != 0 {
					t.Fatal("response sent before transaction released")
				}
				var n int
				if err := app.DB.QueryRow("SELECT COUNT(*) FROM tx_response_rows").Scan(&n); err != nil || n != 0 {
					t.Fatalf("response preceded rollback: rows=%d err=%v", n, err)
				}
			}}
			err := executeFlowHTTP(app, flow, writer, httptest.NewRequest("POST", flow.Trigger.Path, nil))
			if err == nil || !strings.Contains(err.Error(), "original_failure") || writes == 0 {
				t.Fatalf("original failure lost: err=%v writes=%d", err, writes)
			}
			if large {
				if rr.Code != 500 || strings.Contains(rr.Body.String(), "xxxx") {
					t.Fatalf("oversized handler response escaped: %d %s", rr.Code, rr.Body.String())
				}
			} else if rr.Code != 409 || strings.TrimSpace(rr.Body.String()) != "handled" {
				t.Fatalf("handler response after rollback = %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}
