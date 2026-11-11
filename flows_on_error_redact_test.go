//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An on_error handler's `${{ error }}` was the raw step error. A public flow
// whose `run: api` URL carried an env token (in its query or its path)
// answered an anonymous caller with that URL, token included, although
// step_error, the request log and the journal all redact it (2026-10-29,
// build-first integrations app).
func TestOnErrorErrorValueIsRedacted(t *testing.T) {
	const token = "echo-token-not-real-0123456789"
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "ECHO_TOKEN", token)
	flow := &Flow{Name: "lab_error", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/lab-error"},
		Steps: []FlowStep{
			{Name: "call", Type: "api",
				API: &FlowAPICall{Method: "GET", URL: "https://api.telegram.org/bot{{env.ECHO_TOKEN}}/status/404?token={{env.ECHO_TOKEN}}"},
				OnError: []FlowStep{
					{Type: "respond", Respond: &FlowRespond{Status: http.StatusBadGateway, JSON: map[string]any{"error": "{{error}}"}}},
				}},
		}}
	client := &http.Client{Transport: upstreamRejects{}}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/lab-error", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	executeFlowHTTPAsWithAPIClient(app, flow, w, r, nil, client)
	body := w.Body.String()
	if w.Code != http.StatusBadGateway {
		t.Fatalf("handler did not answer: %d %s", w.Code, body)
	}
	if strings.Contains(body, token) || strings.Contains(body, "echo-token-not-real") {
		t.Fatalf("anonymous answer carries the env token:\n%s", body)
	}
	if !strings.Contains(body, "api.telegram.org") || !strings.Contains(body, "[redacted]") || !strings.Contains(body, "returned 400") {
		t.Fatalf("the error lost its useful detail:\n%s", body)
	}
}

// The failure text can quote request input the failed step read, so
// `error` is request input for the sql_dynamic guard when the step read
// any; a step that read none leaves it untainted.
func TestOnErrorErrorValueCarriesRequestTaint(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	run := func(sql string) *FlowContext {
		ctx := &FlowContext{
			App: app, Request: httptest.NewRequest(http.MethodPost, "/api/x", nil), Writer: httptest.NewRecorder(),
			Data: map[string]any{"q": "abc"}, Params: map[string]string{"q": "abc"},
			RequestKeys: map[string]bool{"q": true}, Writes: newFlowWriteLog(),
		}
		executeSteps(ctx, []FlowStep{{Name: "boom", Type: "sql", SQL: sql,
			OnError: []FlowStep{{Name: "fmt", Type: "set", Set: map[string]string{"m": "{{error}}"}}}}})
		if ctx.Error == nil || ctx.Data["error"] == nil {
			t.Fatalf("%s: the step did not fail into its handler (err=%v)", sql, ctx.Error)
		}
		return ctx
	}
	tainted := run("SELECT * FROM no_such_table WHERE a = :q")
	if !tainted.RequestKeys["error"] || !tainted.RequestKeys["fmt.m"] {
		t.Fatalf("error from a step that read :q is not request input: %v", tainted.RequestKeys)
	}
	clean := run("SELECT * FROM no_such_table")
	if clean.RequestKeys["error"] {
		t.Fatalf("error from a step that read no request input was tainted: %v", clean.RequestKeys)
	}
}
