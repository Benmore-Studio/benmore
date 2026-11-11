//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type upstreamRejects struct{}

func (upstreamRejects) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 400, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"ok":false,"description":"Bad Request: chat not found"}`)), Request: r}, nil
}

// An app admin (the app's own role, not a platform member) sees a failed
// step's error since 2.7.309. An api URL that carries a secret in its path -
// a Telegram bot token, a Slack or Discord webhook path - reached that admin
// in step_error and the request log, because the redaction only knew query
// strings and key shapes (round-2 review, 2026-10-23).
func TestFlowFailureRedactsEnvValuesInURLPaths(t *testing.T) {
	const token = "000000000:TEST-not-a-real-bot-token-0000000000"
	f := newServerErrorFixture(t, false)
	SetAppEnv(f.app.Dir, "TG_TOKEN", token)
	adminID, adminSID := gateUser(t, f.app, "admin@example.com")
	mustExec(t, f.app.DB, "UPDATE _benmore_users SET role = 'admin' WHERE id = "+strconv.FormatInt(adminID, 10))
	flow := &Flow{Name: "notify", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/notify"},
		Steps: []FlowStep{
			{Name: "send", Type: "api", API: &FlowAPICall{Method: "POST", URL: "https://api.telegram.org/bot{{env.TG_TOKEN}}/sendMessage", Body: `{"chat_id":"{{chat}}"}`}},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		}}
	client := &http.Client{Transport: upstreamRejects{}}
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		executeFlowHTTPAsWithAPIClient(f.app, flow, w, r, nil, client)
	}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/notify", strings.NewReader(`{"chat":"nope"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+adminSID)
	w := httptest.NewRecorder()
	logged := captureLog(t, func() { f.logged.ServeHTTP(w, r) })
	body := w.Body.String()
	if w.Code != http.StatusInternalServerError || !strings.Contains(body, `"step_error"`) {
		t.Fatalf("admin did not get the step error: %d %s", w.Code, body)
	}
	for where, text := range map[string]string{"answer": body, "journal": logged} {
		if strings.Contains(text, "TEST-not-a-real-bot-token-0000000000") {
			t.Errorf("%s carries the env token:\n%s", where, text)
		}
	}
	if !strings.Contains(body, "[redacted]") || !strings.Contains(body, "api.telegram.org") {
		t.Errorf("answer lost its useful detail:\n%s", body)
	}
}

func TestRedactFlowSecretValuesCoversEscapedFormsAndDerivedValues(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "HOOK_PATH", "T000/B000/xyzSECRETxyz")
	SetAppEnv(app.Dir, "SHORT", "prod")
	ctx := &FlowContext{App: app, Data: map[string]any{"signed": "derived-signature-value"}, SecretKeys: map[string]bool{"signed": true}}
	text := "post https://hooks.slack.com/services/T000%2FB000%2FxyzSECRETxyz failed; sig=derived-signature-value; env=prod"
	got := redactFlowSecretValues(ctx, text)
	for _, leaked := range []string{"xyzSECRETxyz", "derived-signature-value"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("%q survived: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "env=prod") {
		t.Fatalf("a short ordinary value was redacted: %s", got)
	}
}
