//go:build !cli

package main

// Tests for the `run: sms` flow step (flows_gha.go registration +
// sms.go executor). The hooks.yaml side lives in hooks_sms_test.go.
//
// Background: api(at:"sms") documented `run: sms` before the step
// existed. A flow authored against those docs parsed to an unknown
// run-type and never sent. These tests pin the surface so the docs and
// the engine can't drift apart again.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const smsFlowYAML = `on:
  request:
    method: POST
    path: /api/alert
jobs:
  main:
    steps:
      - id: msg
        run: sms
        with:
          to: "+15551234567"
          body: "Your code is 482913"
      - run: respond
        with:
          json:
            sent_to: "${{ steps.msg.outputs.to }}"
`

func loadOneFlow(t *testing.T, dir, body string) Flow {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	return flows[0]
}

func TestSMSStepParsesAndRegisters(t *testing.T) {
	f := loadOneFlow(t, t.TempDir(), smsFlowYAML)
	st := f.Steps[0]

	if st.Type != "sms" {
		t.Fatalf("step Type = %q, want %q", st.Type, "sms")
	}
	if st.SMS == nil {
		t.Fatal("step.SMS not populated from with:")
	}
	if st.SMS.To != "+15551234567" {
		t.Errorf("To = %q, want +15551234567", st.SMS.To)
	}
	if st.SMS.Body != "Your code is 482913" {
		t.Errorf("Body = %q, want %q", st.SMS.Body, "Your code is 482913")
	}

	// Parser<->validator single-source contract (flowRunTypes): the
	// write-time validator must accept what the parser runs. Before
	// "sms" was in flowRunTypes this rejected the flow as an unknown
	// run type while the docs told authors to write it.
	if msg := validateFlowsYAML(smsFlowYAML); msg != "" {
		t.Errorf("validateFlowsYAML rejected a valid run: sms flow: %s", msg)
	}
}

// `text:` is accepted as an alias for `body:`, mirroring run: email's
// html/body generosity. Agents reach for both spellings.
func TestSMSStepTextAlias(t *testing.T) {
	f := loadOneFlow(t, t.TempDir(), `on:
  request:
    method: POST
    path: /api/alert
jobs:
  main:
    steps:
      - run: sms
        with:
          to: "+15551234567"
          text: "via the text alias"
`)
	st := f.Steps[0]
	if st.SMS == nil || st.SMS.Body != "via the text alias" {
		t.Fatalf("text: alias did not fill Body, got %+v", st.SMS)
	}
}

// An unresolved ${{ }} ref must fail loudly. Sending to an empty
// recipient - or reporting success while sending nothing - is the exact
// failure this step was added to fix.
func TestSMSStepEmptyToErrors(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{Type: "sms", SMS: &FlowSMS{To: "", Body: "hi"}}

	err := execStepSMS(ctx, step)
	if err == nil {
		t.Fatal("execStepSMS accepted an empty `to:` - it must error, not silently skip")
	}
	if !strings.Contains(err.Error(), "to:") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestSMSStepEmptyBodyErrors(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{Type: "sms", SMS: &FlowSMS{To: "+15551234567", Body: ""}}

	err := execStepSMS(ctx, step)
	if err == nil {
		t.Fatal("execStepSMS accepted an empty `body:` - it must error, not send an empty text")
	}
	if !strings.Contains(err.Error(), "body:") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

// End-to-end through the executor using the webhook provider as a fake.
// The injected transport captures delivery without weakening the SSRF guard.
func TestSMSStepExecutesViaWebhookProvider(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	type captured struct {
		To   string `json:"to"`
		Body string `json:"body"`
	}
	got := make(chan captured, 1)
	providerURL := testSMSWebhook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var c captured
		_ = json.Unmarshal(raw, &c)
		got <- c
		w.WriteHeader(200)
	}))

	SetAppEnv(app.Dir, "SMS_PROVIDER", "webhook")
	SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", providerURL)

	ctx := &FlowContext{
		App:     app,
		Request: httptest.NewRequest("POST", "/api/alert", nil),
		Writer:  httptest.NewRecorder(),
		Data:    map[string]any{"otp": map[string]any{"code": "482913"}},
		Params:  map[string]string{},
	}
	step := &FlowStep{
		Type: "sms",
		Name: "msg",
		SMS:  &FlowSMS{To: "+15551234567", Body: "Your code is {{otp.code}}"},
	}

	if err := execStepSMS(ctx, step); err != nil {
		t.Fatalf("execStepSMS: %v", err)
	}

	select {
	case c := <-got:
		if c.To != "+15551234567" {
			t.Errorf("provider received to=%q, want +15551234567", c.To)
		}
		if !strings.Contains(c.Body, "482913") {
			t.Errorf("provider received body=%q - the ${{ }} ref did not interpolate", c.Body)
		}
	default:
		t.Fatal("provider was never called - the step reported success without sending")
	}

	// Downstream steps must be able to reference the recipient.
	if ctx.Data["msg.to"] != "+15551234567" {
		t.Errorf("steps.msg.outputs.to not published, Data = %v", ctx.Data)
	}
}

func testSMSWebhook(t *testing.T, handler http.Handler) string {
	t.Helper()
	old := smsHTTPClient.Transport
	t.Cleanup(func() { smsHTTPClient.Transport = old })
	smsHTTPClient.Transport = auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Result(), nil
	})
	return "https://93.184.216.34/synthetic-sms"
}
