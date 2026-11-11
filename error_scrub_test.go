//go:build !cli

package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestErrorScrubEventAndEnvironmentRefresh(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	storeAppEnv(app.Dir, map[string]string{"CUSTOM": "upstream-value", "LONG": "upstream-value-long"})
	message := "upstream-value-long alice@example.com 123456789012 sk_live_" + strings.Repeat("0", 24)
	id := "0123456789abcdef0123456789abcdef"
	ev := errorEvent{Message: message, RequestID: id, Causes: []errorCause{{Message: message}}, Tags: map[string]string{"detail": message},
		Frames:      []errorFrame{{ContextLine: message, PreContext: []string{message}, PostContext: []string{message}}},
		Breadcrumbs: []breadcrumb{{Message: message, Data: map[string]any{"detail": message}}}, Extra: map[string]any{"detail": message}}
	scrubbed := scrubErrorEvent(app, ev)
	data, err := json.Marshal(scrubbed)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"upstream-value", "alice@example.com", "123456789012", "sk_live_"} {
		if strings.Contains(string(data), bad) {
			t.Fatalf("leaked %q: %s", bad, data)
		}
	}
	if scrubbed.RequestID != id {
		t.Fatal("correlation id was scrubbed")
	}
	if !strings.Contains(scrubbed.Message, "[email]") || !strings.Contains(scrubbed.Message, "[number]") || !strings.Contains(scrubbed.Message, "[redacted:env]") {
		t.Fatalf("missing scrub layer: %s", scrubbed.Message)
	}
	if ev.Frames[0].ContextLine != message || ev.Tags["detail"] != message {
		t.Fatal("scrubber mutated its caller's data")
	}
	storeAppEnv(app.Dir, map[string]string{"CUSTOM": "replacement-value"})
	if got := scrubForExport(app, "replacement-value"); got != "[redacted:env]" {
		t.Fatalf("stale environment cache: %s", got)
	}
}

// A failed job or cron run quotes its URL, and a token there is escaped: the
// export must redact every form the flow failure text does, plus the
// runtime-only credentials app code never reads (review F1/F2).
func TestErrorScrubEscapedAndRuntimeSecrets(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	token := "tok/en+abc=def123"
	storeAppEnv(app.Dir, map[string]string{"BOT_TOKEN": token})
	t.Setenv("BENMORE_SERVER_SECRET", "runtime-only-server-secret")
	for _, text := range []string{
		"post https://api.example/bot" + url.PathEscape(token) + "/send: EOF",
		"post https://api.example/send?token=" + url.QueryEscape(token) + ": EOF",
		"post https://api.example/bot" + token + "/send: EOF",
		"signing with runtime-only-server-secret failed",
	} {
		got := scrubErrorEvent(app, errorEvent{Message: text}).Message
		for _, bad := range []string{"tok/en", "tok%2Fen", "def123", "runtime-only-server-secret"} {
			if strings.Contains(got, bad) {
				t.Fatalf("%q exported as %q", text, got)
			}
		}
	}
	// The job path reports jobErrorText, so a cause is never exported raw.
	if got := jobErrorText(app, "Get \"https://api.example/bot"+url.PathEscape(token)+"/send\": EOF"); strings.Contains(got, "tok%2Fen") {
		t.Fatalf("job error text kept the escaped token: %s", got)
	}
}

func TestErrorReportingEnvValidation(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		valid      bool
	}{
		{"SENTRY_DSN", "https://public@93.184.216.34/1", true},
		{"SENTRY_DSN", "http://public@93.184.216.34/1", false},
		{"SENTRY_DSN", "https://privatekey@127.0.0.1/1", false},
		{"SENTRY_DSN", "https://privatekey@10.0.0.1/1", false},
		{"SENTRY_DSN", "https://privatekey:password@93.184.216.34/1", false},
		{"ERROR_SLACK_WEBHOOK", "https://93.184.216.34/services/T/B/x", true},
		{"ERROR_SLACK_WEBHOOK", "http://93.184.216.34/services/T/B/x", false},
		{"ERROR_SLACK_WEBHOOK", "https://127.0.0.1/services/T/B/x", false},
		{"ERROR_SLACK_WEBHOOK", "https://10.0.0.1/hook", false},
		{"ERROR_SLACK_WEBHOOK", "https://0x7f000001/hook", false},
		{"SENTRY_MIN_LEVEL", "warning", true}, {"SENTRY_MIN_LEVEL", "error", true}, {"SENTRY_MIN_LEVEL", "debug", false},
		{"UNRELATED", "anything", true},
	} {
		err := validateAppEnvValue(tc.key, tc.value)
		if (err == nil) != tc.valid {
			t.Fatalf("%s validity=%v err=%v", tc.key, tc.valid, err)
		}
		if err != nil && strings.Contains(err.Error(), "privatekey") {
			t.Fatal("DSN key leaked")
		}
	}
}
