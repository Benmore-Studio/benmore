//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// `verify: X-Legacy-Signature` (the documented header-name form) and a typo
// such as `verify: strpe` ran a lenient generic verifier: a bearer secret
// (with any body, or none), X-Webhook-Secret, and a timestamp-less body HMAC
// in X-Signature / X-Webhook-Signature all passed, although the author
// named none of those headers; a real Stripe signature on the typo got 401
// (2026-10-29, build-first integrations app). The header form now checks
// the named header only.
func TestVerifyHeaderNameChecksOnlyTheNamedHeader(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	const secret = "legacy-webhook-secret"
	SetAppEnv(app.Dir, "LEGACY_SECRET", secret)
	mustExec(t, app.DB, `CREATE TABLE webhook_log (verify TEXT, event TEXT)`)
	flows := []Flow{}
	for _, name := range []string{"X-Legacy-Signature", "strpe"} {
		flows = append(flows, Flow{
			Name:    "hook_" + strings.ReplaceAll(name, "-", "_"),
			Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/hook/" + name},
			Verify:  name,
			Secret:  "{{env.LEGACY_SECRET}}",
			Steps: []FlowStep{
				{Type: "sql", SQL: "INSERT INTO webhook_log (verify, event) VALUES ('" + name + "', :event)"},
				{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
			},
		})
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	forged := []byte(`{"event":"forged"}`)
	send := func(path string, body []byte, headers map[string]string) int {
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr.Code
	}
	unnamed := map[string]struct {
		body    []byte
		headers map[string]string
	}{
		"bearer secret":            {forged, map[string]string{"Authorization": "Bearer " + secret}},
		"bearer secret, no body":   {nil, map[string]string{"Authorization": "Bearer " + secret}},
		"X-Webhook-Secret":         {forged, map[string]string{"X-Webhook-Secret": secret}},
		"X-Signature body HMAC":    {forged, map[string]string{"X-Signature": hmacHex(t, secret, forged)}},
		"X-Webhook-Signature HMAC": {forged, map[string]string{"X-Webhook-Signature": "sha256=" + hmacHex(t, secret, forged)}},
	}
	for _, name := range []string{"X-Legacy-Signature", "strpe"} {
		for label, c := range unnamed {
			if code := send("/api/hook/"+name, c.body, c.headers); code != http.StatusUnauthorized {
				t.Errorf("verify: %s, %s: status %d, want 401", name, label, code)
			}
		}
	}
	signed := []byte(`{"event":"real"}`)
	if code := send("/api/hook/X-Legacy-Signature", signed, map[string]string{"X-Legacy-Signature": hmacHex(t, secret, signed)}); code != http.StatusOK {
		t.Fatalf("a body HMAC in the named header: status %d, want 200", code)
	}
	if code := send("/api/hook/X-Legacy-Signature", signed, map[string]string{"X-Legacy-Signature": "sha256=" + hmacHex(t, secret, signed)}); code != http.StatusOK {
		t.Fatalf("a prefixed body HMAC in the named header: status %d, want 200", code)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	stripe := "t=" + ts + ",v1=" + hmacHex(t, secret, append([]byte(ts+"."), signed...))
	if code := send("/api/hook/strpe", signed, map[string]string{"Stripe-Signature": stripe}); code != http.StatusUnauthorized {
		t.Fatalf("a Stripe signature on the misspelled verifier: status %d, want 401", code)
	}
	var forgedRows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log WHERE event IS NULL OR event <> 'real'`).Scan(&forgedRows); err != nil || forgedRows != 0 {
		t.Fatalf("rows from requests the named header did not sign = %d err=%v, want 0", forgedRows, err)
	}
}

// The write gate and `benmore check` refuse a string verify value that is
// neither a provider nor a header name, with a did-you-mean; the loader
// keeps loading such a file and logs it.
func TestVerifyUnknownNameRefusedAtWrite(t *testing.T) {
	flowFile := func(verify string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/hook\n    verify: " + verify + "\n    secret: \"{{env.WEBHOOK_SECRET}}\"\njobs:\n  receive:\n    steps:\n      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
	}
	refused := map[string]string{
		"strpe":            "Did you mean `verify: stripe`",
		"githb":            "Did you mean `verify: github`",
		"Stripe-Signature": "Did you mean `verify: stripe`",
		"hmac_sha256_body": "verify: { recipe: hmac_sha256_body",
		"hmac":             "is not a known verifier",
		"Signature":        "header name containing a hyphen",
	}
	for verify, want := range refused {
		msg := ValidateOnWrite("flows/hook.yaml", flowFile(verify))
		if !strings.Contains(msg, want) {
			t.Errorf("verify: %s: write gate said %q, want it to contain %q", verify, msg, want)
		}
	}
	for _, verify := range []string{"stripe", "Stripe", "github_sha256", "shopify", "slack", "X-Legacy-Signature", "X-Hub-Signature-256"} {
		if msg := ValidateOnWrite("flows/hook.yaml", flowFile(verify)); msg != "" {
			t.Errorf("verify: %s was refused: %s", verify, msg)
		}
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "hook.yaml"), []byte(flowFile("strpe")), 0o644); err != nil {
		t.Fatal(err)
	}
	if !checkReportHas(runCheck(dir, "", false), filepath.Join("flows", "hook.yaml"), "Did you mean `verify: stripe`") {
		t.Fatalf("benmore check did not refuse verify: strpe")
	}
	loaded := LoadFlowsGHA(dir)
	if len(loaded) != 1 || loaded[0].Verify != "strpe" {
		t.Fatalf("a deployed file with an unknown verify name must still load: flows=%v", loaded)
	}
}
