//go:build !cli

package main

import (
	"reflect"
	"strings"
	"testing"
)

func verifyMapFlow(extra string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/inbound\n    verify:\n      recipe: hmac_timestamp_dot_body\n      header: X-Sig\n      timestamp_header: X-Ts\n      secret: \"${{ env.HOOK_SECRET }}\"\n" + extra +
		"jobs:\n  inbound:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
}

// A `verify:` map key the parser does not read (a misspelled skew_seconds,
// an invented algorithm:) parsed clean and did nothing. The write gate and
// `benmore check` refuse it; the loader still accepts the file.
func TestFlowWriteGateRefusesUnknownVerifyKeys(t *testing.T) {
	for extra, hint := range map[string]string{
		"      skew: 60\n":            "skew_seconds",
		"      tolerance: 60\n":       "skew_seconds",
		"      algorithm: sha256\n":   "recipe",
		"      timestamp-header: X\n": "timestamp_header",
	} {
		msg := ValidateOnWrite("flows/inbound.yaml", verifyMapFlow(extra))
		if !strings.Contains(msg, "unknown key") || !strings.Contains(msg, "on.request.verify") || !strings.Contains(msg, hint) {
			t.Errorf("verify key %q: want an unknown-key refusal naming %s, got %q", strings.TrimSpace(extra), hint, msg)
		}
		if _, err := parseGHAFlowFile("flows/inbound.yaml", []byte(verifyMapFlow(extra))); err != nil {
			t.Errorf("verify key %q: the loader must keep accepting the file: %v", strings.TrimSpace(extra), err)
		}
	}
	if msg := ValidateOnWrite("flows/inbound.yaml", verifyMapFlow("      skew_seconds: 60\n")); msg != "" {
		t.Fatalf("valid verify map refused: %s", msg)
	}
	// The string form is unchanged.
	str := "on:\n  request:\n    method: POST\n    path: /api/inbound\n    verify: stripe\n    secret: \"${{ env.S }}\"\njobs:\n  inbound:\n    steps:\n      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
	if msg := ValidateOnWrite("flows/inbound.yaml", str); strings.Contains(msg, "unknown key") {
		t.Fatalf("string verify refused: %s", msg)
	}
}

// flowVerifyKeys is exactly the set parseVerifyMap reads: every key sets a
// field, and every field is set by some key.
func TestFlowVerifyKeysMatchParser(t *testing.T) {
	all := map[string]any{}
	for k := range flowVerifyKeys {
		switch k {
		case "skew_seconds":
			all[k] = 30
		default:
			all[k] = "v-" + k
		}
	}
	got := reflect.ValueOf(*parseVerifyMap(all))
	for i := range got.NumField() {
		if got.Type().Field(i).IsExported() && got.Field(i).IsZero() {
			t.Errorf("FlowVerify.%s is set by no key in flowVerifyKeys", got.Type().Field(i).Name)
		}
	}
	for k := range flowVerifyKeys {
		one := map[string]any{k: all[k]}
		if reflect.ValueOf(*parseVerifyMap(one)).IsZero() {
			t.Errorf("flowVerifyKeys lists %q but parseVerifyMap ignores it", k)
		}
	}
}
