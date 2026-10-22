//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Keys inside email:/sms:/ws: that the hook structs don't bind were dropped,
// so the hook sent without them. Refused at write time in hooks.yaml and in
// workflows.yaml on_transition entries; the loader still accepts the file.
func TestHookNestedKeysRefusedAtWriteTime(t *testing.T) {
	bad := "on_insert:\n  contacts:\n    - email:\n        to: \"{{email}}\"\n        subject: Welcome\n        html: \"Hi\"\n"
	if msg := ValidateOnWrite("hooks.yaml", bad); !strings.Contains(msg, `unknown key "html" under `+"`email:`") {
		t.Errorf("email.html accepted: %q", msg)
	}
	if _, err := parseHooksYAML([]byte(bad)); err != nil {
		t.Errorf("loader must keep accepting the file: %v", err)
	}
	if msg := ValidateOnWrite("hooks.yaml", "on_insert:\n  contacts:\n    - sms:\n        to: \"{{phone}}\"\n        message: hi\n"); !strings.Contains(msg, "under `sms:`") {
		t.Errorf("sms.message accepted: %q", msg)
	}
	wf := "orders:\n  table: orders\n  field: status\n  transitions:\n    a:\n      b: {}\n  on_transition:\n    b:\n      - ws:\n          channel: x\n"
	if msg := ValidateOnWrite("workflows.yaml", wf); !strings.Contains(msg, "under `ws:`") {
		t.Errorf("ws.channel accepted in on_transition: %q", msg)
	}
	good := "on_insert:\n  contacts:\n    - email:\n        to: \"{{email}}\"\n        subject: Welcome\n        template: welcome\n    - email:\n        to: \"{{email}}\"\n        subject: Confirm\n        body: \"Hi {{name}}\"\n    - sms:\n        to: \"{{phone}}\"\n        body: hi\n    - ws:\n        room: r\n        payload: \"{}\"\n"
	if msg := ValidateOnWrite("hooks.yaml", good); msg != "" {
		t.Errorf("valid hooks refused: %s", msg)
	}
}

// An inline `body:` was dropped by the YAML hook loader, so the hook sent an
// empty email (the _platform subscription confirmation had no link).
func TestHookEmailInlineBodyIsSent(t *testing.T) {
	cfg, err := parseHooksYAML([]byte("on_insert:\n  contacts:\n    - email:\n        to: \"{{email}}\"\n        subject: Confirm\n        body: |\n          <p>Hi {{name}}</p>\n"))
	if err != nil || cfg == nil || len(cfg.OnInsert["contacts"]) != 1 || cfg.OnInsert["contacts"][0].Email == nil {
		t.Fatalf("parse: %+v %v", cfg, err)
	}
	got := hookEmailBody(cfg.OnInsert["contacts"][0].Email, map[string]any{"name": "Ada"}, t.TempDir())
	if !strings.Contains(got, "<p>Hi Ada</p>") {
		t.Fatalf("body = %q, want the interpolated inline body", got)
	}
}
