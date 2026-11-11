//go:build !cli

package main

import (
	"encoding/json"
	"testing"
)

// Every after-hook email goes through the job queue. The payload carried the
// recipient, subject and template but not an inline `body:`, so a hook email
// written with `body:` went out empty (or the provider refused it).
func TestHookEmailInlineBodySurvivesTheJobQueue(t *testing.T) {
	hook := Hook{Email: &EmailHook{To: "{{email}}", Subject: "Thanks", Body: "<p>Thanks {{name}}</p>"}}
	payload := hookJobPayload(hook, "signups", map[string]any{"email": "a@example.com"})
	// The payload is stored as JSON; decode it the way the worker does.
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	hookData, _ := stored["_hook"].(map[string]any)
	got := hookFromJobPayload(hookData)
	if got.Email == nil || got.Email.Body != hook.Email.Body || got.Email.Subject != "Thanks" {
		t.Fatalf("hook email after the queue = %+v, want the inline body kept", got.Email)
	}
}
