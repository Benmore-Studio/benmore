//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The mail and SMS senders logged every recipient in full ("EMAIL [not sent
// ...] to=", "SMS [sent ...] to="), for every message an app sends: sign-in
// codes, reset links, an app's own hooks and flows. Server logs are shipped
// and pasted into tickets; they name a recipient by reference now.
func TestDeliveryLogsNameRecipientsByReference(t *testing.T) {
	dir := t.TempDir()
	out := captureLog(t, func() {
		_ = SendEmailOpts(dir, EmailOpts{To: "private.person@corp.example, second.reader@corp.example", Subject: "Hello", BodyHTML: "<p>hello</p>"})
		_ = SendSMS(dir, "+1 415 555 0123", "hello")
		// The sixth message to one number in ten minutes is refused, and
		// that refusal was logged with the number too.
		for i := 0; i < 6; i++ {
			_ = SendSMS(dir, "+14155550188", "hello")
		}
	})
	for _, marker := range []string{"EMAIL [not sent", "SMS [not sent", "SMS BLOCKED"} {
		if !strings.Contains(out, marker) {
			t.Fatalf("the %q line was not logged at all:\n%s", marker, out)
		}
	}
	for _, private := range []string{"private.person", "second.reader", "corp.example", "4155550123", "4155550188"} {
		if strings.Contains(out, private) {
			t.Errorf("a delivery log line names the recipient (%s):\n%s", private, out)
		}
	}
	// Each recipient keeps its own stable reference, so lines about one
	// recipient can still be found together.
	for _, addr := range []string{"private.person@corp.example", "second.reader@corp.example", "+14155550123", "+14155550188"} {
		if !strings.Contains(out, logAddressRef(addr)) {
			t.Errorf("no line carries the reference of a recipient:\n%s", out)
		}
	}
}

// A hooks.yaml email or sms logs its outcome, and the lines carried the
// recipient the row supplied: a customer's address or phone number in the
// server log on every notification.
func TestHookDeliveryLogsNameRecipientsByReference(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	row := map[string]any{"email": "private.person@corp.example", "phone": "+14155550177", "name": "Ada"}
	out := captureLog(t, func() {
		_ = executeHookResult(app, Hook{Email: &EmailHook{To: "{{email}}", Subject: "Welcome", Body: "<p>Hi {{name}}</p>"}}, "leads", row)
		_ = executeHookResult(app, Hook{SMS: &SMSHook{To: "{{phone}}", Body: "Hi {{name}}"}}, "leads", row)
	})
	if !strings.Contains(out, "HOOK [email]") || !strings.Contains(out, "HOOK [sms]") {
		t.Fatalf("the hook delivery lines were not logged at all:\n%s", out)
	}
	for _, private := range []string{"private.person", "corp.example", "4155550177"} {
		if strings.Contains(out, private) {
			t.Errorf("a hook delivery log line names the recipient (%s):\n%s", private, out)
		}
	}
}
