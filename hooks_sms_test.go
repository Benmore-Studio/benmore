//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// notifyHubHooksYAML is a byte-for-byte copy of the hooks.yaml shipped by the
// deployed notify-hub app. It is reproduced here rather than referenced so the
// test pins the exact shape a real app relies on: if the parser stops honouring
// it, this fails regardless of what that repo does later.
const notifyHubHooksYAML = `# SMS delivery: /api/notify/sms inserts the row; this async hook sends via the
# platform SMS service (shared toll-free number) once carrier approval clears.
on_insert:
  messages:
    - sms:
        to: "{{recipient}}"
        body: "{{sms_body}}"
      when: "channel = 'sms'"
`

func writeHooks(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hooks.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write hooks.yaml: %v", err)
	}
	return dir
}

// TestHookSMSFromNotifyHubYAML is the regression test for the silent no-op.
//
// Before the SMS field existed on HookEntryYAML, yaml.v3 dropped the `sms:` key
// (no KnownFields), so this entry parsed to a Hook carrying only When — an
// action-less hook that fired, evaluated its condition, and did nothing. The
// app's API answered {"ok":true,"status":"queued"} for a text that never sent.
func TestHookSMSFromNotifyHubYAML(t *testing.T) {
	cfg := LoadHooksYAML(writeHooks(t, notifyHubHooksYAML))
	if cfg == nil {
		t.Fatal("LoadHooksYAML returned nil for valid hooks.yaml")
	}

	hooks := cfg.OnInsert["messages"]
	if len(hooks) != 1 {
		t.Fatalf("on_insert.messages: got %d hooks, want 1", len(hooks))
	}
	h := hooks[0]

	if h.SMS == nil {
		t.Fatal("SMS hook is nil - the `sms:` key was dropped and this hook would silently do nothing")
	}
	if h.SMS.To != "{{recipient}}" {
		t.Errorf("SMS.To = %q, want %q", h.SMS.To, "{{recipient}}")
	}
	if h.SMS.Body != "{{sms_body}}" {
		t.Errorf("SMS.Body = %q, want %q", h.SMS.Body, "{{sms_body}}")
	}
	if h.When != "channel = 'sms'" {
		t.Errorf("When = %q, want %q", h.When, "channel = 'sms'")
	}
}

// A `when:` guard that fails to stick would text every recipient rather than the
// filtered subset - a spend and trust problem, not just a correctness one.
func TestHookSMSRetainsWhenGuard(t *testing.T) {
	cfg := LoadHooksYAML(writeHooks(t, notifyHubHooksYAML))
	h := cfg.OnInsert["messages"][0]

	if !evaluateCondition(h.When, map[string]any{"channel": "sms"}) {
		t.Error("when-guard should match channel=sms")
	}
	if evaluateCondition(h.When, map[string]any{"channel": "email"}) {
		t.Error("when-guard matched channel=email - an SMS hook would fire on email rows")
	}
}

// The inline short form, mirroring `- email: someone@example.com`.
func TestHookSMSInlineShortForm(t *testing.T) {
	cfg := LoadHooksYAML(writeHooks(t, `on_insert:
  orders:
    - sms:
        to: "+15551234567"
        body: "Order {{id}} confirmed"
`))
	h := cfg.OnInsert["orders"][0]
	if h.SMS == nil {
		t.Fatal("SMS hook is nil")
	}
	if h.SMS.To != "+15551234567" || h.SMS.Body != "Order {{id}} confirmed" {
		t.Errorf("got To=%q Body=%q", h.SMS.To, h.SMS.Body)
	}
}

// An `sms:` block with no `to:` is a misconfiguration, not a send. It must not
// produce a live hook that would later fail at delivery time with an empty
// recipient.
func TestHookSMSWithoutToIsNotAnAction(t *testing.T) {
	cfg := LoadHooksYAML(writeHooks(t, `on_insert:
  orders:
    - sms:
        body: "no recipient"
`))
	if h := cfg.OnInsert["orders"][0]; h.SMS != nil {
		t.Errorf("SMS hook built without a `to:` - got %+v", h.SMS)
	}
}

// TestSMSHookDeliversThroughJobQueue is the end-to-end regression for the
// silent no-op at the job-queue boundary (review finding #1).
//
// FireHooks does NOT run executeHook directly - it enqueues a durable job via
// EnqueueHookJob, and the worker reconstructs the Hook from the serialized
// payload before calling executeHook. Pre-fix, EnqueueHookJob serialized only
// sql/webhook/body/email_*/notify, so the reconstructed Hook had SMS == nil on
// every real insert: the notify-hub SMS hook fired, reported job success, and
// sent nothing. This drives the full FireHooks → FlushJobs → executeHook path
// and asserts the SMS provider actually received the POST.
func TestSMSHookDeliversThroughJobQueue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)

	got := make(chan map[string]string, 1)
	providerURL := testSMSWebhook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var c map[string]string
		_ = json.Unmarshal(raw, &c)
		got <- c
		w.WriteHeader(200)
	}))

	SetAppEnv(app.Dir, "SMS_PROVIDER", "webhook")
	SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", providerURL)

	app.Hooks = &HookConfig{
		OnInsert: map[string][]Hook{
			"messages": {{
				SMS:  &SMSHook{To: "{{recipient}}", Body: "{{sms_body}}"},
				When: "channel = 'sms'",
			}},
		},
	}

	FireHooks(app, "insert", "messages", map[string]any{
		"recipient": "+15551239876",
		"sms_body":  "Your code is 482913",
		"channel":   "sms",
	})
	FlushJobs(app)

	select {
	case c := <-got:
		if c["to"] != "+15551239876" {
			t.Errorf("SMS provider received to=%q, want +15551239876", c["to"])
		}
		if !strings.Contains(c["body"], "482913") {
			t.Errorf("SMS provider received body=%q - template did not interpolate", c["body"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SMS provider was never called - the `sms:` hook was dropped crossing the job-queue boundary")
	}
}

// TestWSHookSurvivesJobPayloadRoundTrip proves the sibling `ws:` action is also
// carried across the job boundary. The WS broadcast has no easily-observable
// side effect in a unit test (no connected clients), so this asserts the
// serialize → reconstruct round-trip directly via the payload helper the worker
// uses, rather than the executed effect. Pre-fix the reconstructed Hook.WS was
// always nil for the same reason SMS was.
func TestWSHookSurvivesJobPayloadRoundTrip(t *testing.T) {
	in := Hook{
		WS:  &WSHook{Room: "order-{{id}}", Payload: `{"status":"{{status}}"}`},
		SMS: &SMSHook{To: "{{recipient}}", Body: "{{sms_body}}"},
	}
	payload := hookJobPayload(in, map[string]any{"id": 7})
	hookData, _ := payload["_hook"].(map[string]any)
	if hookData == nil {
		t.Fatal("payload missing _hook")
	}
	out := hookFromJobPayload(hookData)
	if out.WS == nil || out.WS.Room != "order-{{id}}" || out.WS.Payload != `{"status":"{{status}}"}` {
		t.Errorf("WS hook did not round-trip through the job payload: %+v", out.WS)
	}
	if out.SMS == nil || out.SMS.To != "{{recipient}}" || out.SMS.Body != "{{sms_body}}" {
		t.Errorf("SMS hook did not round-trip through the job payload: %+v", out.SMS)
	}
}

// Guards the sibling actions against regression from the SMS change.
func TestHookEmailAndWSStillParse(t *testing.T) {
	cfg := LoadHooksYAML(writeHooks(t, `on_insert:
  orders:
    - email:
        to: "{{user_email}}"
        subject: "Thanks"
        template: welcome
    - ws:
        room: "order-{{id}}"
        payload: '{"status":"{{status}}"}'
`))
	hooks := cfg.OnInsert["orders"]
	if len(hooks) != 2 {
		t.Fatalf("got %d hooks, want 2", len(hooks))
	}
	if hooks[0].Email == nil || hooks[0].Email.To != "{{user_email}}" {
		t.Error("email hook regressed")
	}
	if hooks[1].WS == nil || hooks[1].WS.Room != "order-{{id}}" {
		t.Error("ws hook regressed")
	}
}

// The systemic fix: an unrecognized hook key is dropped by yaml.v3, so the
// hook fires and does nothing. That must be rejected at write time.
func TestHooksYAMLUnknownEntryKeyRejected(t *testing.T) {
	cases := map[string]string{
		"sms_body at entry root": `on_insert:
  messages:
    - sms_body: "hello"
`,
		"misspelled action": `on_insert:
  messages:
    - smss:
        to: "+15551234567"
`,
		"fabricated send_email": `on_insert:
  orders:
    - send_email:
        to: "a@b.com"
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			msg := validateHooksYAML(body)
			if msg == "" {
				t.Fatal("validator accepted an unknown hook key - it would be silently dropped at runtime")
			}
			if !strings.Contains(msg, "unknown key") {
				t.Errorf("message should explain the problem, got: %s", msg)
			}
		})
	}
}

// The allowlist is derived from HookEntryYAML, so every real key must pass.
// notify-hub's exact shape is the case that regressed.
func TestHooksYAMLKnownKeysAccepted(t *testing.T) {
	if msg := validateHooksYAML(notifyHubHooksYAML); msg != "" {
		t.Errorf("validator rejected notify-hub's hooks.yaml: %s", msg)
	}

	all := `on_insert:
  orders:
    - sql: "UPDATE x SET y = 1"
      when: "status = 'new'"
    - webhook: "https://example.com/h"
      body: '{"id":"{{id}}"}'
    - email:
        to: "{{user_email}}"
        subject: "Hi"
        template: welcome
    - notify: "{{user_id}}"
      notify_title: "New order"
      notify_body: "Order {{id}}"
      notify_type: info
      notify_link: "/orders/{{id}}"
    - ws:
        room: "order-{{id}}"
        payload: '{"status":"{{status}}"}'
    - sms:
        to: "{{recipient}}"
        body: "{{sms_body}}"
`
	if msg := validateHooksYAML(all); msg != "" {
		t.Errorf("validator rejected a hooks.yaml using every supported key: %s", msg)
	}
}

// Guards the derivation itself: if someone adds a field to HookEntryYAML,
// the allowlist must pick it up without a second edit.
func TestHookEntryKeysDerivedFromStruct(t *testing.T) {
	for _, want := range []string{"webhook", "body", "sql", "when", "notify", "email", "ws", "sms"} {
		if !hookEntryKeys[want] {
			t.Errorf("hookEntryKeys missing %q - derivation from HookEntryYAML is broken", want)
		}
	}
	if hookEntryKeys["definitely_not_a_key"] {
		t.Error("hookEntryKeys contains a key that isn't on the struct")
	}
}
