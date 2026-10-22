//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The mail senders treat To as a comma list, so a value that held a comma
// became several recipients: a public form's "email" field set to fifty
// addresses made a one-recipient confirmation hook mail all fifty (each
// seeing the others), fifty times the flow's own rate limit. A substituted
// value is one recipient; only the author's template, or a value the author
// marks `| recipients`, lists several.
func TestFlowEmailRecipientValueCannotAddRecipients(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "ADMIN_EMAILS", "ops@fixturemail.net,oncall@fixturemail.net")
	build := func(to string, data map[string]any) (string, error) {
		t.Helper()
		ctx := &FlowContext{App: app, Data: data, Params: map[string]string{}}
		for k, v := range data {
			if s, ok := v.(string); ok {
				ctx.Params[k] = s
			}
		}
		opts, _, err := buildEmailOpts(ctx, &FlowStep{Type: "email", Email: &FlowEmail{To: to, Subject: "s", Text: "body"}})
		return opts.To, err
	}
	injected := "lead@fixturemail.net,victim1@fixturemail.net,victim2@fixturemail.net"

	for name, to := range map[string]string{
		"sole reference":       "{{email}}",
		"reference with pipe":  "{{ email | lower }}",
		"colon parameter":      ":email",
		"display name wrapper": "{{name}} <{{email}}>",
		"next to a literal":    "owner@fixturemail.net, {{email}}",
	} {
		got, err := build(to, map[string]any{"email": injected, "name": "Lead"})
		if err == nil || !strings.Contains(err.Error(), "more than one address") {
			t.Errorf("%s: a comma in a recipient value produced To=%q err=%v", name, got, err)
		}
	}

	// One address per value is unchanged, byte for byte.
	for to, want := range map[string]string{
		"{{email}}":                                    "lead@fixturemail.net",
		"{{name}} <{{email}}>":                         "Lead <lead@fixturemail.net>",
		"{{email}}, owner@fixturemail.net":             "lead@fixturemail.net, owner@fixturemail.net",
		"{{email}},{{other}}":                          "lead@fixturemail.net,second@fixturemail.net",
		"owner@fixturemail.net, staff@fixturemail.net": "owner@fixturemail.net, staff@fixturemail.net",
		`"Desk, Front" <desk@fixturemail.net>`:         `"Desk, Front" <desk@fixturemail.net>`,
	} {
		got, err := build(to, map[string]any{"email": "lead@fixturemail.net", "other": "second@fixturemail.net", "name": "Lead"})
		if err != nil || got != want {
			t.Errorf("to=%q: got %q, %v; want %q", to, got, err, want)
		}
	}

	// A list is still possible where the author says the value is one: env
	// (the author's own configuration) and a value marked `| recipients`.
	for to, want := range map[string]string{
		"{{env.ADMIN_EMAILS}}":                      "ops@fixturemail.net,oncall@fixturemail.net",
		"{{ team | recipients }}":                   "a@fixturemail.net,b@fixturemail.net",
		"{{team | lower | recipients}}, {{email}}":  "a@fixturemail.net,b@fixturemail.net, lead@fixturemail.net",
		"owner@fixturemail.net,{{team|recipients}}": "owner@fixturemail.net,a@fixturemail.net,b@fixturemail.net",
	} {
		got, err := build(to, map[string]any{"email": "lead@fixturemail.net", "team": "a@fixturemail.net,b@fixturemail.net"})
		if err != nil || got != want {
			t.Errorf("to=%q: got %q, %v; want %q", to, got, err, want)
		}
	}
}

func TestHookEmailRecipientValueCannotAddRecipients(t *testing.T) {
	dir := t.TempDir()
	SetAppEnv(dir, "ADMIN_EMAILS", "ops@fixturemail.net,oncall@fixturemail.net")
	row := map[string]any{
		"email": "lead@fixturemail.net,victim1@fixturemail.net,victim2@fixturemail.net",
		"owner": "owner@fixturemail.net",
		"team":  "a@fixturemail.net,b@fixturemail.net",
		"name":  "Lead",
	}
	for _, to := range []string{"{{email}}", "{{name}} <{{email}}>", "{{owner}}, {{email}}"} {
		got, err := hookEmailRecipients(to, row, dir)
		if err == nil || !strings.Contains(err.Error(), "more than one address") {
			t.Errorf("hook to=%q: a comma in a row value produced To=%q err=%v", to, got, err)
		}
	}
	for to, want := range map[string]string{
		"{{owner}}":                       "owner@fixturemail.net",
		"{{owner}}, desk@fixturemail.net": "owner@fixturemail.net, desk@fixturemail.net",
		"{{env.ADMIN_EMAILS}}":            "ops@fixturemail.net,oncall@fixturemail.net",
		"{{team | recipients}}":           "a@fixturemail.net,b@fixturemail.net",
		"{{team|recipients}},{{owner}}":   "a@fixturemail.net,b@fixturemail.net,owner@fixturemail.net",
	} {
		got, err := hookEmailRecipients(to, row, dir)
		if err != nil || got != want {
			t.Errorf("hook to=%q: got %q, %v; want %q", to, got, err, want)
		}
	}
}
