//go:build !cli

package main

import (
	"strings"
	"testing"
)

// workflows.yaml keys the parser drops made a workflow silently inert: a
// `workflows:` wrapper (or a missing table/field) protects no state column,
// and `roles:` for `role:` lets anyone with update access take a transition.
func TestWorkflowsWriteGateRefusesDroppedKeys(t *testing.T) {
	wrapped := "workflows:\n  orders:\n    table: orders\n    field: status\n    transitions:\n      pending:\n        shipped: { role: admin }\n"
	cfg, err := parseWorkflowsYAML([]byte(wrapped))
	if err != nil || cfg == nil || cfg.Workflows["workflows"] == nil || cfg.Workflows["workflows"].Table != "" {
		t.Fatalf("expected the wrapper to parse as one table-less workflow: %+v %v", cfg, err)
	}
	base := "orders:\n  table: orders\n  field: status\n  initial: pending\n"
	cases := map[string]string{
		"wrapper":       wrapped,
		"no table":      "orders:\n  field: status\n  transitions:\n    a:\n      b: {}\n",
		"no field":      "orders:\n  table: orders\n  transitions:\n    a:\n      b: {}\n",
		"undeclared":    base + "  states: [pending, shipped]\n  transitions:\n    pending:\n      shiped: {}\n",
		"roles":         base + "  transitions:\n    pending:\n      shipped: { roles: [admin] }\n",
		"timeouts":      base + "  timeouts:\n    shipped: { after: 7d, to: delivered }\n",
		"bad after":     base + "  timeout:\n    shipped: { after: soon, to: delivered }\n",
		"timeout typo":  base + "  timeout:\n    shipped: { afer: 7d, to: delivered }\n",
		"hook key typo": base + "  on_transition:\n    shipped:\n      - webhok: \"{{env.X}}\"\n",
	}
	for name, content := range cases {
		if msg := ValidateOnWrite("workflows.yaml", content); msg == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	good := base + "  transitions:\n    pending:\n      shipped: { role: admin, when: \"tracking IS NOT NULL\" }\n      cancelled: {}\n  timeout:\n    shipped: { after: 14d, to: delivered }\n  on_transition:\n    shipped:\n      - notify: \"{{user_id}}\"\n        notify_title: Shipped\n"
	if msg := ValidateOnWrite("workflows.yaml", good); msg != "" {
		t.Errorf("valid workflow refused: %s", msg)
	}
	if msg := ValidateOnWrite("workflows.yaml", cases["roles"]); !strings.Contains(msg, "role:") {
		t.Errorf("roles refusal should point at role: %q", msg)
	}
}
