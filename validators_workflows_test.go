//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestParseWorkflowsYAMLHonorsDeclaredStates(t *testing.T) {
	cfg, err := parseWorkflowsYAML([]byte(`
orders:
  table: orders
  field: status
  initial: pending
  states: [pending, paid, refunded, archived]
  transitions:
    pending: { paid: {} }
    paid: { refunded: {} }
`))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cfg.Workflows["orders"].States, ",")
	if got != "pending,paid,refunded,archived" {
		t.Fatalf("states = %s; want the declared list in order (archived has no transition)", got)
	}

	cfg, err = parseWorkflowsYAML([]byte(`
orders:
  table: orders
  field: status
  transitions:
    shipped: { delivered: {} }
    pending: { shipped: {}, cancelled: {} }
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Workflows["orders"].States, ","); got != "cancelled,delivered,pending,shipped" {
		t.Fatalf("derived states = %s; want sorted", got)
	}
}

func TestValidateWorkflowsShapeRefusesIgnoredKeysAndStates(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", `model Order {
  id Int @id @default(autoincrement())
  status String?
  updated_at DateTime @updatedAt
}
model Note {
  id Int @id @default(autoincrement())
  status String?
}
`)
	cases := []struct {
		name, yaml, want string
	}{
		{"misspelled timeout key", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: {} } }
  timeouts: { pending: { after: 7d, to: paid } }
`, `unknown key "timeouts"`},
		{"roles on a transition drops the guard", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: { roles: [admin] } } }
`, `unknown key "roles"`},
		{"state missing from states list", `
orders:
  table: orders
  field: status
  initial: pending
  states: [pending, paid]
  transitions: { pending: { paid: {}, refunded: {} } }
`, `"refunded" is not in ` + "`states:`"},
		{"misspelled initial", `
orders:
  table: orders
  field: status
  initial: pendng
  transitions: { pending: { paid: {} } }
`, `"pendng" is not a state any transition names`},
		{"on_transition under unreachable state", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: {} } }
  on_transition:
    payed:
      - sql: "SELECT 1"
`, `"payed" is not a state`},
		{"unparseable timeout", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: {} } }
  timeout: { pending: { after: soon, to: paid } }
`, `after "soon" is not a duration`},
		{"timeout on table without updated_at", `
notes:
  table: notes
  field: status
  transitions: { draft: { published: {} } }
  timeout: { draft: { after: 1h, to: published } }
`, `has no updated_at column`},
		{"on_transition entry key", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: {} } }
  on_transition:
    paid:
      - send_email: { to: a@b.c }
`, `unknown key "send_email"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseWorkflowsYAML([]byte(tc.yaml)); err != nil {
				t.Fatalf("fixture must parse (a deployed file keeps loading): %v", err)
			}
			msg := ValidateOnWriteIn(dir, "workflows.yaml", tc.yaml)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("write gate = %q; want it to contain %q", msg, tc.want)
			}
		})
	}

	ok := `
orders:
  table: orders
  field: status
  initial: pending
  states: [pending, paid, archived]
  transitions:
    pending: { paid: { role: admin, when: "status = 'pending'" } }
  timeout: { pending: { after: 7d, to: archived } }
  on_transition:
    paid:
      - sql: "SELECT 1"
`
	if msg := ValidateOnWriteIn(dir, "workflows.yaml", ok); msg != "" {
		t.Fatalf("valid workflows.yaml refused: %s", msg)
	}
	// benmore check runs the same dispatcher over the file on disk.
	writeTestFile(t, dir, "workflows.yaml", `
orders:
  table: orders
  field: status
  transitions: { pending: { paid: {} } }
  states_list: [pending, paid]
`)
	rpt := RunCompleteCheck(dir, "")
	found := false
	for _, f := range rpt.Findings {
		if f.File == "workflows.yaml" && strings.Contains(f.Message, `unknown key "states_list"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check missed the ignored workflows.yaml key: %+v", rpt.Findings)
	}
}
