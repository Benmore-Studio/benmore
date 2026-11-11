//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Email, sms and webhook steps are named wherever they run inside the
// transaction of a `transaction: true` flow (request or schedule), at every
// nesting depth; on_error handlers (which run after the rollback),
// non-transactional flows and api/enqueue steps are left alone. They are
// warned about, never refused: deployed flow files carry them.
func TestTransactionalSendProblems(t *testing.T) {
	const (
		requestTx   = "on:\n  request: { method: POST, path: /x, auth: required, transaction: true }\njobs:\n  j:\n    steps:\n"
		requestNoTx = "on:\n  request: { method: POST, path: /x, auth: required }\njobs:\n  j:\n    steps:\n"
		scheduleTx  = "on:\n  schedule: { cron: \"*/5 * * * *\", transaction: true }\njobs:\n  j:\n    steps:\n"
		asyncTx     = "on:\n  request: { method: POST, path: /x, auth: required, mode: async, transaction: true }\njobs:\n  j:\n    steps:\n"
	)
	sends := map[string]string{
		"email":   "run: email\n  with: { to: a@example.com, subject: hi, text: hello }",
		"sms":     "run: sms\n  with: { to: \"+15555550100\", body: hello }",
		"webhook": "run: webhook\n  with: { url: \"https://example.com/hook\", body: { a: 1 } }",
	}
	// step indents a step written at column 0 (continuation lines indented
	// two spaces) as a list item at the given depth.
	step := func(s string, indent int) string {
		pad := strings.Repeat(" ", indent)
		return pad + "- " + strings.ReplaceAll(s, "\n", "\n"+pad) + "\n"
	}
	type tc struct {
		src     string
		refused bool
	}
	cases := map[string]tc{}
	for kind, send := range sends {
		cases[kind+" top level"] = tc{requestTx + step(send, 6), true}
		cases[kind+" without transaction"] = tc{requestNoTx + step(send, 6), false}
		cases[kind+" scheduled transaction"] = tc{scheduleTx + step(send, 6), true}
		cases[kind+" async transaction"] = tc{asyncTx + step(send, 6), true}
		cases[kind+" in parallel"] = tc{requestTx + "      - run: parallel\n        steps:\n" + step(send, 10), true}
		cases[kind+" in if"] = tc{requestTx + "      - if: \"1 == 1\"\n        steps:\n" + step(send, 10), true}
		cases[kind+" in else"] = tc{requestTx + "      - if: \"1 == 1\"\n        steps:\n          - query: SELECT 1\n        else:\n" + step(send, 10), true}
		cases[kind+" in for_each"] = tc{requestTx + "      - id: rows\n        query: SELECT 1 AS id\n      - for_each: ${{ steps.rows.outputs.rows }}\n        as: r\n        steps:\n" + step(send, 10), true}
		cases[kind+" in parallel in for_each"] = tc{requestTx + "      - id: rows\n        query: SELECT 1 AS id\n      - for_each: ${{ steps.rows.outputs.rows }}\n        as: r\n        steps:\n          - run: parallel\n            steps:\n" + step(send, 14), true}
		cases[kind+" in on_error"] = tc{requestTx + "      - query: SELECT 1\n        on_error:\n" + step(send, 10), false}
		cases[kind+" in parallel in on_error"] = tc{requestTx + "      - query: SELECT 1\n        on_error:\n          - run: parallel\n            steps:\n" + step(send, 14), false}
	}
	cases["api in transaction"] = tc{requestTx + step("run: api\n  with: { method: POST, url: \"https://example.com/charge\" }", 6), false}
	cases["enqueue in transaction"] = tc{requestTx + step("run: enqueue\n  with: { flow: notify }", 6), false}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var file FlowFileGHA
			if err := decodeConfigYAML([]byte(c.src), &file); err != nil {
				t.Fatalf("decode: %v\n%s", err, c.src)
			}
			sends := flowTransactionalSendProblems(file)
			named := false
			for _, p := range sends {
				if strings.Contains(p, "sends at once and is not undone by a rollback") {
					named = true
				}
			}
			if named != c.refused {
				t.Fatalf("named=%v, want %v\nsends=%q\n%s", named, c.refused, sends, c.src)
			}
			for _, p := range flowStepValueProblems(file) {
				if strings.Contains(p, "sends at once") {
					t.Fatalf("the write gate would refuse a send that deployed files carry: %q", p)
				}
			}
		})
	}
}

// A flow file with a send inside its transaction is accepted by the write
// gate; the post-write check of that file and `benmore check` answer with one
// warning that names the file, the step and what to write instead, and with
// no error. A write of another file does not repeat it.
func TestTransactionalSendIsAWarningNotARefusal(t *testing.T) {
	const flow = `on:
  request: { method: POST, path: /api/order, auth: required, transaction: true }
jobs:
  order:
    steps:
      - id: placed
        query: "INSERT INTO notes (body) VALUES ('order') RETURNING id"
      - id: mail
        run: email
        with: { to: a@example.com, subject: hi, text: hello }
      - run: respond
        with: { status: 200, json: { id: "${{ steps.placed.outputs.id }}" } }
`
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: sends\n")
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id   Int    @id @default(autoincrement())\n  body String\n\n  @@map(\"notes\")\n}\n")
	if msg := ValidateOnWriteIn(dir, "flows/order.yaml", flow); msg != "" {
		t.Fatalf("the write gate refuses a flow shape deployed apps carry: %s", msg)
	}
	writeTestFile(t, dir, "flows/order.yaml", flow)
	sendWarnings := func(report CheckReport) (out []string) {
		for _, f := range report.Findings {
			if strings.Contains(f.Message, "sends at once and is not undone by a rollback") {
				if f.Severity != "warning" || f.Source != "flows" || f.File != "flows/order.yaml" {
					t.Errorf("finding is not a flows warning on the file: %+v", f)
				}
				// The step runs: nothing in the warning may read as a refusal,
				// and its address is the key that states the rule.
				if strings.Contains(f.Message, "can't run") || strings.Contains(f.Message, "refused") {
					t.Errorf("the warning reads as a refusal: %s", f.Message)
				}
				if got := checkFindingDocs(f); got != "flows.transactional_sends" {
					t.Errorf("the warning is documented at %q, want flows.transactional_sends", got)
				}
				out = append(out, f.Message)
			}
		}
		return out
	}
	for name, report := range map[string]CheckReport{
		"the post-write check of the flow file": RunSourceCheck(dir, "flows/order.yaml"),
		"benmore check":                         RunSourceCheck(dir, ""),
	} {
		got := sendWarnings(report)
		if len(got) != 1 || !strings.HasPrefix(got[0], `flows/order.yaml: job "order" step steps[1] ("mail"): `+"`run: email` in a `transaction: true` flow sends at once") || !strings.Contains(got[0], "`run: enqueue`") {
			t.Errorf("%s: got %q", name, got)
		}
		if report.Errors != 0 {
			t.Errorf("%s reports %d error(s): %+v", name, report.Errors, report.Findings)
		}
	}
	if got := sendWarnings(RunSourceCheck(dir, "app.yaml")); len(got) != 0 {
		t.Errorf("a write of another file repeats the warning: %q", got)
	}
}
