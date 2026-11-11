//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The void-invoice flow of a probe app misspelled its guard's step id
// (`steps.lookpu`): push and check were clean, the guard was always false and
// paid invoices were voided.
const voidInvoiceTypoFlow = `on:
  request:
    method: POST
    path: /api/invoices/:id/void
    auth: required
jobs:
  void:
    steps:
      - id: lookup
        run: sql
        query: "SELECT id, CASE WHEN status = 'paid' THEN 1 ELSE 0 END AS is_paid FROM invoices WHERE id = :id AND user_id = :user_id"
        expect_rows: "=1"
      - id: deny_paid
        if: ${{ steps.lookpu.outputs.first.is_paid }} == 1
        steps:
          - run: respond
            with: { status: 409, json: { error: "paid invoices cannot be voided" } }
      - id: v
        run: sql
        query: "UPDATE invoices SET status = 'void' WHERE id = :id AND user_id = :user_id"
        expect_rows: "=1"
      - run: respond
        with: { status: 200, json: { voided: true } }
`

func TestWriteGateRefusesUnknownStepID(t *testing.T) {
	dir := t.TempDir()
	msg := ValidateOnWriteIn(dir, "flows/void-invoice.yaml", voidInvoiceTypoFlow)
	for _, want := range []string{"`steps.lookpu`", `no step in this flow has id "lookpu"`, "Did you mean `steps.lookup`? The flow's step ids are deny_paid, lookup, v.", `job "void" step 1 ("deny_paid")`, "a guard never fires"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("write gate message lacks %q:\n%s", want, msg)
		}
	}

	// benmore check reports it as an error on the file (the shared dispatcher).
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "void-invoice.yaml"), []byte(voidInvoiceTypoFlow), 0o644); err != nil {
		t.Fatal(err)
	}
	report := runCheckWithLive(dir, "", false, func(string) []CheckFinding { return nil })
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, "`steps.lookpu`") {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check did not report the unknown step id: %+v", report.Findings)
	}

	// A deployed file keeps loading: the refusal is write/check time only.
	if flows, err := parseGHAFlowFile("flows/void-invoice.yaml", []byte(voidInvoiceTypoFlow)); err != nil || len(flows) != 1 {
		t.Fatalf("loader refused a flow the write gate only rejects: %v", err)
	}

	// A loop over a step that does not exist ran zero times and answered 200.
	loop := `on:
  request: { method: POST, path: /api/loop }
jobs:
  loop:
    steps:
      - id: agg
        run: sql
        query: "SELECT id FROM invoices"
      - for_each: ${{ steps.agx.outputs.rows }}
        steps:
          - run: sql
            query: "UPDATE invoices SET status = 'seen' WHERE id = :id"
      - run: respond
        with: { status: 200, json: { ok: true } }
`
	if msg := ValidateOnWrite("flows/loop.yaml", loop); !strings.Contains(msg, "`steps.agx`") || !strings.Contains(msg, "Did you mean `steps.agg`?") || !strings.Contains(msg, "for_each over it runs zero times") {
		t.Fatalf("loop over unknown step: %q", msg)
	}

	// No near id: the message lists the ids the flow has.
	far := strings.Replace(voidInvoiceTypoFlow, "steps.lookpu.", "steps.invoice_row.", 1)
	if msg := ValidateOnWrite("flows/void-invoice.yaml", far); !strings.Contains(msg, "The flow's step ids are deny_paid, lookup, v.") {
		t.Fatalf("far id: %q", msg)
	}
}

// References the runtime resolves are accepted: an id defined in a branch, a
// loop body, a parallel block or an on_error handler; a reference before the
// step it names (a loop's later iteration, an on_error handler); `steps` as
// SQL text or quoted text; and a reference in a with: value, params, respond
// body or success_when.
func TestWriteGateAcceptsStepIDsDefinedAnywhereInTheFlow(t *testing.T) {
	flow := `on:
  request: { method: POST, path: /api/ok, auth: required }
jobs:
  ok:
    steps:
      - id: list
        run: sql
        query: "SELECT s.id FROM steps s WHERE s.owner = :user_id"
      - for_each: ${{ steps.list.outputs.rows }}
        as: row
        steps:
          - if: ${{ steps.prev.outputs.first.n }} > 0
            steps:
              - id: in_if
                run: sql
                query: "SELECT 1 AS n"
            else:
              - id: in_else
                run: sql
                query: "SELECT 2 AS n"
          - id: prev
            run: sql
            query: "SELECT :id AS n"
            params: { id: "${{ row.id }}" }
      - id: call
        run: api
        with:
          url: https://api.example.com/x
          success_when: steps.call.outputs.status == 200
        on_error:
          - id: handled
            run: sql
            query: "INSERT INTO failures (status) VALUES (:s)"
            params: { s: "${{ steps.call.outputs.status }}" }
      - run: parallel
        steps:
          - id: par_a
            run: sql
            query: "SELECT 1 AS a"
      - if: steps.in_else.outputs.n == 2 && ${{ steps.handled.outputs.rows_affected }} >= 0
        run: respond
        with: { status: 200, json: { a: "${{ steps.par_a.outputs.first.a }}", b: "${{ steps.in_if.outputs.first.n || 'steps.nothing' }}", c: "steps.literal is text" } }
`
	if problems := unknownStepRefProblems(mustParseGHA(t, flow)); len(problems) > 0 {
		t.Fatalf("refused references the flow defines:\n%s", strings.Join(problems, "\n"))
	}
}

// Each job is its own flow, so a step id from another job never resolves.
func TestWriteGateRefusesStepIDFromAnotherJob(t *testing.T) {
	flow := `on:
  request: { method: POST, path: /api/two }
jobs:
  first:
    steps:
      - id: shared
        run: sql
        query: "SELECT 1 AS n"
  second:
    steps:
      - run: respond
        with: { status: 200, json: { n: "${{ steps.shared.outputs.first.n }}" } }
`
	problems := unknownStepRefProblems(mustParseGHA(t, flow))
	if len(problems) != 1 || !strings.Contains(problems[0], `job "second"`) || !strings.Contains(problems[0], "No step in this flow has an `id:`.") {
		t.Fatalf("problems = %q", problems)
	}
}

func mustParseGHA(t *testing.T, content string) FlowFileGHA {
	t.Helper()
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil {
		t.Fatal(err)
	}
	return file
}
