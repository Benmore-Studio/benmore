//go:build !cli

package main

// The write gate's side of step keys: a key the step's type does not read is
// refused, `benmore check` reports it, and the loader logs it for a deployed
// file. Before, each of these passed the gate and did nothing at run time.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestStepKeyWriteGateRefusesKeysTheRuntimeIgnores(t *testing.T) {
	const sqlStep = "      - id: s\n        run: sql\n        with: { query: \"UPDATE items SET qty = 1\" }\n"
	refused := map[string]struct{ steps, want string }{
		// Step-level keys written under `with:` (only the step root is read).
		"with.retry on api": {
			"      - id: call\n        run: api\n        with: { method: GET, url: \"https://example.com/x\", retry: 3 }\n",
			"step steps[0] (\"call\"): `with.retry` is not read: `retry` is a step-level key. Write it next to `run:`, not under `with:`.",
		},
		"with.retry_delay on sql": {
			"      - run: sql\n        with: { query: \"UPDATE items SET qty = 1\", retry_delay: 5s }\n",
			"`with.retry_delay` is not read: `retry_delay` is a step-level key",
		},
		"with.on_error on email": {
			"      - run: email\n        with:\n          to: a@example.com\n          subject: Hi\n          text: hello\n          on_error:\n            - run: respond\n              with: { status: 502, body: { error: mail } }\n",
			"`with.on_error` is not read: `on_error` is a step-level key",
		},
		"with.if on respond": {
			"      - run: respond\n        with: { status: 403, body: { error: no }, if: \"${{ steps.s.outputs.rows }}\" }\n",
			"`with.if` is not read: `if` is a step-level key",
		},
		"with.id on compute": {
			"      - run: compute\n        with: { id: calc, module: m, function: f, args: {} }\n",
			"`with.id` is not read: `id` is a step-level key",
		},
		// A time limit on a step that cannot be cut off, at either position.
		"with.timeout on sql": {
			"      - run: sql\n        with: { query: \"UPDATE items SET qty = 1\", timeout: 5s }\n",
			"`with.timeout` is not read on a `run: sql` step, so the step would run with no time limit of its own. Only `run: api`, `run: compute` and `run: transcribe` steps can be cut off",
		},
		"with.timeout on sql_dynamic": {
			"      - run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.sql }}\", timeout: 5 }\n",
			"`with.timeout` is not read on a `run: sql_dynamic` step",
		},
		"with.timeout on email": {
			"      - run: email\n        with: { to: a@example.com, subject: Hi, text: hello, timeout: 5s }\n",
			"`with.timeout` is not read on a `run: email` step",
		},
		"with.timeout on sms": {
			"      - run: sms\n        with: { to: \"+15550100\", body: hello, timeout: 5s }\n",
			"`with.timeout` is not read on a `run: sms` step",
		},
		"with.timeout on webhook": {
			"      - run: webhook\n        with: { url: \"https://example.com/hook\", body: \"{}\", timeout: 5s }\n",
			"`with.timeout` is not read on a `run: webhook` step",
		},
		"step-root timeout on sql": {
			"      - id: s\n        run: sql\n        timeout: 5s\n        with: { query: \"UPDATE items SET qty = 1\" }\n",
			"step steps[0] (\"s\"): `timeout` is not read on a `run: sql` step",
		},
		"step-root timeout on the query shorthand": {
			"      - query: \"UPDATE items SET qty = 1\"\n        timeout: 5s\n",
			"`timeout` is not read on a `run: sql` step",
		},
		"step-root timeout on respond": {
			"      - run: respond\n        timeout: 5s\n        with: { status: 200, body: { ok: true } }\n",
			"`timeout` is not read on a `run: respond` step",
		},
		"step-root timeout on an if block": {
			sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        timeout: 5s\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"step steps[1]: `timeout` is not read on an `if:` block, so it would limit nothing.",
		},
		"step-root timeout nested in on_error": {
			sqlStep[:len(sqlStep)-1] + "\n        on_error:\n          - run: webhook\n            timeout: 5s\n            with: { url: \"https://example.com/hook\", body: \"{}\" }\n",
			"step steps[0].on_error[0]: `timeout` is not read on a `run: webhook` step",
		},
		// `run: sql_dynamic` binds nothing.
		"with.params on sql_dynamic": {
			"      - run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.sql }}\", params: { id: \"1\" } }\n",
			"`with.params` is not read on a `run: sql_dynamic` step, which binds nothing",
		},
		"step-root params on sql_dynamic": {
			"      - run: sql_dynamic\n        query: \"${{ steps.plan.outputs.sql }}\"\n        params: { id: \"1\" }\n",
			"`params` is not read on a `run: sql_dynamic` step, which binds nothing",
		},
		// A SQL step with no statement.
		"with.sql for with.query": {
			"      - id: s\n        run: sql\n        with: { sql: \"UPDATE items SET qty = 9\" }\n",
			"step steps[0] (\"s\"): the step has no SQL statement: `with.sql` is not read. Write the statement as `with.query` (or `query:` at the step root). At run time it fails with `no SQL statement`",
		},
		"sql with no query": {
			"      - id: s\n        run: sql\n",
			"the step has no SQL statement: neither `query:` nor `with.query` is set",
		},
		"sql_dynamic with no query": {
			"      - run: sql_dynamic\n        with: {}\n",
			"the step has no SQL statement: neither `query:` nor `with.query` is set",
		},
		"empty with.query": {
			"      - run: sql\n        with: { query: \"  \" }\n",
			"the step has no SQL statement: its query is empty",
		},
		"query that is only a comment": {
			"      - run: sql\n        with:\n          query: |\n            -- UPDATE items SET qty = 9\n",
			"the step has no SQL statement: its query holds only a comment or whitespace",
		},
		"with.query that is not text": {
			"      - run: sql\n        with:\n          query: { select: 1 }\n",
			"the step has no SQL statement: `with.query` must be text",
		},
		"query written twice": {
			"      - run: sql\n        query: \"UPDATE items SET qty = 1\"\n        with: { query: \"UPDATE items SET qty = 2\" }\n",
			"`query` is written twice with different statements, at the step root and under `with:`. Only the step-root one runs.",
		},
		// Step-root keys on a step type that does not read them.
		"step-root query on api": {
			"      - run: api\n        query: \"SELECT 1\"\n        with: { method: GET, url: \"https://example.com/x\" }\n",
			"`query` is not read on a `run: api` step: only a `run: sql` or `run: sql_dynamic` step runs a statement",
		},
		"step-root params on api": {
			"      - run: api\n        params: { id: \"1\" }\n        with: { method: GET, url: \"https://example.com/x\" }\n",
			"`params` is not read on a `run: api` step: only a `run: sql` step binds `params`",
		},
		"steps on a gated action": {
			sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        run: respond\n        with: { status: 200, body: { ok: true } }\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`steps` is not read on a `run: respond` step, so the nested steps would never run",
		},
		"for_each on a run step": {
			"      - id: rows\n        query: \"SELECT id FROM items\"\n      - for_each: ${{ steps.rows.outputs.rows }}\n        as: r\n        run: sql\n        with: { query: \"UPDATE items SET qty = 1 WHERE id = :id\", params: { id: \"${{ r.id }}\" } }\n",
			"`for_each` is not read on a `run: sql` step: the step would run once, not once per item",
		},
		"for_each next to the query shorthand": {
			"      - id: rows\n        query: \"SELECT id FROM items\"\n      - for_each: ${{ steps.rows.outputs.rows }}\n        query: \"UPDATE items SET qty = 1\"\n",
			"`for_each` is not read on a `run: sql` step",
		},
		"as on a run step": {
			"      - run: sql\n        as: row\n        with: { query: \"SELECT 1\" }\n",
			"`as` is not read on a `run: sql` step: it names the loop variable of a `for_each:` step",
		},
		"else without if": {
			"      - run: sql\n        with: { query: \"SELECT 1\" }\n        else:\n          - run: respond\n            with: { status: 404, body: { error: none } }\n",
			"`else` has no `if:` next to it, so its steps would never run",
		},
		"with on an if block": {
			sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        with: { status: 200 }\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`with` is not read on an `if:` block, which has no options of its own",
		},
		"with on a parallel block": {
			"      - run: parallel\n        with: { max: 2 }\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`with` is not read on a `run: parallel` block",
		},
		"retry on an if block": {
			sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        retry: 3\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`retry` is on an `if:` block. A retried block runs its steps again from the top, those that already succeeded included, and still fails with the first error",
		},
		"retry_delay on a for_each loop": {
			"      - id: rows\n        query: \"SELECT id FROM items\"\n      - for_each: ${{ steps.rows.outputs.rows }}\n        retry_delay: 2s\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`retry_delay` is on a `for_each:` loop",
		},
		"retry on a parallel block": {
			"      - run: parallel\n        retry: 2\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`retry` is on a `run: parallel` block",
		},
		"run: for_each with no list": {
			"      - run: for_each\n        as: row\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`run: for_each` has no `for_each:` list, so its steps would never run",
		},
		"run: if with no condition": {
			"      - run: if\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`run: if` has no `if:` condition, so its steps would never run",
		},
		// `with:` keys no row of the table lists.
		"api with.data": {
			"      - run: api\n        with: { method: POST, url: \"https://example.com/x\", data: { a: 1 } }\n",
			"`with.data` is not read on a `run: api` step, so it would be ignored. Under `with:` it reads: auth, body, form, handled_statuses, headers, json, method, paginate, query, sign, success_when, timeout, url.",
		},
		"email with.unsupported_copy": {
			"      - run: email\n        with: { to: a@example.com, unsupported_copy: b@example.com, subject: Hi, text: hello }\n",
			"`with.unsupported_copy` is not read on a `run: email` step",
		},
		"webhook with.headers": {
			"      - run: webhook\n        with: { url: \"https://example.com/hook\", body: \"{}\", headers: { X-Key: k } }\n",
			"`with.headers` is not read on a `run: webhook` step, so it would be ignored. Under `with:` it reads: body, payload, url.",
		},
		"redirect with.status": {
			"      - run: redirect\n        with: { to: /done, status: 301 }\n",
			"`with.status` is not read on a `run: redirect` step",
		},
		"serve_file with.content_type": {
			"      - run: serve_file\n        with: { path: uploads/a.pdf, content_type: application/pdf }\n",
			"`with.content_type` is not read on a `run: serve_file` step",
		},
		"sms with.message": {
			"      - run: sms\n        with: { to: \"+15550100\", message: hello }\n",
			"`with.message` is not read on a `run: sms` step",
		},
		"compute with.timeout_ms": {
			"      - run: compute\n        with: { module: m, function: f, args: {}, timeout_ms: 500 }\n",
			"`with.timeout_ms` is not read on a `run: compute` step",
		},
		"respond with.code": {
			"      - run: respond\n        with: { code: 404, body: { error: none } }\n",
			"`with.code` is not read on a `run: respond` step, so it would be ignored. Under `with:` it reads: body, content_type, headers, json, status.",
		},
		"parse with.format": {
			"      - id: p\n        run: parse\n        with: { source: body, format: json }\n",
			"`with.format` is not read on a `run: parse` step",
		},
		"a key under a nested step": {
			sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        steps:\n          - id: inner\n            run: sql\n            with: { query: \"SELECT 1\", retry: 2 }\n",
			"step steps[1].steps[0] (\"inner\"): `with.retry` is not read",
		},
	}
	for name, tc := range refused {
		msg := ValidateOnWrite("flows/probe.yaml", stepKeyFlow(tc.steps))
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: write gate said %q, want it to contain %q", name, msg, tc.want)
		}
	}

	accepted := map[string]string{
		"step-level modifiers on an action":  "      - id: call\n        if: ${{ params.go }}\n        run: api\n        retry: 3\n        retry_delay: 2s\n        timeout: 20s\n        with: { method: GET, url: \"https://example.com/x\", timeout: 10 }\n        on_error:\n          - run: respond\n            with: { status: 502, body: { error: upstream } }\n",
		"retry and on_error on sql":          "      - run: sql\n        retry: 2\n        retry_delay: 1s\n        with: { query: \"UPDATE items SET qty = 1\" }\n        on_error:\n          - run: respond\n            with: { status: 500, body: { error: db } }\n",
		"timeout on compute, both places":    "      - run: compute\n        timeout: 10s\n        with: { module: m, function: f, args: {}, timeout: 8s }\n",
		"timeout on transcribe, both places": "      - id: t\n        run: transcribe\n        timeout: 60s\n        with: { file: uploads/a.webm, timeout: 90 }\n",
		"else on a gated step":               sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        run: respond\n        with: { status: 200, body: { ok: true } }\n        else:\n          - run: respond\n            with: { status: 404, body: { error: none } }\n",
		"else on an if block":                sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n        else:\n          - run: sql\n            with: { query: \"SELECT 2\" }\n",
		"run: if written out":                sqlStep + "      - run: if\n        if: ${{ steps.s.outputs.rows_affected }}\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
		"on_error on blocks":                 sqlStep + "      - if: ${{ steps.s.outputs.rows_affected }}\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n        on_error:\n          - run: respond\n            with: { status: 500, body: { error: block } }\n      - run: parallel\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n        on_error:\n          - run: respond\n            with: { status: 500, body: { error: fan } }\n",
		"the same query in both places":      "      - run: sql\n        query: \"UPDATE items SET qty = 1\"\n        with: { query: \"UPDATE items SET qty = 1\" }\n",
		"query shorthand with a with block":  "      - query: \"UPDATE items SET qty = :q\"\n        with: { params: { q: \"1\" } }\n",
		"sql_dynamic with a rendered query":  "      - run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.sql }}\" }\n",
		// On `run: set` every `with:` key is a variable, whatever its name.
		"set variables named like step keys": "      - id: vars\n        run: set\n        with: { retry: \"3\", timeout: \"5s\", if: \"x\", id: \"7\", sql: \"SELECT 1\", params: \"p\", payload: \"y\" }\n",
		// A comment before the statement is still a statement.
		"comment-led statement": "      - run: sql\n        with:\n          query: |\n            -- the open ones\n            UPDATE items SET qty = 1\n",
	}
	for name, steps := range accepted {
		if msg := ValidateOnWrite("flows/probe.yaml", stepKeyFlow(steps)); msg != "" {
			t.Errorf("%s: write gate refused a step whose keys are all read: %s", name, msg)
		}
	}
}

// Every problem of a file is listed, not only the first.
func TestStepKeyWriteGateListsEveryProblem(t *testing.T) {
	msg := ValidateOnWrite("flows/probe.yaml", stepKeyFlow(
		"      - id: a\n        run: sql\n        timeout: 5s\n        with: { query: \"SELECT 1\", retry: 2 }\n"+
			"      - id: b\n        run: email\n        with: { to: a@example.com, subject: Hi, text: hello, unsupported_copy: b@example.com }\n"))
	for _, want := range []string{
		"step steps[0] (\"a\"): `timeout` is not read on a `run: sql` step",
		"step steps[0] (\"a\"): `with.retry` is not read",
		"step steps[1] (\"b\"): `with.unsupported_copy` is not read on a `run: email` step",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("write gate message is missing %q:\n%s", want, msg)
		}
	}
}

// captureFlowLoad parses one flow file and returns what the loader logged.
// Goroutines left by earlier tests may log too, so callers look only for
// their own file's lines.
func captureFlowLoad(path, source string) ([]Flow, string, error) {
	var buf bytes.Buffer
	original := log.Writer()
	log.SetOutput(&buf)
	flows, err := parseGHAFlowFile(path, []byte(source))
	log.SetOutput(original)
	return flows, buf.String(), err
}

// A deployed file the write gate would refuse still loads, and the loader's
// log names each key that does nothing.
func TestLoaderLogsStepKeysTheWriteGateRefuses(t *testing.T) {
	source := stepKeyFlow(
		"      - id: slow\n        run: sql\n        timeout: 5s\n        with: { query: \"UPDATE items SET qty = 1\", retry: 3 }\n" +
			"      - id: gen\n        run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.sql }}\", params: { id: \"1\" } }\n" +
			"      - id: empty\n        run: sql\n        with: { sql: \"UPDATE items SET qty = 2\" }\n")
	flows, logged, err := captureFlowLoad("flows/deployed.yaml", source)
	if err != nil || len(flows) != 1 || len(flows[0].Steps) != 4 {
		t.Fatalf("deployed file no longer loads: %v (%d flows)", err, len(flows))
	}
	for _, want := range []string{
		"WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[0] (\"slow\"): `timeout` is not read on a `run: sql` step",
		"WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[0] (\"slow\"): `with.retry` is not read",
		"WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[1] (\"gen\"): `with.params` is not read on a `run: sql_dynamic` step",
		"WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[2] (\"empty\"): the step has no SQL statement: `with.sql` is not read",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("loader log is missing %q:\n%s", want, logged)
		}
	}
	// A file with nothing to say stays quiet.
	_, logged, err = captureFlowLoad("flows/quiet.yaml", stepKeyFlow("      - id: s\n        run: sql\n        retry: 2\n        with: { query: \"UPDATE items SET qty = 2\", params: { a: \"1\" } }\n"))
	if err != nil || strings.Contains(logged, "flows/quiet.yaml") {
		t.Fatalf("clean file: err=%v log=%q", err, logged)
	}
}

// `benmore check` runs the same validator as the write gate.
func TestBenmoreCheckReportsStepKeyProblems(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml": "seo:\n  site_name: T\n",
		"schema.prisma": `model Item {
  id  Int @id @default(autoincrement())
  qty Int
}`,
		"flows/adjust.yaml": `on:
  request:
    method: POST
    path: /api/adjust
jobs:
  adjust:
    steps:
      - id: apply
        run: sql
        with:
          sql: "UPDATE items SET qty = 1 WHERE id = :id"
          retry: 3
      - run: respond
        with: { status: 200, body: { ok: true } }
`,
	})
	report := RunSourceCheck(dir, "")
	var found string
	for _, f := range report.Findings {
		if f.Severity == "error" && f.File == "flows/adjust.yaml" {
			found += f.Message
		}
	}
	for _, want := range []string{"`with.retry` is not read", "the step has no SQL statement: `with.sql` is not read"} {
		if !strings.Contains(found, want) {
			t.Errorf("benmore check did not report %q:\n%s", want, FormatReport(report))
		}
	}
}
