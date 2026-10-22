//go:build !cli

package main

// The write gate's side of expect_rows: what it refuses, what the loader
// logs for a deployed file, and `benmore check`.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// The write gate (and `benmore check`, which runs the same validator) refuses
// every expect_rows the runtime would not check as written.
func TestExpectRowsWriteGate(t *testing.T) {
	sqlStep := func(query, extra string) string {
		return "      - id: s\n        run: sql\n        with:\n          query: \"" + query + "\"\n" + extra
	}
	refused := map[string]struct{ steps, want string }{
		"step root on api": {
			"      - id: call\n        run: api\n        with: { method: GET, url: \"https://example.com/x\" }\n        expect_rows: \">0\"\n",
			"`expect_rows` is on a `run: api` step, which has no row count",
		},
		"step root on for_each": {
			"      - id: rows\n        query: \"SELECT id FROM items\"\n      - for_each: ${{ steps.rows.outputs.rows }}\n        as: r\n        expect_rows: \">0\"\n        steps:\n          - run: sql\n            with: { query: \"UPDATE items SET qty = 1 WHERE id = :id\", params: { id: \"${{ r.id }}\" } }\n",
			"`expect_rows` is on a `for_each:` loop",
		},
		"step root on if block": {
			"      - if: ${{ 1 == 1 }}\n        expect_rows: \">0\"\n        steps:\n          - run: sql\n            with: { query: \"SELECT 1\" }\n",
			"`expect_rows` is on an `if:` block",
		},
		"under with on api": {
			"      - id: call\n        run: api\n        with: { method: GET, url: \"https://example.com/x\", expect_rows: \">0\" }\n",
			"`with.expect_rows` is on a `run: api` step",
		},
		"step root on set": {
			"      - id: vars\n        run: set\n        with: { n: \"1\" }\n        expect_rows: \">0\"\n",
			"`expect_rows` is on a `run: set` step, which has no row count",
		},
		"under with on compute": {
			"      - id: c\n        run: compute\n        with: { module: m, function: f, args: {}, expect_rows: \"=1\" }\n",
			"`with.expect_rows` is on a `run: compute` step",
		},
		"unparsable under with": {
			sqlStep("UPDATE items SET qty = 1", "          expect_rows: at least one\n"),
			"with.expect_rows \"at least one\" is not a row-count comparison",
		},
		"float under with": {
			sqlStep("UPDATE items SET qty = 1", "          expect_rows: 1.0\n"),
			"with.expect_rows \"1.0\" is not a row-count comparison",
		},
		"float at step root": {
			sqlStep("UPDATE items SET qty = 1", "        expect_rows: 1.0\n"),
			"expect_rows \"1.0\" is not a row-count comparison",
		},
		"unquoted != at step root": {
			sqlStep("UPDATE items SET qty = 1", "        expect_rows: !=0\n"),
			"`expect_rows` has no value, so nothing would be asserted",
		},
		"unquoted != under with": {
			sqlStep("UPDATE items SET qty = 1", "          expect_rows: !=0\n"),
			"`with.expect_rows` has no value, so nothing would be asserted",
		},
		"null at step root, nested": {
			"      - if: ${{ 1 == 1 }}\n        steps:\n          - id: s\n            run: sql\n            with: { query: \"UPDATE items SET qty = 1\" }\n            expect_rows:\n",
			"step \"s\": `expect_rows` has no value",
		},
		"conflict": {
			sqlStep("UPDATE items SET qty = 1", "          expect_rows: \"=1\"\n        expect_rows: \">0\"\n"),
			"expect_rows is declared twice with different values (\">0\" at the step root, \"=1\" under with:)",
		},
		"ddl": {
			sqlStep("CREATE TABLE made (id INTEGER)", "        expect_rows: \">0\"\n"),
			"`expect_rows` cannot be checked on this step: its statement does not read as a SELECT, INSERT, UPDATE or DELETE",
		},
		"mixed script": {
			sqlStep("INSERT INTO log (note) VALUES ('x'); SELECT 1", "        expect_rows: \">0\"\n"),
			"`expect_rows` cannot be checked on this step: it holds 2 statements",
		},
		"mixed script under with, in on_error": {
			"      - run: sql\n        with: { query: \"SELECT 1\" }\n        on_error:\n          - id: s\n            run: sql\n            with:\n              query: \"INSERT INTO log (note) VALUES ('x'); UPDATE items SET qty = 1 RETURNING id\"\n              expect_rows: \">0\"\n",
			"`expect_rows` cannot be checked on this step: it holds 2 statements",
		},
	}
	for name, tc := range refused {
		msg := ValidateOnWrite("flows/probe.yaml", expectRowsFlow("", tc.steps))
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: write gate said %q, want it to contain %q", name, msg, tc.want)
		}
	}
	accepted := map[string]string{
		"select":                    sqlStep("SELECT id FROM items WHERE id = :id", "        expect_rows: \"=1\"\n"),
		"with select":               sqlStep("WITH a AS (SELECT 1 AS id) SELECT id FROM a", "        expect_rows: \">0\"\n"),
		"returning":                 sqlStep("UPDATE items SET qty = 1 WHERE id = :id RETURNING id", "        expect_rows: \"=1\"\n"),
		"with insert":               sqlStep("WITH a AS (SELECT 'n' AS name) INSERT INTO items (name) SELECT name FROM a", "        expect_rows: \">0\"\n"),
		"under with":                sqlStep("UPDATE items SET qty = 1 WHERE id = :id", "          expect_rows: \"=1\"\n"),
		"bare integer under with":   sqlStep("UPDATE items SET qty = 1 WHERE id = :id", "          expect_rows: 1\n"),
		"bare integer at step root": sqlStep("UPDATE items SET qty = 1 WHERE id = :id", "        expect_rows: 1\n"),
		"same in both positions":    sqlStep("UPDATE items SET qty = 1 WHERE id = :id", "          expect_rows: 1\n        expect_rows: 1\n"),
		"script of writes":          sqlStep("UPDATE items SET qty = 1; DELETE FROM log", "        expect_rows: \">=0\"\n"),
		"comment-led select":        "      - id: s\n        run: sql\n        with:\n          query: |\n            -- the open ones\n            SELECT id FROM items WHERE qty > 0\n        expect_rows: \">0\"\n",
		"references are parameters": sqlStep("UPDATE items SET name = ${{ steps.returning.outputs.name }} WHERE id = ${{ steps.insert.outputs.id }}", "        expect_rows: \"=1\"\n"),
		"sql_dynamic":               "      - id: s\n        run: sql_dynamic\n        with:\n          query: \"${{ steps.plan.outputs.sql }}\"\n          expect_rows: \">0\"\n",
		"if-gated sql":              "      - id: s\n        if: ${{ 1 == 1 }}\n        run: sql\n        with: { query: \"UPDATE items SET qty = 1\" }\n        expect_rows: \">0\"\n",
		"no expect_rows on ddl":     sqlStep("CREATE TABLE IF NOT EXISTS made (id INTEGER)", ""),
		// On `run: set` a `with:` key is a variable, whatever its name.
		"set variable named expect_rows": "      - id: vars\n        run: set\n        with: { expect_rows: \"1\" }\n",
	}
	for name, steps := range accepted {
		if msg := ValidateOnWrite("flows/probe.yaml", expectRowsFlow("", steps)); msg != "" {
			t.Errorf("%s: write gate refused a checkable assertion: %s", name, msg)
		}
	}
}

// A `run: sql` reference is a bound parameter at run time, so the write gate
// classifies the statement with every reference replaced by `?`.
func TestFlowSQLStaticText(t *testing.T) {
	got := flowSQLStaticText("UPDATE t SET a = ${{ steps.returning.outputs.x | default:'a;b' }}, b = '{{ insert.id }}' WHERE id = :id")
	if want := "UPDATE t SET a = ?, b = '?' WHERE id = :id"; got != want {
		t.Fatalf("flowSQLStaticText = %q, want %q", got, want)
	}
	if shape := classifyFlowSQL(got); shape.kind != flowSQLWrite || shape.statements != 1 {
		t.Fatalf("a reference changed the statement's shape: %+v", shape)
	}
}

// The loader keeps loading a deployed file the write gate would refuse, and
// its log names each expect_rows that is not the assertion its author wrote.
func TestLoaderLogsExpectRowsTheWriteGateRefuses(t *testing.T) {
	source := `on:
  request:
    method: POST
    path: /api/p
jobs:
  p:
    steps:
      - id: rows
        query: "SELECT id FROM items"
      - id: loop
        for_each: ${{ steps.rows.outputs.rows }}
        as: r
        expect_rows: ">0"
        steps:
          - run: sql
            with: { query: "UPDATE items SET qty = 1 WHERE id = :id", params: { id: "${{ r.id }}" } }
      - id: unquoted
        run: sql
        with: { query: "UPDATE items SET qty = 2" }
        expect_rows: !=0
`
	// Captures what one parse logs. Goroutines left by earlier tests may log
	// too, so the assertions look only for this file's lines.
	parse := func(path, source string) ([]Flow, string, error) {
		var buf bytes.Buffer
		original := log.Writer()
		log.SetOutput(&buf)
		flows, err := parseGHAFlowFile(path, []byte(source))
		log.SetOutput(original)
		return flows, buf.String(), err
	}
	flows, logged, err := parse("flows/p.yaml", source)
	if err != nil || len(flows) != 1 {
		t.Fatalf("deployed file no longer loads: %v", err)
	}
	for _, want := range []string{
		"WARNING: flows/p.yaml: flows.yaml: job \"p\" step \"loop\": `expect_rows` is on a `for_each:` loop",
		"WARNING: flows/p.yaml: flows.yaml: job \"p\" step \"unquoted\": `expect_rows` has no value",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("loader log is missing %q:\n%s", want, logged)
		}
	}
	// A file with nothing to say stays quiet.
	_, logged, err = parse("flows/q.yaml", "on:\n  request: { method: POST, path: /api/q }\njobs:\n  q:\n    steps:\n      - run: sql\n        with: { query: \"UPDATE items SET qty = 2\", expect_rows: 1 }\n")
	if err != nil || strings.Contains(logged, "flows/q.yaml") {
		t.Fatalf("clean file: err=%v log=%q", err, logged)
	}
}

// `benmore check` runs the same validator as the write gate.
func TestBenmoreCheckReportsExpectRowsProblems(t *testing.T) {
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
        expect_rows: ">0"
        with:
          query: "UPDATE items SET qty = 1 WHERE id = :id"
          expect_rows: "=1"
      - run: respond
        with: { status: 200, body: { ok: true } }
`,
	})
	report := RunSourceCheck(dir, "")
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" && f.File == "flows/adjust.yaml" && strings.Contains(f.Message, "expect_rows is declared twice with different values") {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check did not report the contradictory expect_rows:\n%s", FormatReport(report))
	}
}
