//go:build !cli

package main

// What the runtime does with the step keys the loader now reads, and with a
// SQL step that has no statement.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stepKeyFlow wraps step YAML (indented six spaces) in a POST flow that ends
// with a respond step.
func stepKeyFlow(steps string) string { return expectRowsFlow("", steps) }

// runStepKeyFlow runs one flow file over HTTP with a query string.
func runStepKeyFlow(t *testing.T, app *App, source, query string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, source)
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path+query, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	err := executeFlowHTTP(app, &flow, rr, req)
	return rr, err
}

// A `run: sql` / `run: sql_dynamic` step with no statement used to reach
// Exec, which runs nothing and reports success: the flow went on and answered
// 200. It now stops the flow with "no SQL statement".
func TestSQLStepWithNoStatementFailsTheFlow(t *testing.T) {
	const after = "      - run: sql\n        with: { query: \"INSERT INTO log (note) VALUES ('after')\" }\n"
	for name, steps := range map[string]string{
		"with.sql for with.query":        "      - id: s\n        run: sql\n        with: { sql: \"UPDATE items SET qty = 9\" }\n",
		"no query at all":                "      - id: s\n        run: sql\n",
		"a query that is only a comment": "      - id: s\n        run: sql\n        with:\n          query: |\n            -- UPDATE items SET qty = 9\n",
		"sql_dynamic renders nothing":    "      - id: plan\n        query: \"SELECT '' AS text\"\n      - id: s\n        run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.text }}\" }\n",
		"sql_dynamic renders a comment":  "      - id: plan\n        query: \"SELECT '/* nothing to do */' AS text\"\n      - id: s\n        run: sql_dynamic\n        with: { query: \"${{ steps.plan.outputs.text }}\" }\n",
	} {
		t.Run(name, func(t *testing.T) {
			app := expectRowsApp(t)
			mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
			rr, err := runExpectRowsFlow(t, app, stepKeyFlow(steps+after))
			if err == nil || !strings.Contains(err.Error(), "no SQL statement") {
				t.Fatalf("flow error = %v (status %d, body %s), want it to say no SQL statement", err, rr.Code, rr.Body.String())
			}
			if rr.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rr.Code)
			}
			if n := expectRowsInt(t, app, `SELECT COUNT(*) FROM log`); n != 0 {
				t.Errorf("the flow went on after the step with no statement (%d later writes)", n)
			}
		})
	}
	// A statement behind a comment, and a statement followed by one, still run.
	for name, query := range map[string]string{
		"comment first": "-- bump\n            UPDATE items SET qty = 9",
		"comment last":  "UPDATE items SET qty = 9; -- bumped",
	} {
		t.Run(name, func(t *testing.T) {
			app := expectRowsApp(t)
			mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
			rr, err := runExpectRowsFlow(t, app, stepKeyFlow("      - id: s\n        run: sql\n        with:\n          query: |\n            "+query+"\n"))
			if err != nil || rr.Code != http.StatusOK {
				t.Fatalf("flow failed: %v (status %d)", err, rr.Code)
			}
			if got := expectRowsInt(t, app, `SELECT qty FROM items WHERE id = 1`); got != 9 {
				t.Errorf("qty = %d, want 9: the statement did not run", got)
			}
		})
	}
}

// `else:` next to a gated step (`if:` + `run:`) is the gate's other branch.
// It used to be read only on an `if:` block, so these steps never ran.
func TestElseOfAGatedStepRuns(t *testing.T) {
	steps := `      - id: found
        query: "SELECT COUNT(*) AS n FROM items WHERE id = :id"
      - if: ${{ steps.found.outputs.n }} > 0
        run: respond
        with: { status: 200, body: { found: true } }
        else:
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('miss')" }
          - run: respond
            with: { status: 404, body: { found: false } }
`
	run := func(id string) (int, string, int) {
		app := expectRowsApp(t)
		mustExec(t, app.DB, `INSERT INTO items (id, name, qty) VALUES (1, 'a', 5)`)
		rr, err := runStepKeyFlow(t, app, stepKeyFlow(steps), "?id="+id)
		if err != nil {
			t.Fatalf("flow failed: %v", err)
		}
		return rr.Code, rr.Body.String(), expectRowsInt(t, app, `SELECT COUNT(*) FROM log`)
	}
	if code, body, misses := run("99"); code != http.StatusNotFound || !strings.Contains(body, `"found":false`) || misses != 1 {
		t.Errorf("no match: status %d body %s, %d else writes; want the else branch (404, found false, 1 write)", code, body, misses)
	}
	if code, body, misses := run("1"); code != http.StatusOK || !strings.Contains(body, `"found":true`) || misses != 0 {
		t.Errorf("match: status %d body %s, %d else writes; want the gated step alone (200, found true)", code, body, misses)
	}
}

// `run: if` written out is the `if:` block it describes. Converting it used
// to recurse without end: the loader, and the write gate of a
// `transaction: true` flow, overflowed the stack and took the process down.
func TestRunIfLoadsAsAnIfBlock(t *testing.T) {
	steps := `      - id: gate
        query: "SELECT :go AS go"
        params: { go: "${{ params.go | default:'0' }}" }
      - run: if
        if: ${{ steps.gate.outputs.go }} == 1
        steps:
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('then')" }
        else:
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('else')" }
`
	for _, onRequest := range []string{"", "    transaction: true\n"} {
		source := expectRowsFlow(onRequest, steps)
		if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
			t.Fatalf("write gate refused `run: if` with a condition: %s", msg)
		}
		for query, want := range map[string]string{"?go=1": "then", "": "else"} {
			app := expectRowsApp(t)
			flow := parseExpectRowsFlow(t, app, source)
			if len(flow.Steps) != 3 || flow.Steps[1].Type != "if" || len(flow.Steps[1].Steps) != 1 || len(flow.Steps[1].ElseSteps) != 1 {
				t.Fatalf("`run: if` loaded as %+v", flow.Steps[1])
			}
			if rr, err := runStepKeyFlow(t, app, source, query); err != nil || rr.Code != http.StatusOK {
				t.Fatalf("flow failed: %v (status %d)", err, rr.Code)
			}
			if got := expectRowsInt(t, app, `SELECT COUNT(*) FROM log WHERE note = '`+want+`'`); got != 1 || expectRowsInt(t, app, `SELECT COUNT(*) FROM log`) != 1 {
				t.Errorf("request %q: the %s branch did not run alone", query, want)
			}
		}
	}
}

// A step-level `timeout:` on `run: compute` caps the function, as it does an
// api call; it wins over `with.timeout`. It used to be accepted and never
// applied: the function ran to the 5-second default (or to `with.timeout`).
func TestComputeStepLevelTimeoutIsApplied(t *testing.T) {
	for name, step := range map[string]string{
		"step level only":           "      - id: c\n        run: compute\n        timeout: 200ms\n        with: { module: loop, function: spin, args: {} }\n",
		"step level over with":      "      - id: c\n        run: compute\n        timeout: 200ms\n        with: { module: loop, function: spin, args: {}, timeout: 20s }\n",
		"with only, as it was read": "      - id: c\n        run: compute\n        with: { module: loop, function: spin, args: {}, timeout: 200ms }\n",
	} {
		t.Run(name, func(t *testing.T) {
			app := expectRowsApp(t)
			if err := os.MkdirAll(filepath.Join(app.Dir, "static"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(app.Dir, "static", "loop.ts"), []byte("export function spin(): never { while (true) {} }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			source := stepKeyFlow(step)
			if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
				t.Fatalf("write gate: %s", msg)
			}
			start := time.Now()
			rr, err := runExpectRowsFlow(t, app, source)
			elapsed := time.Since(start)
			if err == nil || !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("flow error = %v (status %d), want the compute timeout", err, rr.Code)
			}
			// 200ms, with room for a slow machine; the default is 5s.
			if elapsed > 3*time.Second {
				t.Errorf("the function ran %s: the 200ms timeout was not applied", elapsed)
			}
		})
	}
}
