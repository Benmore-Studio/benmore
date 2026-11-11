//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sql_dynamic write gate told authors to use `{{steps.<id>.<field>}}`,
// which never resolves: the reference stayed in the SQL as text, so an
// unquoted one failed in SQLite as "unrecognized token: [redacted]" (the
// credential redaction reads `token: "{"` as a secret) and a quoted one ran
// the statement and only then failed (round 2026-11-05 logic finding 9). The
// gate now names `${{ steps.<id>.outputs.<column> }}`, and an unresolved
// reference fails the step before the statement runs, naming the reference.
func TestSQLDynamicUnresolvedReferenceFailsBeforeRunning(t *testing.T) {
	msg := validateSQLDynamicSafetyAt("lab", "step 0", FlowStepGHA{Run: "sql_dynamic", Query: "SELECT '{{q}}' AS v"})
	if !strings.Contains(msg, "`${{ steps.<id>.outputs.<column> }}`") || strings.Contains(msg, "{{steps.<id>.<field>}}") {
		t.Fatalf("write-gate message: %s", msg)
	}

	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE memos (id INTEGER PRIMARY KEY, title TEXT)")
	ctx := &FlowContext{App: app, Data: map[string]any{"cnt": []map[string]any{{"tbl": "memos"}}}, Params: map[string]string{}}
	err := execStepSQLDynamic(ctx, &FlowStep{Name: "ins", Type: "sql_dynamic", SQL: "INSERT INTO memos (title) VALUES ('{{steps.cnt.tbl}}')"})
	if err == nil || !strings.Contains(err.Error(), "unresolved template reference") || !strings.Contains(err.Error(), "steps.cnt.tbl") {
		t.Fatalf("quoted unresolved reference: %v", err)
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM memos").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the statement ran with the reference as text: %d rows (%v)", n, err)
	}
	// The documented form resolves and runs.
	if err := execStepSQLDynamic(ctx, &FlowStep{Name: "ok", Type: "sql_dynamic", SQL: "SELECT COUNT(*) AS n FROM {{ cnt.tbl }}"}); err != nil {
		t.Fatalf("resolved reference: %v", err)
	}
}

func TestSQLDynamicUnresolvedReferenceAnswer(t *testing.T) {
	f := newServerErrorFixture(t, true)
	run := func(query string) map[string]any {
		t.Helper()
		flows, err := parseGHAFlowFile("flows/dyn.yaml", []byte(`on:
  request: {method: POST, path: /api/dyn}
jobs:
  main:
    steps:
      - id: cnt
        run: sql
        query: "SELECT 'notes' AS tbl"
      - id: a
        run: sql_dynamic
        query: "`+query+`"
      - run: respond
        with: {json: {n: "${{ steps.a.outputs.first.n }}"}}
`))
		if err != nil {
			t.Fatal(err)
		}
		f.handler = func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, &flows[0], w, r) }
		r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/dyn", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		captureLog(t, func() { f.logged.ServeHTTP(w, r) })
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: status %d %s", query, w.Code, w.Body.String())
		}
		_, diag := flowFailureAnswer(t, w)
		return diag
	}

	diag := run("SELECT COUNT(*) AS n FROM {{steps.cnt.tbl}}")
	if stepErr, _ := diag["step_error"].(string); !strings.Contains(stepErr, "unresolved template reference") || !strings.Contains(stepErr, "steps.cnt.tbl") || strings.Contains(stepErr, "[redacted]") {
		t.Fatalf("step_error = %q", stepErr)
	}
	if hint, _ := diag["hint"].(string); !strings.Contains(hint, "${{ steps.<id>.outputs.<column> }}") {
		t.Fatalf("hint = %q", diag["hint"])
	}

	// SQLite's own "unrecognized token" stays redacted (sql_dynamic text can
	// hold env values and row data); the hint says what usually causes it.
	diag = run("SELECT COUNT(*) AS n FROM notes WHERE {x}")
	stepErr, _ := diag["step_error"].(string)
	if !strings.Contains(stepErr, "unrecognized token: [redacted]") {
		t.Fatalf("step_error = %q", stepErr)
	}
	if hint, _ := diag["hint"].(string); !strings.Contains(hint, "redacted") || !strings.Contains(hint, "{{") || !strings.Contains(hint, "${{ steps.<id>.outputs.<column> }}") {
		t.Fatalf("hint = %q", diag["hint"])
	}
}
