//go:build !cli

package main

import (
	"strings"
	"testing"
)

// TestSQLDynamicSafetyCoversNestedSteps pins item 21: the write-time
// sql_dynamic check used to scan only top-level steps, so the same injectable
// query passed validation once it was wrapped in an if/for_each/parallel body,
// an else branch or an on_error handler. Both entry points (write-time
// ValidateOnWrite and `benmore check` via RunCompleteCheck) share the
// dispatcher and must reject every placement.
func TestSQLDynamicSafetyCoversNestedSteps(t *testing.T) {
	const head = "on:\n  request:\n    method: POST\n    path: /api/search\njobs:\n  search:\n    steps:\n"
	const bad = "run: sql_dynamic\n          with: { query: \"SELECT * FROM notes WHERE body = '{{q}}'\" }\n"
	cases := map[string]string{
		"if steps": head +
			"      - if: ${{ params.q }}\n        steps:\n        - " + bad +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
		"else": head +
			"      - if: ${{ params.none }}\n        steps:\n        - run: respond\n          with: { status: 200, body: { ok: true } }\n        else:\n        - " + bad +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
		"for_each": head +
			"      - id: rows\n        query: SELECT 1 AS n\n      - for_each: ${{ steps.rows.outputs.rows }}\n        steps:\n        - " + bad +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
		"parallel": head +
			"      - run: parallel\n        steps:\n        - " + bad +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
		"on_error": head +
			"      - id: first\n        query: SELECT 1 AS n\n        on_error:\n        - " + bad +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
		"deep": head +
			"      - if: ${{ params.q }}\n        steps:\n        - run: parallel\n          steps:\n          - id: x\n            query: SELECT 1\n            on_error:\n            - run: sql_dynamic\n              query: \"DELETE FROM notes WHERE id = :id\"\n" +
			"      - run: respond\n        with: { status: 200, body: { ok: true } }\n",
	}
	for name, content := range cases {
		msg := ValidateOnWrite("flows.yaml", content)
		if !strings.Contains(msg, "sql_dynamic") || !strings.Contains(msg, " > ") {
			t.Errorf("%s: write-time validator must reject nested sql_dynamic with its path, got: %q", name, msg)
		}

		dir := writeApp(t, map[string]string{
			"app.yaml":      "seo:\n  site_name: T\n",
			"schema.prisma": "model Note {\n  id   Int    @id @default(autoincrement())\n  body String\n}\n",
			"flows.yaml":    content,
		})
		rpt := RunCompleteCheck(dir, "")
		found := false
		for _, f := range rpt.Findings {
			if f.Severity == "error" && f.File == "flows.yaml" && strings.Contains(f.Message, "sql_dynamic") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: benmore check must flag nested sql_dynamic, got:\n%s", name, FormatReport(rpt))
		}
	}

	// Server-trusted namespaced refs remain allowed when nested.
	ok := head +
		"      - id: ai\n        query: SELECT 'SELECT 1' AS query\n      - if: ${{ steps.ai.outputs.query }}\n        steps:\n        - run: sql_dynamic\n          query: \"{{ steps.ai.outputs.query }}\"\n" +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
	if msg := ValidateOnWrite("flows.yaml", ok); strings.Contains(msg, "sql_dynamic") {
		t.Errorf("nested sql_dynamic with a step-output ref should pass, got: %s", msg)
	}
}
