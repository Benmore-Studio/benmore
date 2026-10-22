//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var shadowWarnedStepRe = regexp.MustCompile(`step id "([^"]+)" shadows`)

func shadowWarnedSteps(content string) []string {
	var ids []string
	for _, w := range ghaStepShadowWarnings(content) {
		if m := shadowWarnedStepRe.FindStringSubmatch(w); m != nil {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// The shapes of the two _platform flows 2.7.248 silently broke (reduced):
// slack_events read `${{ challenge }}` inside step `challenge`, and
// deliverable_submit read `${{ note }}` inside step `note`. Both must warn,
// for exactly those steps, without being refused.
func TestStepShadowWarnsOnBrokenPlatformShapes(t *testing.T) {
	for file, want := range map[string]string{"slack_events.yaml": "challenge", "deliverable_submit.yaml": "note"} {
		data, err := os.ReadFile(filepath.Join("testdata", "step_shadowing", file))
		if err != nil {
			t.Fatal(err)
		}
		if got := shadowWarnedSteps(string(data)); !slices.Equal(got, []string{want}) {
			t.Errorf("%s: warned steps %v, want [%s]", file, got, want)
		}
		if msg := ValidateOnWrite("flows/"+file, string(data)); msg != "" {
			t.Errorf("%s: the warning must not refuse the write: %s", file, msg)
		}
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "flows", file), data, 0o644); err != nil {
			t.Fatal(err)
		}
		findings := redirectWarnings(dir)
		if len(findings) != 1 || findings[0].Severity != "warning" || !strings.Contains(findings[0].Message, "${{ params."+want+" }}") {
			t.Errorf("%s: benmore check findings %+v", file, findings)
		}
	}
}

func TestStepShadowCases(t *testing.T) {
	flow := func(request, steps string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/x\n" + request + "jobs:\n  x:\n    steps:\n" + steps
	}
	warn := map[string]string{
		"input":     flow("    inputs:\n      code: { type: text }\n", "      - id: code\n        query: SELECT 1\n"),
		"dotted":    flow("", "      - id: coupon\n        if: ${{ coupon.code }}\n        query: SELECT 1 AS d\n"),
		"bind":      flow("", "      - id: note\n        query: UPDATE t SET n = :note\n"),
		"earlier":   flow("", "      - if: ${{ gate == 'x' && params.b }}\n        run: respond\n        with: { status: 200 }\n      - id: gate\n        query: SELECT 1\n"),
		"nested":    flow("", "      - if: ${{ inner }}\n        steps:\n          - id: inner\n            query: SELECT 1\n"),
		"block sql": flow("", "      - id: note\n        run: sql\n        with:\n          query: |\n            UPDATE t\n               SET n = :note\n"),
	}
	for name, content := range warn {
		if len(shadowWarnedSteps(content)) != 1 {
			t.Errorf("%s: expected one warning, got %v", name, ghaStepShadowWarnings(content))
		}
	}
	quiet := map[string]string{
		"namespaced": flow("", "      - id: note\n        query: SELECT 1 AS n\n      - run: respond\n        with: { body: { n: \"${{ steps.note.outputs.n }}\", p: \"${{ params.note }}\", e: \"${{ env.note }}\", u: \"${{ user.note }}\" } }\n"),
		"local bind": flow("", "      - id: note\n        run: sql\n        with:\n          query: UPDATE t SET n = :val\n          params: { val: \"${{ params.note }}\" }\n"),
		"own param":  flow("", "      - id: note\n        query: UPDATE t SET n = :note\n        params: { note: \"${{ params.note }}\" }\n"),
		"with param": flow("", "      - id: note\n        run: sql\n        with:\n          query: UPDATE t SET n = :note\n          params:\n            note: \"${{ params.note }}\"\n"),
		"comment":    flow("", "      # reads ${{ note }} in a comment\n      - id: note\n        query: SELECT 1\n"),
		"pipe arg":   flow("", "      - id: fallback\n        query: SELECT 1\n      - run: respond\n        with: { body: { v: \"${{ params.v | default:fallback }}\" } }\n"),
		"literal":    flow("", "      - id: paid\n        query: SELECT 1\n      - if: ${{ params.status == 'paid' }}\n        run: respond\n        with: { status: 200 }\n"),
		"sql text":   flow("", "      - id: note\n        query: SELECT ':note' AS a, '10:30' AS t\n"),
		"no request": flow("", "      - id: rows\n        query: SELECT 1\n      - run: respond\n        with: { body: { r: \"${{ steps.rows.outputs.rows }}\" } }\n"),
		// Reading the step's output by bare name after it ran is the
		// legacy output form (_platform enqueue_extraction/release_window).
		"after": flow("", "      - id: enq\n        query: UPDATE t SET a = 1\n      - run: respond\n        with: { body: { q: \"${{ enq.rows_affected | default:'0' }}\", v: \"{{enq}}\" } }\n"),
	}
	for name, content := range quiet {
		if w := ghaStepShadowWarnings(content); len(w) != 0 {
			t.Errorf("%s: unexpected warning %v", name, w)
		}
	}
}

// The current _platform flows were renamed after 2.7.248 (commit 454bdab4 on
// fix/security-round-10); none may still shadow a request field.
func TestPlatformFlowsDoNotShadowRequestFields(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("apps", "_platform", "flows", "*.yaml"))
	if len(files) == 0 {
		t.Skip("no _platform flows in this checkout")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if w := ghaStepShadowWarnings(string(data)); len(w) != 0 {
			t.Errorf("%s: %v", f, w)
		}
	}
}
