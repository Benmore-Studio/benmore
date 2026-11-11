//go:build !cli

package main

// A comparison operand the author wrote as a reference, and that has no value
// when the flow runs, never equals what a request sent.
//
// The right-hand side of a single comparison was rendered like any template,
// so a reference with no value stayed as its own text (`{{t.token}}`) and a
// caller who sent that text as the other side matched it: a token check
// against a row that does not exist was passed by sending the placeholder.
// A missing step output on the left, and in a joined condition on either
// side, compared as empty, which an empty or omitted token matched the same
// way.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// unresolvedCondCtx is a flow context holding data, with the flow's own names
// (step ids) marked the way a request flow marks them.
func unresolvedCondCtx(data map[string]any, stepIDs ...string) *FlowContext {
	ctx := &FlowContext{Data: data, Params: map[string]string{}}
	ctx.requestOnlyParams = map[string]bool{}
	for _, id := range stepIDs {
		ctx.requestOnlyParams[id] = true
	}
	return ctx
}

type unresolvedCondCase struct {
	// cond is the author's `if:` text.
	cond string
	data map[string]any
	want bool
}

func runUnresolvedCondCases(t *testing.T, cases []unresolvedCondCase) {
	t.Helper()
	for _, c := range cases {
		ctx := unresolvedCondCtx(c.data, "t", "u", "row")
		if got := evaluateFlowCondition(ghaIfToFlowCondition(c.cond), ctx); got != c.want {
			t.Errorf("`if: %s` with %v = %v, want %v", c.cond, c.data, got, c.want)
		}
	}
}

// row is a step that returned one row; t and u are steps that returned none.
func condData(fields map[string]any) map[string]any {
	data := map[string]any{"row": map[string]any{"token": "abc", "note": "", "n": 5}}
	for k, v := range fields {
		data[k] = v
	}
	return data
}

func TestUnresolvedReferenceNeverEqualsAValue(t *testing.T) {
	const placeholder = "{{t.token}}"
	runUnresolvedCondCases(t, []unresolvedCondCase{
		// The token check: the lookup found no row.
		{"${{ params.token }} == ${{ steps.t.outputs.token }}", condData(map[string]any{"token": placeholder}), false},
		{"${{ params.token }} == ${{ steps.t.outputs.token }}", condData(map[string]any{"token": ""}), false},
		{"${{ params.token }} == ${{ steps.t.outputs.token }}", condData(nil), false},
		{"${{ params.token == steps.t.outputs.token }}", condData(map[string]any{"token": placeholder}), false},
		{"${{ params.token }} != ${{ steps.t.outputs.token }}", condData(map[string]any{"token": placeholder}), true},
		{"${{ params.token }} != ${{ steps.t.outputs.token }}", condData(map[string]any{"token": "x"}), true},
		{"${{ params.token }} != ${{ steps.t.outputs.token }}", condData(nil), true},
		// The same check written the other way round: an empty or omitted
		// token matched the missing step output.
		{"${{ steps.t.outputs.token }} == ${{ params.token }}", condData(map[string]any{"token": ""}), false},
		{"${{ steps.t.outputs.token }} == ${{ params.token }}", condData(map[string]any{"token": "x"}), false},
		{"${{ steps.t.outputs.token }} == ${{ params.token }}", condData(nil), false},
		{"${{ steps.t.outputs.token }} != ${{ params.token }}", condData(map[string]any{"token": ""}), true},
		{"${{ steps.t.outputs.token }} != ${{ params.token }}", condData(map[string]any{"token": "x"}), true},
		// A real match, and a real mismatch, are what they were.
		{"${{ params.token }} == ${{ steps.row.outputs.token }}", condData(map[string]any{"token": "abc"}), true},
		{"${{ params.token }} == ${{ steps.row.outputs.token }}", condData(map[string]any{"token": "abd"}), false},
		{"${{ params.token }} != ${{ steps.row.outputs.token }}", condData(map[string]any{"token": "abc"}), false},
		{"${{ params.token }} != ${{ steps.row.outputs.token }}", condData(map[string]any{"token": "abd"}), true},
		{"${{ steps.row.outputs.token }} == ${{ params.token }}", condData(map[string]any{"token": "abc"}), true},
		// Both sides without a value are not equal.
		{"${{ steps.t.outputs.a }} == ${{ steps.u.outputs.b }}", condData(nil), false},
		{"${{ steps.t.outputs.a }} != ${{ steps.u.outputs.b }}", condData(nil), true},
		{"${{ params.a }} == ${{ params.b }}", condData(nil), false},
		{"${{ params.a }} != ${{ params.b }}", condData(nil), true},
		// A reference with a pipe and no fallback was compared as its text too.
		{"${{ steps.t.outputs.token | upper }} == ${{ params.token }}", condData(map[string]any{"token": "{{t.token | upper}}"}), false},
		{"${{ steps.t.outputs.token | upper }} != ${{ params.token }}", condData(map[string]any{"token": "{{t.token | upper}}"}), true},
		// Ordering against a reference with no value is false.
		{"${{ params.n }} < ${{ steps.t.outputs.max }}", condData(map[string]any{"n": "abc"}), false},
		{"${{ params.n }} <= ${{ steps.t.outputs.max }}", condData(map[string]any{"n": ""}), false},
		{"${{ params.n }} > ${{ steps.t.outputs.max }}", condData(map[string]any{"n": "~"}), false},
		{"${{ params.n }} >= ${{ steps.t.outputs.max }}", condData(map[string]any{"n": "5"}), false},
		// A step output with no value against a request field, with any operator.
		{"${{ steps.t.outputs.n }} < ${{ params.n }}", condData(map[string]any{"n": "5"}), false},
		{"${{ steps.t.outputs.n }} >= ${{ params.n }}", condData(map[string]any{"n": ""}), false},
	})
}

// What is documented and relied on stays: a missing value compares as empty
// against a literal, a missing request field on the left compares as empty
// against anything, and a value is a value whatever it looks like.
func TestMissingValuesKeepTheirDocumentedReading(t *testing.T) {
	runUnresolvedCondCases(t, []unresolvedCondCase{
		// Optional request field against a literal.
		{"${{ params.x }} == ''", condData(nil), true},
		{"${{ params.x }} != ''", condData(nil), false},
		{"${{ params.x }} == 'yes'", condData(nil), false},
		{"${{ params.x }} != 'yes'", condData(nil), true},
		// A step output with no row against a literal ("no row" checks).
		{"${{ steps.t.outputs.id }} == ''", condData(nil), true},
		{"${{ steps.t.outputs.id }} != ''", condData(nil), false},
		{"${{ steps.t.outputs.status }} == 'paid'", condData(nil), false},
		{"${{ steps.t.outputs.status }} != 'paid'", condData(nil), true},
		// A value that is empty is a value.
		{"${{ steps.row.outputs.note }} == ''", condData(nil), true},
		{"${{ steps.row.outputs.note }} == ${{ params.note }}", condData(map[string]any{"note": ""}), true},
		{"${{ params.note }} == ${{ steps.row.outputs.note }}", condData(map[string]any{"note": ""}), true},
		// A missing request field on the left still compares as empty.
		{"${{ params.note }} == ${{ steps.row.outputs.note }}", condData(nil), true},
		{"${{ params.a }} == ${{ params.b }}", condData(map[string]any{"b": ""}), true},
		{"${{ params.a }} != ${{ params.b }}", condData(map[string]any{"b": "x"}), true},
		{"${{ params.n }} < ${{ steps.row.outputs.n }}", condData(nil), true},
		// A step output with no value against another step's value, and against
		// a request field the author gave a fallback, is empty as before
		// (an "expected version" check on a row that does not exist yet).
		{"${{ steps.t.outputs.fingerprint }} != ${{ steps.row.outputs.token }}", condData(nil), true},
		{"${{ steps.t.outputs.fingerprint }} != ${{ steps.row.outputs.note }}", condData(nil), false},
		{"${{ steps.t.outputs.fingerprint }} == ${{ steps.row.outputs.note }}", condData(nil), true},
		{"${{ steps.t.outputs.n }} < ${{ steps.row.outputs.n }}", condData(nil), true},
		{"${{ steps.t.outputs.remind_at }} != ${{ params.expected | default:'' }}", condData(nil), false},
		{"${{ steps.t.outputs.remind_at }} != ${{ params.expected | default:'' }}", condData(map[string]any{"expected": "2026-01-01"}), true},
		{"${{ steps.t.outputs.remind_at }} == ${{ params.expected || '' }}", condData(nil), true},
		// A fallback gives a value.
		{"${{ params.token }} == ${{ steps.t.outputs.token || '' }}", condData(map[string]any{"token": ""}), true},
		{"${{ params.token }} == ${{ steps.t.outputs.token | default:'none' }}", condData(map[string]any{"token": "none"}), true},
		{"${{ steps.t.outputs.token | default:'' }} == ${{ params.token }}", condData(map[string]any{"token": ""}), true},
		// A value that looks like a reference is only ever a value.
		{"${{ params.a }} == ${{ params.b }}", condData(map[string]any{"a": "{{t.token}}", "b": "{{t.token}}"}), true},
		{"${{ params.a }} == ${{ steps.row.outputs.token }}", condData(map[string]any{"a": "{{row.token}}"}), false},
		{"${{ params.a }} == ${{ params.b }}", condData(map[string]any{"a": "{{params.b}}"}), false},
		{"${{ params.a }} != ${{ params.b }}", condData(map[string]any{"a": "!=x", "b": "!=x"}), false},
		// Numbers and text order as before.
		{"${{ params.n }} > ${{ steps.row.outputs.n }}", condData(map[string]any{"n": "10"}), true},
		{"${{ params.n }} < ${{ steps.row.outputs.n }}", condData(map[string]any{"n": "10"}), false},
	})
}

// `&&`, `||`, `!` and parentheses compose over the same comparisons. A joined
// condition used to read every missing value as empty, so an omitted token
// matched a row that does not exist.
func TestUnresolvedReferenceInAJoinedCondition(t *testing.T) {
	runUnresolvedCondCases(t, []unresolvedCondCase{
		{"${{ params.token }} == ${{ steps.t.outputs.token }} && ${{ params.go }} == 'yes'", condData(map[string]any{"go": "yes"}), false},
		{"${{ params.token }} == ${{ steps.t.outputs.token }} && ${{ params.go }} == 'yes'", condData(map[string]any{"go": "yes", "token": ""}), false},
		{"${{ steps.t.outputs.token == params.token && params.go == 'yes' }}", condData(map[string]any{"go": "yes", "token": ""}), false},
		{"${{ steps.t.outputs.token == params.token && params.go == 'yes' }}", condData(map[string]any{"go": "yes"}), false},
		{"${{ params.token }} == ${{ steps.row.outputs.token }} && ${{ params.go }} == 'yes'", condData(map[string]any{"go": "yes", "token": "abc"}), true},
		{"${{ params.token }} == ${{ steps.row.outputs.token }} && ${{ params.go }} == 'yes'", condData(map[string]any{"go": "no", "token": "abc"}), false},
		{"${{ params.token }} == ${{ steps.t.outputs.token }} || ${{ params.admin }} == 'yes'", condData(nil), false},
		{"${{ params.token }} == ${{ steps.t.outputs.token }} || ${{ params.admin }} == 'yes'", condData(map[string]any{"admin": "yes"}), true},
		{"!(${{ params.token }} == ${{ steps.t.outputs.token }})", condData(nil), true},
		{"!(${{ params.token }} == ${{ steps.row.outputs.token }})", condData(map[string]any{"token": "abc"}), false},
		{"(${{ params.token }} != ${{ steps.t.outputs.token }})", condData(nil), true},
		{"(${{ params.token }} != ${{ steps.t.outputs.token }})", condData(map[string]any{"token": ""}), true},
		{"(${{ steps.t.outputs.token || 'none' }} == ${{ params.token }})", condData(map[string]any{"token": "none"}), true},
		{"(${{ steps.t.outputs.token || steps.u.outputs.token }} == ${{ params.token }})", condData(map[string]any{"token": ""}), false},
		{"${{ steps.t.outputs.n }} < ${{ params.n }} && ${{ params.go }} == 'yes'", condData(map[string]any{"n": "5", "go": "yes"}), false},
		// Two step outputs keep the reading a joined condition gives them:
		// missing is empty, so two missing values are equal (an "expected
		// version" check where neither exists yet takes the same branch).
		{"(${{ steps.t.outputs.a }} == ${{ steps.u.outputs.b }})", condData(nil), true},
		{"(${{ steps.t.outputs.a }} != ${{ steps.u.outputs.b }})", condData(nil), false},
		{"(${{ steps.t.outputs.n }} < ${{ steps.row.outputs.n }})", condData(nil), true},
		{"(${{ steps.t.outputs.token }} == ${{ params.token | default:'' }})", condData(nil), true},
		// Documented readings inside a joined condition.
		{"(${{ params.x }} == '')", condData(nil), true},
		{"(${{ steps.t.outputs.id }} == '')", condData(nil), true},
		{"('' == ${{ steps.t.outputs.id }})", condData(nil), true},
		{"(${{ steps.t.outputs.id }} != '')", condData(nil), false},
		{"(${{ params.a }} == ${{ params.b }})", condData(nil), true},
		{"${{ steps.t.outputs.status }} >= 200 && ${{ steps.t.outputs.status }} < 300", condData(nil), false},
		{"${{ steps.row.outputs.n }} >= 1 && ${{ steps.row.outputs.n }} < 10", condData(nil), true},
		{"${{ !steps.t.outputs.rows }}", condData(nil), true},
	})
}

// `success_when:` shares the evaluator: its text is the author's, with the
// reference still in braces on the left.
func TestSuccessWhenWithAnUnresolvedReference(t *testing.T) {
	for _, c := range []struct {
		when string
		data map[string]any
		want bool
	}{
		{"${{ steps.t.outputs.status }} == 'ok'", nil, false},
		{"${{ steps.t.outputs.status }} != 'error'", nil, true},
		{"${{ steps.t.outputs.status }} == ${{ params.expected }}", map[string]any{"expected": "{{t.status}}"}, false},
		{"${{ steps.t.outputs.status }} != ${{ params.expected }}", map[string]any{"expected": "{{t.status}}"}, true},
		{"${{ steps.row.outputs.token }} == 'abc'", nil, true},
		{"${{ steps.row.outputs.token }} == ${{ params.expected }}", map[string]any{"expected": "abc"}, true},
	} {
		ctx := unresolvedCondCtx(condData(c.data), "t", "row")
		if got := evaluateFlowCondition(normalizeGHARefs(c.when), ctx); got != c.want {
			t.Errorf("`success_when: %s` with %v = %v, want %v", c.when, c.data, got, c.want)
		}
	}
}

const tokenFlowHead = `on:
  request:
    method: POST
    path: /api/redeem
jobs:
  redeem:
    steps:
      - id: t
        run: sql
        with: { query: "SELECT token FROM tokens WHERE id = :id" }
`

// The reported case, through a request: a token lookup that finds no row and
// a caller who sends the text of the unresolved reference as the token.
func TestTokenCheckAgainstARowThatDoesNotExist(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE tokens (id INTEGER PRIMARY KEY, token TEXT)`)
	mustExec(t, app.DB, `INSERT INTO tokens (id, token) VALUES (1, 'real-secret')`)
	const grant = "        steps:\n          - run: respond\n            with: { status: 200, json: { granted: true } }\n      - run: respond\n        with: { status: 403, json: { error: forbidden } }\n"
	const deny = "        run: respond\n        with: { status: 403, json: { error: forbidden } }\n      - run: respond\n        with: { status: 200, json: { granted: true } }\n"
	shapes := []struct{ name, flow string }{
		{"== takes the allowing branch", tokenFlowHead + "      - if: ${{ params.token }} == ${{ steps.t.outputs.token }}\n" + grant},
		{"== inside one span", tokenFlowHead + "      - if: ${{ params.token == steps.t.outputs.token }}\n" + grant},
		{"== with the step output on the left", tokenFlowHead + "      - if: ${{ steps.t.outputs.token }} == ${{ params.token }}\n" + grant},
		{"== joined with another test", tokenFlowHead + "      - if: ${{ params.token }} == ${{ steps.t.outputs.token }} && ${{ params.go }} != 'no'\n" + grant},
		{"!= guards the rest of the flow", tokenFlowHead + "      - if: ${{ params.token }} != ${{ steps.t.outputs.token }}\n" + deny},
		{"!= with the step output on the left", tokenFlowHead + "      - if: ${{ steps.t.outputs.token }} != ${{ params.token }}\n" + deny},
		{"!= inside a joined condition", tokenFlowHead + "      - if: ${{ params.token }} != ${{ steps.t.outputs.token }} || ${{ params.go }} == 'no'\n" + deny},
	}
	for _, shape := range shapes {
		for _, c := range []struct {
			body    string
			granted bool
		}{
			{`{"id":1,"token":"real-secret"}`, true},
			{`{"id":1,"token":"wrong"}`, false},
			{`{"id":1,"token":""}`, false},
			{`{"id":1}`, false},
			{`{"id":99,"token":"wrong"}`, false},
			{`{"id":99,"token":"{{t.token}}"}`, false},
			{`{"id":99,"token":""}`, false},
			{`{"id":99}`, false},
		} {
			rr := runProbeGHAFlow(t, app, shape.flow, c.body)
			granted := rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), `"granted":true`)
			if granted != c.granted {
				t.Errorf("%s: %s -> %d %s, want granted=%v", shape.name, c.body, rr.Code, firstLine(rr.Body.String()), c.granted)
			}
			// A refused caller is refused or the flow fails; it is never let through.
			if !c.granted && rr.Code == http.StatusOK {
				t.Errorf("%s: %s answered 200", shape.name, c.body)
			}
		}
	}
}

// A `!=` guard answers every ordinary input as it did: only the caller who
// sends the placeholder text now gets the guard's own answer.
func TestNotEqualGuardAnswersOrdinaryInputsAsBefore(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE tokens (id INTEGER PRIMARY KEY, token TEXT)`)
	mustExec(t, app.DB, `INSERT INTO tokens (id, token) VALUES (1, 'real-secret')`)
	flow := tokenFlowHead + "      - if: ${{ params.token }} != ${{ steps.t.outputs.token }}\n        run: respond\n        with: { status: 403, json: { error: forbidden } }\n      - run: respond\n        with: { status: 200, json: { granted: true } }\n"
	for body, want := range map[string]int{
		`{"id":1,"token":"real-secret"}`: 200,
		`{"id":1,"token":"wrong"}`:       403,
		`{"id":1}`:                       403,
		`{"id":99,"token":"wrong"}`:      403,
		`{"id":99,"token":""}`:           403,
		`{"id":99}`:                      403,
		// The one input that answers differently: it was a 500.
		`{"id":99,"token":"{{t.token}}"}`: 403,
	} {
		if rr := runProbeGHAFlow(t, app, flow, body); rr.Code != want {
			t.Errorf("%s -> %d %s, want %d", body, rr.Code, firstLine(rr.Body.String()), want)
		}
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120]
	}
	return fmt.Sprintf("%q", s)
}
