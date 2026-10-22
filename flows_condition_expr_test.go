//go:build !cli

package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evaluateFlowCondition246 and ghaIfToFlowCondition246 are the 2.7.246
// condition path, kept verbatim as the reference the compatibility table
// below compares against.
func evaluateFlowCondition246(condition string, ctx *FlowContext) bool {
	flat := flatDataForCtx(ctx)
	row := make(map[string]any)
	for k, v := range flat {
		row[k] = v
	}
	if lhs, op, rhs, ok := splitConditionOperator(condition); ok && lhs != "" {
		if strings.Contains(lhs, "&&") || conditionHasConnective(rhs) {
			return false
		}
		rhs = strings.Trim(interpolateCtx(rhs, ctx), `"'`)
		if conditionLHSNeedsResolution(lhs) {
			expr := lhs
			if !strings.Contains(expr, "{{") {
				expr = "{{" + expr + "}}"
			}
			return compareLiteralCondition(interpolateCtx(expr, ctx), op, rhs)
		}
		if !conditionFieldName(lhs) {
			return false
		}
		return compareLiteralCondition(conditionRowValue(row, lhs), op, rhs)
	}
	key := strings.TrimSpace(condition)
	if v, ok := flowLookup(row, key); ok {
		return isTruthyCondition(v)
	}
	if strings.Contains(key, "{{") {
		return isTruthyCondition(strings.TrimSpace(interpolateCtx(condition, ctx)))
	}
	if v, ok := resolveBindExpr(key, flatDataForCtx(ctx)); ok {
		return isTruthyCondition(v)
	}
	return conditionLiteralTruthy(key)
}

func ghaIfToFlowCondition246(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "${{") && strings.HasSuffix(expr, "}}") &&
		strings.Count(expr, "${{") == 1 {
		expr = strings.TrimSpace(expr[3 : len(expr)-2])
	}
	for _, op := range []string{"!=", "==", ">=", "<=", "=", ">", "<"} {
		idx := strings.Index(expr, op)
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+len(op):])
		_, leftBare := unwrapGHA(left)
		rightWasRef, rightBare := unwrapGHA(right)
		leftKey := translateGHAExpr(leftBare)
		rightVal := translateGHAExpr(rightBare)
		rightForEvaluator := rightVal
		if rightWasRef {
			rightForEvaluator = "{{" + rightVal + "}}"
		}
		if op == "==" {
			op = "="
		}
		return fmt.Sprintf("%s %s %s", leftKey, op, rightForEvaluator)
	}
	_, bare := unwrapGHA(expr)
	return translateGHAExpr(bare)
}

// conditionTestContexts are flow states the condition tables run against.
func conditionTestContexts(app *App) []*FlowContext {
	mk := func(data map[string]any) *FlowContext {
		return &FlowContext{App: app, Data: data, Params: map[string]string{}}
	}
	return []*FlowContext{
		mk(map[string]any{
			"call":   map[string]any{"status": int64(204), "body": "ok"},
			"invite": []map[string]any{{"code": "S3CRET", "n": int64(50)}},
			"none":   []map[string]any{},
			"gate":   map[string]any{"ok": true, "no": false},
			"user":   map[string]any{"id": int64(5), "email": "a@b.c"},
			"a":      "",
			"b":      "B",
			"code":   "S3CRET",
			"dl":     "1",
			"zero":   "0",
			"weird":  "!=x",
		}),
		mk(map[string]any{
			"call":   map[string]any{"status": int64(500), "body": ""},
			"invite": []map[string]any{{"code": "OTHER", "n": int64(9)}},
			"none":   []map[string]any{},
			"gate":   map[string]any{"ok": false, "no": true},
			"a":      "A",
			"b":      "",
			"code":   "wrong",
			"dl":     "0",
		}),
		mk(map[string]any{}),
	}
}

// Every condition that is one comparison or operator-less evaluates
// exactly as in 2.7.246: it is routed to the single-comparison evaluator,
// translated the same way, and gives the same result in every context.
func TestFlowConditionSingleComparisonShapesUnchanged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	shapes := []string{
		"${{ steps.call.outputs.status }} == 204",
		"${{ steps.call.outputs.status }} == '204'",
		"${{ steps.call.outputs.status }} != 204",
		"${{ steps.call.outputs.status }} >= 200",
		"${{ steps.call.outputs.status }} <= 204",
		"${{ steps.call.outputs.status }} > 99",
		"${{ steps.call.outputs.status }} < 300",
		"${{ steps.call.outputs.status }}==204",
		"${{ steps.call.outputs.status == 204 }}",
		"${{ steps.call.outputs.body }} == 'ok'",
		"${{ steps.invite.outputs.code }} == ${{ params.code }}",
		"${{ steps.invite.outputs.n }} >= 10",
		"${{ steps.invite.outputs.rows | length }} > 0",
		"${{ steps.none.outputs.rows | length }} == 0",
		"${{ params.code }} == 'S3CRET'",
		"${{ params.code }} == \"S3CRET\"",
		"${{ params.code }} = 'S3CRET'",
		"${{ params.b }} == B",
		"${{ params.a }} == ''",
		"${{ params.a }} != ''",
		"${{ params.missing }} == ''",
		"${{ params.missing }} != ''",
		"${{ params.missing | default:'' }} == ''",
		"${{ params.missing | default:'<none>' }} == '<none>'",
		"${{ params.missing | default:'a>=b' }} != 'a>=b'",
		"${{ params.b | upper }} == 'B'",
		"${{ params.b | lower }} == 'b'",
		"${{ params.a || params.b || '' }} == ''",
		"${{ params.a || params.b || '' }} == 'B'",
		"${{ params.missing || 'x' }} == 'x'",
		"${{ params.dl }} == '1'",
		"${{ params.zero }} == 0",
		"${{ params.weird }} == '!=x'",
		"${{ gate.ok }}",
		"${{ gate.no }}",
		"${{ gate.ok }} == true",
		"${{ gate.ok }} == false",
		"${{ steps.none.outputs.rows }}",
		"${{ steps.invite.outputs.rows }}",
		"${{ steps.invite.outputs.first.code }} == 'S3CRET'",
		"${{ steps.invite.outputs.rows[0].code }} == 'S3CRET'",
		"${{ params.b }}",
		"${{ params.a }}",
		"${{ params.missing }}",
		"${{ params.zero }}",
		"${{ params.a || params.b }}",
		"${{ params.missing | default:'' }}",
		"${{ params.missing || '' }}",
		"${{ user.id }} == 5",
		"${{ user.email }} != ''",
		"${{ env.FEATURE }} == 'on'",
		"params.b == 'B'",
		"steps.call.outputs.status >= 200",
		"b == 'B'",
		"b",
		"missing",
		"true",
		"false",
		"1",
		"0",
		"'x'",
		"''",
		"hold_until <= datetime('now')",
		"null || undefined || 0",
		"a || 'x' == 'x'",
		"${{ params.b }} == 'a=b'",
		"${{ params.b }} != 'a!=b'",
		"${{ params.b }} == 'x && y'",
		"${{ params.b }} == 'x || y'",
		"${{ params.b }} == '(x)'",
		"${{ params.missing | default:(none) }} == '(none)'",
		"${{ params.b }} == !x",
		"${{ params.b }} == (x)",
	}
	for _, raw := range shapes {
		cond := ghaIfToFlowCondition(raw)
		if cond != ghaIfToFlowCondition246(raw) {
			t.Errorf("%q: translation changed: %q, was %q", raw, cond, ghaIfToFlowCondition246(raw))
			continue
		}
		if conditionUsesExpressionSyntax(cond) {
			t.Errorf("%q (stored %q) was routed to the expression grammar", raw, cond)
			continue
		}
		for i, ctx := range conditionTestContexts(app) {
			if got, want := evaluateFlowCondition(cond, ctx), evaluateFlowCondition246(cond, ctx); got != want {
				t.Errorf("%q in context %d: got %v, 2.7.246 gave %v", raw, i, got, want)
			}
		}
	}

	// Shapes 2.7.246 refused (false) that use the new syntax; still false
	// where they don't parse.
	for _, raw := range []string{"count(x) > 0", "(a b) == 1"} {
		for i, ctx := range conditionTestContexts(app) {
			if evaluateFlowCondition(ghaIfToFlowCondition(raw), ctx) {
				t.Errorf("%q in context %d evaluated true", raw, i)
			}
		}
	}

	// Spot checks, so the reference itself is pinned.
	ctx := conditionTestContexts(app)[0]
	for raw, want := range map[string]bool{
		"${{ steps.call.outputs.status }} >= 200":                true,
		"${{ params.a || params.b || '' }} == 'B'":               true,
		"${{ params.missing || 'x' }} == 'x'":                    true,
		"${{ steps.none.outputs.rows }}":                         false,
		"${{ steps.invite.outputs.code }} == ${{ params.code }}": true,
	} {
		if got := evaluateFlowCondition(ghaIfToFlowCondition(raw), ctx); got != want {
			t.Errorf("%q = %v, want %v", raw, got, want)
		}
	}
}

// Legacy (non-GHA) flow files and success_when store the condition
// without the GHA translation; their single comparisons are unchanged too.
func TestFlowConditionLegacyStoredShapesUnchanged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for _, cond := range []string{
		"{{call.status}} == 204",
		"{{call.status}} >= 200",
		"{{invite.code}} = 'S3CRET'",
		"status = 'won'",
		"b = 'B'",
		"{{b}}",
		"{{a}}",
		"gate.ok",
		"{{params.a || params.b}} == 'B'",
		normalizeGHARefs("${{ steps.call.outputs.status }} == 204"),
		normalizeGHARefs("${{ steps.call.outputs.body }} == 'ok'"),
	} {
		if conditionUsesExpressionSyntax(cond) {
			t.Errorf("%q was routed to the expression grammar", cond)
			continue
		}
		for i, ctx := range conditionTestContexts(app) {
			if got, want := evaluateFlowCondition(cond, ctx), evaluateFlowCondition246(cond, ctx); got != want {
				t.Errorf("%q in context %d: got %v, 2.7.246 gave %v", cond, i, got, want)
			}
		}
	}
}

// `&&`, `||` between comparisons, `!` and parentheses evaluate with
// JavaScript semantics.
func TestFlowConditionExpressions(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctxs := conditionTestContexts(app)
	cases := []struct {
		cond string
		want []bool // per context
	}{
		// The production shapes.
		{"${{ steps.call.outputs.status }} >= 200 && ${{ steps.call.outputs.status }} < 300", []bool{true, false, false}},
		{"${{ params.a }} != '' && ${{ params.b }} != ''", []bool{false, false, false}},
		{"${{ params.b }} != '' && ${{ params.code }} != ''", []bool{true, false, false}},
		{"${{ !steps.none.outputs.rows }}", []bool{true, true, true}},
		{"${{ !steps.invite.outputs.rows }}", []bool{false, false, true}},
		{"${{ steps.invite.outputs.n == 50 && steps.call.outputs.status == 204 }}", []bool{true, false, false}},
		{"${{ steps.invite.outputs.n == 9 || steps.call.outputs.status == 204 }}", []bool{true, true, false}},
		// Operators and grouping.
		{"!${{ gate.ok }}", []bool{false, true, true}},
		{"!(${{ params.b }} == 'B')", []bool{false, true, true}},
		{"(${{ params.b }} == 'B' || ${{ params.a }} == 'A') && ${{ gate.ok }}", []bool{true, false, false}},
		{"${{ params.b }} == 'B' || ${{ params.a }} == 'A' && ${{ gate.ok }}", []bool{true, false, false}},
		{"${{ params.missing }} || ${{ params.b }}", []bool{true, false, false}},
		{"${{ params.zero }} || ${{ params.missing }}", []bool{false, false, false}},
		{"${{ gate.no }} || ${{ gate.ok }} && ${{ params.dl }} == '1'", []bool{true, true, false}},
		// A || fallback as an operand, and pipes inside a span.
		{"${{ params.missing || 'x' }} == 'x' && ${{ gate.ok }}", []bool{true, false, false}},
		{"${{ params.missing | default:'n/a' }} == 'n/a' && ${{ params.b | lower }} == 'b'", []bool{true, false, false}},
		{"${{ steps.invite.outputs.rows | length }} > 0 && !${{ gate.no }}", []bool{true, false, false}},
		// Numeric ordering, text equality: compareLiteralCondition.
		{"${{ steps.invite.outputs.n }} > 10 && ${{ steps.invite.outputs.n }} < 100", []bool{true, false, false}},
		{"${{ steps.invite.outputs.n }} == 50.0 || false", []bool{false, false, false}},
		// Bare refs and literals in an expression.
		{"b == 'B' && !a", []bool{true, false, false}},
		{"gate.ok && true", []bool{true, false, false}},
		// Malformed conditions are false.
		{"${{ params.b }} == 'B' &&", []bool{false, false, false}},
		{"(${{ params.b }} == 'B'", []bool{false, false, false}},
		{"${{ steps.invite.outputs.n }} > 1 > 0 && true", []bool{false, false, false}},
		{"contains(params.b, 'B') && true", []bool{false, false, false}},
	}
	for _, c := range cases {
		cond := ghaIfToFlowCondition(c.cond)
		if !conditionUsesExpressionSyntax(cond) {
			t.Errorf("%q (stored %q) was not routed to the expression grammar", c.cond, cond)
			continue
		}
		for i, ctx := range ctxs {
			if got := evaluateFlowCondition(cond, ctx); got != c.want[i] {
				t.Errorf("%q in context %d = %v, want %v", c.cond, i, got, c.want[i])
			}
		}
	}
}

// A value substituted into a condition is an operand, never syntax: a
// request value full of operators and refs compares as its own text.
func TestFlowConditionExpressionValuesAreOperands(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE invites (id INTEGER PRIMARY KEY, code TEXT)`)
	mustExec(t, app.DB, `INSERT INTO invites (id, code) VALUES (1, 'S3CRET-CODE')`)
	flow := `on:
  request:
    method: POST
    path: /api/redeem
jobs:
  redeem:
    steps:
      - id: invite
        run: sql
        with:
          query: "SELECT code FROM invites WHERE id = 1"
      - if: ${{ params.code }} != '' && ${{ steps.invite.outputs.code }} == ${{ params.code }}
        run: respond
        with:
          status: 200
          body: { result: "redeemed" }
      - run: respond
        with:
          status: 403
          body: { result: "denied" }
`
	if rr := runProbeGHAFlow(t, app, flow, `{"code":"S3CRET-CODE"}`); !strings.Contains(rr.Body.String(), "redeemed") {
		t.Fatalf("control: the right code must redeem, got %d %s", rr.Code, rr.Body.String())
	}
	for _, v := range []string{
		"x' || '1' == '1",
		"x || true",
		"') || (true",
		"{{steps.invite.outputs.code}}",
		"${{ steps.invite.outputs.code }}",
		"!= ''",
		"S3CRET-CODE' && '",
	} {
		body := fmt.Sprintf(`{"code":%q}`, v)
		if rr := runProbeGHAFlow(t, app, flow, body); strings.Contains(rr.Body.String(), "redeemed") {
			t.Fatalf("request value %q satisfied the gate without the code: %d %s", v, rr.Code, rr.Body.String())
		}
	}
}

// The documented `disposition: ${{ cond && 'attachment' || 'inline' }}`
// resolves; it used to be compared as literal text, so it never downloaded.
func TestServeFileDispositionTemplate(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "report.pdf"), []byte("%PDF-1.4"), 0o644); err != nil {
		t.Fatal(err)
	}
	flow := `on:
  request:
    method: GET
    path: /api/file
jobs:
  file:
    steps:
      - run: serve_file
        with:
          path: /uploads/report.pdf
          disposition: ${{ params.dl == '1' && 'attachment' || 'inline' }}
`
	get := func(query string) string {
		flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(flow))
		if err != nil || len(flows) != 1 {
			t.Fatalf("parse flow: %v", err)
		}
		f := flows[0]
		req := httptest.NewRequest("GET", "/api/file"+query, nil)
		rr := httptest.NewRecorder()
		executeFlowHTTP(app, &f, rr, req)
		return rr.Header().Get("Content-Disposition")
	}
	if cd := get("?dl=1"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("dl=1: Content-Disposition %q, want attachment", cd)
	}
	if cd := get("?dl=0"); strings.HasPrefix(cd, "attachment") {
		t.Errorf("dl=0: Content-Disposition %q, want inline", cd)
	}
	if cd := get(""); strings.HasPrefix(cd, "attachment") {
		t.Errorf("no dl: Content-Disposition %q, want inline", cd)
	}
}
