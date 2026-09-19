//go:build !cli

package main

// Flow condition evaluation and literal comparisons.

import (
	"fmt"
	"strconv"
	"strings"
)

func evaluateFlowCondition(condition string, ctx *FlowContext) bool {
	flat := flattenData(ctx.Data)
	row := make(map[string]any)
	for k, v := range flat {
		row[k] = v
	}
	// Resolution strategy. We split on the operator, then:
	//
	//   - If the LHS contains a pipe (`|`) or any other template
	//     machinery, resolve it through interpolateCtx so the pipe
	//     applies (`|default:''` / `|upper` / etc) and compare the
	//     resolved literal directly against the resolved RHS. Pre-
	//     2.7.32 the LHS was always handed to evaluateCondition as a
	//     row-key - so `existing.account_id | default:'' = ''` became
	//     `row["existing.account_id | default:''"]`, ALWAYS missing,
	//     ALWAYS resolved to "", ALWAYS true. That's the Stripe-
	//     onboard duplicate-account bug: the `if: ${{...|default:''}}
	//     == ''` gate always fired even when account_id was set, so
	//     every onboard click created a fresh Stripe Connect account.
	//
	//   - Otherwise (bare key like `status`), keep the legacy
	//     row-key lookup path so hook conditions
	//     (`when: status = 'won'`) keep working.
	//
	// Order matters: check longer ops first (>=, <=, !=) before single-char ops.
	for _, op := range []string{">=", "<=", "!=", "=", ">", "<"} {
		if idx := strings.Index(condition, op); idx > 0 {
			lhs := strings.TrimSpace(condition[:idx])
			rhs := strings.TrimSpace(condition[idx+len(op):])
			rhs = interpolateCtx(rhs, ctx)
			if conditionLHSNeedsResolution(lhs) {
				expr := lhs
				if !strings.Contains(expr, "{{") {
					expr = "{{" + expr + "}}"
				}
				resolved := interpolateCtx(expr, ctx)
				return compareLiteralCondition(resolved, op, strings.Trim(rhs, `"'`))
			}
			return evaluateCondition(lhs+" "+op+" "+rhs, row)
		}
	}
	// No operator → boolean truthiness check. evaluateCondition only
	// understands `lhs OP rhs`; handed an operator-less condition it
	// loops, matches no operator, and falls through to `return false` -
	// so bare-boolean gates like `if: ${{ gate.ok }}` (where gate.ok is
	// the boolean true from a compute step) silently NEVER fired,
	// stranding the success branch and 500ing as flow_no_response. The
	// `== false` form worked (it has an operator), which is why only the
	// truthy branch was broken.
	//
	// Resolution order, each step narrower than the last:
	//
	//  1. Direct flattened-row key - a real bool/number/string from a
	//     step output or a request param (`gate.ok`, an empty-string
	//     param) is judged as ITSELF, so `{"x":""}` is correctly falsy.
	//  2. A `{{...}}`-braced expression (legacy hook `when:` /
	//     `success_when:` shapes) - interpolate, judge the rendered text.
	//  3. Otherwise resolve through resolveBindExpr so `| default:`, `||`
	//     and dotted paths actually APPLY. Pre-2.7.136 the no-op path
	//     fell straight to interpolateCtx, which only touches `{{ }}`
	//     braces - but ghaIfToFlowCondition strips those for operator-less
	//     conditions, so `if: ${{ params.x | default:'' }}` arrived as the
	//     bare string `x | default:''`, matched no row key, rendered to
	//     ITSELF (no braces to expand), and `isTruthyCondition` of that
	//     non-empty literal was ALWAYS true. The pipe/`||` never ran. Now
	//     it does: a missing base with `| default:''` resolves to "" →
	//     falsy; `|| ''` falls back to "" → falsy.
	//  4. Still unresolved → a recognized value literal (`true`/`1`/`'x'`)
	//     is judged by its literal truthiness; anything else is an
	//     identifier that referenced ABSENT data, which is falsy JS-style
	//     (the old code returned the bare identifier text → truthy, so an
	//     omitted `${{ params.x }}` wrongly fired the branch).
	key := strings.TrimSpace(condition)
	if v, ok := row[key]; ok {
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

// isTruthyCondition judges an operator-less `if:` value JS-style so a
// compute step returning { ok: true } gates as expected. Real bools use
// their value; everything else is falsey only when empty / "false" / "0"
// / "no" / "null" / "undefined" / "nan" / "<nil>" (case-insensitive).
func isTruthyCondition(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case []any:
		return len(t) > 0 // empty result set / array → falsy
	case []map[string]any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
	switch s {
	// includes the stringified empty-collection forms ("[]", "map[]", "{}")
	// so `if: ${{ steps.x.outputs.rows }}` is FALSE on an empty result.
	case "", "false", "0", "0.0", "no", "null", "undefined", "nan", "<nil>", "[]", "map[]", "{}":
		return false
	}
	return true
}

// conditionLiteralTruthy judges an operator-less `if:` value that did NOT
// resolve as a data ref (no row key, no `{{ }}`, no resolvable bind expr).
// A recognized value literal is judged by its literal truthiness; anything
// else is a bare identifier that referenced ABSENT data and is falsy - the
// JS/GHA reading of an undefined variable in a boolean context. This is the
// branch that stops an omitted `${{ params.x }}` (translated to the bare
// token `x`) from rendering to its own name and reading as truthy.
func conditionLiteralTruthy(s string) bool {
	s = strings.TrimSpace(s)
	// Quoted string literal: 'x' / "x" - truthy iff non-empty inside.
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return strings.TrimSpace(s[1:len(s)-1]) != ""
	}
	switch strings.ToLower(s) {
	case "true":
		return true
	case "", "false", "no", "null", "undefined", "nan":
		return false
	}
	// Numeric literal → JS truthiness (0 / 0.0 false, everything else true).
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f != 0
	}
	// A bare identifier (foo / a.b.c) that reached here didn't resolve in
	// any scope → it's a missing ref, not a literal → falsy.
	return false
}

// conditionLHSNeedsResolution returns true when the LHS of a flow
// condition contains pipe modifiers or template machinery that must
// be processed before comparison. The legacy `status = 'won'` shape
// (bare key) stays on the row-lookup path; anything with a pipe (or
// `{{}}` braces, which shouldn't happen post-normalization but is
// defensive) gets resolved through interpolateCtx.
func conditionLHSNeedsResolution(lhs string) bool {
	if strings.Contains(lhs, "|") {
		return true
	}
	if strings.Contains(lhs, "{{") || strings.Contains(lhs, "}}") {
		return true
	}
	return false
}

// compareLiteralCondition compares two already-resolved string
// literals via the operator. Numeric ops attempt a numeric compare
// first so `count > 5` works as expected (string-only compare would
// order `"10"` before `"5"` lexicographically). Equality ops are
// always string-compared.
func compareLiteralCondition(actual, op, expected string) bool {
	switch op {
	case "=":
		return actual == expected
	case "!=":
		return actual != expected
	case ">", "<", ">=", "<=":
		// Try numeric first; fall through to string if either side
		// isn't a number.
		a, aErr := strconv.ParseFloat(actual, 64)
		b, bErr := strconv.ParseFloat(expected, 64)
		if aErr == nil && bErr == nil {
			switch op {
			case ">":
				return a > b
			case "<":
				return a < b
			case ">=":
				return a >= b
			case "<=":
				return a <= b
			}
		}
		switch op {
		case ">":
			return actual > expected
		case "<":
			return actual < expected
		case ">=":
			return actual >= expected
		case "<=":
			return actual <= expected
		}
	}
	return false
}
