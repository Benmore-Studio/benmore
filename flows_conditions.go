//go:build !cli

package main

// Flow condition evaluation and literal comparisons.

import (
	"fmt"
	"strconv"
	"strings"
)

func evaluateFlowCondition(condition string, ctx *FlowContext) bool {
	// `&&`, `||` between comparisons, `!` and parentheses get the
	// expression grammar (flows_condition_expr.go). Every other shape - one
	// comparison, or an operator-less value - keeps the evaluator below.
	if conditionUsesExpressionSyntax(condition) {
		return evaluateFlowExpression(condition, ctx)
	}
	// flatDataForCtx so a bare `if: ${{ env.FEATURE }} == 'on'` sees the
	// app's env, the same as the pipe form already did via interpolateCtx.
	// Read-only below, so the shared cached table is used as is.
	row := flatDataForCtx(ctx)
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
	// The operator is found in the author's condition BEFORE the right side
	// is interpolated, and the resolved value is compared directly. Joining
	// `lhs op <value>` back into one string and splitting it again let a
	// request value such as `!=x` become the operator.
	if lhs, op, rhs, ok := splitConditionOperator(condition); ok && lhs != "" {
		// Joined comparisons go to the expression grammar above; reading
		// `200 && ...` as the value would pass statuses it should refuse,
		// so anything joined that still reaches here fails closed. Before
		// the operator `||` is a fallback (`a || 'x'`); only `&&` joins
		// there.
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

// splitConditionOperator splits `lhs OP rhs` at the first operator in the
// string, reading a two-character operator (>=, <=, !=, ==) before a
// one-character one (=, >, <) at the same position; `==` means `=`. Quoted
// text and `{{ }}` spans are skipped, so a pipe argument such as
// `default:'<none>'` is not read as the operator.
func splitConditionOperator(condition string) (lhs, op, rhs string, ok bool) {
	for i := 0; i < len(condition); i++ {
		switch c := condition[i]; {
		case c == '\'' || c == '"':
			if end := strings.IndexByte(condition[i+1:], c); end >= 0 {
				i += end + 1
				continue
			}
		case c == '{' && strings.HasPrefix(condition[i:], "{{"):
			if end := strings.Index(condition[i+2:], "}}"); end >= 0 {
				i += end + 3
				continue
			}
		}
		if i+1 < len(condition) {
			switch two := condition[i : i+2]; two {
			case ">=", "<=", "!=", "==":
				if two == "==" {
					two = "="
				}
				return strings.TrimSpace(condition[:i]), two, strings.TrimSpace(condition[i+2:]), true
			}
		}
		switch condition[i] {
		case '=', '>', '<':
			return strings.TrimSpace(condition[:i]), condition[i : i+1], strings.TrimSpace(condition[i+1:]), true
		}
	}
	return "", "", "", false
}

// conditionHasConnective reports whether s joins expressions with && or
// ||, outside quoted text and `{{ }}` spans (a `{{ a || 'x' }}` fallback
// inside a ref is not a connective).
func conditionHasConnective(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' || c == '"':
			if end := strings.IndexByte(s[i+1:], c); end >= 0 {
				i += end + 1
				continue
			}
		case c == '{' && s[i+1] == '{':
			if end := strings.Index(s[i+2:], "}}"); end >= 0 {
				i += end + 3
				continue
			}
		}
		if (s[i] == '&' && s[i+1] == '&') || (s[i] == '|' && s[i+1] == '|') {
			return true
		}
	}
	return false
}

// conditionFieldName reports whether s is a plain field reference (letters,
// digits, `_`, `-`, `.`). A condition whose left side is anything else, such
// as SQL (`hold_until <= datetime('now') AND ...`), is not a comparison this
// evaluator can make, so it fails closed.
func conditionFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c == '-' || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// conditionRowValue formats a condition field for comparison. A missing or
// nil field compares as the empty string, not "<nil>", so `field != ”`
// means "has a value" (mirrors how SQL NULL is usually compared to ”).
func conditionRowValue(row map[string]any, field string) string {
	v, ok := flowLookup(row, field)
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
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
		// Try numeric first; fall through to string if neither side is a
		// number (ISO dates). A number against text that isn't one has no
		// order: comparing them as strings let "1abc" pass `< 50`.
		a, aErr := strconv.ParseFloat(actual, 64)
		b, bErr := strconv.ParseFloat(expected, 64)
		if (aErr == nil) != (bErr == nil) && actual != "" && expected != "" {
			return false
		}
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
