//go:build !cli

package main

// References with no value in a comparison (`if:`, `success_when:`, and a
// comparison inside a `${{ }}` value expression).
//
// A comparison used to read a reference that had no value in two ways, and a
// caller could match both:
//
//   - the right-hand side of a single comparison, and a left side with a pipe,
//     were rendered like any template, so the reference stayed as its own text
//     (`{{t.token}}`). `${{ params.token }} == ${{ steps.t.outputs.token }}`
//     was true when the lookup found no row and the caller sent that text;
//   - a bare left side, and every operand of a joined condition, compared as
//     empty, so the same check written the other way round, or joined with
//     `&&`, was true for an empty or omitted token.
//
// The rule now, in both evaluators:
//
//  1. A side that was compared as its own text has no value: `!=` holds,
//     every other operator is false, whatever the other side is.
//  2. A reference the flow owns (a step output, a set key, a loop variable,
//     the caller's identity, an env value) that has no value never equals a
//     request field read with no fallback: `!=` holds, the rest is false.
//  3. Everything else reads as it did: a missing value is empty against a
//     literal (`${{ steps.x.outputs.id }} == ''`, `${{ params.x }} != ''`),
//     against another value of the flow's own, and against a request field
//     the author gave a fallback (`| default:''`, `|| ''`); a missing request
//     field on the left is empty against anything.
//
// "Has no value" is decided from the author's condition and the resolver's
// found / not found, never from a value: the references are read out of the
// condition text before anything is rendered, and a request value that
// happens to look like `{{t.token}}` is only ever a value (security.md 2b).

import (
	"slices"
	"strings"
)

// condNoValue is the result of a comparison one of whose operands has no
// value: it is not equal to anything and has no order.
func condNoValue(op string) bool {
	return op == "!="
}

// flowRefHasFallback reports a reference the author gave a fallback: a `||`
// operand or a `| default:` pipe. Such a reference always has a value.
func flowRefHasFallback(ref string) bool {
	if indexOutsideQuotes(ref, "||") >= 0 {
		return true
	}
	for _, pipe := range splitOutsideQuotes(ref, "|")[1:] {
		if name, _, hasArg := splitPipeNameArg(pipe); name == "default" && hasArg {
			return true
		}
	}
	return false
}

// flowRefReadsRequest classifies a translated reference by its name: true
// for a request field (`params.<name>`, or a bare name the flow does not
// define, which is how a request field is read without `params.`), false for
// a value the flow owns: the caller's identity, an env value, or a name one
// of the flow's steps writes (flat carries those as markers,
// overlayRequestOnlyParams). src is the reference as the author wrote it,
// when known: `steps.<id>...` is a step output whatever the markers say.
func flowRefReadsRequest(ref, src string, flat map[string]any) bool {
	if strings.HasPrefix(strings.TrimSpace(src), "steps.") {
		return false
	}
	base := ghaRefBase(ref)
	if i := indexOutsideQuotes(base, "||"); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	if strings.HasPrefix(base, "params.") {
		return true
	}
	root := base
	if i := strings.IndexAny(root, ".["); i >= 0 {
		root = root[:i]
	}
	if root == "env" || slices.Contains(flowIdentityKeys, root) || strings.HasPrefix(root, flowIdentityStepPrefix) {
		return false
	}
	if flat[flowRequestOnlyParamsFlatKey+"."+root] == true {
		return false
	}
	return true
}

// condTemplateRefs reads the `{{ }}` references of one side of a condition
// as the author wrote it, the way interpolateCtx will scan it, and resolves
// each: missing is true when any has no value; request is true when the side
// is exactly one request field read with no fallback (whether or not the
// request sent it).
func condTemplateRefs(side string, flat map[string]any) (refs, missing, request bool) {
	for i := 0; i+2 < len(side); i++ {
		if side[i] != '{' || side[i+1] != '{' {
			continue
		}
		end := strings.Index(side[i+2:], "}}")
		if end < 0 {
			break
		}
		expr := strings.TrimSpace(side[i+2 : i+2+end])
		refs = true
		if _, ok := resolveBindExpr(expr, flat); !ok {
			missing = true
		}
		i += end + 3
	}
	if inner, sole := soleFlowExpr(side); sole && !flowValueExprUsesOperators(inner) {
		request = !flowRefHasFallback(inner) && flowRefReadsRequest(inner, "", flat)
	}
	return refs, missing, request
}

// flowMissingValuesReference is api(at:"flows") → missing_values: how a
// comparison reads a reference with no value, for app builders.
func flowMissingValuesReference() string {
	return "How a comparison (`if:`, `success_when:`, a comparison inside a `${{ }}` value) reads a reference with no value: a step that returned no row or did not run, a request field the caller left out. " +
		"Against a literal it is empty: `${{ steps.row.outputs.id }} == ''` and `${{ params.note }} != ''` test for a value. " +
		"A value of the flow's own with no value (a step output, a set key, a loop variable, the caller's identity, an env value) never equals a request field: `${{ params.token }} == ${{ steps.t.outputs.token }}` is false and `!=` is true when the lookup found no row, whatever the request sends (an empty token, no token and the text `{{t.token}}` included), with the step output on either side and inside `&&` / `||`; `>`, `<`, `>=` and `<=` are false. " +
		"In a single comparison a right-hand reference with no value, and a left-hand one written with a pipe, never equals anything: only `!=` holds. " +
		"A missing value is still empty against another value of the flow's own (two step outputs), and against a request field you gave a fallback: `${{ params.expected | default:'' }}` or `${{ params.expected || '' }}` compares as that fallback, so write one when a missing value is meant to match. " +
		"A request field with no value on the left is empty against anything. " +
		"In a scheduled or data-event flow a step output on the left of a single comparison is empty against the event's value too. " +
		"When such a comparison is false and no branch of the `if:` runs, the flow answers 500 with a reason saying a reference had no value, so test for the row first: `if: ${{ !steps.t.outputs.rows }}` with a respond 404."
}
