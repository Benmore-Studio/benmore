//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// What a comparison does with a reference that has no value depends on the
// side it is written on and on which evaluator reads the condition. This
// test records it; nothing here was changed with the step checks in
// flows_unresolved_before_effect_test.go, because every way of making the
// sides agree changes what a deployed flow answers:
//
//   - the left side of one comparison, and both sides of a condition written
//     with `&&`, `||`, `!` or parentheses, compare a missing value as empty;
//   - the right side of one comparison is rendered like any other template:
//     the reference stays as the text `{{name}}`, which is what gets compared,
//     and the `if:` step fails afterwards only when no step of either branch
//     ran (a branch step resets the tally of unresolved references).
//
// Reading the right side as empty too would make `${{ a }} == ${{ b }}` true
// when both are missing (a token check against a row that does not exist,
// called with no token, answers 500 today and would take the branch), and
// failing on a missing left side would break every `if:` on an optional
// request field. Changing a row here is that decision.
func TestIfComparisonWithAMissingReferenceBySide(t *testing.T) {
	app := newGateApp(t)
	gate := func(cond, extra string) string {
		return "      - if: " + cond + "\n        run: respond\n        with: { status: 200, json: { branch: taken } }\n" + extra +
			"      - run: respond\n        with: { status: 200, json: { branch: skipped } }\n"
	}
	const otherwise = "        else:\n          - run: respond\n            with: { status: 200, json: { branch: otherwise } }\n"
	for _, c := range []struct{ name, cond, extra, body, want string }{
		{"right missing, ==", "${{ params.a }} == ${{ params.b }}", "", `{"a":"x"}`, "500"},
		{"right missing, == inside one span", "${{ params.a == params.b }}", "", `{"a":"x"}`, "500"},
		{"right missing, == with else", "${{ params.a }} == ${{ params.b }}", otherwise, `{"a":"x"}`, "otherwise"},
		{"right missing, !=", "${{ params.a }} != ${{ params.b }}", "", `{"a":"x"}`, "taken"},
		{"both missing, ==", "${{ params.a }} == ${{ params.b }}", "", `{}`, "500"},
		{"both missing, !=", "${{ params.a }} != ${{ params.b }}", "", `{}`, "taken"},
		{"left missing, ==", "${{ params.b }} == ${{ params.a }}", "", `{"a":"x"}`, "skipped"},
		{"left missing, !=", "${{ params.b }} != ${{ params.a }}", "", `{"a":"x"}`, "taken"},
		{"right missing with a fallback", "${{ params.a }} == ${{ params.b | default:'' }}", "", `{"a":"x"}`, "skipped"},
		{"expression, right missing", "(${{ params.a }} == ${{ params.b }})", "", `{"a":"x"}`, "skipped"},
		{"expression, both missing", "(${{ params.a }} == ${{ params.b }})", "", `{}`, "taken"},
		{"expression, both missing, !=", "(${{ params.a }} != ${{ params.b }})", "", `{}`, "skipped"},
	} {
		rr, _ := runProbeSteps(t, app, gate(c.cond, c.extra), c.body)
		got := "500"
		if rr.Code == http.StatusOK {
			got, _ = decodeJSONAnswer(t, rr)["branch"].(string)
		} else if reason := decodeJSONAnswer(t, rr)["reason"]; rr.Code != http.StatusInternalServerError || reason != unresolvedReason {
			t.Errorf("%s: answered %d with reason %v", c.name, rr.Code, reason)
		}
		if got != c.want {
			t.Errorf("%s: `if: %s` with %s -> %s, want %s", c.name, c.cond, c.body, got, c.want)
		}
	}
}

// `run: redirect` is the one step left that answers before its reference
// check: the 303 goes out with the placeholder in the target. It is not
// changed here because a flow that redirects with an optional value the
// request left out (`/done?tab=${{ params.tab }}`) reaches its page today and
// would answer 500 instead.
func TestRedirectWithAnUnresolvedReferenceStillRedirects(t *testing.T) {
	app := newGateApp(t)
	rr, _ := runProbeSteps(t, app, "      - run: redirect\n        with: { to: \"/done?tab=${{ params.tab }}\" }\n", `{}`)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/done?tab={{params.tab}}" {
		t.Fatalf("redirect answered %d to %q", rr.Code, rr.Header().Get("Location"))
	}
}
