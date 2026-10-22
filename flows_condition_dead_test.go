//go:build !cli

package main

import (
	"strings"
	"testing"
)

func deadConditionFlow(step string) string {
	return "on:\n  request: { method: POST, path: /api/x, auth: required }\njobs:\n  main:\n    steps:\n" + step +
		"      - run: respond\n        with: { status: 200, body: { ok: true } }\n"
}

// A condition the evaluator can never make true is refused at write time: a
// deny guard written with it would silently never fire.
func TestFlowConditionThatNeverHoldsIsRefused(t *testing.T) {
	for _, cond := range []string{
		"${{ contains(params.role, 'admin') }}",
		"${{ !contains(params.role, 'admin') }}",
		"${{ params.n - 1 > 0 }}",
		"${{ params.a == 'x' && }}",
		"${{ (params.a == 'x' }}",
	} {
		step := "      - if: \"" + cond + "\"\n        steps:\n          - run: respond\n            with: { status: 403, body: { error: no } }\n"
		msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(step))
		if msg == "" || !strings.Contains(msg, "can never be true") {
			t.Errorf("%s: accepted (msg=%q)", cond, msg)
		}
	}
	// Nested and success_when / disposition forms are checked too.
	nested := "      - id: a\n        run: sql\n        with: { query: \"SELECT 1 AS ok\" }\n        on_error:\n          - if: \"${{ startsWith(params.x, 'a') }}\"\n            steps:\n              - run: respond\n                with: { status: 500, body: { e: 1 } }\n"
	if msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(nested)); !strings.Contains(msg, "can never be true") {
		t.Errorf("nested on_error condition accepted: %q", msg)
	}
	api := "      - id: c\n        run: api\n        with:\n          url: https://example.com/x\n          success_when: \"contains(c.body, 'ok')\"\n"
	if msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(api)); !strings.Contains(msg, "success_when") {
		t.Errorf("dead success_when accepted: %q", msg)
	}
	disp := "      - run: serve_file\n        with:\n          path: uploads/a.pdf\n          disposition: \"${{ params.dl == '1' ? 'attachment' : 'inline' }}\"\n"
	if msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(disp)); !strings.Contains(msg, "disposition") {
		t.Errorf("unparseable disposition accepted: %q", msg)
	}
}

// Every shape the evaluator handles stays accepted.
func TestFlowConditionsThatCanHoldAreAccepted(t *testing.T) {
	for _, cond := range []string{
		"${{ steps.a.outputs.rows }}",
		"${{ !steps.a.outputs.rows }}",
		"${{ params.a == 'x' && params.b != 'y' }}",
		"${{ (params.a == 'x' || params.b == 'y') && !steps.a.outputs.ok }}",
		"${{ steps.a.outputs.n > 5 }}",
		"${{ steps.a.outputs.n >= 200 && steps.a.outputs.n < 300 }}",
		"${{ params.x | default:'' }} == ''",
		"${{ params.x || 'none' }} == 'none'",
		"${{ params.a }} || ${{ params.b }}",
		"${{ env.FEATURE }} == 'on'",
		"${{ user.role == 'admin' }}",
		"${{ steps.a.outputs.rows[0].id == params.id }}",
		"${{ params.a == 'a!=b' }}",
	} {
		step := "      - id: a\n        run: sql\n        with: { query: \"SELECT 1 AS ok, 1 AS n\" }\n      - if: \"" + cond + "\"\n        steps:\n          - run: respond\n            with: { status: 403, body: { error: no } }\n"
		if msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(step)); msg != "" {
			t.Errorf("%s: refused: %s", cond, msg)
		}
	}
	ok := "      - id: c\n        run: api\n        with:\n          url: https://example.com/x\n          success_when: \"status >= 200 && status < 300\"\n" +
		"      - run: serve_file\n        with:\n          path: uploads/a.pdf\n          disposition: \"${{ params.dl == '1' && 'attachment' || 'inline' }}\"\n"
	if msg := ValidateOnWrite("flows/x.yaml", deadConditionFlow(ok)); msg != "" {
		t.Errorf("valid success_when/disposition refused: %s", msg)
	}
}

// A file already deployed with such a condition still loads.
func TestFlowWithDeadConditionStillLoads(t *testing.T) {
	step := "      - if: \"${{ contains(params.role, 'admin') }}\"\n        steps:\n          - run: respond\n            with: { status: 403, body: { error: no } }\n"
	flows, err := parseGHAFlowFile("flows/x.yaml", []byte(deadConditionFlow(step)))
	if err != nil || len(flows) != 1 {
		t.Fatalf("deployed file no longer loads: %v %d", err, len(flows))
	}
}
