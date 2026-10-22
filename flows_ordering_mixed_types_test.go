//go:build !cli

package main

import (
	"strings"
	"testing"
)

// An ordering comparison between a number and text that is not a number has
// no answer: it used to fall back to comparing the strings, so a request
// value such as "1abc" satisfied `params.discount < 50` ("1abc" sorts before
// "50") and "9x" satisfied `params.qty > 5`.
func TestOrderingComparisonOfNumberAndTextIsFalse(t *testing.T) {
	for _, tc := range []struct {
		actual, op, expected string
		want                 bool
	}{
		{"1abc", "<", "50", false},
		{"-x", "<=", "50", false},
		{"9x", ">", "5", false},
		{"abc", ">=", "18", false},
		{"1e999", "<", "50", false}, // out of float range: not a usable number
		{"50", ">", "1abc", false},
		// Unchanged: two numbers, two texts (ISO dates), empty as before.
		{"10", ">", "5", true},
		{"2026-01-02", ">", "2026-01-01", true},
		{"abc", "<", "abd", true},
		{"", "<", "50", true},
		{"5", "=", "5", true},
		{"5x", "!=", "5", true},
	} {
		if got := compareLiteralCondition(tc.actual, tc.op, tc.expected); got != tc.want {
			t.Errorf("%q %s %q = %v, want %v", tc.actual, tc.op, tc.expected, got, tc.want)
		}
	}
}

func TestFlowCapGateRejectsNonNumericRequestValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := `on:
  request:
    method: POST
    path: /api/discount
jobs:
  d:
    steps:
      - if: ${{ params.discount }} < 50
        run: respond
        with:
          status: 200
          body: { result: "applied" }
      - run: respond
        with:
          status: 403
          body: { result: "denied" }
`
	if rr := runProbeGHAFlow(t, app, flow, `{"discount":"10"}`); !strings.Contains(rr.Body.String(), "applied") {
		t.Fatalf("control: 10 is under the cap: %d %s", rr.Code, rr.Body.String())
	}
	for _, v := range []string{"1abc", "-9999x"} {
		if rr := runProbeGHAFlow(t, app, flow, `{"discount":"`+v+`"}`); !strings.Contains(rr.Body.String(), "denied") {
			t.Fatalf("%q passed the `< 50` gate: %d %s", v, rr.Code, rr.Body.String())
		}
	}
}
