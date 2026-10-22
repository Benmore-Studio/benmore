//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A request key that is a dotted path into a step id (`coupon.discount`)
// must not fill that skipped step's output either: step outputs are read by
// their flattened dotted keys.
func TestFlowDottedRequestKeyCannotFillSkippedStepOutput(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE coupons (code TEXT, discount INTEGER)`)
	flow := `on:
  request:
    method: POST
    path: /api/price
jobs:
  price:
    steps:
      - if: ${{ params.code }}
        steps:
          - id: coupon
            run: sql
            with:
              query: "SELECT discount FROM coupons WHERE code = :code"
      - run: respond
        with:
          status: 200
          body: { discount: "${{ steps.coupon.outputs.discount | default:'0' }}", sent: "${{ params.coupon.discount | default:'none' }}" }
`
	for _, body := range []string{`{"coupon.discount":"1000"}`, `{"coupon":{"discount":"1000"}}`} {
		rr := runProbeGHAFlow(t, app, flow, body)
		got := rr.Body.String()
		if !strings.Contains(got, `"discount":"0"`) {
			t.Fatalf("body %s filled the skipped step's output: %d %s", body, rr.Code, got)
		}
	}
}
