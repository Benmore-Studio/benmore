//go:build !cli

package main

import (
	"strings"
	"testing"
)

// ${{ env.X }} must mean the app's environment. When X is unset, a request
// body key `env` ({"env":{"X":"on"}}) flattened to "env.X" and stood in for
// the env value in if: conditions, compute args and every template.
func TestFlowRequestCannotSupplyEnvValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := `on:
  request:
    method: POST
    path: /api/gate
jobs:
  gate:
    steps:
      - if: ${{ env.AUDIT_UNSET_BYPASS }} == 'on'
        run: respond
        with:
          status: 200
          body: { result: "bypassed" }
      - run: respond
        with:
          status: 403
          body: { result: "denied" }
`
	for _, body := range []string{`{"env":{"AUDIT_UNSET_BYPASS":"on"}}`, `{"env.AUDIT_UNSET_BYPASS":"on"}`} {
		rr := runProbeGHAFlow(t, app, flow, body)
		if strings.Contains(rr.Body.String(), "bypassed") {
			t.Fatalf("request body %s supplied an env value to an if: gate: %d %s", body, rr.Code, rr.Body.String())
		}
	}
}

// `${{ user.group_id }}` / `${{ user.org_id }}` must be the caller's tenant,
// never a same-named request field.
func TestFlowUserGroupIDComesFromSession(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	mustExec(t, app.DB, `CREATE TABLE members (id INTEGER PRIMARY KEY, email TEXT, org_id TEXT)`)
	mustExec(t, app.DB, `INSERT INTO members (email, org_id) VALUES ('member@example.com', 'org-mine')`)
	sid := createCrudScopeSession(t, app, "member@example.com", "user", "org-mine", "")
	flow := `on:
  request:
    method: POST
    path: /api/tenant
    auth: required
jobs:
  tenant:
    steps:
      - run: respond
        with:
          status: 200
          body: { org: "${{ user.org_id }}", group: "${{ user.group_id | default:'none' }}" }
`
	rr := runProbeGHAFlow(t, app, flow, `{"user_group_id":"org-victim"}`, "Authorization", "Bearer "+sid)
	if got := rr.Body.String(); strings.Contains(got, "org-victim") || strings.Count(got, "org-mine") != 2 {
		t.Fatalf("user.org_id / user.group_id should be the session tenant: %d %s", rr.Code, got)
	}
}

// A request field named like a step id must not stand in for that step's
// output when the step is skipped, and must stay readable as params.
func TestFlowRequestFieldCannotFillSkippedStepOutput(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE coupons (code TEXT, discount INTEGER)`)
	mustExec(t, app.DB, `INSERT INTO coupons VALUES ('SAVE5', 5)`)
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
          body: { discount: "${{ steps.coupon.outputs.discount | default:'0' }}", sent: "${{ params.coupon | default:'none' }}" }
`
	rr := runProbeGHAFlow(t, app, flow, `{"coupon":{"discount":1000}}`)
	if got := rr.Body.String(); !strings.Contains(got, `"discount":"0"`) || !strings.Contains(got, `"sent":{"discount":1000}`) {
		t.Fatalf("a request field filled the skipped step's output: %d %s", rr.Code, got)
	}
	if rr := runProbeGHAFlow(t, app, flow, `{"code":"SAVE5"}`); !strings.Contains(rr.Body.String(), "5") {
		t.Fatalf("control: the step's own output must resolve: %d %s", rr.Code, rr.Body.String())
	}
	// A step may read the same-named request field as params.
	self := `on:
  request:
    method: POST
    path: /api/self
jobs:
  self:
    steps:
      - id: invite
        run: sql
        with:
          query: "SELECT ${{ params.invite }} AS echoed"
      - run: respond
        with:
          status: 200
          body: { echoed: "${{ steps.invite.outputs.echoed }}" }
`
	if rr := runProbeGHAFlow(t, app, self, `{"invite":"tok-1"}`); !strings.Contains(rr.Body.String(), "tok-1") {
		t.Fatalf("params.<step id> should still read the request field: %d %s", rr.Code, rr.Body.String())
	}
}
