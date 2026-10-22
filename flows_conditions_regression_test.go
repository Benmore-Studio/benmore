//go:build !cli

package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// runProbeGHAFlow parses one GHA flow file and runs it over HTTP with body.
func runProbeGHAFlow(t *testing.T, app *App, yaml, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(yaml))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v (%d flows)", err, len(flows))
	}
	f := flows[0]
	req := httptest.NewRequest(f.Trigger.Method, f.Trigger.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &f, rr, req)
	return rr
}

// An `if:` equality between a stored value and a request value must not be
// satisfiable by a request value that carries an operator. The RHS used to
// be interpolated and the whole `lhs op rhs` string re-parsed, so a request
// value "!=x" became the operator.
func TestFlowIfConditionRequestValueCannotRewriteOperator(t *testing.T) {
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
      - if: ${{ steps.invite.outputs.code }} == ${{ params.code }}
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
	if rr := runProbeGHAFlow(t, app, flow, `{"code":"wrong"}`); !strings.Contains(rr.Body.String(), "denied") {
		t.Fatalf("control: a wrong code must be denied, got %d %s", rr.Code, rr.Body.String())
	}
	for _, v := range []string{"!=anything", ">=", "<zzz", "= S3CRET-CODE"} {
		rr := runProbeGHAFlow(t, app, flow, `{"code":"`+v+`"}`)
		if strings.Contains(rr.Body.String(), "redeemed") {
			t.Fatalf("request value %q satisfied `code == params.code` without knowing the code: %d %s", v, rr.Code, rr.Body.String())
		}
	}
}

// A `>=` / `<=` gate on a bare step ref must compare the value. The rebuilt
// "lhs >= rhs" string used to be re-split on "=" first, so the field became
// "n >" (absent) and a quota gate never fired.
func TestFlowIfConditionGreaterOrEqualGateFires(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE usage (id INTEGER PRIMARY KEY, n INTEGER)`)
	mustExec(t, app.DB, `INSERT INTO usage (id, n) VALUES (1, 50)`)
	flow := `on:
  request:
    method: POST
    path: /api/spend
jobs:
  spend:
    steps:
      - id: usage
        run: sql
        with:
          query: "SELECT n FROM usage WHERE id = 1"
      - if: ${{ steps.usage.outputs.n }} >= 10
        run: respond
        with:
          status: 429
          body: { result: "quota exceeded" }
      - run: respond
        with:
          status: 200
          body: { result: "spent" }
`
	rr := runProbeGHAFlow(t, app, flow, `{}`)
	if !strings.Contains(rr.Body.String(), "quota exceeded") {
		t.Fatalf("`n >= 10` with n=50 did not fire: %d %s", rr.Code, rr.Body.String())
	}
}

// `>` on a bare step ref must compare numbers, not text ("9" > "10").
func TestFlowIfConditionGreaterThanIsNumeric(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{"acct": []map[string]any{{"balance": int64(9)}}}, Params: map[string]string{}}
	if evaluateFlowCondition(ghaIfToFlowCondition("${{ steps.acct.outputs.balance }} > 10"), ctx) {
		t.Fatal("balance 9 > 10 evaluated true (lexicographic compare)")
	}
}

// A hook or workflow `when:` with >= / <= used to split on "=" first and
// compare text, so `amount >= 100` never matched. `when:` is SQL now; the
// same conditions hold, and SQL that names no real column fails closed.
func TestEvaluateConditionOrderingOperators(t *testing.T) {
	app := newWhenTestApp(t)
	row := map[string]any{"amount": int64(250), "stage": "won", "note": "a=b"}
	for cond, want := range map[string]bool{
		"amount >= 100":   true,
		"amount <= 100":   false,
		"amount > 99":     true,
		"amount < 1000":   true,
		"stage = 'won'":   true,
		"stage == 'won'":  true,
		"stage != 'lost'": true,
		"note = 'a=b'":    true,
		"hold_until IS NOT NULL AND hold_until <= datetime('now')": false,
	} {
		if got := whenHolds(app.DB, app, "orders", cond, row); got != want {
			t.Errorf("when %q = %v, want %v", cond, got, want)
		}
	}
	for _, cond := range []string{"missing != ''", "consent_id IS NOT NULL AND EXISTS (SELECT 1 FROM c WHERE c.id = x.id)"} {
		if _, err := evaluateWhen(app.DB, app, "orders", cond, row); err == nil {
			t.Errorf("when %q names no real column but evaluated", cond)
		}
	}
}

// Quoted pipe arguments on the left side keep their operator characters.
func TestFlowIfConditionQuotedPipeArgument(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if !evaluateFlowCondition(ghaIfToFlowCondition("${{ params.missing | default:'<none>' }} == '<none>'"), ctx) {
		t.Fatal("a default containing '<' should compare equal to itself")
	}
	if evaluateFlowCondition(ghaIfToFlowCondition("${{ params.missing | default:'a>=b' }} != 'a>=b'"), ctx) {
		t.Fatal("a default containing '>=' should not change the operator")
	}
}

// Joined comparisons evaluate both sides. 2.7.246 failed them closed; the
// position-based splitter before it read `200 && ...` as the value and
// passed error statuses.
func TestFlowIfConditionJoinedComparison(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for status, want := range map[int64]bool{204: true, 200: true, 199: false, 300: false, 404: false, 500: false} {
		ctx := &FlowContext{App: app, Data: map[string]any{"call": map[string]any{"status": status}}, Params: map[string]string{}}
		cond := ghaIfToFlowCondition("${{ steps.call.outputs.status }} >= 200 && ${{ steps.call.outputs.status }} < 300")
		if got := evaluateFlowCondition(cond, ctx); got != want {
			t.Errorf("status %d: 200 <= status < 300 = %v, want %v", status, got, want)
		}
	}
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if !evaluateFlowCondition(ghaIfToFlowCondition("${{ params.missing || 'x' }} == 'x'"), ctx) {
		t.Error("a || fallback inside a ref must still work")
	}
}
