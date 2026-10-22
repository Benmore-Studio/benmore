//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForEachReadsComputedNestedArrays(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, `CREATE TABLE packed_lines (sku TEXT, quantity INTEGER)`)
	os.MkdirAll(filepath.Join(app.Dir, "static"), 0755)
	source := `export function plan(x) { return { groups:[{ lines:x.lines }], empty:[], absent:null }; }`
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "plan.ts"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	flowSource := `on:
  request: {method: POST, path: /api/pack, transaction: true}
jobs:
  pack:
    steps:
      - id: planned
        run: compute
        with: {module: plan, function: plan, args: {lines: '${{ params.lines }}'}}
      - for_each: '${{ steps.planned.outputs.groups[0].lines }}'
        as: line
        steps:
          - run: sql
            query: INSERT INTO packed_lines(sku,quantity) VALUES (:sku,:quantity)
            params: {sku: '${{ line.sku }}', quantity: '${{ line.quantity }}'}
            expect_rows: '=1'
      - id: result
        run: sql
        query: SELECT COUNT(*) AS n, SUM(quantity) AS units FROM packed_lines
      - run: respond
        with: {status: 200, body: {count: '${{ steps.result.outputs.n }}', units: '${{ steps.result.outputs.units }}'}}
`
	flows, err := parseGHAFlowFile("flows/pack.yaml", []byte(flowSource))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/pack", strings.NewReader(`{"lines":[{"sku":"wrench","quantity":2},{"sku":"bolt","quantity":3}]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flows[0], rec, req); err != nil {
		t.Fatalf("flow=%v body=%s", err, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["count"] != float64(2) || got["units"] != float64(5) {
		t.Fatalf("zero/missing loop effects: %d %s", rec.Code, rec.Body.String())
	}
}

func TestForEachNativeNestedLookupPreservesShadowAndTaint(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, `CREATE TABLE loop_values (value TEXT)`)
	for _, tc := range []struct {
		name, key string
		data      map[string]any
		want      int
	}{
		{"nested request", "params.input.lines", map[string]any{"input": map[string]any{"lines": []any{map[string]any{"value": "one"}, map[string]any{"value": "two"}}}}, 2},
		{"nested computed", "computed.nested.lines", map[string]any{"computed": map[string]any{"nested": map[string]any{"lines": []any{map[string]any{"value": "one"}}}}}, 1},
		{"empty", "computed.lines", map[string]any{"computed": map[string]any{"lines": []any{}}}, 0},
		{"null", "computed.lines", map[string]any{"computed": map[string]any{"lines": nil}}, 0},
		{"missing", "computed.lines", map[string]any{"computed": map[string]any{}}, 0},
		{"direct key wins", "computed.lines", map[string]any{"computed": map[string]any{"lines": []any{map[string]any{"value": "nested"}}}, "computed.lines": []any{map[string]any{"value": "flat"}, map[string]any{"value": "flat2"}}}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, app.DB, `DELETE FROM loop_values`)
			ctx := &FlowContext{App: app, Data: tc.data, Params: map[string]string{}, RequestKeys: map[string]bool{"input": true, "computed": true}}
			step := FlowStep{Type: "for_each", ForEach: tc.key, ForAs: "line", Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO loop_values(value) VALUES (:value)", SQLParams: map[string]string{"value": "{{line.value}}"}}}}
			executeSteps(ctx, []FlowStep{step})
			if ctx.Error != nil {
				t.Fatal(ctx.Error)
			}
			var n int
			app.DB.QueryRow(`SELECT COUNT(*) FROM loop_values`).Scan(&n)
			if n != tc.want {
				t.Fatalf("rows=%d want=%d", n, tc.want)
			}
			if tc.want > 0 && ctx.taintedRef("{{line.value}} ") == "" {
				t.Fatal("nested loop dropped request taint")
			}
		})
	}
	// A step-owned name cannot be resurrected from same-named request data.
	ctx := &FlowContext{App: app, Data: map[string]any{"planned": map[string]any{"lines": []any{map[string]any{"value": "forged"}}}}, Params: map[string]string{}, RequestKeys: map[string]bool{"planned": true}}
	steps := []FlowStep{{Type: "if", Condition: "false", Steps: []FlowStep{{Name: "planned", Type: "compute", Compute: &FlowCompute{Module: "unused", Function: "unused"}}}}, {Type: "for_each", ForEach: "planned.lines", ForAs: "line", Steps: []FlowStep{{Type: "set", Set: map[string]string{"executed": "yes"}}}}}
	shadowStepNamedRequestKeys(ctx, steps)
	executeSteps(ctx, steps)
	if ctx.Data["executed"] != nil {
		t.Fatal("loop revived shadowed request value")
	}
}
