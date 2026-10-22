//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestComputeMissingArgumentStopsFlow(t *testing.T) {
	app := writeComputeFixture(t, "args.ts", `export function echo(value: any): any { return value; }`)
	for _, tc := range []struct {
		name string
		args any
	}{
		{"whole", "${{ steps.lookup.outputs.amount }}"},
		{"legacy", "{{lookup.amount}}"},
		{"nested", map[string]any{"rows": []any{map[string]any{"amount": "${{ steps.lookup.outputs.amount }}"}}}},
		{"environment", "${{ env.MISSING_COMPUTE_TEST_VALUE }}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
			executeSteps(ctx, []FlowStep{
				{Type: "compute", Name: "calc", Compute: &FlowCompute{Module: "args", Function: "echo", Args: tc.args}},
				{Type: "set", Set: map[string]string{"continued": "yes"}},
			})
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "unresolved") {
				t.Fatalf("missing compute argument reported success: error=%v, data=%v", ctx.Error, ctx.Data)
			}
			if ctx.FailedStep != "calc" || ctx.FailedType != "compute" {
				t.Fatalf("failure does not identify compute step: %q/%q", ctx.FailedStep, ctx.FailedType)
			}
			if _, ok := ctx.Data["continued"]; ok {
				t.Fatal("flow continued after an unresolved compute argument")
			}
		})
	}
}

func TestComputeArgumentsKeepExplicitNullFalsyAndDefaults(t *testing.T) {
	app := writeComputeFixture(t, "args.ts", `export function check(a: any): boolean {
		return a.nil === null && a.zero === 0 && a.no === false && a.empty === "" && a.fallback === "safe";
	}`)
	ctx := &FlowContext{App: app, Data: map[string]any{"nil": nil, "zero": 0, "no": false, "empty": ""}, Params: map[string]string{}}
	err := executeStep(ctx, &FlowStep{Type: "compute", Name: "checked", Compute: &FlowCompute{
		Module: "args", Function: "check", Args: map[string]any{
			"nil": "${{ nil }}", "zero": "${{ zero }}", "no": "${{ no }}", "empty": "${{ empty }}",
			"fallback": "${{ missing | default:'safe' }}",
		},
	}})
	if err != nil || ctx.Data["checked"] != true {
		t.Fatalf("valid arguments changed: error=%v, result=%v", err, ctx.Data["checked"])
	}
}

// Absent outputs of a step the flow reached (skipped by `if:`, a key the
// module did not return) are optional data and arrive as null; a ref to a
// step that is not in the flow still stops it.
func TestComputeArgumentFromReachedStepIsNull(t *testing.T) {
	app := writeComputeFixture(t, "args.ts", `export function empty(): any { return {}; }
export function isNull(v: any): boolean { return v === null; }
export function nested(a: any): boolean { return a.x === null && a.y === null; }`)
	call := func(name, fn string, args any) FlowStep {
		return FlowStep{Type: "compute", Name: name, Compute: &FlowCompute{Module: "args", Function: fn, Args: args}}
	}
	for _, tc := range []struct {
		name  string
		steps []FlowStep
	}{
		{"skipped by if", []FlowStep{
			{Type: "if", Condition: ghaIfToFlowCondition("${{ flag }} == 'yes'"), Steps: []FlowStep{call("lookup", "empty", nil)}},
			call("checked", "isNull", "${{ steps.lookup.outputs.amount }}"),
		}},
		{"skipped in else branch", []FlowStep{
			{Type: "if", Condition: ghaIfToFlowCondition("${{ flag }} == 'no'"), ElseSteps: []FlowStep{call("lookup", "empty", nil)}},
			call("checked", "isNull", "{{lookup.amount}}"),
		}},
		{"key not returned", []FlowStep{
			call("lookup", "empty", nil),
			call("checked", "isNull", "${{ steps.lookup.outputs.amount }}"),
		}},
		{"nested", []FlowStep{
			call("lookup", "empty", nil),
			call("checked", "nested", map[string]any{"x": "${{ steps.lookup.outputs.first.amount }}", "y": "${{ lookup.amount }}"}),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &FlowContext{App: app, Data: map[string]any{"flag": "no"}, Params: map[string]string{}}
			executeSteps(ctx, tc.steps)
			if ctx.Error != nil || ctx.Data["checked"] != true {
				t.Fatalf("reached-step argument was not null: error=%v, result=%v", ctx.Error, ctx.Data["checked"])
			}
		})
	}

	t.Run("unknown step still stops", func(t *testing.T) {
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
		executeSteps(ctx, []FlowStep{
			call("lookup", "empty", nil),
			call("checked", "isNull", "${{ steps.lookpu.outputs.amount }}"),
		})
		if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "unresolved") || ctx.FailedStep != "checked" {
			t.Fatalf("misspelled step id did not stop the flow: error=%v, step=%q", ctx.Error, ctx.FailedStep)
		}
	})
}
