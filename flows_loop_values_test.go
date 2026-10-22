//go:build !cli

package main

import "testing"

func TestFlowForEachDropsPreviousRowFields(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for _, alias := range []string{"row", ""} {
		t.Run("alias="+alias, func(t *testing.T) {
			name := alias
			if name == "" {
				name = "item"
			}
			ctx := &FlowContext{App: app, Params: map[string]string{}, Data: map[string]any{
				"rows": []map[string]any{
					{"label": "first", "address": map[string]any{"city": "north"}, "tags": []any{map[string]any{"name": "red"}, map[string]any{"name": "blue"}}},
					{"label": "second", "address": map[string]any{}, "tags": []any{map[string]any{"name": "green"}}},
					{},
				},
				name + "Extra": "keep",
			}}
			err := execStepForEach(ctx, &FlowStep{Type: "for_each", ForEach: "rows", ForAs: alias, Steps: []FlowStep{
				{Type: "set", Set: map[string]string{
					"trail": "{{trail | default:''}}[{{" + name + ".label | default:'missing'}}/{{" + name + ".address.city | default:'missing'}}/{{" + name + ".tags.1.name | default:'missing'}}]",
				}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := ctx.Data["trail"], "[first/north/blue][second/missing/missing][missing/missing/missing]"; got != want {
				t.Fatalf("loop used a previous row's fields: got %v, want %s", got, want)
			}
			if ctx.Data[name+"Extra"] != "keep" {
				t.Fatal("loop removed an unrelated variable")
			}
		})
	}
}

func TestFlowForEachMissingFieldStopsInsteadOfReusingPreviousValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Params: map[string]string{}, Data: map[string]any{
		"rows": []any{map[string]any{"code": "first"}, map[string]any{}},
	}}
	err := execStepForEach(ctx, &FlowStep{Type: "for_each", ForEach: "rows", ForAs: "row", Steps: []FlowStep{
		{Type: "set", Name: "capture", Set: map[string]string{"value": "{{row.code}}"}},
	}})
	if err == nil {
		t.Fatalf("missing second-row code reported success with value %v", ctx.Data["value"])
	}
}
