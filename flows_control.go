//go:build !cli

package main

// Branching, iteration, value transformation, body parsing, and compute steps.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func execStepIf(ctx *FlowContext, step *FlowStep) error {
	if evaluateFlowCondition(step.Condition, ctx) {
		executeSteps(ctx, step.Steps)
	} else if len(step.ElseSteps) > 0 {
		executeSteps(ctx, step.ElseSteps)
	}
	return ctx.Error
}

func execStepForEach(ctx *FlowContext, step *FlowStep) error {
	items, ok := ctx.Data[step.ForEach]
	if !ok {
		return nil
	}

	var rows []map[string]any
	switch v := items.(type) {
	case []map[string]any:
		rows = v
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	}

	as := step.ForAs
	if as == "" {
		as = "item"
	}

	for _, row := range rows {
		// Create sub-context with loop variable - recursively flatten nested maps
		ctx.Data[as] = row
		flattenIntoCtx(ctx.Data, as, row)
		executeSteps(ctx, step.Steps)
		if ctx.Stopped || ctx.Error != nil {
			return ctx.Error
		}
	}
	return nil
}

// flattenIntoCtx recursively flattens a map into dot-notation keys in ctx.Data.
// e.g. flattenIntoCtx(data, "geo", {"results": [{"geometry": {"location": {"lat": 39.9}}}]})
// produces data["geo.results"] = [...], and for arrays: data["geo.results.0.geometry.location.lat"] = 39.9
func flattenIntoCtx(data map[string]any, prefix string, m map[string]any) {
	for k, v := range m {
		key := prefix + "." + k
		data[key] = v
		switch val := v.(type) {
		case map[string]any:
			flattenIntoCtx(data, key, val)
		case []any:
			for i, item := range val {
				iKey := fmt.Sprintf("%s.%d", key, i)
				data[iKey] = item
				if im, ok := item.(map[string]any); ok {
					flattenIntoCtx(data, iKey, im)
				}
			}
		}
	}
}

func execStepSet(ctx *FlowContext, step *FlowStep) error {
	// Interpolate all values once, then expose them two ways:
	//   - At ctx.Data[step.Name] = {k: v, ...} so GHA-style references
	//     `${{ steps.<id>.outputs.<k> }}` (translated to `{{<id>.<k>}}`)
	//     resolve correctly. This matches what sql/api/email steps do
	//     and is what the build doc promises.
	//   - At ctx.Data[k] directly, for backwards compat with flows that
	//     reference `{{k}}` without a step name prefix.
	resolved := make(map[string]any, len(step.Set))
	for k, v := range step.Set {
		val := interpolateCtx(v, ctx)
		resolved[k] = val
	}
	ctx.DataMu.Lock()
	for k, val := range resolved {
		ctx.Data[k] = val
	}
	if step.Name != "" {
		ctx.Data[step.Name] = resolved
	}
	ctx.DataMu.Unlock()
	return nil
}

func execStepParse(ctx *FlowContext, step *FlowStep) error {
	if step.Parse == "body" && ctx.Request != nil {
		// Try form data first (Content-Type: application/x-www-form-urlencoded)
		contentType := ctx.Request.Header.Get("Content-Type")
		if strings.Contains(contentType, "form-urlencoded") || strings.Contains(contentType, "multipart") {
			ctx.Request.ParseForm()
			name := step.Name
			if name == "" {
				name = "form"
			}
			formData := make(map[string]any)
			for k, v := range ctx.Request.Form {
				if len(v) > 0 {
					formData[k] = v[0]
					ctx.Data[name+"."+k] = v[0]
				}
			}
			ctx.Data[name] = formData
			return nil
		}

		// Fall back to JSON
		body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, flowVerifyBodyMaxBytes))
		if err != nil {
			return err
		}
		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			return fmt.Errorf("parse body: %w", err)
		}
		name := step.Name
		if name == "" {
			name = "body"
		}
		ctx.Data[name] = data
		if m, ok := data.(map[string]any); ok {
			for k, v := range m {
				ctx.Data[name+"."+k] = v
			}
			// Also flatten into data.object pattern for Stripe-style webhooks
			if obj, ok := m["data"]; ok {
				if om, ok := obj.(map[string]any); ok {
					for k, v := range om {
						ctx.Data[name+".data."+k] = v
					}
					if inner, ok := om["object"]; ok {
						if im, ok := inner.(map[string]any); ok {
							for k, v := range im {
								ctx.Data[name+".data.object."+k] = v
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// execStepCompute runs a `run: compute` step (v2.7.67+) - server-side
// JS execution of a function in a static/ TS/JS module via goja. See
// compute.go for the runtime + sandbox details. The pattern:
//
//   - id: forecast
//     run: sql
//     with: SELECT * FROM forecasts WHERE id = :id
//
//   - id: irr
//     run: compute
//     module: par-engine
//     function: irrForInputs
//     args: ${{ steps.forecast.outputs.first }}
//     timeout: 10s
//
// The function's return value lands at ctx.Data[step.Name] (and a
// `.outputs` alias under the same name) so downstream steps reference
// it via `${{ steps.<id>.outputs }}` - same shape as sql / api steps.
// resolveComputeArgsValue turns a `run: compute` args spec into a native Go
// value for goja. Strings that are a SINGLE whole ref (`${{ x }}` / `{{ x }}`)
// resolve to the native context value (object/array/scalar); maps and slices
// recurse leaf-by-leaf (so `args: {a: ${{...}}, b: ${{...}}}` builds a real
// object); other strings are interpolated; numbers/bools pass through.
func resolveComputeArgsValue(raw any, ctx *FlowContext) any {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return resolveComputeArgString(v, ctx)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, vv := range v {
			out[k] = resolveComputeArgsValue(vv, ctx)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, vv := range v {
			out[i] = resolveComputeArgsValue(vv, ctx)
		}
		return out
	default:
		return v // number, bool, etc.
	}
}

func resolveComputeArgString(s string, ctx *FlowContext) any {
	// Normalize with the SAME translator the rest of the framework uses
	// (translateGHAExpr via normalizeGHARefs): strips `steps.`, collapses
	// `.outputs.rows`/`.outputs.*`/`.outputs.<field>`, and turns `[N]` into
	// `.N`. So `${{ steps.forecast.outputs.rows }}` → {{forecast}} (the array)
	// and `${{ steps.forecast.outputs.rows[0].col }}` → {{forecast.0.col}}.
	// Without this the raw ref never matched the flattened context keys and
	// whole-object/array refs resolved to null.
	norm := normalizeGHARefs(strings.TrimSpace(s))
	if inner := wholeTemplateRef(norm); inner != "" {
		if val, ok := resolveBindExpr(inner, flattenData(ctx.Data)); ok {
			return val
		}
		return nil
	}
	return interpolateCtx(s, ctx) // literal or text with embedded refs
}

// wholeTemplateRef returns the inner expression if the ENTIRE string is one
// `${{ ... }}` or `{{ ... }}` ref (no surrounding text, no second ref), else "".
func wholeTemplateRef(s string) string {
	for _, p := range [][2]string{{"${{", "}}"}, {"{{", "}}"}} {
		if strings.HasPrefix(s, p[0]) && strings.HasSuffix(s, p[1]) && len(s) > len(p[0])+len(p[1]) {
			inner := strings.TrimSpace(s[len(p[0]) : len(s)-len(p[1])])
			if !strings.Contains(inner, "{{") && !strings.Contains(inner, "}}") {
				return inner
			}
		}
	}
	return ""
}

func execStepCompute(ctx *FlowContext, step *FlowStep) error {
	if step.Compute == nil {
		return fmt.Errorf("compute step missing compute config - required keys: module, function")
	}
	if step.Compute.Module == "" {
		return fmt.Errorf("compute step missing `module:` - point at a TS/JS file in static/ (without extension)")
	}
	if step.Compute.Function == "" {
		return fmt.Errorf("compute step missing `function:` - name of the exported function to invoke")
	}
	if ctx.App == nil {
		return fmt.Errorf("compute step requires an app context (current ctx has none - running outside the request path?)")
	}
	// Resolve args to a NATIVE value so goja receives real objects, not a
	// stringified "map[...]". A single whole-string ref (`${{ steps.X.outputs }}`)
	// resolves to that step's actual value; a MAP of refs assembles a real
	// object field-by-field; literals/embedded-text fall back to string
	// interpolation. (Pre-fix this ran interpolateCtx → mangled any object.)
	argsValue := resolveComputeArgsValue(step.Compute.Args, ctx)
	result, err := RunCompute(ctx.App, step.Compute.Module, step.Compute.Function, argsValue, step.Compute.Timeout)
	if err != nil {
		return err
	}
	// Land the result the same way sql/api steps do - at the step
	// name AND under a `.outputs` alias so `steps.<id>.outputs`
	// references in downstream YAML resolve cleanly.
	if step.Name != "" {
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = result
		ctx.Data[step.Name+".outputs"] = result
		ctx.DataMu.Unlock()
	}
	return nil
}
