//go:build !cli

package main

// Branching, iteration, value transformation, body parsing, and compute steps.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
)

func execStepIf(ctx *FlowContext, step *FlowStep) error {
	// The condition reads request fields as they are; the branch not taken
	// is decided here, so what it would have defined is shadowed now
	// (shadowReachedSteps). The taken branch's steps shadow as each is
	// reached.
	if evaluateFlowCondition(step.Condition, ctx) {
		shadowReachedSteps(ctx, step.ElseSteps, true)
		executeSteps(ctx, step.Steps)
	} else {
		shadowReachedSteps(ctx, step.Steps, true)
		if len(step.ElseSteps) > 0 {
			executeSteps(ctx, step.ElseSteps)
		}
	}
	return ctx.Error
}

func execStepForEach(ctx *FlowContext, step *FlowStep) error {
	items, ok := flowDataValue(ctx, step.ForEach)
	if !ok {
		// Compute and nested request values need not have pre-flattened keys
		// in Data. Resolve their native arrays just like compute arguments and
		// response values, while retaining the existing direct-key precedence.
		items, ok = resolveBindExpr(step.ForEach, flatDataForCtx(ctx))
	}
	// The loop is reached: its variable and everything its body defines
	// are shadowed now, before the first iteration and for zero
	// iterations alike (shadowReachedSteps).
	shadowReachedSteps(ctx, []FlowStep{{Type: "for_each", ForAs: step.ForAs, Steps: step.Steps}}, true)
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
	// Iterating request input (a JSON-body array, a tainted set output)
	// makes every loop variable request input too; iterating a
	// secret-derived value makes it secret-derived.
	if ctx.taintedRef("{{"+step.ForEach+"}}") != "" {
		ctx.markTainted(as)
		ctx.copyRequestStepSource(as, "{{"+step.ForEach+"}}")
	}
	if ctx.secretRef("{{"+step.ForEach+"}}") != "" {
		ctx.markSecret(as)
	}

	for _, row := range rows {
		// Replace the whole loop value, including flattened descendants.
		// Otherwise fields absent from this row (or a shorter nested array)
		// still resolve to the previous row's value in templates and SQL binds.
		ctx.DataMu.Lock()
		for key := range ctx.Data {
			if strings.HasPrefix(key, as+".") {
				delete(ctx.Data, key)
			}
		}
		ctx.Data[as] = row
		flattenIntoCtx(ctx.Data, as, row)
		ctx.DataMu.Unlock()
		ctx.markParallelOutput(as)
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
	// A request field with the name of one of this set's keys was shadowed
	// at flow start so it can't stand in for the set if the set is skipped
	// (shadowStepNamedRequestKeys). This set is running and overwrites the
	// key below, so its own values may read the request field again: that
	// is the `page: "${{ page | default:'1' }}"` normalization idiom.
	ctx.DataMu.Lock()
	if shadowed, ok := ctx.Data[flowStepNamedParamsKey].(map[string]any); ok {
		for k := range step.Set {
			if _, present := ctx.Data[k]; present {
				continue
			}
			if v, ok := shadowed[k]; ok {
				ctx.Data[k] = v
			}
		}
	}
	ctx.DataMu.Unlock()
	resolved := make(map[string]any, len(step.Set))
	var tainted, secret []string
	for k, v := range step.Set {
		val := interpolateCtx(v, ctx)
		resolved[k] = val
		// A value computed from request input stays request input under its
		// new names (`{{k}}` and `steps.<id>.outputs.k`), or sql_dynamic
		// would see it as a trusted step output. A value computed from env
		// stays secret-derived the same way (flows_taint.go).
		if ctx.taintedRef(v) != "" {
			tainted = append(tainted, k)
			if step.Name != "" {
				tainted = append(tainted, step.Name+"."+k)
			}
		}
		if ctx.readsSecret(v) {
			secret = append(secret, k)
			if step.Name != "" {
				secret = append(secret, step.Name+"."+k)
			}
		}
	}
	ctx.markTainted(tainted...)
	ctx.markSecret(secret...)
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
	if step.Parse == "headers" && ctx.Request != nil {
		name := step.Name
		if name == "" {
			name = "headers"
		}
		data := make(map[string]any, len(ctx.Request.Header))
		for key, values := range ctx.Request.Header {
			canonical := http.CanonicalHeaderKey(key)
			if canonical == "" {
				continue
			}
			all, _ := data[canonical].([]string)
			data[canonical] = append(append([]string{}, all...), values...)
		}
		ctx.Data[name] = data
		for key, value := range data {
			ctx.Data[name+"."+key] = value
		}
		ctx.markTainted(name) // request headers are untrusted caller input
		return nil
	}
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
			ctx.markTainted(name) // the parsed body IS request input
			return nil
		}

		// Fall back to JSON
		body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, flowVerifyBodyMaxBytes))
		if err != nil {
			return err
		}
		var data any
		decode := func() error {
			if ctx.mcpReadConn == nil {
				return json.Unmarshal(body, &data)
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.UseNumber()
			return decoder.Decode(&data)
		}
		if err := decode(); err != nil {
			return fmt.Errorf("parse body: %w", err)
		}
		name := step.Name
		if name == "" {
			name = "body"
		}
		ctx.Data[name] = data
		ctx.markTainted(name) // the parsed body IS request input
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
	//
	// The lookup table is flatDataForCtx, not flattenData: a whole-string
	// `${{ env.X }}` (or `{{env.X}}`, which this branch catches before
	// InterpolateEnv ever sees it) must resolve the app's env like every
	// other template path. With the bare step data, env refs came through
	// as nil - or silently as their `default:` - so a compute module could
	// never receive a configured secret (e.g. a key it signs with).
	norm := normalizeGHARefs(strings.TrimSpace(s))
	if inner := wholeTemplateRef(norm); inner != "" {
		if val, ok := resolveBindExpr(inner, flatDataForCtx(ctx)); ok {
			// goja writes through Go maps and slices, so the module gets a
			// copy: an earlier step's output, a request field or the user
			// row stays what it was when its own step finished (taint and
			// `if:` checks already ran on it).
			return cloneComputeArg(val)
		}
		// A ref into a step the flow has reached is optional data: a query
		// that matched no row, a step its `if:` skipped, a key the module
		// did not return. Those arrive as null, as they did before 2.7.278.
		// Anything else (a step id that is not in the flow, an unset env
		// value, a request field the caller did not send) stops the flow.
		if ctx.stepReached(flowRefRoot(inner)) {
			return nil
		}
		ctx.noteMissingRef(inner)
		return nil
	}
	// Literal or text with embedded refs. Interpolate the GHA-normalized
	// form: interpolateCtx only understands `{{ ... }}`, so `k=${{ env.X }}`
	// used to render as `k=$value` (the `$` survived). Normalize the
	// untrimmed string so a literal's surrounding whitespace is kept.
	return interpolateCtx(normalizeGHARefs(s), ctx)
}

// markStepsReached records step and, for an if block or a loop, every step
// nested in it: reaching the block decides those steps, whether they then
// run, are skipped or loop zero times. A parallel block's branches record
// their own steps in their own contexts.
func (ctx *FlowContext) markStepsReached(step *FlowStep) {
	if ctx == nil || step == nil {
		return
	}
	if ctx.reachedSteps == nil {
		ctx.reachedSteps = make(map[string]bool)
	}
	var mark func(s *FlowStep, deep bool)
	mark = func(s *FlowStep, deep bool) {
		if s.Name != "" {
			ctx.reachedSteps[s.Name] = true
		}
		if !deep {
			return
		}
		for i := range s.Steps {
			mark(&s.Steps[i], true)
		}
		for i := range s.ElseSteps {
			mark(&s.ElseSteps[i], true)
		}
	}
	mark(step, step.Type == "if" || step.Type == "for_each")
}

func (ctx *FlowContext) stepReached(name string) bool {
	return ctx != nil && name != "" && ctx.reachedSteps[name]
}

// flowRefRoot is the first path segment of a normalized reference, which
// names a step for a step output (`lookup.amount` from
// `steps.lookup.outputs.amount`).
func flowRefRoot(expr string) string {
	if i := strings.Index(expr, "||"); i >= 0 {
		expr = expr[:i]
	}
	base := strings.TrimPrefix(ghaRefBase(expr), "steps.")
	root, _, _ := strings.Cut(base, ".")
	return strings.TrimSpace(root)
}

// cloneComputeArg deep-copies the maps and slices of a flow value, keeping
// every container's type, so goja sees the same shapes it did before.
func cloneComputeArg(v any) any {
	switch x := v.(type) {
	case nil, string, bool, int, int64, float64:
		return v
	case map[string]any:
		if x == nil {
			return x
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneComputeArg(e)
		}
		return out
	case []any:
		if x == nil {
			return x
		}
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneComputeArg(e)
		}
		return out
	case []map[string]any:
		if x == nil {
			return x
		}
		out := make([]map[string]any, len(x))
		for i, e := range x {
			out[i], _ = cloneComputeArg(e).(map[string]any)
		}
		return out
	}
	return cloneComputeReflect(reflect.ValueOf(v)).Interface()
}

func cloneComputeReflect(rv reflect.Value) reflect.Value {
	switch rv.Kind() {
	case reflect.Interface:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type()).Elem()
		out.Set(cloneComputeReflect(rv.Elem()))
		return out
	case reflect.Map:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for it := rv.MapRange(); it.Next(); {
			out.SetMapIndex(it.Key(), cloneComputeReflect(it.Value()))
		}
		return out
	case reflect.Slice:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out.Index(i).Set(cloneComputeReflect(rv.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(rv.Type()).Elem()
		for i := 0; i < rv.Len(); i++ {
			out.Index(i).Set(cloneComputeReflect(rv.Index(i)))
		}
		return out
	case reflect.Pointer:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type().Elem())
		out.Elem().Set(cloneComputeReflect(rv.Elem()))
		return out
	}
	return rv
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
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		return fmt.Errorf("compute: unresolved argument template reference(s): %s", strings.Join(missing, ", "))
	}
	// `with.timeout`, or the step-level `timeout:`, which wins as it does on
	// an api step. The step-level key used to be accepted and never applied.
	timeout := step.Compute.Timeout
	if step.Timeout > 0 {
		timeout = step.Timeout
	}
	var result any
	var err error
	if ctx.mcpReadConn != nil {
		argsValue, err = appMCPComputeArgs(argsValue)
		if err != nil {
			return err
		}
		result, err = RunComputeContext(ctx.Request.Context(), ctx.App, step.Compute.Module, step.Compute.Function, argsValue, timeout)
	} else {
		result, err = RunCompute(ctx.App, step.Compute.Module, step.Compute.Function, argsValue, timeout)
	}
	// argsValue holds copies (cloneComputeArg), so the function cannot
	// have edited ctx.Data; the cache is dropped anyway, as before.
	ctx.flatCache.invalidate()
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
