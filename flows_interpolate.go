//go:build !cli

package main

// Flow value interpolation, SQL binding, JSON values, and context flattening.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// interpolateJSONValues resolves {{var}} placeholders in JSON response values.
// If a value resolves to flow context data (e.g. a query result), it inlines the actual data.
//
// JSON-string inlining (v2.5.9+): when an interpolated value resolves
// to a string that itself parses as a JSON array or object, decode it
// and emit the structured value. This matches what agents expect when
// pairing SQL `json_group_array()` / `json_object()` with respond.json
// - pre-fix, the JSON-encoded TEXT came back from SQLite verbatim and
// got double-quoted in the response (an earlier app build had to
// flatten arrays + reassemble in JS).
func interpolateJSONValues(m map[string]any, ctx *FlowContext) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = resolveJSONValue(v, ctx)
	}
	return result
}

// resolveJSONValue resolves one respond-body value (recursing into nested
// objects + arrays). A whole-value `{{ref}}` is emitted as its NATIVE Go
// value (so arrays/objects become real JSON), not fmt.Sprintf'd.
func resolveJSONValue(v any, ctx *FlowContext) any {
	switch val := v.(type) {
	case string:
		// Whole-value single-ref: `{{x}}` and nothing else around it.
		trimmed := strings.TrimSpace(val)
		if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") && strings.Count(trimmed, "{{") == 1 {
			key := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			// Raw ctx.Data covers top-level step values (`{{r}}`,
			// `{{r.outputs}}`).
			if ctxVal, ok := ctx.Data[key]; ok {
				return maybeDecodeJSONString(ctxVal)
			}
			// NESTED whole-refs (`{{r.years}}`, `{{r.obj}}`) only exist in
			// the FLATTENED view - ctx.Data has the parent map, not the
			// dotted key. Pre-fix this missed here and fell through to
			// fmt.Sprintf, so a slice came out as "[2025 2026]" and a map
			// as "map[a:1 b:2]" (not even valid JSON). Look it up flat so
			// the native array/object/number is emitted. (Refs with pipes
			// or operators won't match either map and correctly fall
			// through to interpolateCtx below, which applies the pipe.)
			if ctxVal, ok := flatDataForCtx(ctx)[key]; ok {
				return maybeDecodeJSONString(ctxVal)
			}
		}
		// Otherwise interpolate as string, then check if the rendered
		// result looks like JSON.
		return maybeDecodeJSONString(interpolateCtx(val, ctx))
	case map[string]any:
		return interpolateJSONValues(val, ctx)
	case []any:
		// Array literals in the body interpolate element-by-element.
		arr := make([]any, len(val))
		for i, item := range val {
			arr[i] = resolveJSONValue(item, ctx)
		}
		return arr
	default:
		return v
	}
}

// maybeDecodeJSONString inlines a stringified JSON value (the typical
// output of SQLite's json_group_array() / json_object()) into the
// native Go value. Non-string inputs pass through. Strings that don't
// look like JSON pass through unchanged.
func maybeDecodeJSONString(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 {
		return v
	}
	first := trimmed[0]
	last := trimmed[len(trimmed)-1]
	if !((first == '[' && last == ']') || (first == '{' && last == '}')) {
		return v
	}
	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return v
	}
	return decoded
}

// resolveBindExpr splits a `{{ key | pipe1 | pipe2:arg }}` expression,
// looks up the base key in flatData, applies pipes left-to-right, and
// returns the final value + ok. The base key is whatever appears before
// the first pipe (or the whole expression if there are no pipes).
//
// Without pipes: returns the native value (slice / map / scalar) so the
// SQL driver can bind scalars and the caller can reject non-scalars
// with a useful error.
//
// With pipes: pipes are applied via ApplyPipe and the result is a
// string (every pipe stringifies, by design). This lets `{{ steps.X.
// outputs.rows | length }}` bind an integer-shaped string into a SQL
// `?` placeholder instead of trying to bind a slice (which the agent
// would otherwise hit as `sql: unrecognized token: "{"`).
func resolveBindExpr(expr string, flatData map[string]any) (any, bool) {
	// JS/GHA-style `a || fallback`: try the left operand; if it's missing
	// OR empty, use the right (a quoted literal or another ref). Agents
	// reach for `||` intuitively (the `| default:` pipe also works). Handle
	// `||` BEFORE the single-pipe split so it isn't mistaken for two pipes.
	if i := strings.Index(expr, "||"); i >= 0 {
		left := strings.TrimSpace(expr[:i])
		right := strings.TrimSpace(expr[i+2:])
		if v, ok := resolveBindExpr(left, flatData); ok && !isEmptyish(v) {
			return v, true
		}
		return resolveFallbackOperand(right, flatData)
	}
	parts := strings.Split(expr, "|")
	base := strings.TrimSpace(parts[0])
	val, ok := flatData[base]
	if !ok {
		// Base ref doesn't resolve in current scope. Pre-v2.7.6 this
		// always returned (nil, false), which the v2.7.5 loud-fail
		// logic then escalated to a `template_unresolved` halt - even
		// for genuinely optional refs the agent had defaulted via
		// `| default:''`. An earlier app build hit this on every
		// `${{ params.optional_field | default:'' }}` template the
		// client could legitimately omit.
		//
		// Now: if ANY pipe in the chain is `default:<value>`, we
		// short-circuit the missing-ref escalation. The default value
		// becomes the resolved value, and any pipes AFTER `default:`
		// (e.g. `| default:'' | upper`) still get applied.
		for i, p := range parts[1:] {
			name, arg, hasArg := splitPipeNameArg(p)
			if name == "default" && hasArg {
				cur := any(arg)
				for _, later := range parts[1+i+1:] {
					cur = ApplyPipe(cur, strings.TrimSpace(later))
				}
				return cur, true
			}
		}
		return nil, false
	}
	if len(parts) == 1 {
		return val, true
	}
	cur := val
	for _, p := range parts[1:] {
		cur = ApplyPipe(cur, strings.TrimSpace(p))
	}
	return cur, true
}

// isEmptyish reports whether a resolved value should trigger an `||`
// fallback - nil, blank string, or an empty collection.
func isEmptyish(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case []map[string]any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// resolveFallbackOperand resolves the right side of an `a || b`: a quoted
// literal ('x' / "x") strips to its contents; otherwise it's resolved as a
// ref (allowing `a || b || c` chains), falling back to the bare text so
// `${{ x || none }}` yields "none" rather than an unresolved-ref halt.
func resolveFallbackOperand(s string, flatData map[string]any) (any, bool) {
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return s[1 : len(s)-1], true
	}
	if v, ok := resolveBindExpr(s, flatData); ok {
		return v, true
	}
	return s, true
}

// splitPipeNameArg splits a pipe expression like `default:”` into
// ("default", "", true) or `length` into ("length", "", false). The
// arg can be quoted with single or double quotes; quotes are stripped.
// Used by resolveBindExpr to detect `default:` short-circuits.
func splitPipeNameArg(pipeExpr string) (name, arg string, hasArg bool) {
	pipeExpr = strings.TrimSpace(pipeExpr)
	colon := strings.Index(pipeExpr, ":")
	if colon < 0 {
		return pipeExpr, "", false
	}
	name = strings.TrimSpace(pipeExpr[:colon])
	arg = strings.TrimSpace(pipeExpr[colon+1:])
	// Strip surrounding quotes if present.
	if len(arg) >= 2 {
		if (arg[0] == '\'' && arg[len(arg)-1] == '\'') ||
			(arg[0] == '"' && arg[len(arg)-1] == '"') {
			arg = arg[1 : len(arg)-1]
		}
	}
	return name, arg, true
}

// sqlBindValue converts a string param to int64/float64 when - and only
// when - the numeric form round-trips back to the EXACT same string.
//
// Why: ctx.Params is map[string]string, so every :param used to bind as
// TEXT. SQLite compares a TEXT value as GREATER than any number when
// neither operand picks up column affinity - which is exactly the shape
// of a flow guard like `WHERE :amt >= (SELECT SUM(...))`: the bound
// '5000' silently beat 10515 and the guard NEVER fired. No error, no
// warning - the worst failure class. Comparisons against real columns
// were saved by column affinity, which is why the bug only bit
// expression comparisons.
//
// The canonical round-trip requirement is the safety valve: '01234',
// '5e3', '1.50' and '+1' all keep binding as TEXT (their numeric form
// prints differently), so zip codes and phone numbers still compare
// byte-for-byte against TEXT columns. A value that DOES round-trip
// ('5000', '6.5') is indistinguishable from its number even against a
// TEXT-affinity column - SQLite converts the number back to the same
// string - so the rewrite is observable only where the old behavior was
// wrong.
//
// Sibling: hooks.go's coerceNumericBind fixes the same trap for hook
// SQL with a more permissive rule (regex; coerces '1.50' → 1.5). Flow
// params come from URLs/JSON where identifier-shaped strings are
// common, so the stricter round-trip rule is deliberate here - don't
// "unify" them without weighing that trade-off.
func sqlBindValue(s string) any {
	if s == "" {
		return s
	}
	if c := s[0]; c != '-' && (c < '0' || c > '9') {
		return s
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if strconv.FormatInt(i, 10) == s {
			return i
		}
		return s
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if strconv.FormatFloat(f, 'f', -1, 64) == s {
			return f
		}
	}
	return s
}

// interpolateCtxSafe replaces {{var}} with ? placeholders for SQL parameterization.
// Processes left-to-right through the string to maintain correct arg ordering.
func interpolateCtxSafe(template string, ctx *FlowContext) (string, []any) {
	// First pass: replace :param with ? placeholders (path params are user input, must be parameterized)
	var paramResult strings.Builder
	var paramArgs []any
	tmp := template
	for {
		// Find the earliest :param match WITH word-boundary enforcement.
		//
		// Pre-v2.7.6 the loop did `strings.Index(tmp, ":"+k)` with no
		// boundary check after the name. If both `:expo` and `:export`
		// were registered params, the search for `:expo` would happily
		// match the first 5 chars of `:export` in the query, leaving
		// the trailing `rt` literal in the SQL after the `?` was
		// inserted. SQLite then either failed to parse or bound the
		// wrong column. Same shape as the v2.7.5 INSERT…RETURNING bug:
		// "prefix-based detection without a boundary" was the root cause.
		//
		// Fix: require the char AFTER the param name to be a non-
		// identifier (or EOF). Valid SQL identifier chars are letters,
		// digits, underscores - so `:expo,` and `:expo)` and `:expo `
		// all match, but `:export` and `:expoXYZ` and `:expo_v2` do not.
		bestIdx := -1
		bestKey := ""
		bestVal := ""
		for k, v := range ctx.Params {
			searchIdx := 0
			for {
				rel := strings.Index(tmp[searchIdx:], ":"+k)
				if rel < 0 {
					break
				}
				abs := searchIdx + rel
				// Boundary check: char after the param name must be a
				// non-identifier (or end of string).
				end := abs + len(":"+k)
				if end < len(tmp) {
					c := tmp[end]
					isIdent := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') || c == '_'
					if isIdent {
						// Not a real match - keep scanning past this position.
						searchIdx = abs + 1
						continue
					}
				}
				if bestIdx < 0 || abs < bestIdx {
					bestIdx = abs
					bestKey = k
					bestVal = v
				}
				break
			}
		}
		if bestIdx < 0 {
			paramResult.WriteString(tmp)
			break
		}
		paramResult.WriteString(tmp[:bestIdx])
		paramResult.WriteByte('?')
		// NullParams sidecar: if the source expression resolved to Go
		// nil, bind SQL NULL rather than the empty string. Distinguishes
		// "explicit null" from "explicit empty string" - both look the
		// same in ctx.Params (which is map[string]string) but mean
		// different things to the column.
		if ctx.NullParams != nil && ctx.NullParams[bestKey] {
			paramArgs = append(paramArgs, nil)
		} else {
			paramArgs = append(paramArgs, sqlBindValue(bestVal))
		}
		tmp = tmp[bestIdx+len(":"+bestKey):]
	}

	result := InterpolateEnv(paramResult.String(), ctx.App.Dir)

	flatData := flatDataForCtx(ctx)

	// Second pass LEFT-TO-RIGHT: scan for {{ }}, resolve each one in order
	// Start with param args collected above, then append data args in order
	args := make([]any, 0, len(paramArgs))
	args = append(args, paramArgs...)
	var output strings.Builder
	i := 0
	for i < len(result) {
		// Check for '{{key}}' (quoted placeholder - inline as literal, SQL-escaped)
		if i+3 < len(result) && result[i] == '\'' && result[i+1] == '{' && result[i+2] == '{' {
			end := strings.Index(result[i+3:], "}}'")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+3 : i+3+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					// Inline the value inside quotes (escape single quotes to prevent injection)
					s := fmt.Sprintf("%v", val)
					s = strings.ReplaceAll(s, "'", "''")
					output.WriteByte('\'')
					output.WriteString(s)
					output.WriteByte('\'')
					i = i + 3 + end + 3
					continue
				}
				// Note the unresolved ref so the step dispatcher can
				// halt with a clear error instead of binding the literal
				// `{{ws.id}}` string into the SQL. Without this branch
				// the placeholder character (?) below would bind the
				// quoted literal text as a string param, the row would
				// land with a malformed foreign key, and the failure
				// would surface three steps later as a UNIQUE constraint
				// rollback with no obvious connection to the unresolved
				// reference.
				ctx.noteMissingRef(expr)
			}
		}
		// Check for {{key}} (unquoted placeholder)
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+2 : i+2+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					output.WriteByte('?')
					// Pipe results stringify by design (resolveBindExpr), so
					// `{{ rows | length }}` arrives here as "3" - give it the
					// same canonical-numeric treatment as :params so it
					// compares numerically too.
					if s, isStr := val.(string); isStr {
						val = sqlBindValue(s)
					}
					args = append(args, val)
					i = i + 2 + end + 2
					continue
				}
				ctx.noteMissingRef(expr)
			}
		}
		output.WriteByte(result[i])
		i++
	}

	return output.String(), args
}

// interpolateCtx replaces {{var}} and {{var | pipe}} with context data.
// Mirrors interpolateCtxSafe's scan-based parser so pipe expressions
// behave identically across SQL (param-bound) and non-SQL (string
// substitution) contexts. Used by respond:, headers:, run: api, etc.
func interpolateCtx(template string, ctx *FlowContext) string {
	result := template
	// Replace :param with param values
	for k, v := range ctx.Params {
		result = strings.ReplaceAll(result, ":"+k, v)
	}
	// Replace {{env.X}}
	result = InterpolateEnv(result, ctx.App.Dir)
	flatData := flatDataForCtx(ctx)

	var output strings.Builder
	i := 0
	for i < len(result) {
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+2 : i+2+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					// Render nil as empty string instead of Go's default
					// "<nil>" - that literal was leaking into UI columns,
					// JSON responses, and SQL inserts (where it landed
					// as the three-character string). For SQL bind, the
					// proper NULL handling lives in interpolateCtxSafe
					// via ctx.NullParams; this branch covers all the
					// non-SQL string-substitution callers (respond:,
					// headers:, run: api URLs).
					if val == nil {
						i = i + 2 + end + 2
						continue
					}
					output.WriteString(fmt.Sprintf("%v", val))
					i = i + 2 + end + 2
					continue
				}
				// Unresolved reference - record it so the step
				// dispatcher can halt with a clear error. Pre-v2.7.5 the
				// literal `{{first_name}}` text was emitted into the
				// surrounding string, then leaked into HTTP responses
				// (where the client saw raw `{{ws.name}}` placeholders),
				// SQL queries (where it parsed as identifier or got bound
				// as a literal string), and webhook bodies.
				ctx.noteMissingRef(expr)
			}
		}
		output.WriteByte(result[i])
		i++
	}
	return output.String()
}

// flattenData walks ctx.Data and produces a flat key→value map keyed
// by dotted paths. Supports nested maps AND slices uniformly:
//
//	ctx.Data = { "stories": [{"id":1,"title":"X"}, {"id":2,"title":"Y"}] }
//
// produces (among others):
//
//	"stories"             → the whole slice
//	"stories.0"           → the first row (map)
//	"stories.0.title"     → "X"
//	"stories.0.id"        → 1
//	"stories.1.title"     → "Y"
//
// AND a single-element-slice promotes its element to the slice key
// itself, so `{{user}}` resolves to `{...}` when the SQL returned
// exactly one row. This preserves the old "1-row → object" template
// ergonomics while making `outputs.*` always work as an array.
// flatDataForCtx is the canonical lookup table for `{{ ... }}`
// references in flow templating. It returns flattenData(ctx.Data)
// PLUS every env var the app can see, surfaced under the `env.<key>`
// namespace.
//
// Why the env overlay (v2.7.7+): InterpolateEnv runs as a pre-pass
// and substitutes the literal `{{env.X}}` form before the main scan
// reaches resolveBindExpr. But it doesn't match pipe-form refs like
// `{{env.X | default:'fallback'}}` - those survive past
// InterpolateEnv and hit the main scanner, which used to find
// nothing in flatData and fall back to the default (masking the
// real env value with the fallback). By overlaying env vars into
// flatData, the pipe-form resolves correctly: present env wins,
// missing env triggers the default-pipe short-circuit added in
// v2.7.6.
//
// The overlay is read-only: we don't mutate the per-app store from
// here, just copy the snapshot at template-resolution time.
func flatDataForCtx(ctx *FlowContext) map[string]any {
	flat := flattenData(ctx.Data)
	if ctx == nil || ctx.App == nil {
		return flat
	}
	for k, v := range AppEnvSnapshot(ctx.App.Dir) {
		flat["env."+k] = v
	}
	return flat
}

func flattenData(data map[string]any) map[string]any {
	flat := make(map[string]any)
	for k, v := range data {
		flattenInto(flat, k, v)
		// Single-element slice → also expose the element under the
		// step's key directly (e.g. `{{user.email}}` works after a
		// `SELECT * FROM users WHERE id = :id`).
		if slice, ok := v.([]map[string]any); ok && len(slice) == 1 {
			for mk, mv := range slice[0] {
				key := k + "." + mk
				if _, exists := flat[key]; !exists {
					flat[key] = mv
				}
			}
		} else if slice, ok := v.([]any); ok && len(slice) == 1 {
			if m, ok := slice[0].(map[string]any); ok {
				for mk, mv := range m {
					key := k + "." + mk
					if _, exists := flat[key]; !exists {
						flat[key] = mv
					}
				}
			}
		}
		// `.first` sugar - always exposes row 0 from a slice result,
		// regardless of how many rows came back. Lets multi-row SELECTs
		// use object access for the top hit (e.g.
		// `${{ steps.recent_posts.outputs.first.title }}`) without
		// resorting to `.0.title` index notation. Distinct from the
		// auto-collapse above: that triggers only on len==1; this one
		// is always-on, and `.first` is the explicit ask.
		firstKey := k + ".first"
		if slice, ok := v.([]map[string]any); ok && len(slice) > 0 {
			flat[firstKey] = map[string]any(slice[0])
			for mk, mv := range slice[0] {
				key := firstKey + "." + mk
				if _, exists := flat[key]; !exists {
					flat[key] = mv
				}
			}
		} else if slice, ok := v.([]any); ok && len(slice) > 0 {
			if m, ok := slice[0].(map[string]any); ok {
				flat[firstKey] = m
				for mk, mv := range m {
					key := firstKey + "." + mk
					if _, exists := flat[key]; !exists {
						flat[key] = mv
					}
				}
			}
		}
	}
	return flat
}

// flattenInto recurses through maps + slices, keyed by dotted path.
func flattenInto(flat map[string]any, prefix string, v any) {
	flat[prefix] = v
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			flattenInto(flat, prefix+"."+k, child)
		}
	case []map[string]any:
		for i, row := range t {
			flattenInto(flat, fmt.Sprintf("%s.%d", prefix, i), map[string]any(row))
		}
	case []any:
		for i, child := range t {
			flattenInto(flat, fmt.Sprintf("%s.%d", prefix, i), child)
		}
	}
}
