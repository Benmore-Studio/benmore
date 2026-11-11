//go:build !cli

package main

// Request text stays text in JSON bodies.
//
// A respond `json:`, a `run: api` `json:` or text body, a `run: webhook` body
// and a broadcast payload decode a value that is JSON text of an object or
// array, so a json_group_array() column or a step's JSON-text output arrives
// as structure (resolveJSONValue, interpolateCtxJSON). The same decode turned
// a form field `a={"admin":true}` into an object: text the caller sent could
// add structure (a NoSQL operator object, extra keys) to the response or to an
// outbound request. A string the caller sent now stays a string there. Values
// a JSON request body sent as objects or arrays keep their structure (the
// caller typed them), and so do step outputs.
//
// Request text is a string value read through a request-tainted key
// (RequestKeys) that does not hold computed data (computedKeys): the
// request's own fields, a parse step's output, a `run: set` value or a loop
// variable built from request text. A step that reads request input and
// returns data (a SQL lookup keyed by `:id`) is tainted for sql_dynamic but
// is computed here, so its json_group_array() column still decodes.

import "strings"

// markComputed records keys whose value is computed data, not request text.
func (ctx *FlowContext) markComputed(keys ...string) {
	if ctx == nil || len(keys) == 0 {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if ctx.computedKeys == nil {
		ctx.computedKeys = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		if k != "" {
			ctx.computedKeys[k] = true
		}
	}
}

// unmarkComputed records that keys now hold request text again (the latest
// write of a key decides what it holds).
func (ctx *FlowContext) unmarkComputed(keys ...string) {
	if ctx == nil {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	for _, k := range keys {
		delete(ctx.computedKeys, k)
	}
}

// flowExprRawRefPaths is flowExprRefPaths with a leading `params.` kept, so
// a caller can tell an explicit request-field read from a step output of the
// same name.
func flowExprRawRefPaths(expr string) []string {
	var out []string
	if flowValueExprUsesOperators(expr) {
		for _, ref := range flowValueExprRefs(expr, false) {
			if ref = strings.ReplaceAll(strings.ReplaceAll(ref, "[", "."), "]", ""); ref != "" {
				out = append(out, ref)
			}
		}
		return out
	}
	for _, operand := range strings.Split(expr, "||") {
		base := strings.TrimSpace(strings.SplitN(operand, "|", 2)[0])
		if base == "" || base[0] == '\'' || base[0] == '"' {
			continue
		}
		if i := strings.IndexAny(base, " \t\r\n"); i >= 0 {
			base = base[:i]
		}
		if base = strings.ReplaceAll(strings.ReplaceAll(base, "[", "."), "]", ""); base != "" {
			out = append(out, base)
		}
	}
	return out
}

// refReadsRequest reports whether ref reads a request-tainted key that holds
// request input rather than computed data. `params.X` always reads the
// request field X, even when a step shares its name.
func (ctx *FlowContext) refReadsRequest(ref string) bool {
	key, explicit := strings.CutPrefix(ref, "params.")
	if key == "" {
		return false
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	for k := range ctx.RequestKeys {
		if k == "" || !explicit && ctx.computedKeys[k] {
			continue
		}
		if flowPathsOverlap(key, k) {
			return true
		}
	}
	return false
}

// exprReadsRequestKey reports whether the `{{ ... }}` expression expr reads
// request input of any type (a loop over a JSON body array iterates the
// request's own values).
func (ctx *FlowContext) exprReadsRequestKey(expr string) bool {
	if ctx == nil {
		return false
	}
	for _, ref := range flowExprRawRefPaths(expr) {
		if ctx.refReadsRequest(ref) {
			return true
		}
	}
	return false
}

// exprReadsRequestText reports whether the `{{ ... }}` expression expr reads
// a string the caller sent. flat is flatDataForCtx(ctx).
func (ctx *FlowContext) exprReadsRequestText(expr string, flat map[string]any) bool {
	if ctx == nil {
		return false
	}
	for _, ref := range flowExprRawRefPaths(expr) {
		if !ctx.refReadsRequest(ref) {
			continue
		}
		if v, ok := flowLookup(flat, ref); ok {
			if _, text := v.(string); text {
				return true
			}
		}
	}
	return false
}

// readsRequestText reports whether template, as interpolateCtx scans it,
// substitutes a string the caller sent: through a `:name` request parameter
// or a `{{ ... }}` expression.
func (ctx *FlowContext) readsRequestText(template string, flat map[string]any) bool {
	if ctx == nil || len(ctx.RequestKeys) == 0 {
		return false
	}
	for i := 0; i < len(template); {
		if n, _, ok := colonParamAt(template, i, ctx.Params); ok {
			// ctx.Params holds text even for a JSON body's typed values,
			// so a request parameter is always text here.
			name := template[i+1 : i+n]
			ctx.DataMu.Lock()
			request := ctx.RequestKeys[name] && !ctx.computedKeys[name]
			ctx.DataMu.Unlock()
			if request {
				return true
			}
			i += n
			continue
		}
		if i+2 < len(template) && template[i] == '{' && template[i+1] == '{' {
			if end := strings.Index(template[i+2:], "}}"); end >= 0 {
				if ctx.exprReadsRequestText(strings.TrimSpace(template[i+2:i+2+end]), flat) {
					return true
				}
				i += end + 4
				continue
			}
		}
		i++
	}
	return false
}

// keepRequestTextString returns v unchanged when it is request text, and
// otherwise decodes JSON text of an object or array as before.
func keepRequestTextString(v any, requestText bool) any {
	if _, text := v.(string); text && requestText {
		return v
	}
	return maybeDecodeJSONString(v)
}

// jsonContainerText reports text that would decode as a JSON object or array.
func jsonContainerText(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && (s[0] == '{' || s[0] == '[')
}
