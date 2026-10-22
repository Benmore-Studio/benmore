//go:build !cli

package main

// Request-taint propagation for the sql_dynamic guard (M-1).
//
// FlowContext.RequestKeys starts as the set of keys the HTTP entry point
// copied from the request (path, query, form, JSON body). Steps that copy a
// value from one key to another must carry that taint to the new key, or a
// request value laundered through `run: set`, a for_each loop variable, a
// parsed request body or an enqueued job payload reaches sql_dynamic as raw
// SQL text without tripping the guard. Taint is only ever added: a later
// write of a trusted value to a tainted key keeps the key tainted, because
// ctx.Params (which `:name` substitution reads) may still hold the request
// value.

import (
	"reflect"
	"sort"
	"strings"
)

// flowExprRefPaths returns the data paths a `{{ ... }}` expression reads:
// the base (text before the first pipe) of every `||` operand, with `[N]`
// indexes normalized to `.N`. Quoted fallback literals are not references.
func flowExprRefPaths(expr string) []string {
	var out []string
	for _, operand := range strings.Split(expr, "||") {
		base := strings.TrimSpace(strings.SplitN(operand, "|", 2)[0])
		if base == "" || base[0] == '\'' || base[0] == '"' {
			continue
		}
		if i := strings.IndexAny(base, " \t\r\n"); i >= 0 {
			base = base[:i]
		}
		base = strings.ReplaceAll(strings.ReplaceAll(base, "[", "."), "]", "")
		// `params.X` reads the request field X (flowLookup).
		base = strings.TrimPrefix(base, "params.")
		if base != "" {
			out = append(out, base)
		}
	}
	return out
}

// flowPathsOverlap reports whether reading ref can observe the value stored
// at key: the same path, a field below key (`key.sub`), or an ancestor that
// renders key as part of a whole map (`{{copy}}` when `copy.val` is tainted).
func flowPathsOverlap(ref, key string) bool {
	return ref == key || strings.HasPrefix(ref, key+".") || strings.HasPrefix(key, ref+".")
}

// flowTemplateRefsKey reports whether template reads key, either as a
// `:key` placeholder (word-bounded, so `:user` does not match `:user_id`) or
// through any `{{ ... }}` reference path that overlaps key.
func flowTemplateRefsKey(template, key string) bool {
	if key == "" {
		return false
	}
	for idx := 0; ; {
		at := strings.Index(template[idx:], ":"+key)
		if at < 0 {
			break
		}
		pos := idx + at
		after := pos + 1 + len(key)
		if after >= len(template) || !flowIsIdentChar(template[after]) {
			return true
		}
		idx = after
	}
	for i := 0; i+1 < len(template); i++ {
		if template[i] != '{' || template[i+1] != '{' {
			continue
		}
		end := strings.Index(template[i+2:], "}}")
		if end < 0 {
			break
		}
		for _, ref := range flowExprRefPaths(template[i+2 : i+2+end]) {
			if flowPathsOverlap(ref, key) {
				return true
			}
		}
		i = i + 2 + end + 1
	}
	return false
}

// taintedRef returns the first request-tainted key template reads (sorted
// for a deterministic error message), or "" when it reads none.
func (ctx *FlowContext) taintedRef(template string) string {
	if ctx == nil || template == "" {
		return ""
	}
	ctx.DataMu.Lock()
	keys := make([]string, 0, len(ctx.RequestKeys))
	for k := range ctx.RequestKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	ctx.DataMu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		if flowTemplateRefsKey(template, k) {
			return k
		}
	}
	return ""
}

// isTainted reports whether key itself is in the request-taint set.
func (ctx *FlowContext) isTainted(key string) bool {
	if ctx == nil || key == "" {
		return false
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	return ctx.RequestKeys[key]
}

// markTainted adds keys to the request-taint set.
func (ctx *FlowContext) markTainted(keys ...string) {
	if ctx == nil || len(keys) == 0 {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if ctx.RequestKeys == nil {
		ctx.RequestKeys = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		if k != "" {
			ctx.RequestKeys[k] = true
		}
	}
}

// flowStepTemplateStrings collects every string a step's own configuration
// holds (SQL, with.params, api URL/query/headers/body/sign bindings, compute
// args, email/sms fields, ...). Nested child steps are skipped: each child
// taints its own outputs when it runs.
func flowStepTemplateStrings(step *FlowStep) []string {
	var out []string
	var walk func(v reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			out = append(out, v.String())
		case reflect.Ptr, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				walk(v.MapIndex(k))
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i))
				}
			}
		}
	}
	rv := reflect.ValueOf(step).Elem()
	for i := 0; i < rv.NumField(); i++ {
		switch rv.Type().Field(i).Name {
		case "Steps", "ElseSteps", "OnError", "Name", "Type":
			continue
		}
		walk(rv.Field(i))
	}
	return out
}

// taintStepOutputs marks a named step's outputs as request-tainted when any
// template the step is built from reads a tainted key. The sql, compute, api
// and every other output-producing step type land their result at
// ctx.Data[<id>]; without this, `SELECT :q AS c` (or a compute over a request
// field) launders request input into a value sql_dynamic treats as trusted.
// Steps with their own precise propagation (set, parse, enqueue) and control
// steps (if, for_each, parallel) are handled where they run; sql_dynamic
// itself has already passed the guard, so its output is not derived from
// request text.
//
// The same pass marks the outputs secret-derived when a template reads an
// env value or a secret-derived key (sql_dynamic included: its text may
// read env).
func (ctx *FlowContext) taintStepOutputs(step *FlowStep) {
	if ctx == nil || step == nil || step.Name == "" {
		return
	}
	switch step.Type {
	case "set", "parse", "enqueue", "if", "for_each", "parallel":
		return
	}
	templates := flowStepTemplateStrings(step)
	for _, tmpl := range templates {
		if ctx.readsSecret(tmpl) {
			ctx.markSecret(step.Name)
			break
		}
	}
	if step.Type == "sql_dynamic" {
		return
	}
	for _, tmpl := range templates {
		if ctx.taintedRef(tmpl) != "" {
			ctx.markTainted(step.Name)
			ctx.noteRequestStepSource(step.Name, templates)
			return
		}
	}
}

// Secret taint. SecretKeys marks values derived from the app's env: a step
// whose templates read an env value or a secret-derived key yields
// secret-derived outputs, and set, for_each and enqueue carry the mark key
// by key, the way request taint travels. A `run: api` or `run: webhook`
// call that sends a secret-derived value carries the app's secrets as much
// as one with `{{env.X}}` written into it, so request input may not choose
// its host (flows_api_url.go). Without this, a SQL step binding
// `${{ env.CLIENT_SECRET }}` and an api call sending its output to a
// request-chosen URL handed the secret to any host.

// flowTemplateRefsEnv reports whether template reads an env value: an
// `env.` path inside a `{{ ... }}` expression, including a quoted inner
// template such as `{{ '{{env.ID}}:{{env.KEY}}' | base64 }}`. A step
// output key named env (`x.env.y`) is not an env read.
func flowTemplateRefsEnv(template string) bool {
	for i := 0; i+1 < len(template); i++ {
		if template[i] != '{' || template[i+1] != '{' {
			continue
		}
		end := strings.Index(template[i+2:], "}}")
		if end < 0 {
			return false
		}
		expr := template[i+2 : i+2+end]
		for at := 0; ; {
			j := strings.Index(expr[at:], "env.")
			if j < 0 {
				break
			}
			j += at
			if j == 0 || !(flowIsIdentChar(expr[j-1]) || expr[j-1] == '.') {
				return true
			}
			at = j + len("env.")
		}
		i = i + 2 + end + 1
	}
	return false
}

// secretRef returns the first secret-derived key template reads (sorted
// for a deterministic error message), or "" when it reads none. A direct
// env reference is flowTemplateRefsEnv's concern.
func (ctx *FlowContext) secretRef(template string) string {
	if ctx == nil || template == "" {
		return ""
	}
	ctx.DataMu.Lock()
	keys := make([]string, 0, len(ctx.SecretKeys))
	for k := range ctx.SecretKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	ctx.DataMu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		if flowTemplateRefsKey(template, k) {
			return k
		}
	}
	return ""
}

// readsSecret reports whether template reads an env value or a
// secret-derived key.
func (ctx *FlowContext) readsSecret(template string) bool {
	return flowTemplateRefsEnv(template) || ctx.secretRef(template) != ""
}

// markSecret adds keys to the secret-derived set.
func (ctx *FlowContext) markSecret(keys ...string) {
	if ctx == nil || len(keys) == 0 {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if ctx.SecretKeys == nil {
		ctx.SecretKeys = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		if k != "" {
			ctx.SecretKeys[k] = true
		}
	}
}

// noteRequestStepSource records the author-written strings of the step
// that produced the request-tainted key name (flowValueAuthoredByStep).
func (ctx *FlowContext) noteRequestStepSource(name string, templates []string) {
	if ctx == nil || name == "" {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if ctx.requestStepSources == nil {
		ctx.requestStepSources = make(map[string][]string)
	}
	ctx.requestStepSources[name] = templates
}

// copyRequestStepSource gives key the recorded step strings of the
// request-tainted keys template reads, when every one has them: a for_each
// loop variable is a row of the step it iterates.
func (ctx *FlowContext) copyRequestStepSource(key, template string) {
	keys := ctx.taintedKeys(template)
	if ctx == nil || key == "" || len(keys) == 0 {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	var merged []string
	for _, k := range keys {
		src, ok := ctx.requestStepSources[k]
		if !ok {
			return
		}
		merged = append(merged, src...)
	}
	ctx.requestStepSources[key] = merged
}

// taintedKeys returns every request-tainted key template reads, sorted.
func (ctx *FlowContext) taintedKeys(template string) []string {
	if ctx == nil || template == "" {
		return nil
	}
	ctx.DataMu.Lock()
	keys := make([]string, 0, len(ctx.RequestKeys))
	for k := range ctx.RequestKeys {
		if k != "" {
			keys = append(keys, k)
		}
	}
	ctx.DataMu.Unlock()
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		if flowTemplateRefsKey(template, k) {
			out = append(out, k)
		}
	}
	return out
}

// flowValueAuthoredByStep reports whether text, the whole value of the
// request-tainted reference ref, is a value the author fixed in every step
// ref reads it from: a quoted string literal ('...' or "...") in the step's
// strings, or exactly the value of an env variable the step reads. A step
// that reads the request (so its outputs are tainted) and also picks one of
// several URLs it spells out (`CASE ... THEN 'https://login.example.com/
// oauth/token' ... END`) or passes a configured URL through
// (`:base AS base_url` with `base: ${{ env.APP_BASE_URL }}`) still sends to
// a host the author chose. A value the request supplies, one read from a
// table, or one built by joining text onto either is not authored.
func (ctx *FlowContext) flowValueAuthoredByStep(ref, text string) bool {
	if text == "" {
		return false
	}
	keys := ctx.taintedKeys(ref)
	if len(keys) == 0 {
		return false
	}
	env := flowEnvSnapshot(ctx)
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	for _, k := range keys {
		src, ok := ctx.requestStepSources[k]
		if !ok || !(flowStringsQuoteLiteral(src, text) || flowStringsEnvValue(src, env, text)) {
			return false
		}
	}
	return true
}

// flowStringsEnvValue reports whether text is exactly the value of an env
// variable one of strs reads (`{{env.NAME ...}}`).
func flowStringsEnvValue(strs []string, env map[string]string, text string) bool {
	for _, s := range strs {
		for _, expr := range flowTemplateExprs(s) {
			for at := 0; ; {
				j := strings.Index(expr[at:], "env.")
				if j < 0 {
					break
				}
				j += at
				at = j + len("env.")
				if j > 0 && (flowIsIdentChar(expr[j-1]) || expr[j-1] == '.') {
					continue
				}
				end := at
				for end < len(expr) && flowIsIdentChar(expr[end]) {
					end++
				}
				if v, ok := env[expr[at:end]]; ok && end > at && v == text {
					return true
				}
			}
		}
	}
	return false
}

// flowTemplateExprs returns the text of every `{{ ... }}` region of
// template, each cut at the first `}}` (the scan flowTemplateRefsKey uses).
func flowTemplateExprs(template string) []string {
	var out []string
	for i := 0; i+1 < len(template); i++ {
		if template[i] != '{' || template[i+1] != '{' {
			continue
		}
		end := strings.Index(template[i+2:], "}}")
		if end < 0 {
			break
		}
		out = append(out, template[i+2:i+2+end])
		i = i + 2 + end + 1
	}
	return out
}

// flowStringsQuoteLiteral reports whether text appears in one of strs as a
// whole quoted literal: right after a ' or " and right before the same quote.
func flowStringsQuoteLiteral(strs []string, text string) bool {
	for _, s := range strs {
		for at := 0; ; {
			i := strings.Index(s[at:], text)
			if i < 0 {
				break
			}
			i += at
			end := i + len(text)
			if i > 0 && end < len(s) && (s[i-1] == '\'' || s[i-1] == '"') && s[end] == s[i-1] {
				return true
			}
			at = i + 1
		}
	}
	return false
}
