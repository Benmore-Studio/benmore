//go:build !cli

package main

// `${{ }}` value expressions: the `if:` grammar (flows_condition_expr.go)
// wherever a flow writes a value - respond bodies and headers, SQL binds,
// api URLs, query, headers and bodies, set, enqueue, email, sms, compute
// args, for_each sources. `${{ params.id && 'yes' || 'no' }}` used to render
// "no" whatever id was: the value resolver knew only refs, pipes and the `||`
// fallback, so the left side `params.id && 'yes'` was an unknown ref and the
// fallback won, with no error. It now evaluates as it does in `if:`:
// comparisons, `&&`, `||`, `!` and parentheses with JavaScript semantics
// (`&&` and `||` return an operand, comparisons and `!` a boolean).
//
// The expression is the author's template text and is parsed before any
// value is looked up; a resolved value is only ever an operand (security.md
// 2b). A ref with pipes and a lone `||` fallback keep resolveBindRef, as they
// do in an `if:` condition, so every template that resolved before resolves
// the same. An expression that doesn't parse resolves to nothing, which the
// step reports as an unresolved reference (template_unresolved); the write
// gate and `benmore check` refuse it first (ghaValueExpressionViolation).
//
// Every analysis that reads the refs of a `{{ }}` expression - request and
// secret taint (flowExprRefPaths), env-only and pre-encoded URL values
// (flowExprIsEnvOnly, flowExprEndsInURLEncode) - reads an expression's refs
// from the parsed tree too, so a ref behind `&&` is never missed.

import (
	"fmt"
	"log"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// flowValueExprUsesOperators reports whether the text of a `{{ }}` value
// template uses the expression grammar: `&&`, a comparison (== = != > < >=
// <=) or a unary `!`, outside quoted text and pipe arguments. A ref, its
// pipes and the `||` fallback alone do not.
func flowValueExprUsesOperators(expr string) bool {
	pipeArg := false
	operandStart := true // a unary `!` is read only where an operand begins
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '\'', '"':
			end := strings.IndexByte(expr[i+1:], c)
			if end < 0 {
				return false
			}
			i += end + 1
			operandStart = false
			continue
		case '&':
			if i+1 < len(expr) && expr[i+1] == '&' {
				return true
			}
		case '|':
			if i+1 < len(expr) && expr[i+1] == '|' {
				pipeArg, operandStart = false, true
				i++
				continue
			}
			pipeArg = true
		case '=', '<', '>':
			if !pipeArg {
				return true
			}
		case '!':
			if !pipeArg && (operandStart || (i+1 < len(expr) && expr[i+1] == '=')) {
				return true
			}
		case '(':
			if !pipeArg {
				operandStart = true
				continue
			}
		}
		operandStart = false
	}
	return false
}

// resolveValueExpression evaluates a value expression. ok is false only when
// it doesn't parse; a missing ref inside it is a falsy operand, as in `if:`.
func resolveValueExpression(expr string, flat map[string]any) (any, bool) {
	e, err := parseFlowValueExpr(expr)
	if err != nil {
		return nil, false
	}
	return e.eval(flat), true
}

// valueExprCache holds parsed value expressions by their text, like
// condExprCache does for conditions (kept apart so each logs its own parse
// error once).
var (
	valueExprCache  sync.Map
	valueExprCached atomic.Int64
)

// parseFlowValueExpr parses (and caches) a value expression. A parse error is
// logged the first time that expression is seen.
func parseFlowValueExpr(expr string) (*condExpr, error) {
	if v, ok := valueExprCache.Load(expr); ok {
		p := v.(condParsed)
		return p.expr, p.err
	}
	e, err := parseCondExpr(expr)
	if err != nil {
		log.Printf("flows: value expression %q does not parse (%v); the step reports it as an unresolved reference", truncate(expr, 200), err)
	}
	if valueExprCached.Load() < condExprCacheCap {
		if _, loaded := valueExprCache.LoadOrStore(expr, condParsed{e, err}); !loaded {
			valueExprCached.Add(1)
		}
	}
	return e, err
}

// condExprRefs returns the refs of a parsed expression in source order: as
// the runtime reads them (the translated ref before any pipe), or as written
// when written is set.
func condExprRefs(e *condExpr, written bool) []string {
	var out []string
	var walk func(*condExpr)
	walk = func(n *condExpr) {
		if n == nil {
			return
		}
		if n.kind == condRef {
			if written {
				out = append(out, n.src)
			} else {
				out = append(out, strings.TrimSpace(strings.SplitN(n.ref, "|", 2)[0]))
			}
		}
		walk(n.left)
		walk(n.right)
	}
	walk(e)
	return out
}

// valueExprWordRe finds every ref-shaped word of an expression that doesn't
// parse (flowValueExprRefPaths reads them all, pipe names included).
var valueExprWordRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.\-]*(?:\[\d+\][A-Za-z0-9_.\-]*)*`)

// flowValueExprRefs returns the refs of a value expression, as the runtime
// reads them (translated, before any pipe) or as written: from the parsed
// tree, or every ref-shaped word of an expression that doesn't parse.
func flowValueExprRefs(expr string, written bool) []string {
	if e, err := parseCondExpr(expr); err == nil {
		return condExprRefs(e, written)
	}
	var refs []string
	for _, word := range valueExprWordRe.FindAllString(flowExprWithoutQuoted(expr), -1) {
		switch strings.ToLower(word) {
		case "true", "false", "null", "undefined":
			continue
		}
		if !written {
			word = translateGHAExpr(word)
		}
		refs = append(refs, word)
	}
	return refs
}

// flowValueExprRefPaths returns the data paths a value expression reads,
// normalized as flowExprRefPaths normalizes a ref. An expression that
// doesn't parse is never evaluated, but every word in it is reported, so an
// analysis that asks what it reads errs toward "the request".
func flowValueExprRefPaths(expr string) []string {
	var out []string
	for _, ref := range flowValueExprRefs(expr, false) {
		ref = strings.ReplaceAll(strings.ReplaceAll(ref, "[", "."), "]", "")
		ref = strings.TrimPrefix(ref, "params.")
		if ref != "" && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	return out
}

// flowExprWithoutQuoted is expr with the contents of quoted text removed.
func flowExprWithoutQuoted(expr string) string {
	var b strings.Builder
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '\'' || c == '"' {
			end := strings.IndexByte(expr[i+1:], c)
			if end < 0 {
				break
			}
			b.WriteByte(' ')
			i += end + 1
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// flowValueExprSpans returns the text of every `{{ }}` region of a flow
// value as the runtime reads it (GHA refs normalized; `{{{ }}}` and
// `{{{{ }}}}` read without their extra braces).
func flowValueExprSpans(text string) []string {
	norm := normalizeGHARefs(text)
	var out []string
	for i := 0; i+1 < len(norm); i++ {
		if norm[i] != '{' || norm[i+1] != '{' {
			continue
		}
		j := i + 2
		for j < len(norm) && norm[j] == '{' {
			j++
		}
		end := strings.Index(norm[j:], "}}")
		if end < 0 {
			break
		}
		out = append(out, strings.TrimSpace(norm[j:j+end]))
		i = j + end + 1
	}
	return out
}

// valueExpressionGrammar is the advice a refused value expression carries.
const valueExpressionGrammar = " A `${{ }}` value is a ref with pipes (`${{ params.x | default:'' }}`), a `||` fallback, or an expression in the `if:` grammar: compare with == != > < >= <=, join with && || and ! and parentheses, quote text literals (a bare word is a ref). `&&` and `||` return an operand, so `${{ params.id && 'yes' || 'no' }}` is 'yes' when id is set. Functions, arithmetic and `in` are not supported; compute those in SQL (CASE WHEN) or a compute step. See api({at:'flows'}) value_expressions."

// ghaValueExpressionViolation refuses a `${{ }}` value expression that uses
// the expression grammar but doesn't parse: at run time it resolves to
// nothing and fails its step with template_unresolved. `if:` and api
// `success_when:` are conditions and serve_file `disposition:` has its own
// check (ghaDeadConditionViolation); every other step value is read here,
// at any nesting depth. Jobs are visited in name order for a stable message.
func ghaValueExpressionViolation(file FlowFileGHA) string {
	var walk func(job, parent string, steps []FlowStepGHA) string
	walk = func(job, parent string, steps []FlowStepGHA) string {
		for i, s := range steps {
			label := fmt.Sprintf("step %d", i)
			if parent != "" {
				label = fmt.Sprintf("%s[%d]", parent, i)
			}
			where := fmt.Sprintf("flows.yaml: job %q %s", job, label)
			if s.ID != "" {
				where += fmt.Sprintf(" (%q)", s.ID)
			}
			run := strings.ToLower(strings.TrimSpace(s.Run))
			var texts []string
			var collect func(key string, v any)
			collect = func(key string, v any) {
				switch t := v.(type) {
				case string:
					texts = append(texts, t)
				case map[string]any:
					for _, k := range slices.Sorted(maps.Keys(t)) {
						collect(k, t[k])
					}
				case []any:
					for _, item := range t {
						collect(key, item)
					}
				}
			}
			for _, k := range slices.Sorted(maps.Keys(s.With)) {
				if (k == "success_when" && run == "api") || (k == "disposition" && run == "serve_file") {
					continue
				}
				collect(k, s.With[k])
			}
			collect("query", s.Query)
			collect("params", s.RawParams)
			collect("for_each", s.ForEach)
			for _, text := range texts {
				for _, expr := range flowValueExprSpans(text) {
					if !flowValueExprUsesOperators(expr) {
						continue
					}
					if _, err := parseCondExpr(expr); err != nil {
						return fmt.Sprintf("%s: the value `${{ %s }}` doesn't parse as an expression (%s), so it never resolves and the step fails with template_unresolved.%s", where, truncate(expr, 200), err, valueExpressionGrammar)
					}
				}
			}
			for _, b := range []struct {
				name  string
				steps []FlowStepGHA
			}{{ghaNestedBodyName(s) + " steps", s.Steps}, {"else", s.Else}, {"on_error", s.OnError}} {
				if msg := walk(job, label+" > "+b.name, b.steps); msg != "" {
					return msg
				}
			}
		}
		return ""
	}
	jobs := make([]string, 0, len(file.Jobs))
	for name := range file.Jobs {
		jobs = append(jobs, name)
	}
	slices.Sort(jobs)
	for _, name := range jobs {
		if msg := walk(name, "", file.Jobs[name].Steps); msg != "" {
			return msg
		}
	}
	return ""
}
