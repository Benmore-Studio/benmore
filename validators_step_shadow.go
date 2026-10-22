//go:build !cli

package main

// Step-id shadowing warning.
//
// Since 2.7.248 a request field whose name equals a declared step id is
// readable only as `${{ params.<name> }}` (shadowStepNamedRequestKeys,
// flows.go): a bare `{{name}}` / `${{ name }}` / `${{ name.x }}` / `:name`
// in that flow resolves to the step's output (or to nothing before the step
// has run), never to the request value. Flows written before that change -
// `- id: challenge` with `if: ${{ challenge }}` - silently stopped seeing the
// request field. Advisory only: the flow loads and the write goes through;
// the warning surfaces in the post-write check and in `benmore check`.
//
// A bare ref AFTER the step ran is the legacy way to read that step's output
// (`- id: enq ...` then `${{ enq.rows_affected }}`) and still works, so only
// a ref in the step itself or in a step that runs before it is reported -
// there it can only have meant the request field.

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var (
	// `{{ ... }}` with an optional leading `$`; the inner expression is
	// scanned for identifiers.
	shadowTemplateRe = regexp.MustCompile(`\$?\{\{([^{}]*)\}\}`)
	// Identifier paths inside an expression (`a`, `a.b.c`), after quoted
	// literals are blanked out.
	shadowIdentRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*`)
	// `:name` binds in SQL text (not `::`, not `a:b`).
	shadowBindRe = regexp.MustCompile(`(^|[^:A-Za-z0-9_]):([A-Za-z_][A-Za-z0-9_]*)`)
	// Quoted literals, blanked before identifiers are read.
	shadowQuotedRe = regexp.MustCompile(`'[^']*'|"[^"]*"`)
)

// shadowNamespaces are the explicit prefixes that never read a request
// field by bare name.
var shadowNamespaces = map[string]bool{"steps": true, "params": true, "env": true, "user": true}

// shadowExprWords are condition keywords/literals, not references.
var shadowExprWords = map[string]bool{"true": true, "false": true, "null": true, "nil": true, "and": true, "or": true, "not": true}

// shadowScan records, in step execution (document pre-)order, where each
// step id is declared and where each bare name is first read.
type shadowScan struct {
	next     int
	idAt     map[string]int // step id -> index of its step
	firstRef map[string]int // bare name -> index of the earliest step reading it
}

// ghaStepShadowWarnings reports, per job, every step id that equals a
// declared on.request.inputs name, or a bare template/bind name read in that
// step or before it. Shared by the write path (MCP write_file/edit_file
// report through RunCompleteCheck) and `benmore check`.
func ghaStepShadowWarnings(content string) []string {
	var raw map[string]any
	if err := yamlUnmarshal([]byte(content), &raw); err != nil || raw == nil {
		return nil
	}
	jobs, _ := raw["jobs"].(map[string]any)
	if len(jobs) == 0 {
		return nil
	}
	inputs := map[string]bool{}
	if on, ok := raw["on"].(map[string]any); ok {
		if req, ok := on["request"].(map[string]any); ok {
			if in, ok := req["inputs"].(map[string]any); ok {
				for name := range in {
					inputs[name] = true
				}
			}
		}
	}
	var out []string
	for _, job := range slices.Sorted(maps.Keys(jobs)) {
		body, _ := jobs[job].(map[string]any)
		scan := &shadowScan{idAt: map[string]int{}, firstRef: map[string]int{}}
		scan.steps(body["steps"])
		for _, id := range slices.Sorted(maps.Keys(scan.idAt)) {
			var why string
			if inputs[id] {
				why = fmt.Sprintf("on.request.inputs declares %q", id)
			} else if at, read := scan.firstRef[id]; read && at <= scan.idAt[id] {
				why = fmt.Sprintf("the flow reads a bare `%s` (`{{%s}}`, `${{ %s }}`, `${{ %s.… }}` or `:%s`) in that step or before it runs", id, id, id, id, id)
			} else {
				continue
			}
			out = append(out, fmt.Sprintf(
				"job %q: step id %q shadows the request field of the same name - %s. A request field named like a step is readable only as `${{ params.%s }}`; a bare ref or bind reads the STEP (nothing before it has run), not the request value. Rename the step, or read the request value as `${{ params.%s }}`.",
				job, id, why, id, id))
		}
	}
	return out
}

// steps walks a step list in execution order; nested steps/else/on_error
// (and parallel bodies) are numbered after the step that holds them.
func (sc *shadowScan) steps(v any) {
	list, _ := v.([]any)
	for _, s := range list {
		step, ok := s.(map[string]any)
		if !ok {
			continue
		}
		at := sc.next
		sc.next++
		if id, ok := step["id"].(string); ok && strings.TrimSpace(id) != "" {
			if _, dup := sc.idAt[strings.TrimSpace(id)]; !dup {
				sc.idAt[strings.TrimSpace(id)] = at
			}
		}
		// A `:name` bind the step defines under params:/with.params: reads
		// the step's own param; its template value is scanned like any other.
		local := map[string]bool{}
		for _, p := range []any{step["params"], shadowMapValue(step["with"], "params")} {
			if pm, ok := p.(map[string]any); ok {
				for k := range pm {
					local[k] = true
				}
			}
		}
		var nested []any
		for _, k := range slices.Sorted(maps.Keys(step)) {
			switch k {
			case "steps", "else", "on_error":
				nested = append(nested, step[k])
			default:
				sc.strings(step[k], k, at, local)
			}
		}
		for _, n := range nested {
			sc.steps(n)
		}
	}
}

func shadowMapValue(v any, key string) any {
	m, _ := v.(map[string]any)
	return m[key]
}

// strings records the heads of bare references in every string below v:
// identifiers inside `{{ }}` / `${{ }}` (first pipe segment only - pipe names
// and arguments are not refs) and `:name` binds in SQL (`query:` / `sql:`
// values). Namespaced refs (steps./params./env./user.) are skipped.
func (sc *shadowScan) strings(v any, key string, at int, local map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			sc.strings(vv, k, at, local)
		}
	case []any:
		for _, vv := range x {
			sc.strings(vv, key, at, local)
		}
	case string:
		for _, m := range shadowTemplateRe.FindAllStringSubmatch(x, -1) {
			expr, _, _ := strings.Cut(m[1], "|")
			expr = shadowQuotedRe.ReplaceAllString(expr, "''")
			for _, ident := range shadowIdentRe.FindAllString(expr, -1) {
				head, _, _ := strings.Cut(ident, ".")
				if shadowNamespaces[head] || shadowExprWords[strings.ToLower(head)] {
					continue
				}
				sc.ref(head, at)
			}
		}
		if key == "query" || key == "sql" {
			sqlText := shadowQuotedRe.ReplaceAllString(shadowTemplateRe.ReplaceAllString(x, ""), "''")
			for _, m := range shadowBindRe.FindAllStringSubmatch(sqlText, -1) {
				if !local[m[2]] {
					sc.ref(m[2], at)
				}
			}
		}
	}
}

func (sc *shadowScan) ref(name string, at int) {
	if prev, ok := sc.firstRef[name]; !ok || at < prev {
		sc.firstRef[name] = at
	}
}
