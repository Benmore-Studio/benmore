//go:build !cli

package main

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// A `${{ steps.<id>... }}` whose id names no step in the flow reads as empty
// at run time: an `if:` on it is always false, so a deny guard written with a
// misspelled id (`steps.lookpu`) never fires, and a for_each over it runs zero
// times while the flow answers 200. The runtime cannot tell a typo from an
// optional value, so the write gate and `benmore check` refuse the reference
// (unknownStepRefProblems). A deployed file keeps loading.
//
// Every id is collected first, from the whole job (the flow) at any depth:
// if/else branches, for_each and parallel bodies and on_error handlers. A
// reference before the step that defines it (inside a loop, a later iteration
// reads it; in an on_error handler, the step that failed) is therefore not
// refused; only an id no step in the flow has.

// stepRefIDRe finds the id of every `steps.<id>` in text whose quoted parts
// are already removed. The id stops at a dot or bracket, as the runtime reads
// it (translateGHAExpr).
var stepRefIDRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.\-])steps\.([A-Za-z_][A-Za-z0-9_\-]*)`)

// stepRefIDs returns the step ids a step's text references: anywhere in a
// condition or loop source (they read bare refs: `if: steps.x.outputs.n > 0`),
// and inside `${{ }}` everywhere else, so SQL such as `FROM steps s` is not
// read as a reference.
func stepRefIDs(text string, bare bool) []string {
	var exprs []string
	if bare {
		exprs = append(exprs, strings.NewReplacer("${{", " ", "}}", " ").Replace(text))
	} else {
		exprs = ghaWrittenExprs(text)
	}
	var ids []string
	for _, expr := range exprs {
		for _, m := range stepRefIDRe.FindAllStringSubmatch(flowExprWithoutQuoted(expr), -1) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// ghaWrittenExprs returns the text inside every `${{ }}` of text, as written
// (`${{{ }}}` and `${{{{ }}}}` read without their extra braces).
func ghaWrittenExprs(text string) []string {
	var out []string
	for {
		i := strings.Index(text, "${{")
		if i < 0 {
			return out
		}
		rest := strings.TrimLeft(text[i+3:], "{")
		end := strings.Index(rest, "}}")
		if end < 0 {
			return out
		}
		out = append(out, rest[:end])
		text = rest[end+2:]
	}
}

// ghaJobStepIDs returns every step id a job defines, at any depth.
func ghaJobStepIDs(steps []FlowStepGHA) map[string]bool {
	ids := map[string]bool{}
	var walk func([]FlowStepGHA)
	walk = func(steps []FlowStepGHA) {
		for _, s := range steps {
			if id := strings.TrimSpace(s.ID); id != "" {
				ids[id] = true
			}
			walk(s.Steps)
			walk(s.Else)
			walk(s.OnError)
		}
	}
	walk(steps)
	return ids
}

// closestStepID returns the defined id nearest to id (case first, then edit
// distance at most a third of the longer name), or "".
func closestStepID(id string, ids map[string]bool) string {
	best, bestDist := "", -1
	for _, cand := range slices.Sorted(maps.Keys(ids)) {
		if strings.EqualFold(cand, id) {
			return cand
		}
		d := levenshtein(strings.ToLower(cand), strings.ToLower(id))
		limit := max(len(cand), len(id))/3 + 1
		if d <= limit && (bestDist < 0 || d < bestDist) {
			best, bestDist = cand, d
		}
	}
	return best
}

// stepIDList names a flow's step ids in order, at most 20 of them.
func stepIDList(ids map[string]bool) string {
	names := slices.Sorted(maps.Keys(ids))
	if len(names) > 20 {
		return strings.Join(names[:20], ", ") + fmt.Sprintf(" and %d more", len(names)-20)
	}
	return strings.Join(names, ", ")
}

// unknownStepRefProblems returns one message per reference to a step id that
// no step of its job (flow) defines. Jobs are visited in name order and steps
// in file order, for stable messages.
func unknownStepRefProblems(file FlowFileGHA) []string {
	var problems []string
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		steps := file.Jobs[job].Steps
		ids := ghaJobStepIDs(steps)
		reported := map[string]bool{}
		var walk func(parent string, steps []FlowStepGHA)
		walk = func(parent string, steps []FlowStepGHA) {
			for i, s := range steps {
				label := fmt.Sprintf("step %d", i)
				if parent != "" {
					label = fmt.Sprintf("%s[%d]", parent, i)
				}
				where := fmt.Sprintf("flows.yaml: job %q %s", job, label)
				if s.ID != "" {
					where += fmt.Sprintf(" (%q)", s.ID)
				}
				var refs []string
				refs = append(refs, stepRefIDs(s.If, true)...)
				refs = append(refs, stepRefIDs(s.When, true)...)
				refs = append(refs, stepRefIDs(s.ForEach, true)...)
				if cond, ok := s.With["success_when"].(string); ok {
					refs = append(refs, stepRefIDs(cond, true)...)
				}
				for _, text := range []string{s.Query, s.ExpectRows, s.Timeout, s.RetryDelay, flowStepWithText(s.With), flowStepWithText(map[string]any{"params": s.RawParams})} {
					refs = append(refs, stepRefIDs(text, false)...)
				}
				for _, id := range refs {
					if ids[id] || reported[label+"\x00"+id] {
						continue
					}
					reported[label+"\x00"+id] = true
					suggest := "No step in this flow has an `id:`."
					if len(ids) > 0 {
						suggest = "The flow's step ids are " + stepIDList(ids) + "."
					}
					if near := closestStepID(id, ids); near != "" {
						suggest = fmt.Sprintf("Did you mean `steps.%s`? ", near) + suggest
					}
					problems = append(problems, fmt.Sprintf("%s reads `steps.%s`, but no step in this flow has id %q. %s A reference to a step that does not exist reads as empty when the flow runs: an `if:` on it is always false, so a guard never fires, and a for_each over it runs zero times. Reference the id of a step in this flow (`id:` on that step).", where, id, id, suggest))
				}
				for _, b := range []struct {
					name  string
					steps []FlowStepGHA
				}{{ghaNestedBodyName(s) + " steps", s.Steps}, {"else", s.Else}, {"on_error", s.OnError}} {
					walk(label+" > "+b.name, b.steps)
				}
			}
		}
		walk("", steps)
	}
	return problems
}
