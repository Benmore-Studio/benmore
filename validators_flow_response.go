//go:build !cli

package main

import (
	"fmt"
	"slices"
	"strings"
)

// A synchronous HTTP response stops execution. Refuse unreachable siblings at
// write/check time, while retaining the loader's compatibility with existing
// source. Async and scheduled flows have no response writer, so respond is a
// no-op there and does not make following work unreachable.
func flowUnreachableResponseViolation(file FlowFileGHA) string {
	if file.On.Request == nil || strings.EqualFold(strings.TrimSpace(file.On.Request.Mode), "async") {
		return ""
	}
	var walk func(string, []FlowStep) string
	walk = func(path string, steps []FlowStep) string {
		for i, step := range steps {
			where := fmt.Sprintf("%s step %d", path, i)
			if step.Type == "respond" && i+1 < len(steps) {
				return where + ": steps after an unconditional `run: respond` cannot run. Move required work before the response, or put a conditional response inside an `if:` branch. See api({at:'flows'})."
			}
			for _, branch := range []struct {
				name  string
				steps []FlowStep
			}{{"steps", step.Steps}, {"else", step.ElseSteps}, {"on_error", step.OnError}} {
				if msg := walk(where+" > "+branch.name, branch.steps); msg != "" {
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
		// Conversion preserves per-step if gates as wrapper branches, so an
		// inline conditional respond cannot hide reachable following work.
		if msg := walk("flows.yaml: job "+quoteForHint(name), convertGHASteps(file.Jobs[name].Steps)); msg != "" {
			return msg
		}
	}
	return ""
}
