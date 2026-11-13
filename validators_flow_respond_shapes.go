//go:build !cli

package main

// A `run: respond` in a synchronous request flow that answers something
// other than it reads as. Deployed files carry each shape, so none is
// refused: each is a warning when the file is written and in `benmore check`
// (respondShapeWarnings) and a log line when the file loads. (In an async
// flow a respond is a no-op: asyncRespondWarnings.)
//
//   - No `with:` at all: the step answers 200 with an empty body and ends the
//     run, so a stray one in front of a refusal turns the refusal into a 200.
//   - `body` and `json` together: the step sends one body, and a `body`
//     written as text, a map or a list is read first (withToRespond). Blank
//     text is no body, so it is not this shape (respondBodyValue).
//   - A `body` that YAML reads as a number or a boolean is sent as that JSON
//     value, not as the text the author typed; a number with no JSON form
//     (`.nan`, `.inf`) is not sent at all. An unquoted date is sent as the
//     text written (flows_respond_written_text.go) and is not a shape here.

import (
	"fmt"
	"maps"
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// bareRespondProblem is the text for a respond with no `with:`;
// bareRespondAdvice ends it unless the next step is the answer it hides.
const (
	bareRespondProblem = "this `run: respond` has no `with:`, so it answers 200 with an empty body and ends the flow here; later steps do not run."
	bareRespondAdvice  = " Give it a `status:` (and a body), or delete it."
)

// respondShapeProblems lists each such step of a flow file with what it
// answers and what to write instead, at every nesting depth, jobs in name
// order.
func respondShapeProblems(file FlowFileGHA) []string {
	if file.On.Request == nil || flowRunsInBackground(file.On) {
		return nil
	}
	var out []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			if ghaStepRunType(s) == "respond" {
				where := fmt.Sprintf("job %q step %s", job, here)
				if s.ID != "" {
					where += fmt.Sprintf(" (%q)", s.ID)
				}
				var problems []string
				if len(s.With) == 0 {
					problem := bareRespondProblem + bareRespondAdvice
					if i+1 < len(steps) {
						if hidden := bareRespondHides(s, steps[i+1]); hidden != "" {
							problem = bareRespondProblem + hidden
						}
					}
					problems = []string{problem}
				} else {
					problems = respondBodyShapeProblems(s.With)
				}
				for _, problem := range problems {
					out = append(out, where+": "+problem)
				}
			}
			walk(job, here+".steps", s.Steps)
			walk(job, here+".else", s.Else)
			walk(job, here+".on_error", s.OnError)
		}
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		walk(job, "steps", file.Jobs[job].Steps)
	}
	return out
}

// bareRespondHides is the rest of the warning when next, the step after a
// respond with no `with:`, is a respond with one under the same condition:
// the answer the author wrote, which the bare step always takes the place
// of. "" for any other next step.
func bareRespondHides(bare, next FlowStepGHA) string {
	if ghaStepRunType(next) != "respond" || len(next.With) == 0 || strings.TrimSpace(next.If) != strings.TrimSpace(bare.If) {
		return ""
	}
	status := ""
	if n, _ := respondStatusFromWith(next.With["status"]); n != 0 {
		status = fmt.Sprintf(" (status %d)", n)
	}
	if strings.TrimSpace(bare.If) == "" {
		return fmt.Sprintf(" The next step is a `run: respond`%s and can never answer: the caller gets this step's 200 instead. Delete this step.", status)
	}
	return fmt.Sprintf(" The next step is a `run: respond` under the same `if:`%s and can never answer: when the condition holds, the caller gets this step's 200 instead. Delete this step.", status)
}

// respondBodyShapeProblems checks the `body` and `json` of one respond
// step's `with:`. What the step sends is read from withToRespond, the
// loader's own reading, so the texts cannot drift from it.
func respondBodyShapeProblems(with map[string]any) []string {
	r := withToRespond(with)
	sendsNothing := r.Body == "" && r.JSON == nil && r.JSONArray == nil
	status := "its status"
	if r.StatusTemplate == "" {
		status = fmt.Sprintf("status %d", r.Status)
	}
	var out []string

	if respondBodyValue(with) != nil && with["json"] != nil && !sendsNothing {
		alone := maps.Clone(with)
		delete(alone, "json")
		sent := "json"
		if b := withToRespond(alone); b.Body == r.Body && reflect.DeepEqual(b.JSON, r.JSON) && reflect.DeepEqual(b.JSONArray, r.JSONArray) {
			sent = "body"
		}
		out = append(out, fmt.Sprintf("this `run: respond` sets both `with.body` and `with.json`, and sends one body: only the `%s` one is sent. Keep one.", sent))
	}

	for _, key := range respondBodyKeys {
		switch v := with[key].(type) {
		case bool, int, int64, uint64, float64:
			scalar := respondScalarBody(v)
			kind := "number"
			if _, isBool := v.(bool); isBool {
				kind = "boolean"
			}
			switch f, _ := v.(float64); {
			case scalar == "" && (math.IsNaN(f) || math.IsInf(f, 0)):
				if sendsNothing {
					out = append(out, fmt.Sprintf("this `run: respond` has a `with.%s` that YAML reads as a number with no JSON form, and it is not sent: the step answers %s with an empty body. Put the value in quotes to send it as text.", key, status))
				}
			case key == "body" && scalar != "" && r.Body == scalar && r.JSON == nil && r.JSONArray == nil:
				out = append(out, fmt.Sprintf("this `run: respond` has a `with.body` that YAML reads as a %s, not as text: the step answers the JSON value `%s` (Content-Type %s), which need not be the text as typed. For text, put the value in quotes; for the JSON value, write it under `json:`.", kind, scalar, r.ContentType))
			}
		}
	}
	return out
}

// respondShapeWarnings reports respondShapeProblems for the flow file just
// written, or for every flow file on a full check.
func respondShapeWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := readFileInRoot(dir, rel)
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil {
			continue
		}
		name := filepath.ToSlash(rel)
		for _, problem := range respondShapeProblems(file) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: name,
				Message: name + ": " + problem})
		}
	}
	return findings
}
