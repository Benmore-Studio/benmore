//go:build !cli

package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// edgeReplacedStatus reports a response status whose body Cloudflare, in
// front of every hosted app, replaces with its own "error code: 502" page:
// the caller never sees the flow's JSON, its headers, its error message or
// request id. Measured on a hosted app: a `respond:` 502 with a JSON body
// arrived as text/plain "error code: 502"; the same body with 503 arrived
// intact. 504 and 520 were replaced the same way, 500, 503 and 599 were not
// (round 2026-11-05). 520-530 are Cloudflare's own error codes, so the whole
// range is treated as replaced.
func edgeReplacedStatus(status int) bool {
	return status == 502 || status == 504 || (status >= 520 && status <= 530)
}

// edgeReplacedStatusEffect says what the replacement costs the caller; both
// warnings below carry it.
const edgeReplacedStatusEffect = "On the hosted platform Cloudflare replaces a 502, 504 or 520-530 response with its own text page (\"error code: 502\"), so the caller never sees this body or its headers (its error message, request id)."

// statusExpressionReplacedAnswers lists the statuses Cloudflare replaces (see
// edgeReplacedStatus) that a respond `status:` template can answer: a literal
// written as one of the expression's results - after `&&` or `||`, as a
// `default:` pipe argument, or alone - not one it compares against
// (`params.code == 502`) or one inside a name (`steps.s502`).
func statusExpressionReplacedAnswers(template string) []int {
	if !strings.Contains(template, "{{") {
		return nil
	}
	var out []int
	seen := map[int]bool{}
	for i := 0; i < len(template); {
		c := template[i]
		if c < '0' || c > '9' {
			i++
			continue
		}
		j := i
		for j < len(template) && template[j] >= '0' && template[j] <= '9' {
			j++
		}
		start, end := i, j
		i = j
		if start > 0 && statusExprNameByte(template[start-1]) || end < len(template) && statusExprNameByte(template[end]) {
			continue
		}
		before := strings.TrimRight(template[:start], " \t'\"")
		after := strings.TrimLeft(template[end:], " \t'\"")
		if !(strings.HasSuffix(before, "&&") || strings.HasSuffix(before, "||") || strings.HasSuffix(before, "default:") ||
			strings.HasSuffix(before, "{{") || strings.HasSuffix(before, "(")) {
			continue
		}
		if strings.HasPrefix(after, "==") || strings.HasPrefix(after, "!=") || strings.HasPrefix(after, "<") || strings.HasPrefix(after, ">") {
			continue
		}
		n, err := strconv.Atoi(template[start:end])
		if err != nil || !edgeReplacedStatus(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func statusExprNameByte(c byte) bool {
	return c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// edgeReplacedStatusWarnings lists the `run: respond` steps that answer, or
// can answer, a status Cloudflare replaces (502, 504, 520-530). It reads the flow file just written, or every flow file on a full
// check, so a push of some other file does not repeat it.
func edgeReplacedStatusWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil {
			continue
		}
		for _, where := range edgeReplacedRespondSteps(file) {
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "edge_status",
				File:     filepath.ToSlash(rel),
				Message:  fmt.Sprintf("%s: %s. %s Answer 503 for an unavailable upstream, 500 for an unexpected failure, or 4xx when the request itself is at fault.", filepath.ToSlash(rel), where, edgeReplacedStatusEffect),
			})
		}
		for _, where := range upstreamStatusRespondSteps(file) {
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "edge_status",
				File:     filepath.ToSlash(rel),
				Message:  fmt.Sprintf("%s: %s. When the upstream answers 502, 504 or 520-530, so does this flow. %s Answer 503 for those instead: an `if:` on the api step's outputs.status before this step, or a fixed status.", filepath.ToSlash(rel), where, edgeReplacedStatusEffect),
			})
		}
	}
	return findings
}

// edgeReplacedRespondSteps names each respond step of a flow file, at every
// nesting depth (on_error handlers included), whose literal status is one
// Cloudflare replaces (edgeReplacedStatus), or whose status expression can
// answer one (statusExpressionReplacedAnswers).
func edgeReplacedRespondSteps(file FlowFileGHA) []string {
	var out []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			if ghaStepRunType(s) == "respond" {
				name := ""
				if s.ID != "" {
					name = fmt.Sprintf(" (%q)", s.ID)
				}
				status, template := respondStatusFromWith(s.With["status"])
				if edgeReplacedStatus(status) {
					out = append(out, fmt.Sprintf("job %q step %s%s responds %d", job, here, name, status))
				}
				if answers := statusExpressionReplacedAnswers(template); len(answers) > 0 {
					codes := make([]string, len(answers))
					for i, n := range answers {
						codes[i] = strconv.Itoa(n)
					}
					written, _ := s.With["status"].(string)
					if strings.TrimSpace(written) == "" {
						written = template
					}
					out = append(out, fmt.Sprintf("job %q step %s%s can respond %s (status: %s)", job, here, name, strings.Join(codes, " or "), strings.TrimSpace(written)))
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
