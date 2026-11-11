//go:build !cli

package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Flow shapes that load and pass the write gate but behave differently at
// run time than they read. Each is a warning filed under the flow file, so a
// push of that file shows it (writeRelevantFindings) as well as `benmore
// check`.

// transactionTimeoutWarnings flags a `transaction: true` request flow whose
// `on.request.timeout` is longer than the app's write-transaction limit
// (BENMORE_DB_WRITE_TX_LIMIT, 60 s by default): the database rolls the
// transaction back at that limit, so the flow answers 503 rolled_back before
// its own time limit. It reads the flow file just written, or every flow file
// on a full check.
func transactionTimeoutWarnings(dir, writtenPath string) []CheckFinding {
	var findings []CheckFinding
	limit, limitText := appWriteTxLimit(dir)
	if limit <= 0 {
		return nil
	}
	for _, rel := range flowFilesFor(dir, writtenPath) {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil || file.On.Request == nil || !file.On.Request.Transaction {
			continue
		}
		req := file.On.Request
		if strings.EqualFold(strings.TrimSpace(req.Mode), "async") {
			continue
		}
		timeout, err := parseFlowRequestTimeout(req.Timeout)
		if err != nil || timeout <= limit {
			continue
		}
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "flows",
			File:     filepath.ToSlash(rel),
			Message: fmt.Sprintf("%s: on.request.timeout %q is longer than the app's write-transaction limit (%s, BENMORE_DB_WRITE_TX_LIMIT). A `transaction: true` flow runs in one database write transaction, which is rolled back when it reaches that limit: a run that long answers 503 `rolled_back` after %s, not at its own timeout. Raise the limit for this app to at least the timeout (`benmore env set BENMORE_DB_WRITE_TX_LIMIT=%s`), shorten the timeout, or move the slow work out of the transaction (an async flow, or `run: api` calls before the writes).",
				filepath.ToSlash(rel), req.Timeout, limitText, limitText, timeout),
		})
	}
	return findings
}

// appWriteTxLimit is the write-transaction limit the app's process runs with:
// BENMORE_DB_WRITE_TX_LIMIT from its generated environment file (hosted),
// its loaded environment, or this process's environment (self-hosted), else
// the default. 0 means the limit is off.
func appWriteTxLimit(dir string) (time.Duration, string) {
	const key = "BENMORE_DB_WRITE_TX_LIMIT"
	raw := ""
	if data, err := readOptionalConfig(dir, ".benmore/env"); err == nil && data != nil {
		if vars, err := parseAppEnvironmentFile(string(data)); err == nil {
			raw = vars[key]
		}
	}
	if raw == "" {
		raw = GetAppEnv(dir, key)
	}
	if raw == "" {
		raw = os.Getenv(key)
	}
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(raw) {
	case "":
		return defaultWriteTxLimit, defaultWriteTxLimit.String()
	case "0", "off", "none", "false":
		return 0, ""
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return defaultWriteTxLimit, defaultWriteTxLimit.String()
	}
	return d, d.String()
}

// asyncRespondWarnings flags `mode: async` flows that still carry a respond:/
// redirect: step. Under async the 202 + job_id is sent immediately and the
// flow runs in the worker, where respond/redirect are no-ops - so the step is
// dead code that signals the author expected a synchronous response. Completion
// should be signaled via the data layer (a row / notification the client polls
// at status_url). Each warning names the flow's own file, so a push of
// flows/<name>.yaml shows it; it used to be filed under flows.yaml, which a
// push of any other flow file dropped, so only `benmore check` showed it.
func asyncRespondWarnings(dir string) []CheckFinding {
	var findings []CheckFinding
	for _, f := range LoadFlowsGHA(dir) {
		if f.Async && flowHasRespondStep(f.Steps) {
			file := f.Source
			if file == "" {
				file = "flows.yaml"
			}
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "flows",
				File:     file,
				Message: fmt.Sprintf("flow %q is `mode: async` but has a respond:/redirect: step - it's a no-op (the 202 + job_id already went out before the worker runs). Remove it; signal completion via the data layer (write a row / notification the client polls at status_url).",
					f.Name),
			})
		}
	}
	return findings
}

// bareRespondProblem warns about a `run: respond` with no `with:` in a
// synchronous request flow: it answers 200 and ends the run, so a stray one
// in front of a refusal turns the refusal into a 200. Deployed files carry
// it, so it is a warning when the file is written and in `benmore check` and
// a log line when the file loads, never a refusal. (In an async flow a
// respond is a no-op: asyncRespondWarnings.)
const bareRespondProblem = "this `run: respond` has no `with:`, so it answers 200 with an empty body and ends the flow here; later steps do not run. Give it a `status:` (and a body), or delete it."

// bareRespondSteps names each such step of a flow file, at every nesting
// depth, jobs in name order.
func bareRespondSteps(file FlowFileGHA) []string {
	if file.On.Request == nil || flowRunsInBackground(file.On) {
		return nil
	}
	var out []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			if ghaStepRunType(s) == "respond" && len(s.With) == 0 {
				where := fmt.Sprintf("job %q step %s", job, here)
				if s.ID != "" {
					where += fmt.Sprintf(" (%q)", s.ID)
				}
				out = append(out, where)
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

// bareRespondWarnings reports bareRespondSteps for the flow file just
// written, or for every flow file on a full check.
func bareRespondWarnings(dir, writtenPath string) []CheckFinding {
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
		for _, where := range bareRespondSteps(file) {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "flows", File: name,
				Message: name + ": " + where + ": " + bareRespondProblem})
		}
	}
	return findings
}

// upstreamStatusRespondSteps names each respond step whose status passes a
// `run: api` step's `outputs.status` through: an upstream 502 or 504 then
// reaches the caller as Cloudflare's "error code: 502" page on the hosted
// platform (edgeReplacedStatus), whatever body the step writes.
func upstreamStatusRespondSteps(file FlowFileGHA) []string {
	var out []string
	var walk func(job, path string, steps []FlowStepGHA)
	walk = func(job, path string, steps []FlowStepGHA) {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			if ghaStepRunType(s) == "respond" {
				if raw, ok := s.With["status"].(string); ok && strings.Contains(raw, ".outputs.status") {
					name := ""
					if s.ID != "" {
						name = fmt.Sprintf(" (%q)", s.ID)
					}
					out = append(out, fmt.Sprintf("job %q step %s%s answers the upstream's status (%s)", job, here, name, strings.TrimSpace(raw)))
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
