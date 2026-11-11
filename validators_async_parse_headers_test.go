//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const asyncParseHeadersSteps = `jobs:
  main:
    steps:
      - id: hdr
        run: parse
        with: { source: headers }
      - run: sql
        with:
          query: "SELECT :k AS k"
          params: { k: "${{ steps.hdr.outputs.Authorization | default:'' }}" }
`

const asyncParseHeadersNested = `jobs:
  main:
    steps:
      - if: ${{ params.go }}
        steps:
          - id: hdr
            run: parse
            with: { source: headers }
      - run: sql
        with: { query: "SELECT 1 AS ok" }
        on_error:
          - id: hdr2
            run: parse
            with: { source: headers }
`

// A background flow has no live request, so a headers parse can only work if
// the headers are queued with the job, which would write Authorization and
// Cookie values into `_benmore_jobs.payload`. The write gate refuses the
// shape on every background trigger, at any nesting depth.
func TestParseHeadersRefusedInBackgroundFlows(t *testing.T) {
	triggers := map[string]string{
		"async": "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: async\n",
		"ASYNC": "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: ASYNC\n",
		"cron":  "on:\n  schedule:\n    cron: \"*/5 * * * *\"\n",
		"event": "on:\n  event:\n    table: notes\n    op: insert\n",
	}
	for name, trigger := range triggers {
		for shape, steps := range map[string]string{"top level": asyncParseHeadersSteps, "nested": asyncParseHeadersNested} {
			t.Run(name+" "+shape, func(t *testing.T) {
				msg := ValidateOnWrite("flows/probe.yaml", trigger+steps)
				for _, want := range []string{"source: headers", "credentials", "job payloads"} {
					if !strings.Contains(msg, want) {
						t.Fatalf("write gate = %q, want it to mention %q", msg, want)
					}
				}
			})
		}
	}
}

// An inline flow reads the live request's headers and queues nothing, and a
// background flow may still parse its body.
func TestParseHeadersAllowedWhereItIsNotQueued(t *testing.T) {
	inline := "on:\n  request:\n    method: POST\n    path: /api/probe\n"
	for name, source := range map[string]string{
		"inline headers":     inline + asyncParseHeadersSteps,
		"inline explicit":    "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: sync\n" + asyncParseHeadersSteps,
		"async default body": "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: async\njobs:\n  main:\n    steps:\n      - id: b\n        run: parse\n      - run: sql\n        with: { query: \"SELECT 1 AS ok\" }\n",
	} {
		if msg := ValidateOnWrite("flows/probe.yaml", source); strings.Contains(msg, "source: headers") {
			t.Errorf("%s: refused: %s", name, msg)
		}
	}
}

// `benmore check` reports the same refusal for a file already on disk.
func TestParseHeadersInBackgroundFlowInCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: async\n" + asyncParseHeadersSteps
	if err := os.WriteFile(filepath.Join(dir, "flows", "probe.yaml"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	report := RunSourceCheck(dir, "")
	for _, f := range report.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, "source: headers") {
			return
		}
	}
	t.Fatalf("benmore check did not refuse a headers parse in an async flow: %+v", report.Findings)
}

// A file already deployed keeps loading: the loader logs the problem, as it
// does for every step value problem, and the step stays a no-op in the worker.
func TestParseHeadersInDeployedAsyncFlowStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	source := "on:\n  request:\n    method: POST\n    path: /api/probe\n    mode: async\n" + asyncParseHeadersSteps
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	flows, err := parseGHAFlowFile(path, []byte(source))
	if err != nil || len(flows) != 1 || !flows[0].Async {
		t.Fatalf("flows = %+v, err = %v, want one async flow", flows, err)
	}
}
