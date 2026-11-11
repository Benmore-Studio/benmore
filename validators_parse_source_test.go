//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseSourceFlow(with string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/lab-parse\njobs:\n  main:\n    steps:\n      - id: p\n        run: parse\n" + with +
		"      - run: respond\n        with: {json: {ok: true}}\n"
}

// `run: parse` reads only `source: body` and `source: headers`. Any other
// source ran as a silent no-op (no outputs), yet passed the write gate and
// `benmore check`.
func TestParseStepRefusesUnsupportedSource(t *testing.T) {
	for _, tc := range []struct {
		with string
		ok   bool
	}{
		{"", true},
		{"        with: {source: body}\n", true},
		{"        with: {source: headers}\n", true},
		{"        with: {source: query}\n", false},
		{"        with: {source: Body}\n", false},
		{"        with: {source: \"${{ steps.x.outputs.body }}\"}\n", false},
		{"        with: {source: 5}\n", false},
	} {
		msg := ValidateOnWrite("flows/lab-parse.yaml", parseSourceFlow(tc.with))
		if (msg == "") != tc.ok {
			t.Errorf("%q: write gate = %q, want ok=%v", tc.with, msg, tc.ok)
		}
		if !tc.ok && !strings.Contains(msg, "source") {
			t.Errorf("%q: refusal does not name the source: %q", tc.with, msg)
		}
	}
}

// `benmore check` reports the same refusal for a file already on disk.
func TestParseStepUnsupportedSourceInCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "lab-parse.yaml"), []byte(parseSourceFlow("        with: {source: query}\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	report := RunSourceCheck(dir, "")
	for _, f := range report.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, "source") && strings.Contains(f.Message, "query") {
			return
		}
	}
	t.Fatalf("benmore check did not refuse `source: query`: %+v", report.Findings)
}
