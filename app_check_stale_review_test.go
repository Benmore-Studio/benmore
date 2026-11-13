//go:build !cli

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// staleReviewScaffold is a scaffolded app with a reviewed starter mcp.yaml
// and one served file edited after the review.
func staleReviewScaffold(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "notes")
	if err := WriteHTMLScaffoldFiles(dir, "Notes"); err != nil {
		t.Fatal(err)
	}
	css := filepath.Join(dir, "static", "styles.css")
	old, err := os.ReadFile(css)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(css, append(old, []byte("\n/* edited after the review */\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func captureServeBootCheck(t *testing.T, dir string) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	serveBootCheck(dir)
	_ = w.Close()
	os.Stderr = oldStderr
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The one finding a stale connector review raises: a warning under its own
// label, with the review instruction and no rewrite advice.
func assertStaleReviewWarning(t *testing.T, where string, report CheckReport) {
	t.Helper()
	if report.Errors != 0 || !report.Clean() || len(report.Findings) != 1 {
		t.Fatalf("%s: want exactly one warning and no error, got errors=%d findings=%+v", where, report.Errors, report.Findings)
	}
	f := report.Findings[0]
	if f.Severity != "warning" || f.Source != "mcp_review" || f.File != "mcp.yaml" {
		t.Fatalf("%s: finding is %s [%s] %s, want warning [mcp_review] mcp.yaml", where, f.Severity, f.Source, f.File)
	}
	for _, want := range []string{"connector", "off", "`benmore mcp review <appdir> --reviewed`", "`benmore mcp check <appdir>`", "digest mismatch"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("%s: message lacks %q: %s", where, want, f.Message)
		}
	}
	next := "push the reviewed files together"
	if editionName == "framework" {
		next = "reload (SIGHUP) or restart the service"
	}
	if !strings.Contains(f.Message, next) {
		t.Errorf("%s: the %s edition's message lacks its next step %q: %s", where, editionName, next, f.Message)
	}
	if strings.Contains(f.Message, "re-Write the entire file") || strings.Contains(f.Message, "fall back to Edit") {
		t.Errorf("%s: a stale review is not fixed by rewriting mcp.yaml: %s", where, f.Message)
	}
	if f.Docs != "connector.stale_review" {
		t.Errorf("%s: docs %q, want connector.stale_review", where, f.Docs)
	}
}

// A scaffolded app's first edit to a served file makes the starter review
// stale. That turns only the connector off, so every check reports it as a
// warning that names the review command: `benmore serve`'s start-up check,
// the complete check (check_app), the check after a write, and `benmore test`.
func TestStaleMCPReviewIsReportedAsAWarning(t *testing.T) {
	dir := staleReviewScaffold(t)

	assertStaleReviewWarning(t, "source check", RunSourceCheck(dir, ""))
	assertStaleReviewWarning(t, "check after a schema write", RunSourceCheck(dir, "schema.prisma"))
	if failed := sourceCheckTestResults(dir); len(failed) != 0 {
		t.Errorf("benmore test fails on a stale review: %+v", failed)
	}

	out := captureServeBootCheck(t, dir)
	for _, want := range []string{"check: 1 warning(s)", "WARNING [mcp_review] mcp.yaml:", "`benmore mcp review <appdir> --reviewed`", "the app starts and runs", "MCP connector stays off"} {
		if !strings.Contains(out, want) {
			t.Errorf("serve start-up check lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"[syntax]", "ERROR", "error(s)", "re-Write the entire file", "would be rejected", "⚠"} {
		if strings.Contains(out, not) {
			t.Errorf("serve start-up check says %q for a stale review:\n%s", not, out)
		}
	}
	// The live layers ran too (they are skipped only after an error).
	assertStaleReviewWarning(t, "complete check", RunCompleteCheck(dir, ""))

	// The app starts with the connector withheld, as before.
	if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("the strict load (review, mcp check, a write of mcp.yaml) must still refuse a stale review, got %v", err)
	}
	served, err := loadServedRuntimeConfig(dir)
	if err != nil || served.mcp != nil || served.mcpWithheld == "" {
		t.Fatalf("served load: err=%v, want the connector withheld", err)
	}
}

// Writing a stale mcp.yaml is still refused: the write gate rejects that file.
func TestWriteOfAStaleMCPManifestIsStillRefused(t *testing.T) {
	dir := staleReviewScaffold(t)
	manifest, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	msg := ValidateOnWriteIn(dir, "mcp.yaml", string(manifest))
	if !strings.Contains(msg, "digest mismatch") || !strings.Contains(msg, "connector.connector_source_review") {
		t.Fatalf("write of a stale mcp.yaml: %q", msg)
	}
}

// An mcp.yaml that does not parse is the file's own error: refused, labelled
// as the write gate's finding, with the rewrite advice and the push line.
func TestMCPManifestSyntaxErrorIsStillAnError(t *testing.T) {
	dir := staleReviewScaffold(t)
	if err := os.WriteFile(filepath.Join(dir, "mcp.yaml"), []byte("version: 1\ntools: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := RunSourceCheck(dir, "")
	if report.Errors != 1 || len(report.Findings) != 1 {
		t.Fatalf("want one error, got %+v", report.Findings)
	}
	f := report.Findings[0]
	if f.Severity != "error" || f.Source != "syntax" || f.File != "mcp.yaml" || !strings.HasSuffix(f.Message, writeRejectionFooter) {
		t.Fatalf("finding %+v, want an error [syntax] mcp.yaml ending in the rewrite advice", f)
	}
	out := captureServeBootCheck(t, dir)
	for _, want := range []string{"ERROR [syntax] mcp.yaml:", "re-Write the entire file", "would be rejected by `benmore push`"} {
		if !strings.Contains(out, want) {
			t.Errorf("serve start-up check lacks %q:\n%s", want, out)
		}
	}
	// This one stops the load too, so the line must not promise a start.
	if strings.Contains(out, "the app will boot") {
		t.Errorf("serve start-up check promises a start the load refuses:\n%s", out)
	}
	if _, err := loadServedRuntimeConfig(dir); err == nil {
		t.Error("an mcp.yaml that does not parse must refuse the load")
	}
	if failed := sourceCheckTestResults(dir); len(failed) != 1 {
		t.Errorf("benmore test must fail on an mcp.yaml that does not parse: %+v", failed)
	}
}

// The scaffold a hosted CLI writes has no mcp.yaml: an edit raises nothing.
func TestScaffoldWithoutConnectorHasNoReviewFinding(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plain")
	if err := writeHTMLScaffoldFiles(dir, "", false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "extra.css"), []byte("body{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if report := RunCompleteCheck(dir, ""); len(report.Findings) != 0 {
		t.Fatalf("findings on a scaffold with no mcp.yaml: %+v", report.Findings)
	}
	if out := captureServeBootCheck(t, dir); strings.TrimSpace(out) != "" {
		t.Fatalf("serve start-up check printed %q", out)
	}
}

// With warnings only, the closing line says the app runs; "rejected by push"
// is kept for findings a push refuses.
func TestServeBootCheckOutcomeLine(t *testing.T) {
	warn := CheckReport{Warnings: 1, Findings: []CheckFinding{{Severity: "warning", Source: "schema", Message: "a note"}}}
	if got := serveBootCheckOutcome(warn); !strings.Contains(got, "the app starts and runs") || strings.Contains(got, "rejected") || strings.Contains(got, "MCP connector") {
		t.Errorf("warnings only: %q", got)
	}
	refused := CheckReport{Errors: 1, Warnings: 1, Findings: []CheckFinding{
		{Severity: "error", Source: "syntax", File: "flows.yaml", Message: "bad"},
		{Severity: "warning", Source: "mcp_review", File: "mcp.yaml", Message: "stale"},
	}}
	if got := serveBootCheckOutcome(refused); !strings.Contains(got, "1 error(s) above") || !strings.Contains(got, "would be rejected by `benmore push`") {
		t.Errorf("an error a push refuses: %q", got)
	}
	load := CheckReport{Errors: 1, Findings: []CheckFinding{{Severity: "error", Source: "app_load", Message: "boom"}}}
	if got := serveBootCheckOutcome(load); !strings.Contains(got, "stops the app from starting") || strings.Contains(got, "rejected") {
		t.Errorf("a load error: %q", got)
	}
	if got := serveBootCheckOutcome(CheckReport{}); got != "" {
		t.Errorf("clean report: %q", got)
	}
}
