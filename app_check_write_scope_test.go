//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An app-wide warning (a protected column name in the schema) is reported
// when the schema is written or checked, not on every push of other files.
func TestWriteCheckReportsOnlyTheWrittenFilesWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Scope fixture"); err != nil {
		t.Fatal(err)
	}
	schema := "model Member {\n  id   Int    @id @default(autoincrement())\n  role String @default(\"viewer\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}
	protected := func(r CheckReport) bool {
		for _, f := range r.Findings {
			if strings.Contains(f.Message, "framework-protected field name") {
				return true
			}
		}
		return false
	}
	if !protected(RunSourceCheck(dir, "schema.prisma")) {
		t.Fatal("schema write did not report the protected column")
	}
	if !protected(runCheck(dir, "", false)) {
		t.Fatal("full check did not report the protected column")
	}
	for _, other := range []string{"static/app.tsx", "static/styles.css", "static/index.html"} {
		if protected(RunSourceCheck(dir, other)) {
			t.Fatalf("push of %s repeated the schema's warning", other)
		}
	}
}

func TestWriteRelevantFindingsKeepsErrorsAndOwnWarnings(t *testing.T) {
	findings := []CheckFinding{
		{Severity: "error", File: "schema.prisma", Message: "broken schema"},
		{Severity: "warning", File: "schema.prisma", Message: "schema note"},
		{Severity: "warning", File: "static/app.tsx", Message: "own note"},
		{Severity: "warning", Message: "cross-file note"},
	}
	got := writeRelevantFindings("static/app.tsx", findings)
	if len(got) != 2 || got[0].Message != "broken schema" || got[1].Message != "own note" {
		t.Fatalf("static write kept %+v", got)
	}
	got = writeRelevantFindings("hooks.yaml", findings)
	if len(got) != 2 || got[1].Message != "cross-file note" {
		t.Fatalf("config write kept %+v", got)
	}
	if got := writeRelevantFindings("flows.yaml", findings); len(got) != len(findings) {
		t.Fatalf("shared file write kept %+v", got)
	}
}

// Every scaffolded app ships a reviewed mcp.yaml; its first edit makes the
// review stale, which withholds only the connector. A schema push must not
// answer ok:false for that.
func TestWriteCheckStaleMCPReviewIsAWarning(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Stale fixture"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "hero.png"), []byte("\x89PNG-hero"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := func(r CheckReport) (CheckFinding, bool) {
		for _, f := range r.Findings {
			if f.File == "mcp.yaml" && strings.Contains(f.Message, "digest mismatch") {
				return f, true
			}
		}
		return CheckFinding{}, false
	}
	write := RunSourceCheck(dir, "schema.prisma")
	if f, ok := stale(write); !ok || f.Severity != "warning" || write.Errors != 0 {
		t.Fatalf("schema write: stale review %+v present=%v errors=%d", f, ok, write.Errors)
	}
	if f, ok := stale(runCheck(dir, "", false)); !ok || f.Severity != "error" {
		t.Fatalf("benmore check must keep reporting the stale review as an error: %+v %v", f, ok)
	}
}
