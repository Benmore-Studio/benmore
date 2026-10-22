//go:build !cli

package main

import (
	"path/filepath"
	"testing"
)

// Hosted apps refuse auto-run config and deploy skips it, so a reviewed digest
// must not cover the developer's local copy, or the review could never match.
func TestAppMCPDigestLeavesOutAutoRunConfig(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLScaffoldFiles(dir, "Notes fixture"); err != nil {
		t.Fatal(err)
	}
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("reviewed starter reported stale: %s", notice)
	}
	writeTestFile(t, dir, ".vscode/settings.json", "{}\n")
	writeTestFile(t, dir, ".mcp.json", "{}\n")
	writeTestFile(t, dir, "flows/.cursor/rules.json", "{}\n")
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("local editor config made the review stale: %s", notice)
	}
	writeTestFile(t, dir, "static/.vscode/served.js", "export {}\n")
	if notice := appMCPConnectorWithheldNotice(dir); notice == "" {
		t.Fatal("a served static file must stay in the digest")
	}
}

func TestWorkspaceAutoRunPath(t *testing.T) {
	for path, want := range map[string]bool{
		".vscode/tasks.json": true, ".vscode": true, "a/.claude/settings.json": true, ".mcp.json": true,
		"mise.toml/.": true, "static/../.envrc": true, "x.code-workspace": true, "CLAUDE~1/x": true,
		".sdd/plan.md": false, ".github/workflows/ci.yml": false, "static/.vscode/x.js": false,
		"static/.mcp.json": false, "app.yaml": false, ".well-known/x": false,
	} {
		if got := workspaceAutoRunPath(path, false); got != want {
			t.Errorf("workspaceAutoRunPath(%q) = %v, want %v", path, got, want)
		}
	}
	if !workspaceAutoRunPath(".vscode", true) || !workspaceAutoRunPath("CLAUDE~1", true) || workspaceAutoRunPath(".sdd", true) {
		t.Error("directory forms misjudged")
	}
	if !pullDeniedPath("mise.toml/.") || !pullDeniedPath("static/../.sdd/x") {
		t.Error("pullDeniedPath must judge the resolved path too")
	}
}
