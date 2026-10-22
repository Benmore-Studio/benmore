//go:build !cli

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A hidden directory under a runtime tree (flows/) is part of the reviewed
// source, but pull never writes it, so a review made in a pulled workspace can
// never match the server. The stale-review notice must say which files are the
// reason. Hidden files the runtime never reads (.sdd/) are not part of it.
func TestAppMCPWithheldNoticeNamesSourcesPullNeverWrites(t *testing.T) {
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
	writeTestFile(t, dir, ".sdd/plan.md", "notes the runtime never reads\n")
	writeTestFile(t, dir, "docs/x/.verify/sweep.json", "{}\n")
	writeTestFile(t, dir, ".claude/settings.json", "{}\n") // outside the digest: not a reason
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("files outside the runtime sources made the review stale: %s", notice)
	}
	writeTestFile(t, dir, "flows/.drafts/plan.yaml", "notes planted on the server\n")
	notice := appMCPConnectorWithheldNotice(dir)
	if !strings.Contains(notice, "benmore mcp review") {
		t.Fatalf("stale review not reported: %q", notice)
	}
	if !strings.Contains(notice, "flows/.drafts/plan.yaml") || !strings.Contains(notice, "never writes") {
		t.Fatalf("notice does not name the source pull never writes: %q", notice)
	}
	if strings.Contains(notice, ".claude/settings.json") {
		t.Fatalf("notice names a file the digest does not cover: %q", notice)
	}
}

func TestAppMCPSourceCoversMatchesTheDigestWalk(t *testing.T) {
	for path, want := range map[string]bool{
		"app.yaml":              true,
		".sdd/plan.md":          true,
		"flows/.drafts/x.yaml":  true,
		"static/.claude/x.js":   true,
		".claude/settings.json": false,
		"a/node_modules/x.js":   false,
		"env.yaml":              false,
		"mcp.yaml":              false,
	} {
		if got := appMCPSourceCovers(path, nil); got != want {
			t.Errorf("appMCPSourceCovers(%q, nil) = %v, want %v", path, got, want)
		}
	}
}
