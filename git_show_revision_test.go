//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// git_show (viewer-level MCP tool) and /platform/git/show pass a
// caller-supplied revision to gitShow in the router process. It must be
// treated only as a revision, never as a git option.
func TestGitShowTreatsInputOnlyAsRevision(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: show\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := gitEnsureRepo(dir, "Show App"); err != nil {
		t.Fatal(err)
	}

	out, err := gitShow(dir, "HEAD")
	if err != nil {
		t.Fatalf("gitShow(HEAD): %v", err)
	}
	if !strings.Contains(out, "app.yaml") {
		t.Fatalf("gitShow(HEAD) should include the committed file, got:\n%s", out)
	}
	commits, err := gitLog(dir, 1)
	if err != nil || len(commits) != 1 {
		t.Fatalf("gitLog: %v (%d commits)", err, len(commits))
	}
	if _, err := gitShow(dir, commits[0].SHA[:7]); err != nil {
		t.Fatalf("short sha must still resolve: %v", err)
	}

	for _, rev := range []string{"--stat", "-p", "--format=%H"} {
		if out, err := gitShow(dir, rev); err == nil {
			t.Fatalf("gitShow(%q) must be refused as a non-revision, got output:\n%s", rev, out)
		}
	}
}
