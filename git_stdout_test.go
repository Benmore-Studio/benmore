//go:build !cli && !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Git can succeed while warning about an unreadable untracked directory. Keep
// that deterministic on root CI runners, where chmod alone cannot force it.
func installGitStderrWarning(t *testing.T) {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := t.TempDir()
	quotedGit := "'" + strings.ReplaceAll(realGit, "'", "'\\''") + "'"
	script := "#!/bin/sh\nfor arg do\n" +
		"  case \"$arg\" in\n" +
		"    ls-files) printf '%s\\n' \"warning: could not open directory '.cache/dconf/': Permission denied\" >&2 ;;\n" +
		"    test-stderr-failure) printf 'partial stdout\\n'; printf 'synthetic git failure\\n' >&2; exit 9 ;;\n" +
		"  esac\ndone\nexec " + quotedGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(wrapperDir, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestGitSourceSnapshotIgnoresSuccessfulStderr(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "app.yaml", "name: fixture\n")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	before := historyGit(t, dir, "rev-parse", "HEAD")
	installGitStderrWarning(t)

	path := "static/literal[1]\nview.html"
	historyWrite(t, dir, path, "<h1>new source</h1>\n")
	out, err := gitRun(dir, "ls-files", "-z", "--others", "--exclude-standard")
	if err != nil || out != path+"\x00" {
		t.Fatalf("successful git stdout was contaminated: %q, %v", out, err)
	}
	if err := gitAutoCommit(dir, "source save after git warning"); err != nil {
		t.Fatal(err)
	}
	if after := historyGit(t, dir, "rev-parse", "HEAD"); after == before {
		t.Fatal("source save did not commit")
	}
	if got := historyGit(t, dir, "show", "HEAD:"+path); got != "<h1>new source</h1>" {
		t.Fatalf("saved source changed: %q", got)
	}
	if _, err := gitSnapshotHeadChecked(dir, "unchanged source after warning"); err != nil {
		t.Fatal(err)
	}
}

func TestGitRunFailureRetainsStderrDiagnostic(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	installGitStderrWarning(t)
	out, err := gitRun(dir, "test-stderr-failure")
	if out != "partial stdout\n" {
		t.Fatalf("failed git stdout = %q", out)
	}
	if err == nil || !strings.Contains(err.Error(), "synthetic git failure") || !strings.Contains(err.Error(), "exit status 9") {
		t.Fatalf("git stderr diagnostic was lost: %v", err)
	}
}
