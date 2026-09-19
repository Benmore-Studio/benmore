//go:build !cli

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Skip the suite if `git` isn't installed on the test host. Per-app
// git is a no-op when the binary isn't present; the tests cover the
// happy path, so a missing binary is grounds for skip not fail.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not installed on this host - skipping per-app git tests")
	}
}

// gitEnsureRepo creates the .git directory, writes .gitignore, and
// makes an initial commit. Idempotent across repeat calls.
func TestGitEnsureRepo_InitializesAndIsIdempotent(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: test"), 0644)

	if err := gitEnsureRepo(dir, "Test App"); err != nil {
		t.Fatalf("first init failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		t.Fatalf(".git not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatalf(".gitignore not written: %v", err)
	}
	// Second call must not fail or rewrite history.
	if err := gitEnsureRepo(dir, "Test App"); err != nil {
		t.Fatalf("second init failed: %v", err)
	}
	commits, _ := gitLog(dir, 10)
	if len(commits) != 1 {
		t.Errorf("expected exactly 1 initial commit after two init calls, got %d", len(commits))
	}
	if !strings.Contains(commits[0].Message, "Test App") {
		t.Errorf("initial commit message should include display name, got %q", commits[0].Message)
	}
}

// gitAutoCommit stages everything + commits with the supplied message.
// A second call with no changes is a no-op (no empty commits).
func TestGitAutoCommit_CommitsAndSkipsWhenClean(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("v1"), 0644)
	if err := gitEnsureRepo(dir, "auto"); err != nil {
		t.Fatal(err)
	}

	// Mutate and commit.
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("v2"), 0644)
	gitAutoCommit(dir, "write_file: app.yaml")

	commits, _ := gitLog(dir, 10)
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits (init + write), got %d", len(commits))
	}
	if commits[0].Message != "write_file: app.yaml" {
		t.Errorf("top commit message wrong: %q", commits[0].Message)
	}

	// Second commit with no change should NOT create a new commit.
	gitAutoCommit(dir, "should be skipped")
	commits2, _ := gitLog(dir, 10)
	if len(commits2) != 2 {
		t.Errorf("no-op autocommit added a commit: now %d", len(commits2))
	}
}

// .gitignore must keep runtime state out of git - data.db, env.yaml,
// uploads/, .benmore/ would all flood diffs with binary/secret churn.
func TestGitEnsureRepo_GitignoreExcludesRuntimeState(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("ok"), 0644)
	os.WriteFile(filepath.Join(dir, "data.db"), []byte("sqlite-binary"), 0644)
	os.WriteFile(filepath.Join(dir, "env.yaml"), []byte("SECRET=x"), 0644)
	os.MkdirAll(filepath.Join(dir, "uploads"), 0755)
	os.WriteFile(filepath.Join(dir, "uploads", "file.bin"), []byte("blob"), 0644)
	os.MkdirAll(filepath.Join(dir, ".benmore", "backups"), 0755)
	os.WriteFile(filepath.Join(dir, ".benmore", "backups", "pre.db"), []byte("backup"), 0644)

	if err := gitEnsureRepo(dir, "ignore-test"); err != nil {
		t.Fatal(err)
	}

	// `git ls-files` lists everything tracked. Runtime state must be absent.
	out, err := gitRun(dir, "ls-files")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"data.db", "env.yaml", "uploads/", ".benmore/"} {
		if strings.Contains(out, banned) {
			t.Errorf("git tracked %q despite .gitignore - listing:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "app.yaml") {
		t.Errorf("expected app.yaml tracked, got listing:\n%s", out)
	}
}

// gitRevert makes the working tree match a prior commit + records a
// NEW commit on top. History must NOT be rewritten - both the
// original commits and the revert commit remain.
func TestGitRevert_NonDestructive(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("v1"), 0644)
	if err := gitEnsureRepo(dir, "revert-test"); err != nil {
		t.Fatal(err)
	}
	initial, _ := gitLog(dir, 1)
	if len(initial) == 0 {
		t.Fatal("no initial commit")
	}
	originalSHA := initial[0].SHA

	// v2 change - mutate the existing file AND add a brand-new file.
	// The added file is the trip-wire for the bug we shipped a fix for:
	// `git checkout <sha> -- .` only restores files that existed in
	// <sha> and leaves later-added files in place, so the working
	// tree didn't actually match the target commit. read-tree --reset
	// removes them too. This assertion catches the regression.
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("v2"), 0644)
	os.WriteFile(filepath.Join(dir, "added_later.txt"), []byte("only in v2"), 0644)
	gitAutoCommit(dir, "v2 update + add file")
	// v3 change - we'll roll back from here.
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("v3"), 0644)
	gitAutoCommit(dir, "v3 update")

	// Revert to the original commit.
	revertCommit, err := gitRevert(dir, originalSHA)
	if err != nil {
		t.Fatalf("revert failed: %v", err)
	}
	if !strings.Contains(revertCommit.Message, originalSHA) && !strings.Contains(revertCommit.Message, "revert") {
		t.Errorf("revert commit message should mention the target SHA, got %q", revertCommit.Message)
	}

	// Working tree now matches v1.
	got, _ := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if string(got) != "v1" {
		t.Errorf("working tree didn't roll back: %q", got)
	}

	// And the file that was added later is GONE from the working tree.
	if _, err := os.Stat(filepath.Join(dir, "added_later.txt")); err == nil {
		t.Errorf("added_later.txt should be removed by revert (it didn't exist in target commit)")
	}

	// History preserved: 4 commits total (init + v2 + v3 + revert).
	commits, _ := gitLog(dir, 10)
	if len(commits) != 4 {
		t.Errorf("expected 4 commits after revert, got %d:\n%+v", len(commits), commits)
	}
}

// gitLog returns nothing (not an error) for an uninitialized directory.
// The MCP tool surfaces this as "no history yet" rather than an error.
func TestGitLog_EmptyForUninitialized(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	commits, err := gitLog(dir, 10)
	if err != nil {
		t.Errorf("uninitialized dir should return nil, nil - got err: %v", err)
	}
	if len(commits) != 0 {
		t.Errorf("expected empty log for uninitialized dir, got %d commits", len(commits))
	}
}
