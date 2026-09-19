//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func historyWrite(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func historyGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitRun(dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

func TestGitHistoryStagesOnlySourceDespiteIgnoreOverrides(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, ".gitignore", "custom.tmp\n!env.yaml\n")
	historyWrite(t, dir, "nested/.gitignore", "!env.yaml\n!.env\n!*.key\n!*.pem\n!*.log\n!data.db\n!uploads/\n")
	historyWrite(t, dir, "app.yaml", "name: example")
	historyWrite(t, dir, "custom.tmp", "app exclusion")
	protected := []string{"env.yaml", "secrets.yaml", ".env", ".env.production", "tls.key", "cert.pem", "data.db", "data.db-wal", "data.db-shm", "uploads/blob", ".benmore/recovery/data.db", "Benmore/bin", "nested/env.yaml", "nested/.env", "nested/private.key", "nested/cert.pem", "nested/runtime.log", "nested/data.db", "nested/uploads/blob"}
	for _, path := range protected {
		historyWrite(t, dir, path, "synthetic private content")
	}
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	initial := historyGit(t, dir, "ls-files", "-z")
	if strings.Contains(initial, "custom.tmp\x00") {
		t.Fatal("app ignore rule lost on initialization")
	}
	for _, path := range protected {
		if strings.Contains("\x00"+initial, "\x00"+path+"\x00") {
			t.Fatalf("initial commit included %s", path)
		}
	}
	for _, mode := range []string{"removed", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "removed" {
				if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil {
					t.Fatal(err)
				}
			} else {
				historyWrite(t, dir, ".gitignore", "custom.tmp\n!*\n")
			}
			historyWrite(t, dir, "app.yaml", mode)
			if _, err := gitSnapshotHeadChecked(dir, "source mirror "+mode); err != nil {
				t.Fatal(err)
			}
			tracked := historyGit(t, dir, "ls-files", "-z")
			for _, path := range protected {
				if strings.Contains("\x00"+tracked, "\x00"+path+"\x00") {
					t.Fatalf("commit included %s", path)
				}
			}
			if !strings.Contains(tracked, "app.yaml\x00") {
				t.Fatal("source was not tracked")
			}
			for _, path := range protected {
				data, err := os.ReadFile(filepath.Join(dir, path))
				if err != nil || string(data) != "synthetic private content" {
					t.Fatalf("runtime file changed: %s: %v", path, err)
				}
			}
		})
	}
}

func TestGitHistoryRestorePreservesProtectedDirectoryObstructions(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "nested", "old source file")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	old := historyGit(t, dir, "rev-parse", "HEAD")
	if err := os.Remove(filepath.Join(dir, "nested")); err != nil {
		t.Fatal(err)
	}
	historyWrite(t, dir, "nested/app.yaml", "new source")
	historyWrite(t, dir, "nested/.gitignore", "!env.yaml\n")
	historyWrite(t, dir, "nested/env.yaml", "synthetic runtime secret")
	if err := gitAutoCommit(dir, "directory now contains runtime state"); err != nil {
		t.Fatal(err)
	}
	if err := gitHardRestore(dir, old); err == nil {
		t.Fatal("restore allowed runtime directory removal")
	}
	if _, err := gitRevert(dir, old); err == nil {
		t.Fatal("revert allowed runtime directory removal")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "nested/env.yaml")); err != nil || string(data) != "synthetic runtime secret" {
		t.Fatal("runtime state changed")
	}
}

func TestGitHistoryStagesLiteralNamesAndDeletions(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	paths := []string{"*.txt", ":(glob)*", "line\nbreak.txt", "normal.txt", "delete.txt"}
	for _, path := range paths {
		historyWrite(t, dir, path, "v1")
	}
	if err := gitEnsureRepo(dir, "literal fixture"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	historyWrite(t, dir, "*.txt", "v2")
	if _, err := gitSnapshotHeadChecked(dir, "literal and deletion"); err != nil {
		t.Fatal(err)
	}
	if tracked := historyGit(t, dir, "ls-files", "-z"); strings.Contains(tracked, "delete.txt\x00") {
		t.Fatal("deletion was not committed")
	}
}

func TestGitHistoryPreservesSourceTypeChanges(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "source/child.txt", "directory version")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	prior := historyGit(t, dir, "rev-parse", "HEAD")
	if err := os.RemoveAll(filepath.Join(dir, "source")); err != nil {
		t.Fatal(err)
	}
	historyWrite(t, dir, "source", "file version")
	if err := gitAutoCommit(dir, "directory becomes file"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitRevert(dir, prior); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "source/child.txt")); err != nil || string(got) != "directory version" {
		t.Fatal("source type change was not reverted")
	}
}

func TestGitHistoryRefusesStagedAndCommittedRuntimeData(t *testing.T) {
	requireGit(t)
	for _, state := range []string{"staged", "committed", "staged removal"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			historyWrite(t, dir, "app.yaml", "v1")
			if err := gitEnsureRepo(dir, "fixture"); err != nil {
				t.Fatal(err)
			}
			historyWrite(t, dir, "env.yaml", "synthetic secret")
			historyGit(t, dir, "add", "-f", "env.yaml")
			if state != "staged" {
				historyGit(t, dir, "commit", "-qm", "unsafe historical fixture")
			}
			if state == "staged removal" {
				historyGit(t, dir, "rm", "--cached", "env.yaml")
			}
			before := historyGit(t, dir, "rev-parse", "HEAD")
			historyWrite(t, dir, "app.yaml", "saved source")
			if err := gitAutoCommit(dir, "must refuse"); err == nil {
				t.Fatal("unsafe history accepted")
			}
			if _, ok := gitSnapshotHead(dir, "must refuse snapshot"); ok {
				t.Fatal("unsafe snapshot accepted")
			}
			if after := historyGit(t, dir, "rev-parse", "HEAD"); before != after {
				t.Fatal("refusal changed HEAD")
			}
		})
	}
}

func TestGitHistoryRestoreAndPublishRejectHistoricalSecrets(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "app.yaml", "v1")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitPublishHead(dir); err != nil {
		t.Fatal(err)
	}
	historyWrite(t, dir, "env.yaml", "old synthetic secret")
	historyGit(t, dir, "add", "-f", "env.yaml")
	historyGit(t, dir, "commit", "-qm", "historical secret")
	unsafe := historyGit(t, dir, "rev-parse", "HEAD")
	historyGit(t, dir, "rm", "--cached", "env.yaml")
	historyGit(t, dir, "commit", "-qm", "no secret in latest tree")
	historyWrite(t, dir, "env.yaml", "current synthetic secret")
	before := historyGit(t, dir, "rev-parse", "HEAD")
	if _, err := gitPublishHead(dir); err == nil {
		t.Fatal("deleted historical secret allowed into push")
	}
	if err := gitHardRestore(dir, unsafe); err == nil {
		t.Fatal("restore accepted unsafe target")
	}
	if _, err := gitRevert(dir, unsafe); err == nil {
		t.Fatal("revert accepted unsafe target")
	}
	if after := historyGit(t, dir, "rev-parse", "HEAD"); before != after {
		t.Fatal("refused operations changed HEAD")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "env.yaml")); string(data) != "current synthetic secret" {
		t.Fatal("refused restore touched live secrets")
	}
}

func TestGitHistoryCommitFailureCannotReturnStaleSnapshot(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "app.yaml", "v1")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	historyWrite(t, dir, "app.yaml", "v2")
	historyWrite(t, dir, ".git/index.lock", "fixture lock")
	if err := gitAutoCommit(dir, "must fail"); err == nil {
		t.Fatal("commit failure hidden")
	}
	if _, ok := gitSnapshotHead(dir, "must fail"); ok {
		t.Fatal("stale snapshot returned")
	}
}

func TestGitHistoryPublishChecksMergedHistory(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	historyWrite(t, dir, "app.yaml", "fixture")
	if err := gitEnsureRepo(dir, "fixture"); err != nil {
		t.Fatal(err)
	}
	historyGit(t, dir, "checkout", "-qb", "side")
	historyWrite(t, dir, "env.yaml", "synthetic secret")
	historyGit(t, dir, "add", "-f", "env.yaml")
	historyGit(t, dir, "commit", "-qm", "secret on second parent")
	historyGit(t, dir, "rm", "--cached", "env.yaml")
	historyGit(t, dir, "commit", "-qm", "clean side tree")
	historyGit(t, dir, "checkout", "-q", "main")
	historyGit(t, dir, "merge", "--no-ff", "-qm", "merge side", "side")
	if _, err := gitPublishHead(dir); err == nil {
		t.Fatal("second-parent secret escaped audit")
	}
}

func TestGitHistoryRejectsRedirectsAndIgnoresInheritedRepository(t *testing.T) {
	requireGit(t)
	outside := t.TempDir()
	historyWrite(t, outside, "app.yaml", "outside")
	if err := gitEnsureRepo(outside, "outside"); err != nil {
		t.Fatal(err)
	}
	before := historyGit(t, outside, "rev-parse", "HEAD")
	for _, kind := range []string{"git symlink", "git file", "worktree config", "ignore symlink", "inherited"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			historyWrite(t, dir, "app.yaml", "inside")
			var err error
			switch kind {
			case "git symlink":
				err = os.Symlink(filepath.Join(outside, ".git"), filepath.Join(dir, ".git"))
			case "git file":
				historyWrite(t, dir, ".git", "gitdir: "+filepath.Join(outside, ".git")+"\n")
			case "worktree config":
				if err := gitEnsureRepo(dir, "fixture"); err != nil {
					t.Fatal(err)
				}
				historyGit(t, dir, "config", "core.worktree", outside)
			case "ignore symlink":
				err = os.Symlink(filepath.Join(outside, "app.yaml"), filepath.Join(dir, ".gitignore"))
			case "inherited":
				t.Setenv("GIT_DIR", filepath.Join(outside, ".git"))
				t.Setenv("GIT_WORK_TREE", outside)
				t.Setenv("GIT_INDEX_FILE", filepath.Join(outside, ".git/index"))
			}
			if err != nil {
				t.Fatal(err)
			}
			err = gitAutoCommit(dir, "fixture")
			if (kind == "inherited") != (err == nil) {
				t.Fatalf("unexpected result: %v", err)
			}
			if after := historyGit(t, outside, "rev-parse", "HEAD"); before != after {
				t.Fatal("outside history changed")
			}
		})
	}
}
