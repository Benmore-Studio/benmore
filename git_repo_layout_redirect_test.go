//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The router runs git with its own uid in every tenant's repo, and that uid
// can read and write every tenant tree. A tenant owns its .git directory, so
// repository metadata that points git at another directory (a .git file,
// .git/commondir, object alternates, symlinked refs or objects) would let one
// tenant read another tenant's history through its own dashboard, or commit
// into it, while the config audit reads a clean config.
func TestGitRepoLayoutCannotRedirectToAnotherRepo(t *testing.T) {
	requireGit(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	newRepo := func(t *testing.T, marker string) string {
		t.Helper()
		dir := t.TempDir()
		must(os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: "+marker+"\n"), 0644))
		must(gitEnsureRepo(dir, marker))
		must(os.WriteFile(filepath.Join(dir, "s.txt"), []byte(marker+"\n"), 0644))
		must(gitAutoCommit(dir, marker+" commit"))
		return dir
	}
	leaks := func(t *testing.T, a, secret string) bool {
		t.Helper()
		commits, _ := gitLog(a, 50)
		for _, c := range commits {
			if strings.Contains(c.Message, secret) {
				return true
			}
		}
		out, _ := gitShow(a, "HEAD")
		return strings.Contains(out, secret)
	}

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, a, b string)
	}{
		{"commondir", func(t *testing.T, a, b string) {
			must(os.WriteFile(filepath.Join(a, ".git", "commondir"), []byte(filepath.Join(b, ".git")+"\n"), 0644))
		}},
		{"gitfile", func(t *testing.T, a, b string) {
			must(os.RemoveAll(filepath.Join(a, ".git")))
			must(os.WriteFile(filepath.Join(a, ".git"), []byte("gitdir: "+filepath.Join(b, ".git")+"\n"), 0644))
		}},
		{"git dir symlink", func(t *testing.T, a, b string) {
			must(os.RemoveAll(filepath.Join(a, ".git")))
			must(os.Symlink(filepath.Join(b, ".git"), filepath.Join(a, ".git")))
		}},
		{"symlinked refs and objects", func(t *testing.T, a, b string) {
			for _, name := range []string{"refs", "objects", "packed-refs"} {
				must(os.RemoveAll(filepath.Join(a, ".git", name)))
				if _, err := os.Lstat(filepath.Join(b, ".git", name)); err == nil {
					must(os.Symlink(filepath.Join(b, ".git", name), filepath.Join(a, ".git", name)))
				}
			}
		}},
		{"symlinked branch ref", func(t *testing.T, a, b string) {
			ref := filepath.Join(a, ".git", "refs", "heads", "main")
			must(os.Remove(ref))
			must(os.Symlink(filepath.Join(b, ".git", "refs", "heads", "main"), ref))
		}},
		{"alternates", func(t *testing.T, a, b string) {
			info := filepath.Join(a, ".git", "objects", "info")
			must(os.MkdirAll(info, 0755))
			must(os.WriteFile(filepath.Join(info, "alternates"), []byte(filepath.Join(b, ".git", "objects")+"\n"), 0644))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newRepo(t, "tenant-a")
			b := newRepo(t, "tenant-b-secret")
			tc.setup(t, a, b)
			if tc.name == "alternates" {
				// Alternates need the victim's ids; the audit must refuse
				// the layout before git reads any object through it.
				if err := gitAuditLocalConfig(a); err == nil {
					t.Fatal("audit accepted a repo with object alternates")
				}
				return
			}
			if leaks(t, a, "tenant-b-secret") {
				t.Fatal("tenant A's history tools showed tenant B's history")
			}
			if err := gitAuditLocalConfig(a); err == nil {
				t.Fatal("audit accepted a redirected repository")
			}
			before, err := gitRun(b, "rev-parse", "HEAD")
			must(err)
			must(os.WriteFile(filepath.Join(a, "s.txt"), []byte("planted\n"), 0644))
			_ = gitAutoCommit(a, "planted")
			after, err := gitRun(b, "rev-parse", "HEAD")
			must(err)
			if before != after {
				t.Fatal("a commit in tenant A's directory landed in tenant B's history")
			}
		})
	}
}

// An ordinary Benmore repo passes the layout audit.
func TestGitRepoLayoutAuditAcceptsPlainRepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := gitEnsureRepo(dir, "X"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitRun(dir, "gc", "-q"); err != nil {
		t.Fatal(err)
	}
	if err := gitAuditLocalConfig(dir); err != nil {
		t.Fatalf("plain repo refused: %v", err)
	}
	if commits, err := gitLog(dir, 5); err != nil || len(commits) == 0 {
		t.Fatalf("gitLog on a plain repo: %v %v", commits, err)
	}
}
