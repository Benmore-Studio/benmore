//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The router runs git in tenant-owned repos. The tenant's own uid owns
// .git/config, and .gitattributes is ordinary app source, so a filter or
// textconv driver defined there must never execute in the router.
func TestGitRepoConfigCannotExecutePrograms(t *testing.T) {
	requireGit(t)
	for _, tc := range []struct{ name, cfg, attrs string }{
		{"clean filter", "[filter \"x\"]\n\tclean = %s\n", "*.txt filter=x\n"},
		{"textconv", "[diff \"x\"]\n\ttextconv = %s\n", "*.txt diff=x\n"},
		{"include", "[include]\n\tpath = extra\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(t.TempDir(), "pwned")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: x\n"), 0644))
			must(gitEnsureRepo(dir, "X"))
			script := filepath.Join(t.TempDir(), "drv.sh")
			must(os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\ncat \"$@\"\n"), 0755))
			cfg := tc.cfg
			if tc.name != "include" {
				cfg = sprintfMarker(tc.cfg, script)
			} else {
				must(os.WriteFile(filepath.Join(dir, ".git", "extra"), []byte("[filter \"x\"]\n\tclean = "+script+"\n"), 0644))
				tc.attrs = "*.txt filter=x\n"
			}
			f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
			must(err)
			_, err = f.WriteString(cfg)
			must(err)
			must(f.Close())
			must(os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte(tc.attrs), 0644))
			must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi\n"), 0644))
			_ = gitAutoCommit(dir, "one")
			must(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi2\n"), 0644))
			_ = gitAutoCommit(dir, "two")
			_, _ = gitShow(dir, "HEAD")
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("repo-local git config executed a program in the router")
			}
		})
	}
}

func sprintfMarker(format, marker string) string {
	out := ""
	for i := 0; i < len(format); i++ {
		if i+1 < len(format) && format[i] == '%' && format[i+1] == 's' {
			out += marker
			i++
			continue
		}
		out += string(format[i])
	}
	return out
}

// Newer git writes extensions.* for its object and ref formats; those carry no
// program to run, so the audit must not refuse a repo that has them.
func TestGitConfigAuditAllowsFormatExtensions(t *testing.T) {
	for _, k := range []string{"extensions.refstorage", "extensions.objectformat"} {
		if !gitAllowedLocalConfig[k] {
			t.Errorf("%s should be allowed", k)
		}
	}
	for _, k := range []string{"filter.x.clean", "diff.x.textconv", "include.path", "core.gitproxy", "core.fsmonitor", "core.hookspath", "url.x.insteadof", "extensions.worktreeconfig"} {
		if gitAllowedLocalConfig[k] {
			t.Errorf("%s must stay refused", k)
		}
	}
}
