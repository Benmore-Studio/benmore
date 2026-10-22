//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A commit that adds a large text file made git_show buffer the whole diff in
// the router (then cut it to 200 KB for the reply).
func TestGitShowDoesNotBufferHugeDiffs(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: t"), 0644)
	if err := gitEnsureRepo(dir, "big"); err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 99) + "\n"
	os.WriteFile(filepath.Join(dir, "big.txt"), []byte(strings.Repeat(line, 600_000)), 0644) // ~60 MB
	gitAutoCommit(dir, "add big file")

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, err := gitShow(dir, "HEAD")
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	grown := after.TotalAlloc - before.TotalAlloc
	t.Logf("output=%d bytes allocated=%d MB", len(out), grown>>20)
	if len(out) > gitShowMaxBytes {
		t.Errorf("gitShow returned %d bytes; cap %d", len(out), gitShowMaxBytes)
	}
	if !strings.Contains(out, "add big file") {
		t.Error("truncated output lost the commit header")
	}
	if grown > 16<<20 {
		t.Errorf("gitShow allocated %d MB for a capped result", grown>>20)
	}
}
