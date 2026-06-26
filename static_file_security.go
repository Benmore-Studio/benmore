//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// resolveServableFile fail-closed resolves target under root, enforcing both
// lexical and evaluated-symlink containment, and returns the real absolute
// path of an existing regular file (ok=false otherwise). Callers don't need
// the FileInfo - http.ServeFile re-stats the path itself - so it isn't
// returned.
func resolveServableFile(root, target string) (string, bool) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil || !pathWithinDir(rootAbs, targetAbs) {
		return "", false
	}
	// No pre-EvalSymlinks os.Stat here: the post-resolution os.Stat below is
	// the authoritative existence/dir check, and dropping the redundant stat
	// also closes one TOCTOU window (the gap between resolution and ServeFile
	// remains, but it's a low-risk, read-only race).
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", false
	}
	realTarget, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return "", false
	}
	realRootAbs, err := filepath.Abs(filepath.Clean(realRoot))
	if err != nil {
		return "", false
	}
	realTargetAbs, err := filepath.Abs(filepath.Clean(realTarget))
	if err != nil || !pathWithinDir(realRootAbs, realTargetAbs) {
		return "", false
	}
	st, err := os.Stat(realTargetAbs)
	if err != nil || st.IsDir() {
		return "", false
	}
	return realTargetAbs, true
}

func pathWithinDir(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
