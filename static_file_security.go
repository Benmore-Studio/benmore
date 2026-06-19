//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
)

func resolveServableFile(root, target string) (string, os.FileInfo, bool) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", nil, false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil || !pathWithinDir(rootAbs, targetAbs) {
		return "", nil, false
	}
	st, err := os.Stat(targetAbs)
	if err != nil || st.IsDir() {
		return "", nil, false
	}
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", nil, false
	}
	realTarget, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return "", nil, false
	}
	realRootAbs, err := filepath.Abs(filepath.Clean(realRoot))
	if err != nil {
		return "", nil, false
	}
	realTargetAbs, err := filepath.Abs(filepath.Clean(realTarget))
	if err != nil || !pathWithinDir(realRootAbs, realTargetAbs) {
		return "", nil, false
	}
	st, err = os.Stat(realTargetAbs)
	if err != nil || st.IsDir() {
		return "", nil, false
	}
	return realTargetAbs, st, true
}

func pathWithinDir(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
