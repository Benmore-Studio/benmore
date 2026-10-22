//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// resolveServableFile fail-closed resolves target under root, enforcing both
// lexical and evaluated-symlink containment, and returns the real absolute
// path of an existing regular file (ok=false otherwise). This is a pathname
// lookup only: callers reading bytes must use openServableFile so replacement
// after resolution cannot redirect the read.
func resolveServableFile(root, target string) (string, bool) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil || !pathWithinDir(rootAbs, targetAbs) {
		return "", false
	}
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
	if err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	return realTargetAbs, true
}

// servableFile binds containment and any subsequent access checks to the file
// handle used for reading. relative is the symlink-resolved path inside the
// pinned root, so callers can also enforce private/ and reserved namespaces.
type servableFile struct {
	*os.File
	info     os.FileInfo
	path     string
	relative string
}

// serveHTTP retains ServeFile's URL checks and index redirect without reopening
// the validated pathname. Content, ranges and conditional requests use the handle.
func (f *servableFile) serveHTTP(w http.ResponseWriter, r *http.Request) {
	for _, part := range strings.FieldsFunc(r.URL.Path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			http.Error(w, "invalid URL path", http.StatusBadRequest)
			return
		}
	}
	if strings.HasSuffix(r.URL.Path, "/index.html") {
		target := "./"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}
	http.ServeContent(w, r, f.path, f.info.ModTime(), f)
}

// openServableFile permits roots mounted through symlinks and aliases whose
// targets stay within the root, just like resolveServableFile. After resolving
// those aliases it walks each canonical component using pinned directory
// handles, refusing substitutions with symlinks or nonregular files.
func openServableFile(root, target string) (*servableFile, bool) {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil || !pathWithinDir(rootAbs, targetAbs) {
		return nil, false
	}
	dir, err := openTreeDir(rootAbs)
	if err != nil {
		return nil, false
	}
	defer func() { dir.Close() }()
	rootInfo, err := dir.root.Stat(".")
	if err != nil {
		return nil, false
	}
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return nil, false
	}
	realTarget, err := filepath.EvalSymlinks(targetAbs)
	if err != nil || !pathWithinDir(realRoot, realTarget) {
		return nil, false
	}
	// A mount/root replacement during resolution must not change which
	// directory the resolved relative path is interpreted against.
	resolvedRootInfo, err := os.Stat(realRoot)
	if err != nil || !os.SameFile(rootInfo, resolvedRootInfo) {
		return nil, false
	}
	rel, err := filepath.Rel(realRoot, realTarget)
	if err != nil || rel == "." {
		return nil, false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, err := dir.openDir(part)
		if err != nil {
			return nil, false
		}
		dir.Close()
		dir = next
	}
	f, info, err := dir.openRegular(parts[len(parts)-1])
	if err != nil {
		return nil, false
	}
	return &servableFile{File: f, info: info, path: realTarget, relative: rel}, true
}

func pathWithinDir(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
