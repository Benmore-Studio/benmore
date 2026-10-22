package main

import (
	"path/filepath"
	"strings"
)

// appPathProtected reports whether rel (relative to an app dir) is a
// framework-owned or secret-bearing path that no file tool may touch.
func appPathProtected(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(rel, "/")))
	if rel == "." || rel == "" {
		return false
	}
	segs := strings.Split(rel, "/")
	for _, seg := range segs {
		switch strings.ToLower(seg) {
		case ".git", ".benmore":
			return true
		}
	}
	base := strings.ToLower(segs[len(segs)-1])
	switch base {
	case "env.yaml", "secrets.yaml", ".env", ".gitmodules":
		return true
	}
	if strings.HasPrefix(base, "data.db") || strings.HasPrefix(base, ".env.") ||
		strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") {
		return true
	}
	return false
}
