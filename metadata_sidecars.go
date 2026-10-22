package main

import (
	"path/filepath"
	"strings"
)

// isMetadataSidecar reports whether a file name is a desktop-metadata
// artifact rather than app content: a macOS AppleDouble sidecar
// (`._index.html`), a Finder `.DS_Store`, or a Windows `Thumbs.db`.
//
// Why this exists: tar on macOS stores extended attributes as `._<name>`
// entries, and Linux extracts them as real files. Because pages are
// discovered by filename, a `._docs.html` sidecar became a live `/._docs`
// route and a sitemap URL on the production website (twelve of them, plus
// twenty-nine more from the sync that removed those). The loader now treats
// such names as absent everywhere a filename turns into a route, partial, or
// servable asset, and the write-time validator refuses to create them.
func isMetadataSidecar(name string) bool {
	base := filepath.Base(filepath.ToSlash(name))
	if strings.HasPrefix(base, "._") {
		return true
	}
	switch strings.ToLower(base) {
	case ".ds_store", "thumbs.db", "desktop.ini":
		return true
	}
	return false
}

// pathHasMetadataSidecar reports whether any component of a slash- or
// OS-separated relative path is a metadata sidecar, so a request such as
// `/static/partials/._nav.html` is refused as a whole.
func pathHasMetadataSidecar(rel string) bool {
	for _, part := range strings.FieldsFunc(filepath.ToSlash(rel), func(r rune) bool { return r == '/' }) {
		if isMetadataSidecar(part) {
			return true
		}
	}
	return false
}
