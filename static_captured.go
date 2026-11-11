//go:build !cli

package main

// Static files of an app whose reviewed mcp.yaml is loaded.
//
// Such an app serves the source generation captured when it loaded (the bytes
// the review's digests were checked against), never the directory as it is
// now: a file edited after the review, or left behind by a refused reload,
// must not reach a browser as if it were the reviewed app. Everything here
// reads that capture and nothing else.
//
// Two things follow from serving a fixed set of bytes:
//
//   - A path form the directory-backed handlers offer has to be offered from
//     the capture too, or it answers 404 the moment a manifest is loaded. The
//     URL-root alias of static/ (/assets/app.js for static/assets/app.js) was
//     lost that way.
//   - A version derived from the capture names bytes that cannot change while
//     that capture is served, and a new capture gets a new version, so the
//     ?v= URL pages carry can be cached for a year exactly as it is for an
//     app without a manifest. The version must come from the capture: the
//     directory's hash names bytes this app is not serving.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// capturedStaticSnapshot returns the loaded reviewed manifest and the source
// generation published with it (reloadAppConfigStaged replaces both under one
// lock); a nil manifest means the app serves its directory.
func capturedStaticSnapshot(app *App) (*AppMCPManifest, map[string][]byte) {
	if app == nil {
		return nil, nil
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.MCP, app.sourceFiles
}

// capturedStaticKey is the capture key of static/<rel>. The capture also holds
// the app's other source trees, so rel must stay inside static/; metadata
// sidecars are never app content.
func capturedStaticKey(rel string) (string, bool) {
	name := filepath.Clean(filepath.FromSlash(rel))
	if name == "." || !filepath.IsLocal(name) || pathHasMetadataSidecar(name) {
		return "", false
	}
	return "static/" + filepath.ToSlash(name), true
}

// capturedSourceVersion is the version of a reviewed generation as a whole:
// every captured path with its digest, and the framework release. It is the
// ?v= of the generation's /static/*.js URLs. A script may be a bundle, and a
// bundle is built from the staged generation (its imports, plus the
// tsconfig.json and package.json the compiler reads beside static/), by this
// release's compiler; anything narrower than the whole set could leave an
// input out and let one URL name two different bundles.
func capturedSourceVersion(hashes map[string]string) string {
	if len(hashes) == 0 {
		return ""
	}
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	// The label keeps a captured version from ever equalling the version an
	// app without a manifest computes over the same files
	// (staticSourceTreeVersion): the two are built by different code paths.
	fmt.Fprintf(h, "captured\x00%s\x00", version)
	for _, name := range names {
		fmt.Fprintf(h, "%s\x00%s\n", name, hashes[name])
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// capturedFileVersion is the ?v= that names data, the captured bytes at key.
//
// Any file but a script is named by its own content: the first 12 hex digits
// of its SHA-256, the same value an app without a manifest writes for the same
// bytes. A script carries the generation's version, and only while the digest
// the generation recorded for it is the digest of data, so the version is
// never attached to bytes it was not computed over.
func capturedFileVersion(manifest *AppMCPManifest, key string, data []byte) (string, bool) {
	own := strings.Trim(capturedAssetETag(data), `"`) // 16 hex digits of the SHA-256
	if !strings.HasSuffix(key, ".js") {
		return own[:12], true
	}
	if manifest == nil || manifest.sourceVersion == "" || !strings.HasPrefix(manifest.sourceHashes[key], own) {
		return "", false
	}
	return manifest.sourceVersion, true
}

// capturedStaticVersion is the ?v= pages carry for /static/<rel> in a reviewed
// generation; false when the generation serves nothing there, so a reference
// to a missing file is left as written.
func capturedStaticVersion(manifest *AppMCPManifest, sources map[string][]byte, rel string) (string, bool) {
	key, ok := capturedStaticKey(rel)
	if !ok || manifest == nil {
		return "", false
	}
	if data := sources[key]; data != nil {
		return capturedFileVersion(manifest, key, data)
	}
	// /static/app.js compiled from static/app.tsx (serveTSXIfPresent).
	if stem, isScript := strings.CutSuffix(key, ".js"); isScript && manifest.sourceVersion != "" {
		for _, ext := range []string{".tsx", ".ts", ".jsx"} {
			if sources[stem+ext] != nil {
				return manifest.sourceVersion, true
			}
		}
	}
	return "", false
}

// capturedVersionRequested reports a request whose query is exactly
// ?v=<version>: the URL the framework writes into pages, nothing appended.
func capturedVersionRequested(r *http.Request, version string) bool {
	return version != "" && r.URL.RawQuery == "v="+version
}

// capturedBundleImmutable reports whether a bundle compiled from the reviewed
// generation may be cached for a year: the request names that generation's
// version, and the body is a real bundle. A build that failed is served as a
// module that throws the compiler's message, which is never pinned.
func capturedBundleImmutable(r *http.Request, manifest *AppMCPManifest, body []byte) bool {
	return manifest != nil && capturedVersionRequested(r, manifest.sourceVersion) &&
		!bytes.HasPrefix(body, []byte(`throw new Error("[bm-tsx-compile]`))
}

// serveCapturedStatic answers a request for static/<requested> with the
// reviewed generation's bytes. It reports false, with nothing written, when
// the generation holds no such file.
//
// The answer carries a strong content validator. A request for the versioned
// URL (capturedFileVersion) is cached for a year; every other request keeps
// the revalidated answer (setRevalidateCacheHeaders: the browser stores the
// bytes and asks again before each use, CDNs do not store them), so a page
// view costs a 304 rather than a download and a new generation's different
// bytes are seen on the very next load.
func serveCapturedStatic(w http.ResponseWriter, r *http.Request, manifest *AppMCPManifest, sources map[string][]byte, requested string) bool {
	key, ok := capturedStaticKey(requested)
	if !ok || manifest == nil {
		return false
	}
	data := sources[key]
	if data == nil {
		return false
	}
	w.Header().Set("ETag", capturedAssetETag(data))
	if ver, ok := capturedFileVersion(manifest, key, data); ok && capturedVersionRequested(r, ver) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		setRevalidateCacheHeaders(w)
	}
	http.ServeContent(w, r, filepath.Base(key), time.Time{}, bytes.NewReader(data))
	return true
}

// serveCapturedRootFile serves /<rel> as the URL-root alias of the reviewed
// generation's static/<rel>: the same bytes and headers /static/<rel> answers
// with, under the same refusals (script source and `run: compute` modules are
// not browser assets). Compiled bundles stay under /static/ only, as they do
// for an app without a manifest.
func serveCapturedRootFile(w http.ResponseWriter, r *http.Request, app *App, rel string) bool {
	if staticServerSource(app, rel) {
		return false
	}
	manifest, sources := capturedStaticSnapshot(app)
	return serveCapturedStatic(w, r, manifest, sources, rel)
}
