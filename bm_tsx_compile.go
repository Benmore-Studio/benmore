//go:build !cli

package main

// On-the-fly TSX/TS → JS compilation via embedded esbuild.
//
// Goal: the agent writes static/index.tsx, the HTML references
// /static/index.js, the framework intercepts the request, transpiles
// the .tsx counterpart with esbuild, serves the JS. No build step
// the agent runs; no /dist/ directory; nothing to .gitignore.
//
// Cache strategy: in-memory keyed by the entry's absolute path,
// invalidated against the mtime of EVERY source file esbuild pulled
// into the bundle - not just the entry. esbuild bundles the whole
// import graph (Bundle: true), so a cache keyed on the entry's mtime
// alone serves a stale bundle whenever an *imported* module changes
// (edit static/boards.tsx, app.tsx's mtime is untouched → false hit).
// We ask esbuild for a Metafile, record each input file's mtime at
// compile time, and treat the cache entry as fresh only while all of
// those inputs are unchanged. esbuild is fast (~10ms typical) but we
// still cache because Cloudflare hits us repeatedly for the same file.
// Bound the cache at ~512 entries so it doesn't grow forever on a
// long-running process; LRU eviction when full.
//
// 'bm' import: marked external so esbuild doesn't try to bundle it.
// The HTML uses an import map pointing 'bm' at /_internal/bm.js
// (the runtime SDK file). Compiled output keeps `import * as bm from 'bm'`
// as a bare specifier; the browser resolves via the map.
//
// Errors: esbuild diagnostics are returned as a JS module that throws
// on load, so the agent sees a clear console error in the browser
// AND a 200 OK that doesn't break SPA bootstrapping.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

// tsxCacheEntry is one compiled-output blob plus the mtime of every
// source file that went into the bundle (entry + all bundled imports),
// keyed by absolute path. The entry is fresh only while all of those
// inputs still have the recorded mtime - see tsxCacheEntryFresh.
type tsxCacheEntry struct {
	body   []byte
	inputs map[string]time.Time // absolute source path → mtime at compile time
	when   time.Time            // for LRU
}

// tsxCacheEntryFresh reports whether every source file that fed the
// cached bundle is still present and unchanged. A removed file or any
// mtime delta means the bundle must be recompiled. An entry with no
// recorded inputs (defensive: a metafile parse that yielded nothing)
// is treated as stale so we never serve a bundle we can't validate.
func tsxCacheEntryFresh(entry *tsxCacheEntry) bool {
	if entry == nil || len(entry.inputs) == 0 {
		return false
	}
	for path, mt := range entry.inputs {
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().Equal(mt) {
			return false
		}
	}
	return true
}

var (
	tsxCacheMu sync.RWMutex
	tsxCache   = map[string]*tsxCacheEntry{} // key: absolute path to .tsx
)

const tsxCacheLimit = 512

// compileTSXOrTS reads `srcPath` (must end in .tsx or .ts), bundles
// it with esbuild, and returns the JS output. `'bm'` is treated as
// an external - the browser resolves it via an import map. Imports
// of other local .tsx/.ts files are recursively bundled into the
// same output.
func compileTSXOrTS(srcPath string) ([]byte, error) {
	info, err := os.Stat(srcPath)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	entryMtime := info.ModTime()

	tsxCacheMu.RLock()
	if entry, ok := tsxCache[srcPath]; ok && tsxCacheEntryFresh(entry) {
		entry.when = time.Now()
		body := entry.body
		tsxCacheMu.RUnlock()
		return body, nil
	}
	tsxCacheMu.RUnlock()

	// esbuild reports metafile input paths relative to its working
	// directory. Pin it to the entry's directory so we can resolve those
	// paths back to absolute on-disk locations deterministically,
	// regardless of the host process's cwd.
	absWorkingDir := filepath.Dir(srcPath)

	// Compile. Format: ESM (so the agent writes modern code), target
	// ES2020 (every modern browser; preserves async/await + optional
	// chaining unchanged). 'bm' is external - runtime import-map
	// resolves it to /_internal/bm.js. Metafile is requested so we can
	// invalidate the cache against the whole import graph, not just the
	// entry file.
	result := esbuild.Build(esbuild.BuildOptions{
		EntryPoints:   []string{srcPath},
		AbsWorkingDir: absWorkingDir,
		Metafile:      true,
		Bundle:        true,
		Format:        esbuild.FormatESModule,
		Target:        esbuild.ES2020,
		// JSXAutomatic uses the modern transform that imports `jsx` from
		// "react/jsx-runtime" (or whatever the agent's tsconfig sets as
		// jsxImportSource). For now we treat JSX as a syntax-only
		// feature - agents pulling in a renderer (Preact/React/HTMX
		// alternative) will provide the runtime. Most demos won't need
		// JSX at all; plain TSX without <Tag/> elements just gives them
		// types + autocomplete.
		JSX: esbuild.JSXAutomatic,
		// External 'bm' + 'sdui' - resolved at runtime via the HTML's
		// import map (both injected/served by the framework). Left as bare
		// specifiers so esbuild doesn't try to bundle them from disk.
		External: []string{"bm", "sdui"},
		Loader: map[string]esbuild.Loader{
			".tsx": esbuild.LoaderTSX,
			".ts":  esbuild.LoaderTS,
			".jsx": esbuild.LoaderJSX,
			".js":  esbuild.LoaderJS,
			".css": esbuild.LoaderCSS,
			// .png / .svg / etc. are intentionally NOT loaders here.
			// `LoaderFile` would need an Outdir which conflicts with
			// our in-memory Write:false model. If the agent wants to
			// embed an image, they reference it as /static/foo.png
			// directly (same-origin) - esbuild doesn't need to know.
		},
		Write:         false,
		Sourcemap:     esbuild.SourceMapInline,
		LegalComments: esbuild.LegalCommentsNone,
		Platform:      esbuild.PlatformBrowser,
		LogLevel:      esbuild.LogLevelSilent,
	})

	if len(result.Errors) > 0 {
		// Emit a JS module that throws so the agent sees the error in
		// the browser console immediately. Far easier to diagnose than
		// a silent 500.
		var msg strings.Builder
		for _, e := range result.Errors {
			loc := ""
			if e.Location != nil {
				loc = fmt.Sprintf("%s:%d:%d ", filepath.Base(e.Location.File), e.Location.Line, e.Location.Column)
			}
			fmt.Fprintf(&msg, "%s%s\n", loc, e.Text)
		}
		js := fmt.Sprintf("throw new Error(%q);\n", "[bm-tsx-compile] "+msg.String())
		// Still cache the error result so we don't recompile a known-broken
		// file every request, but DON'T treat the build as successful. A
		// failed build has no reliable input graph, so key invalidation on
		// the entry file alone - the next edit to it triggers a retry, and
		// once it compiles we record the full graph.
		setTSXCache(srcPath, []byte(js), map[string]time.Time{srcPath: entryMtime})
		return []byte(js), nil
	}

	if len(result.OutputFiles) == 0 {
		return nil, fmt.Errorf("esbuild returned no output for %s", srcPath)
	}
	out := result.OutputFiles[0].Contents
	// Record the mtime of every source file esbuild bundled so an edit to
	// any imported module (not just the entry) invalidates this entry.
	inputs := bundleInputMtimes(result.Metafile, absWorkingDir)
	if len(inputs) == 0 {
		// Metafile parse yielded nothing (shouldn't happen) - fall back to
		// entry-only invalidation rather than caching an unvalidatable blob.
		inputs = map[string]time.Time{srcPath: entryMtime}
	}
	setTSXCache(srcPath, out, inputs)
	return out, nil
}

// bundleInputMtimes parses esbuild's metafile JSON and returns the
// absolute path → current mtime of every source file that fed the
// bundle. Metafile input keys are relative to absWorkingDir (the dir we
// pinned on the build); we resolve them back to absolute and stat each.
// Files that vanish between build and stat are skipped - a missing input
// will simply make the entry look stale on the next freshness check,
// forcing a recompile. The external 'bm' specifier never appears here
// because esbuild doesn't resolve externals to files.
func bundleInputMtimes(metafile, absWorkingDir string) map[string]time.Time {
	if metafile == "" {
		return nil
	}
	var meta struct {
		Inputs map[string]json.RawMessage `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(metafile), &meta); err != nil {
		return nil
	}
	inputs := make(map[string]time.Time, len(meta.Inputs))
	for rel := range meta.Inputs {
		abs := rel
		if !filepath.IsAbs(abs) {
			abs = filepath.Clean(filepath.Join(absWorkingDir, rel))
		}
		if st, err := os.Stat(abs); err == nil {
			inputs[abs] = st.ModTime()
		}
	}
	return inputs
}

func setTSXCache(key string, body []byte, inputs map[string]time.Time) {
	tsxCacheMu.Lock()
	defer tsxCacheMu.Unlock()
	if len(tsxCache) >= tsxCacheLimit {
		// LRU evict: drop the oldest 16 entries to amortize.
		evictTSXCacheLocked(16)
	}
	tsxCache[key] = &tsxCacheEntry{body: body, inputs: inputs, when: time.Now()}
}

// evictTSXCacheLocked drops the N least-recently-used entries.
// Caller must hold tsxCacheMu write-locked.
func evictTSXCacheLocked(n int) {
	type kt struct {
		key string
		t   time.Time
	}
	all := make([]kt, 0, len(tsxCache))
	for k, v := range tsxCache {
		all = append(all, kt{k, v.when})
	}
	// Partial selection - find the n oldest. For small n this is faster
	// than a full sort.
	for i := 0; i < n && i < len(all); i++ {
		oldestIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j].t.Before(all[oldestIdx].t) {
				oldestIdx = j
			}
		}
		all[i], all[oldestIdx] = all[oldestIdx], all[i]
		delete(tsxCache, all[i].key)
	}
}

// resolveTSXSource maps an incoming `/static/<rel>` request to a .tsx
// or .ts source file in `<appDir>/static/`. Returns the absolute
// source path, or "" when no compilable source exists for this URL.
//
// Mapping rules:
//
//	/static/index.js   → static/index.tsx | static/index.ts | static/index.jsx
//	/static/foo.js     → static/foo.tsx   | …
//	/static/a/b.js     → static/a/b.tsx   | …
//
// Only `.js` URLs trigger compilation; CSS/PNG/etc still resolve to the
// real file via the normal static handler.
func resolveTSXSource(appDir, urlRel string) string {
	if !strings.HasSuffix(urlRel, ".js") {
		return ""
	}
	stem := strings.TrimSuffix(urlRel, ".js")
	candidates := []string{stem + ".tsx", stem + ".ts", stem + ".jsx"}
	staticRoot := filepath.Join(appDir, "static")
	for _, c := range candidates {
		full := filepath.Join(staticRoot, c)
		if resolved, ok := resolveServableFile(staticRoot, full); ok {
			return resolved
		}
	}
	return ""
}

// serveTSXIfPresent returns true when the request was handled here
// (compiled + served). False means the caller should fall through to
// the normal static-file handler.
//
// Cache strategy (v2.7.28+): strong ETag based on the compiled output's
// content hash + Cache-Control: no-cache, must-revalidate. This tells
// every cache in the path (browser, Cloudflare, intermediaries) that
// they may store the body BUT must always revalidate before serving.
// Each request becomes a conditional GET - If-None-Match: <etag> →
// 304 Not Modified when nothing changed (a ~50 byte response). When
// the agent edits a .tsx and pushes, the very next request gets
// fresh JS with no manual cache-bust dance.
//
// Pre-v2.7.28 we set `max-age=300` and trusted nobody to override it,
// but Cloudflare's edge bumped it to 3600 in practice - meaning code
// changes took up to an hour to reach users, even after a deploy +
// hard refresh. The ETag path bypasses that entirely because CF
// honours strong ETags for revalidation.
func serveTSXIfPresent(w http.ResponseWriter, r *http.Request, app *App, urlRel string) bool {
	src := resolveTSXSource(app.Dir, urlRel)
	if src == "" {
		return false
	}
	body, err := compileTSXOrTS(src)
	if err != nil {
		http.Error(w, "esbuild: "+err.Error(), http.StatusInternalServerError)
		return true
	}

	// Strong ETag = sha256(compiled body)[:16] in hex. Quoted per RFC 7232
	// to mark it strong (unquoted/W/ would be a weak ETag, which CF
	// treats more cautiously).
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`

	if match := r.Header.Get("If-None-Match"); match != "" {
		// Honour either an exact match (strong) or a weak-tag equivalent
		// (CF sometimes downgrades strong → weak in transit).
		for _, candidate := range strings.Split(match, ",") {
			c := strings.TrimSpace(candidate)
			if c == etag || c == "W/"+etag {
				setRevalidateCacheHeaders(w)
				w.Header().Set("ETag", etag)
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("ETag", etag)
	setRevalidateCacheHeaders(w)
	w.Write(body)
	return true
}

// setRevalidateCacheHeaders writes a header trio that defeats Cloudflare's
// edge-side caching while still allowing browser ETag revalidation:
//
//   - Cache-Control: private - browsers cache, CDNs MUST NOT.
//   - CDN-Cache-Control: no-store - explicit signal to CDNs (RFC 9213).
//   - Cloudflare-CDN-Cache-Control: no-store - Cloudflare-specific
//     override that wins over the dashboard's Browser Cache TTL setting.
//
// Net effect: every request hits origin, which serves either 200 with
// fresh JS (when the .tsx changed) or 304 Not Modified (when it didn't).
// Latency cost is minimal because we cache the compiled output in-process.
// This is the same pattern the type generator uses for /_internal/bm.d.ts
// (which had the same "stale code after deploy" symptom pre-typed-system).
func setRevalidateCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
