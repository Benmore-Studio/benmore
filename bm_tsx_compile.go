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
// /static/ is exempt from the request rate limit, so the hot path is kept
// cheap: the request path re-stats a bundle's inputs at most once per
// tsxFreshnessInterval, the ETag and a gzip copy are computed once per
// compile, concurrent misses share one build, and builds take a slot from a
// process-wide budget (tsxCompileSlots).
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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

// tsxCacheEntry is one compiled-output blob plus the mtime of every
// source file that went into the bundle (entry + all bundled imports),
// keyed by absolute path. The entry is fresh only while all of those
// inputs still have the recorded mtime - see tsxCacheEntryFresh.
type tsxCacheEntry struct {
	body    []byte
	inputs  map[string]time.Time // absolute source path → mtime at compile time
	when    atomic.Int64         // unix nanos of the last use, for LRU
	expires time.Time            // failed builds only: recompile after this

	// Serving form, computed once per compile instead of once per request.
	served *tsxServed
	// treeVersion is the static tree version (staticSourceTreeVersion, the
	// ?v= HTML emits) the bundle was built from: measured fresh before and
	// after the build and recorded only when both agree, and only for a real
	// bundle (never a compile-error module). A ?v= equal to it names exactly
	// this body, which is what makes the immutable response safe.
	treeVersion string
	compiled    time.Time
	checked     atomic.Int64 // unix nanos of the last full input check
}

// tsxServed is a compiled module ready to serve: its strong validator and,
// when it pays, a pre-compressed copy.
type tsxServed struct {
	body []byte
	etag string // strong ETag over body
	gz   []byte // gzip of body; nil when compression doesn't pay
}

func newTSXServed(body []byte) *tsxServed {
	sum := sha256.Sum256(body)
	s := &tsxServed{body: body, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	if len(body) >= 1024 {
		var buf bytes.Buffer
		if zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression); err == nil {
			_, werr := zw.Write(body)
			if cerr := zw.Close(); werr == nil && cerr == nil && buf.Len() < len(body) {
				s.gz = buf.Bytes()
			}
		}
	}
	return s
}

// tsxFreshnessInterval bounds how often a served bundle re-stats its inputs:
// at most once per interval per entry on the request path, so an edit is
// picked up within it. Direct compiles (compileTSXOrTS) always check.
var tsxFreshnessInterval = time.Second

// tsxCompileSlots bounds concurrent compiles process-wide: in-process esbuild
// builds and captured-compiler children alike. /static/ is exempt from the
// request rate limit, so cache misses must not fan out into unbounded builds.
var tsxCompileSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// tsxCompileRuns counts esbuild builds of browser modules (observability for
// tests).
var tsxCompileRuns atomic.Uint64

func acquireCompileSlot(ctx context.Context) (func(), error) {
	select {
	case tsxCompileSlots <- struct{}{}:
		return func() { <-tsxCompileSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tsxErrorCacheTTL bounds how long a failed build is reused. A failure's
// input graph is incomplete (an unresolved import names no file to watch),
// so the cached error also expires on its own.
var tsxErrorCacheTTL = 3 * time.Second

// tsxCacheEntryFresh reports whether every source file that fed the
// cached bundle is still present and unchanged. A removed file or any
// mtime delta means the bundle must be recompiled. An entry with no
// recorded inputs (defensive: a metafile parse that yielded nothing)
// is treated as stale so we never serve a bundle we can't validate.
func tsxCacheEntryFresh(entry *tsxCacheEntry) bool {
	if entry == nil || len(entry.inputs) == 0 {
		return false
	}
	if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
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

// tsxCacheEntryUsable is the request-path freshness check: the full input
// check, run at most once per tsxFreshnessInterval per entry.
func tsxCacheEntryUsable(entry *tsxCacheEntry, throttle bool) bool {
	if entry == nil || len(entry.inputs) == 0 {
		return false
	}
	if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
		return false
	}
	now := time.Now()
	if throttle && now.Sub(time.Unix(0, entry.checked.Load())) < tsxFreshnessInterval {
		return true
	}
	if !tsxCacheEntryFresh(entry) {
		return false
	}
	entry.checked.Store(now.UnixNano())
	return true
}

var (
	tsxCacheMu sync.RWMutex
	tsxCache   = map[string]*tsxCacheEntry{} // key: absolute path to .tsx

	// tsxInflight shares one compile among concurrent misses of an entry.
	tsxInflightMu sync.Mutex
	tsxInflight   = map[string]*tsxCompileCall{}
)

type tsxCompileCall struct {
	done  chan struct{}
	entry *tsxCacheEntry
	err   error
}

const tsxCacheLimit = 512

// compileTSXOrTS reads `srcPath` (must end in .tsx or .ts), bundles
// it with esbuild, and returns the JS output. `'bm'` is treated as
// an external - the browser resolves it via an import map. Imports
// of other local .tsx/.ts files are recursively bundled into the
// same output. Every bundled input must resolve inside staticRoot (the app's
// static/ dir): the output is public, so an import such as '../env.yaml'
// must never inline a server-side file into it.
func compileTSXOrTS(srcPath, staticRoot string) ([]byte, error) {
	return compileTSXOrTSContext(context.Background(), srcPath, staticRoot)
}

func compileTSXOrTSContext(ctx context.Context, srcPath, staticRoot string) ([]byte, error) {
	entry, err := compileTSXEntry(ctx, srcPath, staticRoot, false, "")
	if err != nil {
		return nil, err
	}
	return entry.body, nil
}

// tsxCacheLookup returns the cached entry when it may be served: fresh
// (throttled on the request path) and, when wantTree is set, built from that
// tree version - unless it was compiled within the last tsxFreshnessInterval,
// which bounds the recompiles a ?v= for a newer tree can cause.
func tsxCacheLookup(srcPath string, throttle bool, wantTree string) *tsxCacheEntry {
	tsxCacheMu.RLock()
	entry := tsxCache[srcPath]
	tsxCacheMu.RUnlock()
	// A page that names a tree this entry wasn't built from has just seen
	// the tree change: check the inputs now rather than within the interval.
	if entry != nil && wantTree != "" && entry.treeVersion != wantTree {
		throttle = false
	}
	if !tsxCacheEntryUsable(entry, throttle) {
		return nil
	}
	if wantTree != "" && entry.treeVersion != wantTree && entry.expires.IsZero() &&
		time.Since(entry.compiled) >= tsxFreshnessInterval {
		return nil
	}
	entry.when.Store(time.Now().UnixNano())
	return entry
}

// compileTSXEntry returns the cache entry for srcPath, compiling on a miss.
// Concurrent misses share one compile, and compiles take a process-wide slot.
// throttle selects the request-path freshness check; wantTree (a ?v= that
// matches the current tree) asks for a bundle built from that tree.
func compileTSXEntry(ctx context.Context, srcPath, staticRoot string, throttle bool, wantTree string) (*tsxCacheEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if entry := tsxCacheLookup(srcPath, throttle, wantTree); entry != nil {
		return entry, nil
	}
	tsxInflightMu.Lock()
	call := tsxInflight[srcPath]
	if call == nil {
		call = &tsxCompileCall{done: make(chan struct{})}
		tsxInflight[srcPath] = call
		// The shared compile outlives a departing first requester; esbuild
		// builds of a static/ tree are short and the slot bounds how many run.
		go func(ctx context.Context) {
			defer func() {
				tsxInflightMu.Lock()
				delete(tsxInflight, srcPath)
				tsxInflightMu.Unlock()
				close(call.done)
			}()
			call.entry, call.err = compileTSXFresh(ctx, srcPath, staticRoot, throttle)
		}(context.WithoutCancel(ctx))
	}
	tsxInflightMu.Unlock()
	select {
	case <-call.done:
		return call.entry, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// compileTSXFresh builds srcPath and stores the entry. A request-path build
// (trackTree) also records the tree version it was built from; direct
// compiles (tests, the captured-compiler child) never serve a ?v= URL.
func compileTSXFresh(ctx context.Context, srcPath, staticRoot string, trackTree bool) (*tsxCacheEntry, error) {
	release, err := acquireCompileSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	tsxCompileRuns.Add(1)
	treeBefore := ""
	if trackTree {
		treeBefore, _ = staticSourceTreeVersion(staticRoot)
	}
	built, err := compileTSXBuild(ctx, srcPath, staticRoot)
	if err != nil {
		return nil, err
	}
	entry := &tsxCacheEntry{body: built.body, inputs: built.inputs, expires: built.expires,
		served: newTSXServed(built.body), compiled: time.Now()}
	entry.when.Store(entry.compiled.UnixNano())
	entry.checked.Store(entry.compiled.UnixNano())
	if built.bundle && treeBefore != "" {
		if treeAfter, _ := staticSourceTreeVersion(staticRoot); treeAfter == treeBefore {
			entry.treeVersion = treeBefore
		}
	}
	storeTSXEntry(srcPath, entry)
	return entry, nil
}

// tsxBuildResult is one esbuild run's outcome.
type tsxBuildResult struct {
	body    []byte
	inputs  map[string]time.Time
	expires time.Time // failed builds: reuse only until then
	bundle  bool      // a real bundle, not a module that throws a build error
}

func compileTSXBuild(ctx context.Context, srcPath, staticRoot string) (tsxBuildResult, error) {
	info, err := os.Stat(srcPath)
	if err != nil {
		return tsxBuildResult{}, fmt.Errorf("stat: %w", err)
	}
	entryMtime := info.ModTime()

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
	result, buildErr := buildAppSources(ctx, esbuild.BuildOptions{
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
		// Refuse, before esbuild reads it, any file outside static/: the
		// output is public, a failed build's error text included
		// (bundle_containment.go).
		Plugins: []esbuild.Plugin{staticContainmentPlugin(staticRoot)},
	})

	if buildErr != nil {
		return tsxBuildResult{}, buildErr
	}
	if len(result.Errors) > 0 {
		// Emit a JS module that throws so the agent sees the error in
		// the browser console immediately. Far easier to diagnose than
		// a silent 500. The module is public, so a message located in a
		// file outside static/ keeps neither its text nor its location.
		result.Errors = redactOutsideBuildMessages(result.Errors, staticRoot, absWorkingDir)
		var msg strings.Builder
		for _, e := range result.Errors {
			loc := ""
			if e.Location != nil {
				loc = fmt.Sprintf("%s:%d:%d ", filepath.Base(e.Location.File), e.Location.Line, e.Location.Column)
			}
			fmt.Fprintf(&msg, "%s%s\n", loc, e.Text)
		}
		js := fmt.Sprintf("throw new Error(%q);\n", "[bm-tsx-compile] "+msg.String())
		// Cache the error briefly so a broken page doesn't recompile on every
		// request, keyed on the entry, whatever the metafile saw, and every
		// file an error points at: fixing an imported module clears it at
		// once. An unresolved import names nothing to watch, so the entry
		// also expires after tsxErrorCacheTTL.
		inputs := bundleInputMtimes(result.Metafile, absWorkingDir)
		if inputs == nil {
			inputs = map[string]time.Time{}
		}
		inputs[srcPath] = entryMtime
		for _, e := range result.Errors {
			if e.Location == nil || e.Location.File == "" {
				continue
			}
			file := e.Location.File
			if !filepath.IsAbs(file) {
				file = filepath.Join(absWorkingDir, file)
			}
			if st, err := os.Stat(file); err == nil {
				inputs[filepath.Clean(file)] = st.ModTime()
			}
		}
		return tsxBuildResult{body: []byte(js), inputs: inputs, expires: time.Now().Add(tsxErrorCacheTTL)}, nil
	}

	if len(result.OutputFiles) == 0 {
		return tsxBuildResult{}, fmt.Errorf("esbuild returned no output for %s", srcPath)
	}
	out := result.OutputFiles[0].Contents
	// Record the mtime of every source file esbuild bundled so an edit to
	// any imported module (not just the entry) invalidates this entry.
	inputs := bundleInputMtimes(result.Metafile, absWorkingDir)
	if outside := bundleInputOutside(inputs, staticRoot); outside != "" {
		js := fmt.Sprintf("throw new Error(%q);\n", "[bm-tsx-compile] "+filepath.Base(srcPath)+" imports a file outside static/ ("+filepath.Base(outside)+"); browser bundles may only import files inside the app's static/ directory")
		return tsxBuildResult{body: []byte(js), inputs: inputs}, nil
	}
	if len(inputs) == 0 {
		// Metafile parse yielded nothing (shouldn't happen) - fall back to
		// entry-only invalidation rather than caching an unvalidatable blob.
		inputs = map[string]time.Time{srcPath: entryMtime}
	}
	return tsxBuildResult{body: out, inputs: inputs, bundle: true}, nil
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

// bundleInputOutside returns the first bundled input that does not resolve
// (symlinks followed) inside root, or "" when all of them do.
func bundleInputOutside(inputs map[string]time.Time, root string) string {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootReal = filepath.Clean(root)
	}
	for path := range inputs {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path
		}
		rel, err := filepath.Rel(rootReal, real)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return path
		}
	}
	return ""
}

func storeTSXEntry(key string, entry *tsxCacheEntry) {
	tsxCacheMu.Lock()
	defer tsxCacheMu.Unlock()
	if _, replacing := tsxCache[key]; !replacing && len(tsxCache) >= tsxCacheLimit {
		// LRU evict: drop the oldest 16 entries to amortize.
		evictTSXCacheLocked(16)
	}
	tsxCache[key] = entry
}

// evictTSXCacheLocked drops the N least-recently-used entries.
// Caller must hold tsxCacheMu write-locked.
func evictTSXCacheLocked(n int) {
	type kt struct {
		key string
		t   int64
	}
	all := make([]kt, 0, len(tsxCache))
	for k, v := range tsxCache {
		all = append(all, kt{k, v.when.Load()})
	}
	// Partial selection - find the n oldest. For small n this is faster
	// than a full sort.
	for i := 0; i < n && i < len(all); i++ {
		oldestIdx := i
		for j := i + 1; j < len(all); j++ {
			if all[j].t < all[oldestIdx].t {
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
	for _, c := range candidates {
		staticRoot := filepath.Join(appDir, "static")
		full := filepath.Join(staticRoot, c)
		// Resolve symlinks + confirm containment within static/ (a .tsx source
		// symlinked outside static/ must not be readable). See
		// static_file_security.go.
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
//
// The one exception is the versioned URL HTML already emits
// (/static/app.js?v=<tree version>, versionStaticAssets): when ?v= is the
// tree version the served bundle was built from, the URL names exactly these
// bytes, so it is served `public, max-age=31536000, immutable`. Any other ?v=
// (stale, future, forged) gets the revalidated response above.
//
// The ETag and a gzip copy are computed once per compile and kept with the
// cached bundle; a client that accepts gzip gets the compressed bytes
// directly, unless an outer layer has already taken over the encoding.
func serveTSXIfPresent(w http.ResponseWriter, r *http.Request, app *App, urlRel string) bool {
	app.mu.RLock()
	manifest, sources := app.MCP, app.sourceFiles
	app.mu.RUnlock()
	if manifest != nil {
		name := filepath.Clean(urlRel)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) || pathHasMetadataSidecar(name) || !strings.HasSuffix(name, ".js") {
			return false
		}
		stem := strings.TrimSuffix(filepath.ToSlash(name), ".js")
		present := false
		for _, extension := range []string{".tsx", ".ts", ".jsx"} {
			if _, exists := sources["static/"+stem+extension]; exists {
				present = true
				break
			}
		}
		if !present {
			return false
		}
		served, found, err := compileCapturedBrowserAsset(r.Context(), sources, manifest.sourceHashes, urlRel)
		if !found {
			return false
		}
		if r.Context().Err() != nil {
			return true
		}
		if err != nil {
			serverError(w, r, app, "static "+urlRel, err, "esbuild: build unavailable")
			return true
		}
		writeTSXAsset(w, r, served, false)
		return true
	}

	src := resolveTSXSource(app.Dir, urlRel)
	if src == "" {
		return false
	}
	if r.Context().Err() != nil {
		return true
	}
	staticRoot := filepath.Join(app.Dir, "static")
	entry, err := compileTSXEntry(r.Context(), src, staticRoot, true, "")
	version := r.URL.Query().Get("v")
	if err == nil && version != "" && entry.treeVersion != version && entry.expires.IsZero() {
		// The page names a tree this bundle wasn't built from. If that is the
		// current tree (an edit outside the bundle's inputs, or one the
		// throttled check hasn't seen yet), rebuild so the URL can be cached.
		if current, ok := cachedStaticTreeVersion(staticRoot); ok && current == version {
			entry, err = compileTSXEntry(r.Context(), src, staticRoot, true, version)
		}
	}
	if err != nil {
		serverError(w, r, app, "static "+urlRel, err, "esbuild: build unavailable")
		return true
	}
	if r.Context().Err() != nil {
		return true
	}
	writeTSXAsset(w, r, entry.served, version != "" && entry.treeVersion == version)
	return true
}

// writeTSXAsset writes a compiled module: 304 on a matching validator,
// otherwise the body, gzip-encoded when the client accepts it.
func writeTSXAsset(w http.ResponseWriter, r *http.Request, s *tsxServed, immutable bool) {
	h := w.Header()
	if immutable {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		setRevalidateCacheHeaders(w)
	}
	h.Add("Vary", "Accept-Encoding")
	// An outer layer that already set Content-Encoding is compressing the
	// response itself; hand it the identity bytes.
	gz := s.gz != nil && h.Get("Content-Encoding") == "" && acceptsGzip(r)
	etag := s.etag
	if gz {
		// A distinct strong validator per representation (RFC 9110 8.8.3).
		etag = strings.TrimSuffix(s.etag, `"`) + `-gz"`
	}
	h.Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" {
		// Honour either representation's tag, strong or weak (CF sometimes
		// downgrades strong → weak in transit).
		gzTag := strings.TrimSuffix(s.etag, `"`) + `-gz"`
		for _, candidate := range strings.Split(match, ",") {
			c := strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
			if c == s.etag || c == gzTag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	h.Set("Content-Type", "application/javascript; charset=utf-8")
	body := s.body
	if gz {
		h.Set("Content-Encoding", "gzip")
		body = s.gz
	}
	if h.Get("Content-Encoding") == "" || gz {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// setRevalidateCacheHeaders asks browsers to revalidate stored modules and
// instructs shared caches not to store them:
//
//   - Cache-Control: private, no-cache, must-revalidate - a browser may store
//     the body but must revalidate (If-None-Match → 304) before each use;
//     shared caches must not store it.
//   - CDN-Cache-Control: no-store - explicit signal to CDNs (RFC 9213).
//   - Cloudflare-CDN-Cache-Control: no-store - Cloudflare-specific
//     no-store directive.
//
// CDN cache rules may override these origin headers; deployment must verify
// the effective cache policy and separately remove any old cached objects.
// When a request reaches origin, it serves either current JS or a matching 304.
// The browser directive used to include no-store too, which forbade the
// stored copy that a 304 refers to, so every page view re-downloaded the
// whole bundle. No-cache requires revalidation when clients honor the policy;
// generated private metadata uses its own stricter no-store directives.
func setRevalidateCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-cache, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}
