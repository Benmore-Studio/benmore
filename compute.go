//go:build !cli

package main

// compute.go - server-side JS execution for pure-function algorithms
// that don't fit SQL. New in v2.7.67.
//
// Use case: financial pro-forma engines (IRR, goal-seek), scoring
// algorithms, simulation passes, anything iterative or with per-row
// math that flows / SQL can't express. The agent writes the algorithm
// ONCE as a TypeScript module in static/, imports it from feature TSX
// for client-side compute, and references it from flows.yaml for
// server-side compute via `run: compute`.
//
//   - id: irr
//     run: compute
//     module: par-engine            # static/par-engine.ts (or .js)
//     function: irrForInputs        # named export of that module
//     args: ${{ steps.forecast.outputs.first }}
//
// Implementation
//   - TS modules are compiled to ES5 IIFE via the framework's
//     embedded esbuild (same dep as the browser TSX path). Output
//     is bundle-shape: a single self-contained script that defines
//     a module.exports-like object. We capture that object via a
//     small wrapper and call the requested named function.
//   - Execution happens in github.com/dop251/goja - a Go-native
//     ECMAScript engine. No V8, no Node, no network dep.
//   - Every invocation runs in a FRESH Runtime (no shared state
//     between calls). Cheap to create - sub-millisecond. Prevents
//     accidental state leaks across requests.
//   - Compilation is cached per (app, module) and checked against each
//     bundled source's content hash; a stat stamp (size, mtime, ctime,
//     inode) stands in for re-hashing once a file has been stable for a
//     second. Recompile is automatic on edit. Reviewed (MCP) generations
//     are cached by module name + reviewed source hashes.
//   - 5-second wall-clock timeout per invocation via goja.Interrupt.
//     Caller can override via Step.Timeout. CPU loops break at
//     statement boundaries.
//   - Resource bounds (M-10): input/output payloads are size-capped and
//     recursion depth is bounded (see the Resource bounds block below).
//     NOTE: goja exposes no hard heap cap, so a module that allocates a
//     huge structure internally can still OOM the process before the
//     wall-clock interrupt fires. This is a documented limitation, not a
//     fully sandboxed memory guarantee.
//
// Sandbox
//   - No fetch, no XMLHttpRequest, no fs, no process, no require -
//     goja's default is a bare ECMAScript runtime. Compute modules
//     are PURE FUNCTIONS only.
//   - eval and new Function are disabled - even though goja allows
//     them by default, we strip both from the global so a compromised
//     module can't escape, and seal the `constructor` of every function
//     prototype (Function, AsyncFunction, GeneratorFunction,
//     AsyncGeneratorFunction) so `(() => {}).constructor` can't reach them.
//   - At most 2 x NumCPU compute executions run at once per process.
//   - No timers (setTimeout / setInterval) - there's nothing to
//     schedule against since we exit as soon as the function returns.
//   - The Runtime has no access to the per-app DB. Compute is for
//     PURE algorithms; if you need data, FETCH it via a sql step
//     before the compute step and pass it in as args.
//   - Import containment: esbuild bundles the module's import graph, so a
//     module could otherwise `import x from '../env.yaml'` (secrets) or
//     `../../otherapp/data.db` (cross-tenant on a shared FS) and have those
//     bytes inlined into the returned value. CompileComputeModule REJECTS
//     any bundled input that resolves outside the app's static/ dir - the
//     "no fs" boundary is enforced, not just documented.
//   - The result must be JSON-serialisable and within the output cap. A
//     function value or a cyclic object (which export from goja but fail
//     json.Marshal) is refused, so it can neither bypass the size cap nor
//     poison a downstream flow step that marshals the output.
//   - Caller bound: vm.Interrupt only fires between JS statements, NOT
//     inside a native Go call (built-ins, and regex via dlclark/regexp2,
//     which has no match timeout). Execution runs in its own goroutine and
//     the caller waits against the deadline, so a catastrophic-backtracking
//     regex returns a timeout to the caller instead of hanging the request.
//     RESIDUAL: the abandoned goroutine runs until the native call returns.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dlclark/regexp2"
	"github.com/dop251/goja"
)

// computeRegexMatchTimeout bounds one backtracking regex match. goja runs
// patterns RE2 can't express (lookaround, backreferences) on regexp2, whose
// default match timeout is unlimited, and vm.Interrupt can't stop a match in
// progress. With this bound the goroutine a timed-out compute call leaves
// behind ends shortly after its deadline; goja reports a timed-out match as
// no match. Only compute runs goja in this process.
const computeRegexMatchTimeout = 5 * time.Second

func init() { regexp2.DefaultMatchTimeout = computeRegexMatchTimeout }

// computeCacheEntry is a parsed goja program ready to invoke.
type computeCacheEntry struct {
	program   *goja.Program
	source    []byte // compiler child only; ordinary cache retains no duplicate source
	entryPath string
	// hashes maps every source file the bundle pulled in to its content
	// hash at compile time, so restored mtimes cannot serve stale code.
	hashes map[string]string
	// stamps holds each source's fileStamp taken just before it was read.
	// A cache hit whose files still carry a trusted, unchanged stamp skips
	// re-hashing them: a stat per file instead of reading and SHA-256ing
	// the whole import graph on every call. ctime is part of the stamp, so
	// an edit that restores the mtime still forces the content check.
	stamps map[string]fileStamp
}

var (
	computeCacheMu sync.RWMutex
	computeCache   = map[string]*computeCacheEntry{} // key = absolute source path
)

// ===== Resource bounds (M-10) =====
//
// LIMITATION: goja (this version) exposes NO heap/allocation cap - there
// is no Runtime.SetMemoryLimit and no per-allocation hook. A single
// pathological allocation inside the JS module (e.g. `new Array(1e9)`,
// or building one enormous string) can therefore OOM the per-app process
// BEFORE the wall-clock Interrupt fires, because the interrupt is only
// checked between statements / loop iterations, not mid-allocation. A
// hard memory cap is NOT achievable here without forking goja or running
// each invocation in a separate, cgroup/rlimit-constrained child process
// (a larger change tracked separately).
//
// What IS feasible, and is enforced below as defense-in-depth, are bounds
// on the things we control at the Go boundary plus a stack-depth cap:
//   - cap the SIZE of the args we marshal INTO the runtime (a huge input
//     is the most common way a caller blows up compute);
//   - cap the SIZE of the result we marshal OUT of the runtime;
//   - bound the call-stack depth so runaway recursion fails fast with a
//     RangeError instead of growing Go's stack unbounded.
//
// These do not stop a module that allocates internally without touching
// the boundary, but they remove the easy OOM vectors and make the limits
// explicit. The wall-clock timeout remains the backstop for CPU loops.
const (
	// cryptoComputeMaxInputBytes caps the JSON size of args passed into a
	// compute call. 8 MiB comfortably covers row/object payloads from a
	// preceding sql step while rejecting obviously abusive inputs.
	cryptoComputeMaxInputBytes = 8 << 20 // 8 MiB
	// cryptoComputeMaxOutputBytes caps the JSON size of the value a
	// compute function may return. Prevents a module from handing back a
	// multi-gigabyte structure that then has to be materialised in Go.
	cryptoComputeMaxOutputBytes = 16 << 20 // 16 MiB
	// cryptoComputeMaxCallStack bounds recursion depth. goja turns an
	// overflow into a catchable RangeError ("Maximum call stack size
	// exceeded") rather than letting recursion grow Go's stack until the
	// process dies.
	cryptoComputeMaxCallStack = 2000
)

// cryptoComputeWithinSize reports whether v, JSON-encoded, is at most
// limit bytes. Non-serialisable values (which json.Marshal rejects) are
// treated as within-limit here - they'll surface their own error later at
// the goja boundary; this guard is specifically about runaway SIZE.
func cryptoComputeWithinSize(v any, limit int) (int, bool) {
	if v == nil {
		return 0, true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return 0, true
	}
	return len(b), len(b) <= limit
}

// computeWrapperJS wraps the bundled module in an IIFE that exposes
// `__exports` after evaluation. esbuild emits CommonJS-shape code
// when format=CJS - `exports.foo = ...`. We capture `exports` into
// the wrapper-local name so the caller can pick out the named
// function without polluting the global namespace.
//
// The {{BODY}} sentinel is replaced with the compiled module source.
const computeWrapperJS = `var __exports = (function() {
  var module = { exports: {} };
  var exports = module.exports;
  // ----- compiled module -----
  {{BODY}}
  // ----- end compiled module -----
  return module.exports;
})();
`

// CompileComputeModule compiles a TS/JS module from disk for server-
// side execution. Cached by source content; recompiles when the entry
// or any imported file changes. Returns the parsed program.
//
// `modulePath` is the absolute file path (caller resolves the YAML
// `module:` name to a path under the app's static/ dir).
//
// `allowedRoot` is the app's static/ directory: every file esbuild pulls
// into the bundle MUST resolve inside it. `resolveComputeModulePath` only
// guards the ENTRY path; without this second check a compute module could
// `import x from '../env.yaml'` (or `../../otherapp/data.db`) and esbuild
// would inline that file's bytes into the returned value - reaching
// secrets / another tenant's files that the "pure function, no fs" sandbox
// exists to keep out. The containment is enforced against the metafile
// inputs (covers static + dynamic imports and CSS @import alike).
func CompileComputeModule(modulePath, allowedRoot string) (*goja.Program, error) {
	return compileComputeModule(modulePath, allowedRoot, nil)
}

// reviewedHashes, when present, binds both cache reuse and the exact bytes
// supplied to esbuild. A later disk digest check alone cannot exclude ABA edits.
func compileComputeModule(modulePath, allowedRoot string, reviewedHashes map[string]string) (*goja.Program, error) {
	return compileComputeModuleContext(context.Background(), modulePath, allowedRoot, reviewedHashes)
}

func compileComputeModuleContext(ctx context.Context, modulePath, allowedRoot string, reviewedHashes map[string]string) (*goja.Program, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var err error
	modulePath, err = filepath.Abs(modulePath)
	if err != nil {
		return nil, err
	}
	allowedRoot = containmentRoot(allowedRoot)
	reviewRoot := containmentRoot(filepath.Dir(allowedRoot))
	matchesReview := func(path, hash string) bool {
		if reviewedHashes == nil {
			return true
		}
		rel, err := filepath.Rel(reviewRoot, realPathForContainment(path))
		return err == nil && reviewedHashes[filepath.ToSlash(rel)] == hash
	}
	if _, err := os.Stat(modulePath); err != nil {
		return nil, fmt.Errorf("compute: stat %s: %w", filepath.Base(modulePath), err)
	}

	entryPath := realPathForContainment(modulePath)
	computeCacheMu.RLock()
	if entry, ok := computeCache[modulePath]; ok {
		// Fresh only if every bundled source still has its compile-time hash.
		fresh := entry.entryPath == entryPath && insideContainmentRoot(containmentRoot(allowedRoot), entryPath)
		for p, hash := range entry.hashes {
			var current string
			var err error
			if stamp, ok := entry.stamps[p]; ok && reviewedHashes == nil && capturedCompilerFiles == nil && stamp.trusted() {
				// Reviewed callers keep the full content check: their
				// cache reuse is bound to exact reviewed bytes.
				if now, ok := statFileStamp(p); ok && stamp.sameFile(now) {
					continue
				}
			}
			if capturedCompilerFiles != nil {
				contents, exists := capturedCompilerFiles[filepath.Clean(p)]
				if !exists {
					err = os.ErrNotExist
				} else {
					current = hashBytesSHA256([]byte(contents))
				}
			} else {
				current, err = hashFileSHA256(p)
			}
			if err != nil || current != hash || !matchesReview(p, hash) {
				fresh = false
				break
			}
		}
		if fresh {
			prog := entry.program
			computeCacheMu.RUnlock()
			return prog, nil
		}
	}
	computeCacheMu.RUnlock()

	// Hash the same byte strings supplied to esbuild, not files sampled after it.
	var sourceMu sync.Mutex
	hashes := map[string]string{}
	stamps := map[string]fileStamp{}
	snapshotPlugin := esbuild.Plugin{Name: "benmore-compute-source", Setup: func(build esbuild.PluginBuild) {
		build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "file"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
			if !insideContainmentRoot(containmentRoot(allowedRoot), args.Path) {
				return esbuild.OnLoadResult{}, errOutsideStatic
			}
			var data []byte
			var stamp fileStamp
			var stamped bool
			if capturedCompilerFiles != nil {
				contents, exists := capturedCompilerFiles[filepath.Clean(args.Path)]
				if !exists {
					return esbuild.OnLoadResult{}, fmt.Errorf("missing captured compiler source")
				}
				data = []byte(contents)
			} else {
				// Stamp BEFORE reading: a write after this point changes
				// the stamp, so the cached program can't outlive it.
				stamp, stamped = statFileStamp(args.Path)
				var err error
				data, err = os.ReadFile(args.Path)
				if err != nil {
					return esbuild.OnLoadResult{}, err
				}
			}
			if !matchesReview(args.Path, hashBytesSHA256(data)) {
				return esbuild.OnLoadResult{}, fmt.Errorf("compute: source does not match reviewed generation")
			}
			contents := string(data)
			sourceMu.Lock()
			realPath := realPathForContainment(args.Path)
			recordErr := recordComputeSourceFingerprint(hashes, realPath, hashBytesSHA256(data))
			if recordErr == nil && stamped {
				stamps[realPath] = stamp
			}
			sourceMu.Unlock()
			if recordErr != nil {
				return esbuild.OnLoadResult{}, recordErr
			}
			return esbuild.OnLoadResult{Contents: &contents, Loader: esbuild.LoaderDefault, ResolveDir: filepath.Dir(args.Path)}, nil
		})
	}}

	// Compile. ES5 target so goja's syntax coverage is sufficient -
	// async/await + optional chaining etc. transpile down. CommonJS
	// format so the wrapper's `module.exports` pattern works. No
	// externals (server-side has no 'bm' SDK - compute is pure).
	result, buildErr := buildAppSources(ctx, esbuild.BuildOptions{
		EntryPoints:   []string{modulePath},
		AbsWorkingDir: filepath.Dir(modulePath),
		Bundle:        true,
		Format:        esbuild.FormatCommonJS,
		Target:        esbuild.ES2017, // goja handles ES2017 well; safer than ES2020
		Metafile:      true,
		Loader: map[string]esbuild.Loader{
			".tsx": esbuild.LoaderTSX,
			".ts":  esbuild.LoaderTS,
			".jsx": esbuild.LoaderJSX,
			".js":  esbuild.LoaderJS,
		},
		LogLevel: esbuild.LogLevelSilent,
		Write:    false,
		// Refuse, before esbuild reads it, any file outside static/
		// (bundle_containment.go). The input check below stays.
		Plugins: []esbuild.Plugin{staticContainmentPlugin(allowedRoot), snapshotPlugin},
	})
	if buildErr != nil {
		return nil, buildErr
	}
	if len(result.Errors) > 0 {
		// Compile errors reach flow logs and step errors: a message located
		// in a file outside static/ keeps neither its text nor its location.
		result.Errors = redactOutsideBuildMessages(result.Errors, allowedRoot, filepath.Dir(modulePath))
		msgs := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			loc := ""
			if e.Location != nil {
				loc = fmt.Sprintf(" (%s:%d)", filepath.Base(e.Location.File), e.Location.Line)
			}
			msgs = append(msgs, e.Text+loc)
		}
		return nil, fmt.Errorf("compute: esbuild errors in %s: %s",
			filepath.Base(modulePath), strings.Join(msgs, "; "))
	}
	if len(result.OutputFiles) == 0 {
		return nil, fmt.Errorf("compute: esbuild produced no output for %s", filepath.Base(modulePath))
	}
	bundled := string(result.OutputFiles[0].Contents)
	wrapped := strings.Replace(computeWrapperJS, "{{BODY}}", bundled, 1)

	program, err := goja.Compile(filepath.Base(modulePath), wrapped, true /* strict */)
	if err != nil {
		return nil, fmt.Errorf("compute: goja compile failed for %s: %w", filepath.Base(modulePath), err)
	}

	// Containment root - the app's static/ dir, symlinks resolved. Every
	// bundled input must live under it.
	rootReal := allowedRoot
	if r, err := filepath.EvalSymlinks(allowedRoot); err == nil {
		rootReal = r
	}

	// Build the import-graph content-hash map for cache invalidation AND enforce
	// that every file esbuild bundled is inside static/. esbuild reports
	// metafile input paths relative to AbsWorkingDir (= the entry's dir).
	if result.Metafile == "" {
		return nil, fmt.Errorf("compute: esbuild produced no dependency metadata for %s", filepath.Base(modulePath))
	}
	var meta struct {
		Inputs map[string]struct{} `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(result.Metafile), &meta); err != nil {
		return nil, fmt.Errorf("compute: parse esbuild metafile for %s: %w", filepath.Base(modulePath), err)
	}
	for rel := range meta.Inputs {
		abs := filepath.Join(filepath.Dir(modulePath), rel)
		if filepath.IsAbs(rel) {
			abs = rel
		}
		// Reject any input that resolves outside static/ - this is
		// the fs-sandbox boundary. Resolve symlinks so a link
		// planted inside static/ can't point out of it.
		checkPath := abs
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			checkPath = r
		}
		if relToRoot, err := filepath.Rel(rootReal, checkPath); err != nil ||
			relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("compute: module %s imports a file outside static/ (%s) - compute modules may only import files inside the app's static/ directory", filepath.Base(modulePath), rel)
		}
		if _, ok := hashes[realPathForContainment(abs)]; !ok {
			return nil, fmt.Errorf("compute: missing compiled source fingerprint")
		}
	}
	if _, ok := hashes[realPathForContainment(modulePath)]; !ok {
		return nil, fmt.Errorf("compute: missing entry source fingerprint")
	}

	var compiledSource []byte
	if len(os.Args) == 3 && os.Args[1] == capturedCompilerFlag && os.Getenv(capturedCompilerEnv) == "1" {
		compiledSource = []byte(wrapped)
	}
	computeCacheMu.Lock()
	computeCache[modulePath] = &computeCacheEntry{
		program:   program,
		source:    compiledSource,
		entryPath: entryPath,
		hashes:    hashes,
		stamps:    stamps,
	}
	computeCacheMu.Unlock()
	return program, nil
}

// Caller holds sourceMu: aliases may coincide, but conflicting loaded bytes
// must never erase an earlier dependency fingerprint from the cached program.
func recordComputeSourceFingerprint(hashes map[string]string, path, hash string) error {
	if previous, exists := hashes[path]; exists && previous != hash {
		return fmt.Errorf("compute: source changed during compilation")
	}
	hashes[path] = hash
	return nil
}

// RunCompute invokes a named function in a compute module and returns
// the result (Go-typed via goja's Export). args is passed as the first
// (and only) argument to the function - typically a row/object from a
// preceding sql step's outputs.
//
// timeout is the wall-clock cap; 0 means use the 5-second default.
// On timeout the goja Runtime is interrupted at the next statement
// boundary and RunCompute returns an error tagged "compute_timeout".
func RunCompute(app *App, moduleName, functionName string, args any, timeout time.Duration) (any, error) {
	return RunComputeContext(context.Background(), app, moduleName, functionName, args, timeout)
}

func RunComputeContext(parent context.Context, app *App, moduleName, functionName string, args any, timeout time.Duration) (any, error) {
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if app == nil || app.Dir == "" {
		return nil, fmt.Errorf("compute: app not initialised")
	}
	if functionName == "" {
		return nil, fmt.Errorf("compute: function name required")
	}
	// M-10: reject oversized inputs BEFORE we build the runtime - a huge
	// args payload is the cheapest way to OOM compute and goja gives us no
	// in-runtime memory cap to fall back on.
	if n, ok := cryptoComputeWithinSize(args, cryptoComputeMaxInputBytes); !ok {
		return nil, fmt.Errorf("compute: input too large (%d bytes > %d cap) - fetch/aggregate less data before the compute step", n, cryptoComputeMaxInputBytes)
	}
	if computeGoNestingExceeds(args, computeMaxNesting) {
		return nil, fmt.Errorf("compute: input nested more than %d levels deep", computeMaxNesting)
	}
	// Strict JSON requests retain json.Number for exact SQL/input validation.
	// goja exposes that named Go string as an object, not a JavaScript number.
	// Convert only at the compute boundary, leaving the source context intact.
	args, numberErr := computeJSONNumbers(args)
	if numberErr != nil {
		return nil, numberErr
	}
	var reviewedHashes map[string]string
	var reviewedSources map[string][]byte
	if command, present := parent.Value(appMCPCommandComputeKey{}).(*appMCPCommandCapability); present {
		if command == nil || command.generation == nil || command.generation.view != app || command.validateLifetime() != nil || !commandPhaseAllowsCompute(command.command, command.currentPhaseName(), moduleName) {
			return nil, errAppMCPGrantDenied
		}
		manifest := command.generation.manifest
		if manifest == nil || len(manifest.sourceHashes) == 0 {
			return nil, errAppMCPGrantDenied
		}
		reviewedHashes, reviewedSources = manifest.sourceHashes, command.generation.sourceFiles
	} else if identity, present := parent.Value(appMCPPrivateFlowKey{}).(*appMCPPrivateFlow); present {
		app.mu.RLock()
		manifest, sources := app.MCP, app.sourceFiles
		app.mu.RUnlock()
		if identity == nil || identity.app != app || identity.manifest == nil || len(identity.manifest.sourceHashes) == 0 || manifest != identity.manifest {
			return nil, errAppMCPGrantDenied
		}
		reviewedHashes, reviewedSources = identity.manifest.sourceHashes, sources
	}
	var program *goja.Program
	var err error
	if reviewedHashes != nil {
		program, err = compileReviewedComputeProgram(parent, moduleName, reviewedSources, reviewedHashes)
	} else {
		var modulePath string
		modulePath, err = resolveComputeModulePath(app.Dir, moduleName)
		if err != nil {
			return nil, err
		}
		if err := parent.Err(); err != nil {
			return nil, err
		}
		program, err = compileComputeModuleContext(parent, modulePath, filepath.Join(app.Dir, "static"), nil)
	}
	if err != nil {
		return nil, err
	}

	if err := parent.Err(); err != nil {
		return nil, err
	}
	vm := goja.New()
	// M-10: bound recursion depth so runaway recursion fails with a
	// catchable RangeError instead of exhausting the process.
	vm.SetMaxCallStackSize(cryptoComputeMaxCallStack)
	// Disable eval + new Function. Defense in depth - compute modules
	// shouldn't need either, and removing them shrinks the attack
	// surface if someone slips a payload through the agent.
	vm.Set("eval", goja.Undefined())
	vm.Set("Function", goja.Undefined())
	// Removing the global is not enough: every function object reaches its
	// constructor through the prototype chain - `(() => {}).constructor`
	// is Function, and async / generator / async-generator functions reach
	// their own constructors the same way. Each compiles a string into code.
	if err := sealComputeFunctionConstructors(vm); err != nil {
		return nil, err
	}
	// Keep the built-ins that recurse natively over nested values within
	// computeMaxNesting levels (compute_nesting.go): a Go stack overflow
	// there is fatal to the process, not an error.
	if err := hardenComputeBuiltins(vm); err != nil {
		return nil, err
	}

	// Server-side crypto helpers (v2.7.122). The sandbox has no fetch/fs/
	// require, and goja ships no WebCrypto - so before this, agents
	// hand-rolled SHA-256 in JS (slow, and a silent-empty-hash footgun if
	// they got it wrong). These are implemented in Go and exposed as a
	// `crypto` global. NOTE: SERVER-ONLY - they do NOT exist in the
	// browser, so a module that calls them won't run client-side. Use
	// them for inherently-server-side work (password/token hashing, HMAC
	// signing, unguessable token generation); keep dual-use math (the
	// import-from-TSX-too path) in pure JS. All synchronous (unlike the
	// browser's async crypto.subtle.digest).
	vm.Set("crypto", map[string]any{
		// sha256(input) -> lowercase hex of SHA-256(utf8 bytes).
		"sha256": func(input string) string {
			sum := sha256.Sum256([]byte(input))
			return hex.EncodeToString(sum[:])
		},
		// hmacSha256(key, input) -> lowercase hex of HMAC-SHA256.
		"hmacSha256": func(key, input string) string {
			m := hmac.New(sha256.New, []byte(key))
			m.Write([]byte(input))
			return hex.EncodeToString(m.Sum(nil))
		},
		// randomHex(nBytes) -> crypto-random lowercase hex (default 16,
		// capped at 4096). For unguessable share tokens etc.
		"randomHex": func(n int) string {
			if n <= 0 || n > 4096 {
				n = 16
			}
			b := make([]byte, n)
			if _, err := rand.Read(b); err != nil {
				return ""
			}
			return hex.EncodeToString(b)
		},
		// randomUUID() -> RFC-4122 v4 UUID (matches the browser's sync API).
		"randomUUID": func() string {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				return ""
			}
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		},
	})

	// Timeout interrupt. goja checks for an interrupt between
	// statements, so even a tight loop eventually halts.
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		if ctx.Err() != nil {
			vm.Interrupt("compute_timeout")
		}
	}()

	// Run the whole goja invocation in its own goroutine and wait on it
	// against the deadline. vm.Interrupt only fires between JS statements -
	// it does NOT interrupt a native Go call (goja built-ins, and notably
	// regexp matching, which uses dlclark/regexp2 with no match timeout). So
	// a catastrophic-backtracking regex, or any long built-in, would run the
	// CALLER's goroutine (an HTTP handler) unbounded despite the timeout.
	// Bounding the wait here guarantees the caller gets a timeout error at
	// the deadline regardless. RESIDUAL: the abandoned goroutine keeps
	// running until the native call returns (same class as the documented
	// no-heap-cap OOM limit) - only per-process isolation could kill it.
	type computeResult struct {
		out any
		err error
	}
	// A slot is held until the goroutine itself finishes, not until the
	// caller gives up, so goroutines abandoned at their deadline (inside a
	// native call) count against the limit instead of piling up unbounded.
	select {
	case computeSlots <- struct{}{}:
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("compute: %s.%s timed out after %s waiting for a free compute slot", moduleName, functionName, timeout)
		}
		return nil, fmt.Errorf("compute: %s.%s cancelled: %w", moduleName, functionName, ctx.Err())
	}
	resCh := make(chan computeResult, 1)
	go func() {
		defer func() { <-computeSlots }()
		o, e := runComputeInVM(vm, program, functionName, moduleName, args)
		resCh <- computeResult{out: o, err: e}
	}()
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("compute: %s.%s timed out after %s", moduleName, functionName, timeout)
		}
		return nil, fmt.Errorf("compute: %s.%s cancelled: %w", moduleName, functionName, ctx.Err())
	case r := <-resCh:
		if r.err != nil {
			return nil, r.err
		}
		out := r.out
		if out == nil {
			return nil, nil
		}
		// M-10: cap what we hand back AND refuse a result that can't be
		// JSON-serialised. A function value or a cyclic object exports fine
		// from goja but fails json.Marshal - the old lenient size check
		// treated that "error" as within-limit, so a huge non-serialisable
		// payload bypassed the cap and a cyclic value then poisoned every
		// downstream step that tried to marshal the flow output. A compute
		// result must serialise to JSON to be usable as a flow output.
		b, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("compute: %s.%s returned a value that is not JSON-serialisable (%v) - return plain objects/arrays/scalars", moduleName, functionName, err)
		}
		if len(b) > cryptoComputeMaxOutputBytes {
			return nil, fmt.Errorf("compute: %s.%s returned too much data (%d bytes > %d cap)", moduleName, functionName, len(b), cryptoComputeMaxOutputBytes)
		}
		return out, nil
	}
}

// computeJSONNumbers gives JSON numbers the same IEEE-754 semantics as a
// JavaScript JSON.parse call. Connector callers keep their earlier, stricter
// exact-number check; ordinary flow data outside compute is not rewritten.
func computeJSONNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Float64()
		if err != nil || math.IsInf(n, 0) || math.IsNaN(n) {
			return nil, fmt.Errorf("compute: JSON number is outside the finite JavaScript number range")
		}
		return n, nil
	case map[string]any:
		if v == nil {
			return v, nil
		}
		out := make(map[string]any, len(v))
		for key, item := range v {
			converted, err := computeJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		if v == nil {
			return v, nil
		}
		out := make([]any, len(v))
		for i, item := range v {
			converted, err := computeJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case []map[string]any:
		if v == nil {
			return v, nil
		}
		out := make([]map[string]any, len(v))
		for i, item := range v {
			converted, err := computeJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			out[i] = converted.(map[string]any)
		}
		return out, nil
	default:
		return value, nil
	}
}

// computeSlots bounds concurrent compute executions per process. A call
// that times out inside a native goja call leaves its goroutine running
// until the call returns; without a bound those could accumulate.
var computeSlots = make(chan struct{}, 2*runtime.NumCPU())

// sealComputeFunctionConstructors makes Function, AsyncFunction,
// GeneratorFunction and AsyncGeneratorFunction unreachable: each one's
// prototype gets a non-writable, non-configurable `constructor` of
// undefined, so `(() => {}).constructor("...")` and its async/generator
// variants throw. A function syntax this goja build doesn't parse has no
// reachable constructor to seal.
func sealComputeFunctionConstructors(vm *goja.Runtime) error {
	for _, src := range []string{"(function(){})", "(async function(){})", "(function*(){})", "(async function*(){})"} {
		fn, err := vm.RunString(src)
		if err != nil {
			continue
		}
		proto := fn.ToObject(vm).Prototype()
		if proto == nil {
			continue
		}
		if err := proto.DefineDataProperty("constructor", goja.Undefined(), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE); err != nil {
			return fmt.Errorf("compute: sealing function constructors: %w", err)
		}
	}
	return nil
}

// reviewedComputePrograms caches programs compiled from a reviewed source
// generation. The key covers the module name and every reviewed source
// path and hash: staging verifies each staged byte against those hashes
// and nothing else is staged, so the compiler child's output is a function
// of the key. A hit skips re-staging the generation into a temp dir and
// spawning a compiler child on every call.
var reviewedComputePrograms = struct {
	sync.Mutex
	programs map[string]*goja.Program
}{programs: map[string]*goja.Program{}}

const reviewedComputeProgramsMax = 256

func reviewedComputeProgramKey(moduleName string, hashes map[string]string) string {
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	fmt.Fprintf(digest, "compute\x00%s", strings.TrimSpace(moduleName))
	for _, name := range names {
		fmt.Fprintf(digest, "\n%s\x00%s", name, hashes[name])
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// compileReviewedComputeProgram returns the program for moduleName in a
// reviewed source generation: from reviewedComputePrograms, or by staging
// the generation and compiling it in a compiler child.
func compileReviewedComputeProgram(parent context.Context, moduleName string, sources map[string][]byte, hashes map[string]string) (*goja.Program, error) {
	key := reviewedComputeProgramKey(moduleName, hashes)
	if program := cachedReviewedComputeProgram(key); program != nil {
		return program, nil
	}
	root, cleanup, err := stageAppCompilerSources(parent, sources, hashes)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	modulePath, err := resolveComputeModulePath(root, moduleName)
	if err != nil {
		return nil, err
	}
	defer func() {
		computeCacheMu.Lock()
		delete(computeCache, modulePath)
		computeCacheMu.Unlock()
	}()
	if err := parent.Err(); err != nil {
		return nil, err
	}
	wrapped, err := compileCapturedAppSource(parent, "compute", root, modulePath, hashes)
	if err != nil {
		return nil, err
	}
	program, err := goja.Compile(filepath.Base(modulePath), string(wrapped), true)
	if err != nil {
		return nil, err
	}
	storeReviewedComputeProgram(key, program)
	return program, nil
}

func cachedReviewedComputeProgram(key string) *goja.Program {
	reviewedComputePrograms.Lock()
	defer reviewedComputePrograms.Unlock()
	return reviewedComputePrograms.programs[key]
}

func storeReviewedComputeProgram(key string, program *goja.Program) {
	reviewedComputePrograms.Lock()
	defer reviewedComputePrograms.Unlock()
	for k := range reviewedComputePrograms.programs {
		if len(reviewedComputePrograms.programs) < reviewedComputeProgramsMax {
			break
		}
		delete(reviewedComputePrograms.programs, k) // arbitrary eviction
	}
	reviewedComputePrograms.programs[key] = program
}

// runComputeInVM evaluates the compiled program, resolves the named export
// and calls it with args. Runs entirely inside one goroutine (goja Runtimes
// are not goroutine-safe); the caller bounds it against the deadline.
func runComputeInVM(vm *goja.Runtime, program *goja.Program, functionName, moduleName string, args any) (out any, err error) {
	// Converting values across the Go boundary can run script code (a getter
	// or Proxy trap on the returned object) outside any JS try frame; goja
	// reports a throw there as a Go panic. In this goroutine that would end
	// the process, so it fails the step instead.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("compute: %s.%s failed: %v", moduleName, functionName, r)
		}
	}()
	if _, err := vm.RunProgram(program); err != nil {
		if strings.Contains(err.Error(), "compute_timeout") {
			return nil, fmt.Errorf("compute: %s timed out", moduleName)
		}
		return nil, fmt.Errorf("compute: %s module init failed: %w", moduleName, err)
	}

	// Pull the named function off the __exports object the wrapper
	// stashed in the top-level scope.
	exportsVal := vm.Get("__exports")
	if exportsVal == nil || goja.IsUndefined(exportsVal) || goja.IsNull(exportsVal) {
		return nil, fmt.Errorf("compute: %s exposes no module.exports - make sure your TS file uses `export function %s` (esbuild emits the CommonJS shape)", moduleName, functionName)
	}
	exportsObj := exportsVal.ToObject(vm)
	if exportsObj == nil {
		return nil, fmt.Errorf("compute: %s __exports is not an object", moduleName)
	}
	fnVal := exportsObj.Get(functionName)
	if fnVal == nil || goja.IsUndefined(fnVal) {
		// Surface what IS exported so the agent can fix the typo.
		keys := exportsObj.Keys()
		return nil, fmt.Errorf("compute: %s has no exported function %q. Available exports: %s",
			moduleName, functionName, strings.Join(keys, ", "))
	}
	fn, ok := goja.AssertFunction(fnVal)
	if !ok {
		return nil, fmt.Errorf("compute: %s.%s is not a function", moduleName, functionName)
	}

	// Coerce args from Go into a goja value. Maps, slices, scalars
	// round-trip naturally. The function receives a single argument
	// - agents passing multiple values should wrap them in an object.
	gojaArg := vm.ToValue(args)
	result, err := fn(goja.Undefined(), gojaArg)
	if err != nil {
		if strings.Contains(err.Error(), "compute_timeout") {
			return nil, fmt.Errorf("compute: %s.%s timed out", moduleName, functionName)
		}
		// Pull the JS error message out for a clean stack-free signal.
		return nil, fmt.Errorf("compute: %s.%s threw: %s", moduleName, functionName, err.Error())
	}
	if result == nil {
		return nil, nil
	}
	// Export recurses in Go over nested arrays and objects; measure first.
	if computeNestingExceeds(result, computeMaxNesting) {
		return nil, fmt.Errorf("compute: %s.%s returned a value nested more than %d levels deep", moduleName, functionName, computeMaxNesting)
	}
	return result.Export(), nil
}

// resolveComputeModulePath maps a YAML `module: foo` name to a file
// on disk. Searches static/ in this order:
//
//	static/foo.ts
//	static/foo.js
//	static/foo.tsx
//	static/foo.jsx
//
// The agent can also pass a path with a subdirectory (`compute/par`)
// - same lookup rule, relative to static/.
//
// Disallows `..` to keep the lookup inside the app dir; absolute
// paths and paths escaping static/ are rejected.
func resolveComputeModulePath(appDir, moduleName string) (string, error) {
	moduleName = strings.TrimSpace(moduleName)
	if moduleName == "" {
		return "", fmt.Errorf("compute: module name required")
	}
	if strings.Contains(moduleName, "..") || strings.HasPrefix(moduleName, "/") {
		return "", fmt.Errorf("compute: module name %q must be a relative path under static/", moduleName)
	}
	// If the agent gave us an extension already, look up that file
	// directly. Otherwise try .ts → .js → .tsx → .jsx.
	cleanName := filepath.Clean(moduleName)
	staticDir := filepath.Join(appDir, "static")
	hasExt := filepath.Ext(cleanName) != ""
	candidates := []string{}
	if hasExt {
		candidates = append(candidates, filepath.Join(staticDir, cleanName))
	} else {
		for _, ext := range []string{".ts", ".js", ".tsx", ".jsx"} {
			candidates = append(candidates, filepath.Join(staticDir, cleanName+ext))
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			// Verify the resolved path is INSIDE static/ - defense in
			// depth against symlinks or earlier path tricks.
			rel, err := filepath.Rel(staticDir, c)
			if err != nil || strings.HasPrefix(rel, "..") {
				return "", fmt.Errorf("compute: module %q resolved outside static/", moduleName)
			}
			return c, nil
		}
	}
	return "", fmt.Errorf("compute: module %q not found - looked for %s",
		moduleName, strings.Join(candidates, ", "))
}
