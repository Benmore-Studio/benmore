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
//   - Compilation is cached per (app, module) by source mtime,
//     same shape as the TSX cache. Recompile is automatic on edit.
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
//     module can't escape.
//   - No timers (setTimeout / setInterval) - there's nothing to
//     schedule against since we exit as soon as the function returns.
//   - The Runtime has no access to the per-app DB. Compute is for
//     PURE algorithms; if you need data, FETCH it via a sql step
//     before the compute step and pass it in as args.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	esbuild "github.com/evanw/esbuild/pkg/api"
)

// computeCacheEntry is a parsed goja program ready to invoke.
type computeCacheEntry struct {
	program *goja.Program
	// mtimes maps every source file the bundle pulled in to its
	// mtime at compile time. Cache invalidates when ANY of these
	// files changes - matches the bm_tsx_compile.go behaviour for
	// imported-module edits.
	mtimes map[string]time.Time
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
// side execution. Cached by source mtime; recompiles only when the
// entry or any imported file changes. Returns the parsed program.
//
// `modulePath` is the absolute file path (caller resolves the YAML
// `module:` name to a path under the app's static/ dir).
func CompileComputeModule(modulePath string) (*goja.Program, error) {
	info, err := os.Stat(modulePath)
	if err != nil {
		return nil, fmt.Errorf("compute: stat %s: %w", filepath.Base(modulePath), err)
	}
	entryMtime := info.ModTime()

	computeCacheMu.RLock()
	if entry, ok := computeCache[modulePath]; ok {
		// Fresh if entry mtime matches AND every imported file is
		// still at its compile-time mtime.
		fresh := true
		for p, mt := range entry.mtimes {
			if i, err := os.Stat(p); err != nil || !i.ModTime().Equal(mt) {
				fresh = false
				break
			}
		}
		if fresh && entry.mtimes[modulePath].Equal(entryMtime) {
			prog := entry.program
			computeCacheMu.RUnlock()
			return prog, nil
		}
	}
	computeCacheMu.RUnlock()

	// Compile. ES5 target so goja's syntax coverage is sufficient -
	// async/await + optional chaining etc. transpile down. CommonJS
	// format so the wrapper's `module.exports` pattern works. No
	// externals (server-side has no 'bm' SDK - compute is pure).
	result := esbuild.Build(esbuild.BuildOptions{
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
	})
	if len(result.Errors) > 0 {
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

	// Build the import-graph mtime map for cache invalidation.
	mtimes := map[string]time.Time{modulePath: entryMtime}
	if result.Metafile != "" {
		var meta struct {
			Inputs map[string]struct{} `json:"inputs"`
		}
		if json.Unmarshal([]byte(result.Metafile), &meta) == nil {
			for rel := range meta.Inputs {
				abs := filepath.Join(filepath.Dir(modulePath), rel)
				if i, err := os.Stat(abs); err == nil {
					mtimes[abs] = i.ModTime()
				}
			}
		}
	}

	computeCacheMu.Lock()
	computeCache[modulePath] = &computeCacheEntry{
		program: program,
		mtimes:  mtimes,
	}
	computeCacheMu.Unlock()
	return program, nil
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
	modulePath, err := resolveComputeModulePath(app.Dir, moduleName)
	if err != nil {
		return nil, err
	}
	program, err := CompileComputeModule(modulePath)
	if err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			vm.Interrupt("compute_timeout")
		}
	}()

	if _, err := vm.RunProgram(program); err != nil {
		if strings.Contains(err.Error(), "compute_timeout") {
			return nil, fmt.Errorf("compute: %s timed out after %s", moduleName, timeout)
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
			return nil, fmt.Errorf("compute: %s.%s timed out after %s", moduleName, functionName, timeout)
		}
		// Pull the JS error message out for a clean stack-free signal.
		return nil, fmt.Errorf("compute: %s.%s threw: %s", moduleName, functionName, err.Error())
	}
	if result == nil {
		return nil, nil
	}
	out := result.Export()
	// M-10: cap the size of what we hand back. A module can't be stopped
	// from allocating internally (no goja memory cap), but we refuse to
	// materialise an unbounded result into the rest of the process.
	if n, ok := cryptoComputeWithinSize(out, cryptoComputeMaxOutputBytes); !ok {
		return nil, fmt.Errorf("compute: %s.%s returned too much data (%d bytes > %d cap)", moduleName, functionName, n, cryptoComputeMaxOutputBytes)
	}
	return out, nil
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
