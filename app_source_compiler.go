//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

// serveCapturedStaticAsset serves a reviewed generation's static file with a
// strong content validator instead of no-store: the browser keeps the bytes
// but revalidates on every use (setRevalidateCacheHeaders, CDNs never store
// it), so a page view costs a 304 rather than a download, and a new
// generation's different bytes are seen on the very next load.
func serveCapturedStaticAsset(w http.ResponseWriter, r *http.Request, name string, data []byte) {
	w.Header().Set("ETag", capturedAssetETag(data))
	setRevalidateCacheHeaders(w)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// capturedAssetETags memoizes validators by the captured slice itself: a
// generation's bytes never change in place, so its backing array identifies
// the content and the hash is computed once per generation, not per request.
var capturedAssetETags = struct {
	sync.Mutex
	m map[capturedAssetKey]string
}{m: map[capturedAssetKey]string{}}

type capturedAssetKey struct {
	first *byte
	n     int
}

func capturedAssetETag(data []byte) string {
	if len(data) == 0 {
		sum := sha256.Sum256(nil)
		return `"` + hex.EncodeToString(sum[:8]) + `"`
	}
	key := capturedAssetKey{&data[0], len(data)}
	capturedAssetETags.Lock()
	tag, ok := capturedAssetETags.m[key]
	capturedAssetETags.Unlock()
	if ok {
		return tag
	}
	sum := sha256.Sum256(data)
	tag = `"` + hex.EncodeToString(sum[:8]) + `"`
	capturedAssetETags.Lock()
	if len(capturedAssetETags.m) >= 4096 {
		clear(capturedAssetETags.m) // superseded generations are released
	}
	capturedAssetETags.m[key] = tag
	capturedAssetETags.Unlock()
	return tag
}

// Use the existing compiler/resolver against a private copy of the captured
// generation, including configuration and absent files. No tenant files change.
// Reviewed callers compile this tree only in the filesystem-confined child.
// ponytail: copy at most 64 MiB/10,000 files per compile; cache a generation's
// private tree only if measured compilation IO warrants lifecycle bookkeeping.
func stageAppCompilerSources(ctx context.Context, sources map[string][]byte, hashes map[string]string) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if sources == nil || len(hashes) == 0 || len(hashes) > 10000 {
		return "", nil, fmt.Errorf("missing or oversized captured compiler generation")
	}
	for name := range hashes {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if _, exists := sources[name]; !exists {
			return "", nil, fmt.Errorf("missing captured compiler source")
		}
	}
	var total int
	for name, data := range sources {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if data == nil && hashes[name] == "" {
			continue // Checked loader sentinels represent directories/absent files.
		}
		local := filepath.FromSlash(name)
		if name == "." || !filepath.IsLocal(local) || filepath.ToSlash(filepath.Clean(local)) != name || hashes[name] != hashBytesSHA256(data) {
			return "", nil, fmt.Errorf("invalid captured compiler source")
		}
		total += len(data)
		if total > 64<<20 {
			return "", nil, fmt.Errorf("captured compiler generation exceeds source limit")
		}
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "benmore-reviewed-compile-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	root := filepath.Join(dir, "app")
	if err := os.Mkdir(root, 0700); err != nil {
		cleanup()
		return "", nil, err
	}
	// Fixed empty parent configurations preserve ordinary defaults when the app
	// omits its own config. The child filesystem policy confines metadata reads.
	for _, name := range []string{"package.json", "tsconfig.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	for name, data := range sources {
		if err := ctx.Err(); err != nil {
			cleanup()
			return "", nil, err
		}
		if data == nil && hashes[name] == "" {
			continue
		}
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			cleanup()
			return "", nil, err
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			cleanup()
			if writeErr != nil {
				return "", nil, writeErr
			}
			return "", nil, closeErr
		}
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return "", nil, err
	}
	return root, cleanup, nil
}

// capturedBrowserModules holds browser modules compiled from reviewed
// generations. /static/ is exempt from the request rate limit and each compile
// copies the whole captured tree and starts a compiler child, so a module is
// compiled once per generation, with concurrent requests sharing one compile.
// The key covers every captured digest (the bytes are verified against them
// when staged) and the module; a failed compile is never kept.
// served holds each cached body's serving form (ETag, gzip), built once.
var capturedBrowserModules = struct {
	sync.Mutex
	bodies   map[string][]byte
	served   map[string]*tsxServed
	size     int
	inflight map[string]*capturedBrowserCompile
}{bodies: map[string][]byte{}, served: map[string]*tsxServed{}, inflight: map[string]*capturedBrowserCompile{}}

const capturedBrowserModulesLimit = 64 << 20

type capturedBrowserCompile struct {
	done  chan struct{}
	body  []byte
	found bool
	err   error
}

// compileCapturedBrowserModule returns the compiled module for urlRel (a
// /static/ path ending in .js) of the reviewed generation; found is false when
// the generation has no source for it.
func compileCapturedBrowserModule(ctx context.Context, sources map[string][]byte, hashes map[string]string, urlRel string) (body []byte, found bool, err error) {
	body, _, found, err = compileCapturedBrowserModuleKeyed(ctx, sources, hashes, urlRel)
	return body, found, err
}

// compileCapturedBrowserAsset is compileCapturedBrowserModule in serving
// form: the body with its ETag and gzip copy, computed once per cached body.
func compileCapturedBrowserAsset(ctx context.Context, sources map[string][]byte, hashes map[string]string, urlRel string) (*tsxServed, bool, error) {
	body, key, found, err := compileCapturedBrowserModuleKeyed(ctx, sources, hashes, urlRel)
	if err != nil || !found {
		return nil, found, err
	}
	cache := &capturedBrowserModules
	cache.Lock()
	defer cache.Unlock()
	// Same backing array: the serving form was built from this very body.
	if s := cache.served[key]; s != nil && len(s.body) == len(body) && (len(body) == 0 || &s.body[0] == &body[0]) {
		return s, true, nil
	}
	s := newTSXServed(body)
	if _, cached := cache.bodies[key]; cached {
		cache.served[key] = s
	}
	return s, true, nil
}

func compileCapturedBrowserModuleKeyed(ctx context.Context, sources map[string][]byte, hashes map[string]string, urlRel string) (body []byte, key string, found bool, err error) {
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	fmt.Fprintf(digest, "browser\x00%s", filepath.ToSlash(filepath.Clean(urlRel)))
	for _, name := range names {
		fmt.Fprintf(digest, "\n%s\x00%s", name, hashes[name])
	}
	key = hex.EncodeToString(digest.Sum(nil))
	cache := &capturedBrowserModules
	cache.Lock()
	if cached, ok := cache.bodies[key]; ok {
		cache.Unlock()
		return cached, key, true, nil
	}
	call := cache.inflight[key]
	if call == nil {
		call = &capturedBrowserCompile{done: make(chan struct{})}
		cache.inflight[key] = call
		// The shared compile outlives a departing first requester; the child's
		// own timeout bounds it.
		go func(ctx context.Context) {
			call.body, call.found, call.err = compileCapturedBrowserModuleOnce(ctx, sources, hashes, urlRel)
			cache.Lock()
			delete(cache.inflight, key)
			if call.err == nil && call.found && len(call.body) <= capturedBrowserModulesLimit {
				for k, v := range cache.bodies {
					if cache.size+len(call.body) <= capturedBrowserModulesLimit {
						break
					}
					delete(cache.bodies, k) // ponytail: arbitrary eviction; LRU if hit rates are measured
					delete(cache.served, k)
					cache.size -= len(v)
				}
				cache.bodies[key] = call.body
				cache.size += len(call.body)
			}
			cache.Unlock()
			close(call.done)
		}(context.WithoutCancel(ctx))
	}
	cache.Unlock()
	select {
	case <-call.done:
		return call.body, key, call.found, call.err
	case <-ctx.Done():
		return nil, key, true, ctx.Err()
	}
}

func compileCapturedBrowserModuleOnce(ctx context.Context, sources map[string][]byte, hashes map[string]string, urlRel string) ([]byte, bool, error) {
	root, cleanup, err := stageAppCompilerSources(ctx, sources, hashes)
	if err != nil {
		return nil, true, fmt.Errorf("invalid captured compiler generation")
	}
	defer cleanup()
	src := resolveTSXSource(root, urlRel)
	if src == "" {
		return nil, false, nil
	}
	body, err := compileCapturedAppSource(ctx, "browser", root, src, hashes)
	return body, true, err
}

// Cancellation uses the existing native compiler. OnStart observes an active
// rebuild, so Cancel cannot be lost in the race before Rebuild begins. Native
// plugin callbacks still have to return before esbuild can finish cancellation.
func buildAppSources(ctx context.Context, options esbuild.BuildOptions) (esbuild.BuildResult, error) {
	if len(os.Args) == 3 && os.Args[1] == capturedCompilerFlag && os.Getenv(capturedCompilerEnv) == "1" {
		options.InputFiles = capturedCompilerFiles
	}
	if err := ctx.Err(); err != nil {
		return esbuild.BuildResult{}, err
	}
	if ctx.Done() == nil {
		return esbuild.Build(options), ctx.Err()
	}
	started := make(chan struct{})
	options.Plugins = append(options.Plugins, esbuild.Plugin{Name: "benmore-build-cancellation", Setup: func(build esbuild.PluginBuild) {
		build.OnStart(func() (esbuild.OnStartResult, error) {
			close(started)
			return esbuild.OnStartResult{}, ctx.Err()
		})
	}})
	build, err := esbuild.Context(options)
	if err != nil {
		return esbuild.BuildResult{}, err
	}
	defer build.Dispose()
	finished, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			select {
			case <-started:
				build.Cancel()
			case <-finished:
			}
		case <-finished:
		}
	}()
	result := build.Rebuild()
	close(finished)
	<-watcherDone
	return result, ctx.Err()
}
