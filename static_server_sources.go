//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// staticServerSource reports a /static/ request for something that is source
// or server code rather than a browser asset:
//
//   - TypeScript and JSX source (.ts, .tsx, .mts, .cts, .jsx). Browsers run
//     the compiled /static/*.js; the source was served as written, and a
//     `run: compute` module - server code, which must live in static/ - was
//     downloadable with whatever it held. Two live apps served a hardcoded
//     private key that way (static/server/pushsign.ts).
//   - A module a flow runs with `run: compute`, as JS: the framework compiles
//     any static/*.ts to a public /static/*.js on request, so the server
//     module reached the browser compiled instead. No fleet page loads one.
//
// It is the one predicate for every URL form that can return bytes of a file
// under static/; refuseStaticServerSource and openStaticAsset apply it.
func staticServerSource(app *App, requested string) bool {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(requested)), "/")
	ext := filepath.Ext(clean)
	switch {
	case extensionFolds(ext, ".ts", ".tsx", ".mts", ".cts", ".jsx"):
		return true
	case extensionFolds(ext, ".js", ".mjs", ".cjs"):
		stems := computeModuleStems(app)
		if len(stems) == 0 {
			return false
		}
		if stems[strings.TrimSuffix(clean, filepath.Ext(clean))] {
			return true
		}
		return computeImportsServed(app, stems, clean)
	}
	return false
}

// extensionFolds reports ext as one of names under Unicode case folding, the
// comparison a case-insensitive file system makes: there app.ts also opens as
// app.TS and as app.t\u017f (the long s folds to s), and a lower-cased
// comparison let the second spelling through.
func extensionFolds(ext string, names ...string) bool {
	for _, name := range names {
		if strings.EqualFold(ext, name) {
			return true
		}
	}
	return false
}

// refuseStaticServerSource is the gate every URL form that maps a request to
// static/<rel> passes before it compiles, opens or reads anything:
// /static/<rel> (serveStaticAsset) and the URL-root alias /<rel> with its
// clean-URL, directory and index.html fallbacks (serveStaticHTML). It reports
// true after writing the one answer all forms give, the 404 of a file that is
// not there.
//
// The root alias did not ask: /app.tsx and /server/key.ts answered 200 with
// the source /static/app.tsx refuses (round 2026-11-09). A handler that adds
// a path form calls this with the static/-relative path; openStaticAsset
// refuses the file for one that forgets.
func refuseStaticServerSource(w http.ResponseWriter, r *http.Request, app *App, rel string) bool {
	if !staticServerSource(app, rel) {
		return false
	}
	writeStaticSourceRefusal(w, r)
	return true
}

// writeStaticSourceRefusal is the answer to a refused static/ request,
// whichever form asked.
func writeStaticSourceRefusal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.NotFound(w, r)
}

// openStaticAsset opens target, a path under app's static/, to answer a
// request with its bytes. Handlers get a file under static/ only here, so the
// refusal does not depend on each one remembering the gate. refused reports
// script source or server code, by the name asked for or by the name the file
// resolved to: a link inside static/ (notes.txt -> server/key.ts) passes
// every check made on the request path. The caller answers a refused open
// with writeStaticSourceRefusal.
func openStaticAsset(app *App, target string) (file *servableFile, refused, ok bool) {
	staticRoot := filepath.Join(app.Dir, "static")
	asked, err := filepath.Rel(staticRoot, target)
	if err == nil && staticServerSource(app, asked) {
		return nil, true, false
	}
	file, ok = openServableFile(staticRoot, target)
	if !ok {
		return nil, false, false
	}
	if file.relative != asked && staticServerSource(app, file.relative) {
		file.Close()
		return nil, true, false
	}
	return file, false, true
}

// computeImportsServed reports a /static/*.js request whose source a compute
// module imports. Blocking only the entry module left its helpers public: a
// key in static/server/key.ts, imported by the compute module
// static/server/main.ts, was served compiled at /static/server/key.js (round-2
// review, 2026-10-23). The import graph is the compiled bundle's inputs, from
// the same cached compile the flow runs. A module that does not compile has
// no known graph, so every source in its directory is refused instead.
func computeImportsServed(app *App, stems map[string]bool, requested string) bool {
	staticRoot := filepath.Join(app.Dir, "static")
	var served []string
	if source := resolveTSXSource(app.Dir, requested); source != "" {
		served = append(served, realPathForContainment(source))
	}
	served = append(served, realPathForContainment(filepath.Join(staticRoot, filepath.FromSlash(requested))))
	graph := computeServerSources(app, staticRoot, stems)
	for _, path := range served {
		if graph.files[path] {
			return true
		}
		for _, dir := range graph.dirs {
			if strings.HasPrefix(path, dir) {
				return true
			}
		}
		if graph.holds(path, strings.Count(requested, "/")) {
			return true
		}
	}
	return false
}

// computeSourceGraph is every file the app's compute modules pull in, plus
// the directories of modules that do not compile.
//
// fileIDs and dirIDs are the same files and directories as the file system
// identifies them, with every compute module itself. Paths alone miss a
// request that reaches a file under another spelling: a case-insensitive file
// system opens server/key.ts as SERVER/key.ts, the path comparison saw a
// different file, and /static/SERVER/key.js answered with the compiled helper.
type computeSourceGraph struct {
	files   map[string]bool
	dirs    []string
	fileIDs []os.FileInfo
	dirIDs  []os.FileInfo
}

// holds reports path as one of the graph's files, or as a file inside one of
// its directories, by identity. parents bounds how many directories above
// path are compared.
func (g computeSourceGraph) holds(path string, parents int) bool {
	if len(g.fileIDs) == 0 && len(g.dirIDs) == 0 {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	for _, id := range g.fileIDs {
		if os.SameFile(info, id) {
			return true
		}
	}
	for dir := filepath.Dir(path); parents > 0 && len(g.dirIDs) > 0; dir, parents = filepath.Dir(dir), parents-1 {
		info, err := os.Stat(dir)
		if err != nil {
			return false
		}
		for _, id := range g.dirIDs {
			if os.SameFile(info, id) {
				return true
			}
		}
	}
	return false
}

// identify records path in ids when it exists.
func identify(ids []os.FileInfo, path string) []os.FileInfo {
	if info, err := os.Stat(path); err == nil {
		return append(ids, info)
	}
	return ids
}

// One graph per app and static/ tree version (refreshed at most once a
// second by cachedStaticTreeVersion), so a page's many /static/*.js requests
// do not re-check every compute module each.
var computeSourceGraphs = struct {
	sync.Mutex
	m map[string]computeSourceGraphEntry
}{m: map[string]computeSourceGraphEntry{}}

type computeSourceGraphEntry struct {
	key   string
	graph computeSourceGraph
}

func computeServerSources(app *App, staticRoot string, stems map[string]bool) computeSourceGraph {
	names := make([]string, 0, len(stems))
	for stem := range stems {
		names = append(names, stem)
	}
	sort.Strings(names)
	version, versioned := cachedStaticTreeVersion(staticRoot)
	key := version + "\x00" + strings.Join(names, "\x00")
	if versioned {
		computeSourceGraphs.Lock()
		entry, hit := computeSourceGraphs.m[staticRoot]
		computeSourceGraphs.Unlock()
		if hit && entry.key == key {
			return entry.graph
		}
	}
	graph := computeSourceGraph{files: map[string]bool{}}
	for _, stem := range names {
		modulePath, err := resolveComputeModulePath(app.Dir, stem)
		if err == nil {
			graph.fileIDs = identify(graph.fileIDs, modulePath)
			_, err = compileComputeModuleContext(context.Background(), modulePath, staticRoot, nil)
		}
		if err != nil {
			dir := filepath.Dir(filepath.Join(staticRoot, filepath.FromSlash(stem)))
			if dir != staticRoot { // refusing static/ itself would refuse every asset
				graph.dirs = append(graph.dirs, realPathForContainment(dir)+string(filepath.Separator))
				graph.dirIDs = identify(graph.dirIDs, dir)
			}
			continue
		}
		var inputs []string
		computeCacheMu.RLock()
		if entry := computeCache[modulePath]; entry != nil {
			for path := range entry.hashes {
				graph.files[path] = true
				inputs = append(inputs, path)
			}
		}
		computeCacheMu.RUnlock()
		for _, path := range inputs {
			graph.fileIDs = identify(graph.fileIDs, path)
		}
	}
	if versioned {
		computeSourceGraphs.Lock()
		if len(computeSourceGraphs.m) >= 4096 {
			clear(computeSourceGraphs.m)
		}
		computeSourceGraphs.m[staticRoot] = computeSourceGraphEntry{key: key, graph: graph}
		computeSourceGraphs.Unlock()
	}
	return graph
}

// computeModuleStem is a compute module name as a static/-relative path
// without its extension.
func computeModuleStem(module string) string {
	m := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.TrimSpace(module))), "static/")
	switch strings.ToLower(filepath.Ext(m)) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts":
		m = strings.TrimSuffix(m, filepath.Ext(m))
	}
	return m
}

// computeModuleStems is the static/-relative path, without extension, of
// every module the app's flows run with `run: compute`.
func computeModuleStems(app *App) map[string]bool {
	stems := map[string]bool{}
	if app == nil {
		return stems
	}
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	var walk func(steps []FlowStep)
	walk = func(steps []FlowStep) {
		for i := range steps {
			s := &steps[i]
			if s.Compute != nil && s.Compute.Module != "" {
				stems[computeModuleStem(s.Compute.Module)] = true
			}
			walk(s.Steps)
			walk(s.ElseSteps)
			walk(s.OnError)
		}
	}
	for i := range flows {
		walk(flows[i].Steps)
	}
	return stems
}

// computeModuleImportsSource reports whether /static refuses the static/
// file rel (app-relative, e.g. static/lib/pricing/rates.ts) because a
// `run: compute` module named in the app's flow files is that file or
// imports it at any depth, or because it sits in the directory of a compute
// module that does not compile (computeImportsServed's rules). Such a file is
// server-only. A write's next_steps hint said it was "served on its own at
// /static/... only when a page loads that URL directly", which is false for
// these (round 2026-11-05).
//
// It runs where the app is not loaded (the platform's write_file), so it
// reads the flow files itself and bundles each module only for its input
// list: no goja compile and no compute cache entry. Bounded by a deadline; on
// any failure to tell, it answers false and the hint stays general.
func computeModuleImportsSource(appDir, rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if !strings.HasPrefix(rel, "static/") {
		return false
	}
	stems := computeModuleStemsInFlowFiles(appDir)
	if len(stems) == 0 {
		return false
	}
	staticRoot := filepath.Join(appDir, "static")
	allowedRoot := containmentRoot(staticRoot)
	target := realPathForContainment(filepath.Join(appDir, filepath.FromSlash(rel)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := make([]string, 0, len(stems))
	for stem := range stems {
		names = append(names, stem)
	}
	sort.Strings(names)
	for _, stem := range names {
		modulePath, err := resolveComputeModulePath(appDir, stem)
		if err == nil && realPathForContainment(modulePath) == target {
			return true
		}
		var inputs map[string]bool
		if err == nil {
			inputs, err = computeModuleInputs(ctx, modulePath, allowedRoot)
		}
		if ctx.Err() != nil {
			return false
		}
		if err != nil {
			dir := filepath.Dir(filepath.Join(staticRoot, filepath.FromSlash(stem)))
			if dir != staticRoot && strings.HasPrefix(target, realPathForContainment(dir)+string(filepath.Separator)) {
				return true
			}
			continue
		}
		if inputs[target] {
			return true
		}
	}
	return false
}

// computeModuleInputs is every file esbuild reads to bundle a compute module,
// symlinks resolved. The platform runs it on an app's files, so it gives
// esbuild an empty tsconfig: no tsconfig.json (or the file its `extends`
// names) is read from disk. A module that relies on tsconfig `paths` may then
// fail to bundle here, and the hint treats it as a module that does not
// compile.
func computeModuleInputs(ctx context.Context, modulePath, allowedRoot string) (map[string]bool, error) {
	options := computeBuildOptions(modulePath, staticContainmentPlugin(allowedRoot))
	options.TsconfigRaw = "{}"
	result, err := buildAppSources(ctx, options)
	if err != nil {
		return nil, err
	}
	if len(result.Errors) > 0 || result.Metafile == "" {
		return nil, os.ErrInvalid
	}
	var meta struct {
		Inputs map[string]struct{} `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(result.Metafile), &meta); err != nil {
		return nil, err
	}
	inputs := make(map[string]bool, len(meta.Inputs))
	for rel := range meta.Inputs {
		abs := rel
		if !filepath.IsAbs(rel) {
			abs = filepath.Join(filepath.Dir(modulePath), rel)
		}
		inputs[realPathForContainment(abs)] = true
	}
	return inputs, nil
}

// computeModuleStemsInFlowFiles is computeModuleStems read from the flow
// files on disk instead of a loaded app. A file that does not parse is
// skipped.
func computeModuleStemsInFlowFiles(appDir string) map[string]bool {
	stems := map[string]bool{}
	var walk func(steps []FlowStepGHA)
	walk = func(steps []FlowStepGHA) {
		for _, s := range steps {
			if ghaStepRunType(s) == "compute" {
				if module, ok := s.With["module"].(string); ok && strings.TrimSpace(module) != "" {
					stems[computeModuleStem(module)] = true
				}
			}
			walk(s.Steps)
			walk(s.Else)
			walk(s.OnError)
		}
	}
	for _, rel := range flowFilesFor(appDir, "") {
		data, err := os.ReadFile(filepath.Join(appDir, rel))
		if err != nil {
			continue
		}
		var file FlowFileGHA
		if decodeConfigYAML(data, &file) != nil {
			continue
		}
		for _, job := range file.Jobs {
			walk(job.Steps)
		}
	}
	return stems
}
