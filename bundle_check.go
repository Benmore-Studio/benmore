//go:build !cli

package main

// Write-time and check-time builds of browser bundles.
//
// A browser bundle (bm_tsx_compile.go) is built when a page first requests
// /static/<name>.js. The write gate only parsed the written file
// (validators_script_syntax.go), so push, delete-file and `benmore check`
// accepted TSX whose bundle could not build: an import outside static/ (the
// build refuses it, bundle_containment.go), an import that resolves to no
// file, a named import its module does not export, and the deletion of a
// module another file still imports (round 2026-11-05: deleting the
// scaffold's views/notes.tsx broke the login and signup scripts while check
// stayed clean). Each surfaced only when a visitor loaded the page, as a
// module that throws.
//
// The write gate, delete_file and `benmore check` now build the bundles a
// change affects with the runtime's own options and containment plugin
// (browserBundleOptions), in one esbuild run:
//
//   - The build reads an in-memory copy of static/ with the change applied
//     (BuildOptions.InputFiles, esbuild's captured filesystem), so it judges
//     the app as the change leaves it and esbuild opens no file itself. The
//     gate runs in the router, so the copy is read through an os.Root at the
//     app directory, non-blocking and regular files only: no link takes the
//     read to another tenant's tree and no FIFO can hang it. Only contents a
//     build loads (scripts, CSS, JSON) are read, and a script over 1 MiB (a
//     vendored or generated bundle) is replaced by an empty CommonJS module;
//     the app's root tsconfig.json and jsconfig.json are copied as well,
//     since they steer resolution.
//   - Entries are the files /static/<name>.js compiles: each .tsx, .ts or
//     .jsx under static/ (not .d.ts), the first of those per name, as
//     resolveTSXSource picks, except tests kept beside the code (x.test.ts,
//     __tests__/), which no page loads. A connector widget component's
//     import of the MCP Apps module, which the widget build supplies, is
//     accepted. A change affects the entries whose imports reach it, found
//     from the relative specifiers in the copy's scripts; a script with a
//     bare specifier (a tsconfig paths alias, a package) counts as importing
//     anything. Only those entries are built.
//   - A build takes a compile slot (tsxCompileSlots) and has a deadline. A
//     static/ tree over bundleCheckMaxFiles or bundleCheckMaxBytes, a
//     directory link in it, or a build that cannot finish in time is not
//     judged; the runtime still reports at request time. Results are memoized
//     by the copy's digest, so the post-write check reuses the gate's build.
//
// What is refused:
//   - A write: errors located in the written file. A batch write that defers
//     its reload (deploy, a multi-file push) can be followed by the file that
//     supplies a missing module or export, so there only an import outside
//     static/ is refused; the post-write check reports the rest and the CLI
//     checks the app again when the batch ends.
//   - A delete: errors it causes in other files, compared with the same
//     entries built before the delete.
//
// Errors a write leaves in other files are reported by the post-write check,
// not refused: refusing them would deadlock a change spanning two files that
// are pushed one at a time (an export renamed together with its import).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

const (
	bundleCheckMaxFiles = 10000
	bundleCheckMaxBytes = 64 << 20
	bundleCheckTimeout  = 10 * time.Second
	// bundleCheckShown bounds the errors one refusal or finding quotes.
	bundleCheckShown = 8
	// bundleCheckStubBytes: a script larger than this (a vendored or
	// generated bundle; an Expo export runs 1-2 MB per file) is not read. The
	// copy holds bundleCheckLargeScriptStub in its place, a CommonJS module,
	// so an import of it resolves and any name imported from it is accepted;
	// what it imports itself is not checked.
	bundleCheckStubBytes       = 1 << 20
	bundleCheckLargeScriptStub = "module.exports = {};\n"
)

// bundleCheckContentExts are the files a browser build reads: its loaders
// (browserBundleOptions) and esbuild's default ones for these extensions.
var bundleCheckContentExts = map[string]bool{
	".tsx": true, ".ts": true, ".jsx": true, ".js": true, ".mjs": true, ".cjs": true,
	".mts": true, ".cts": true, ".css": true, ".json": true,
}

// bundleCheckEntryExts are the sources /static/<name>.js compiles, in the
// order resolveTSXSource tries them.
var bundleCheckEntryExts = []string{".tsx", ".ts", ".jsx"}

// bundleCheckRootConfigs are read from the app root: esbuild looks for them
// in every directory above a source file, and they steer resolution
// (tsconfig paths, jsx).
var bundleCheckRootConfigs = []string{"tsconfig.json", "jsconfig.json", "package.json"}

// bundleTree is the copy of static/ a check builds against.
type bundleTree struct {
	appDir     string            // absolute
	staticRoot string            // absolute, appDir/static
	names      map[string]bool   // absolute path of every file in static/, after the change
	sizes      map[string]int64  // absolute path → size on disk, from the listing
	contents   map[string]string // absolute path → contents, for the files a build reads
	changed    map[string]bool   // files whose contents the change set (never read from disk)
	graph      *bundleImportGraph
}

// loadBundleTree lists static/ (none yet is an empty tree). ok is false when
// the tree cannot be judged: static/ leaves the app, a directory cannot be
// read or is a link, or there are more than bundleCheckMaxFiles files.
func loadBundleTree(appDir string) (*bundleTree, bool) {
	abs, err := filepath.Abs(appDir)
	if err != nil {
		return nil, false
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, false
	}
	defer root.Close()
	t := &bundleTree{appDir: abs, staticRoot: filepath.Join(abs, "static"), names: map[string]bool{},
		sizes: map[string]int64{}, contents: map[string]string{}, changed: map[string]bool{}}
	static, err := root.OpenRoot("static")
	if errors.Is(err, fs.ErrNotExist) {
		// No static/ yet: the change is its first file.
		return t, true
	}
	if err != nil {
		return nil, false
	}
	defer static.Close()
	ok := true
	walkErr := fs.WalkDir(static.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			ok = false
			return fs.SkipAll
		}
		if p == "." || d.IsDir() {
			return nil
		}
		var size int64
		if d.Type()&fs.ModeSymlink != 0 {
			info, err := static.Stat(p)
			if err != nil {
				// A link that leaves static/ (or names nothing): the
				// containment plugin refuses an import of it by its real path.
				return nil
			}
			if info.IsDir() {
				// The copy would not hold the files under it.
				ok = false
				return fs.SkipAll
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			size = info.Size()
		} else if !d.Type().IsRegular() {
			return nil
		} else if info, err := d.Info(); err == nil {
			size = info.Size()
		}
		if len(t.names) >= bundleCheckMaxFiles {
			ok = false
			return fs.SkipAll
		}
		abs := t.abs("static/" + p)
		t.names[abs] = true
		t.sizes[abs] = size
		return nil
	})
	if walkErr != nil || !ok {
		return nil, false
	}
	return t, true
}

// abs is the absolute path of an app-relative, slash-separated rel.
func (t *bundleTree) abs(rel string) string {
	return filepath.Join(t.appDir, filepath.FromSlash(rel))
}

// rel is the app-relative, slash-separated form of abs ("" outside the app).
func (t *bundleTree) rel(abs string) string {
	r, err := filepath.Rel(t.appDir, abs)
	if err != nil || !filepath.IsLocal(r) {
		return ""
	}
	return filepath.ToSlash(r)
}

// set applies the change: rel's new contents, or its removal (content nil).
func (t *bundleTree) set(rel string, content *string) {
	abs := t.abs(rel)
	t.changed[abs] = true
	t.graph = nil
	if content == nil {
		delete(t.names, abs)
		delete(t.contents, abs)
		return
	}
	t.names[abs] = true
	t.contents[abs] = *content
}

// readContents reads the files a build loads (except those the change set)
// and the app's root configuration. false: the copy would pass
// bundleCheckMaxBytes, or a file could not be read.
func (t *bundleTree) readContents() bool {
	root, err := os.OpenRoot(t.appDir)
	if err != nil {
		return false
	}
	defer root.Close()
	total := 0
	for abs := range t.contents {
		total += len(t.contents[abs])
	}
	for abs := range t.names {
		ext := strings.ToLower(filepath.Ext(abs))
		if t.changed[abs] || !bundleCheckContentExts[ext] {
			continue
		}
		if bundleScriptExts[ext] && t.sizes[abs] > bundleCheckStubBytes {
			t.contents[abs] = bundleCheckLargeScriptStub
			continue
		}
		data, err := readBundleSource(root, t.rel(abs), bundleCheckMaxBytes-total)
		if err != nil {
			return false
		}
		total += len(data)
		t.contents[abs] = string(data)
	}
	for _, name := range bundleCheckRootConfigs {
		data, err := readBundleSource(root, name, min(1<<20, bundleCheckMaxBytes-total))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotRegularBundleSource) {
				continue
			}
			return false
		}
		total += len(data)
		t.contents[t.abs(name)] = string(data)
	}
	t.graph = nil
	return true
}

var errNotRegularBundleSource = errors.New("not a regular file")

// readBundleSource reads rel through root: non-blocking, a regular file
// only, at most limit bytes (a longer file is an error).
func readBundleSource(root *os.Root, rel string, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("static/ is too large to check")
	}
	f, err := root.OpenFile(filepath.FromSlash(rel), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegularBundleSource
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("static/ is too large to check")
	}
	return data, nil
}

// entryPoints are the sources /static/<name>.js compiles, sorted.
func (t *bundleTree) entryPoints() []string {
	stems := map[string]string{}
	rank := map[string]int{}
	for abs := range t.names {
		lower := strings.ToLower(abs)
		if strings.HasSuffix(lower, ".d.ts") || pathHasMetadataSidecar(t.rel(abs)) || bundleCheckTestFile(t.rel(abs)) {
			continue
		}
		ext := filepath.Ext(abs)
		for i, want := range bundleCheckEntryExts {
			if ext != want {
				continue
			}
			stem := strings.TrimSuffix(abs, ext)
			if prev, ok := rank[stem]; !ok || i < prev {
				stems[stem], rank[stem] = abs, i
			}
		}
	}
	out := make([]string, 0, len(stems))
	for _, abs := range stems {
		out = append(out, abs)
	}
	sort.Strings(out)
	return out
}

// bundleCheckTestFile reports a test kept beside the code (x.test.ts,
// x.spec.tsx, anything under __tests__/): a local test runner runs it with
// its own modules ("bun:test"); no page loads it, so it is no entry.
func bundleCheckTestFile(rel string) bool {
	if strings.Contains("/"+rel, "/__tests__/") {
		return true
	}
	base := path.Base(rel)
	stem := strings.TrimSuffix(base, path.Ext(base))
	return strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec")
}

// bundleCheckExternals are bare specifiers no static/ file provides: the
// import map's bm and sdui (browserBundleOptions), and the MCP Apps module a
// connector widget component imports, which the widget build supplies
// (mcp_apps_widget.go). Components live in static/ and would otherwise read
// as broken browser bundles.
var bundleCheckExternals = []string{"bm", "sdui", mcpAppsSpecifier, mcpAppsVendorSpecifier}

// bundleImportSpecifiers finds module specifiers: `from "x"`, `import "x"`,
// `import("x")`, `require("x")` and CSS `@import "x"`. It over-matches
// (text in comments and strings), which only widens the entries checked. A
// literal scan: the gate runs it over every script of static/ on each write,
// and a regexp took 230-300 ms over the largest apps' 8-10 MB (this, ~10 ms).
func bundleImportSpecifiers(src string) []string {
	var out []string
	for _, kw := range []string{"from", "import", "require"} {
		for i := 0; ; {
			j := strings.Index(src[i:], kw)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(kw)
			if at > 0 && bundleIdentByte(src[at-1]) || i < len(src) && bundleIdentByte(src[i]) {
				continue
			}
			k := i
			for k < len(src) && (src[k] == ' ' || src[k] == '\t' || src[k] == '\n' || src[k] == '\r') {
				k++
			}
			if k < len(src) && src[k] == '(' {
				k++
				for k < len(src) && (src[k] == ' ' || src[k] == '\t' || src[k] == '\n' || src[k] == '\r') {
					k++
				}
			}
			if k >= len(src) || (src[k] != '"' && src[k] != '\'' && src[k] != '`') {
				continue
			}
			quote := src[k]
			end := strings.IndexAny(src[k+1:], string(quote)+"\r\n")
			if end < 0 || src[k+1+end] != quote {
				continue
			}
			spec := src[k+1 : k+1+end]
			if quote == '`' && strings.Contains(spec, "${") {
				continue
			}
			out = append(out, spec)
		}
	}
	return out
}

func bundleIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// bundleScriptExts are extensions an import may name for a script esbuild
// resolves under another one ("./x.js" finds x.ts).
var bundleScriptExts = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true}

// bundleImportGraph maps a possible import target to the files whose
// relative specifiers could name it.
type bundleImportGraph struct {
	importers map[string][]string // target key → importing files
	wildcard  []string            // files with a bare specifier: they may import anything
}

func (t *bundleTree) importGraph() *bundleImportGraph {
	if t.graph != nil {
		return t.graph
	}
	g := &bundleImportGraph{importers: map[string][]string{}}
	files := make([]string, 0, len(t.contents))
	for abs := range t.contents {
		files = append(files, abs)
	}
	sort.Strings(files)
	for _, abs := range files {
		if !t.names[abs] || !bundleCheckContentExts[strings.ToLower(filepath.Ext(abs))] || strings.ToLower(filepath.Ext(abs)) == ".json" {
			continue
		}
		wildcard := false
		seen := map[string]bool{}
		for _, spec := range bundleImportSpecifiers(t.contents[abs]) {
			if i := strings.IndexAny(spec, "?#"); i >= 0 {
				spec = spec[:i]
			}
			switch {
			case spec == "" || slices.Contains(bundleCheckExternals, spec):
			case spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
				base := filepath.Clean(filepath.Join(filepath.Dir(abs), filepath.FromSlash(spec)))
				keys := []string{base, base + string(filepath.Separator) + "index"}
				if bundleScriptExts[strings.ToLower(filepath.Ext(base))] {
					keys = append(keys, strings.TrimSuffix(base, filepath.Ext(base)))
				}
				for _, k := range keys {
					if !seen[k] {
						seen[k] = true
						g.importers[k] = append(g.importers[k], abs)
					}
				}
			case strings.HasPrefix(spec, "/") || strings.Contains(spec, ":"):
				// An absolute path (outside static/ unless written out in
				// full) or a URL.
			default:
				wildcard = true
			}
		}
		if wildcard {
			g.wildcard = append(g.wildcard, abs)
		}
	}
	t.graph = g
	return g
}

// affectedEntries are the entries whose bundles include rel or may: rel
// itself if it is an entry, and every entry from which rel can be reached
// through imports. Call it after readContents.
func (t *bundleTree) affectedEntries(rel string) []string {
	g := t.importGraph()
	start := t.abs(rel)
	visited := map[string]bool{start: true}
	queue := []string{start}
	wildcards := false
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		keys := []string{n}
		if ext := filepath.Ext(n); ext != "" {
			keys = append(keys, strings.TrimSuffix(n, ext))
		}
		var next []string
		for _, k := range keys {
			next = append(next, g.importers[k]...)
		}
		if !wildcards {
			wildcards = true
			next = append(next, g.wildcard...)
		}
		for _, imp := range next {
			if !visited[imp] {
				visited[imp] = true
				queue = append(queue, imp)
			}
		}
	}
	var out []string
	for _, e := range t.entryPoints() {
		if visited[e] {
			out = append(out, e)
		}
	}
	return out
}

// inputFiles is the build's captured filesystem: every file of static/ (a
// file no loader reads is empty) and the app's root configuration.
func (t *bundleTree) inputFiles() map[string]string {
	files := make(map[string]string, len(t.names)+len(bundleCheckRootConfigs))
	for abs := range t.names {
		files[abs] = t.contents[abs]
	}
	for _, name := range bundleCheckRootConfigs {
		if data, ok := t.contents[t.abs(name)]; ok {
			files[t.abs(name)] = data
		}
	}
	return files
}

// bundleProblem is one build error.
type bundleProblem struct {
	file        string // app-relative, slash-separated; "" when the message names none
	line, col   int    // 1-based; 0 when unknown
	text        string
	containment bool // an import that reaches outside static/
}

func (p bundleProblem) String() string {
	switch {
	case p.file == "":
		return p.text
	case p.line > 0:
		return fmt.Sprintf("%s:%d:%d: %s", p.file, p.line, p.col, p.text)
	}
	return p.file + ": " + p.text
}

// bundleCheckMemo keeps recent build results by the digest of their input,
// so the post-write check reuses the gate's build of the same tree.
var bundleCheckMemo = struct {
	sync.Mutex
	m map[string]bundleCheckMemoEntry
}{m: map[string]bundleCheckMemoEntry{}}

type bundleCheckMemoEntry struct {
	problems []bundleProblem
	at       time.Time
}

const bundleCheckMemoTTL = time.Minute
const bundleCheckMemoMax = 64

// bundleCheckBuilds counts esbuild runs of the check (observability for tests).
var bundleCheckBuilds atomic.Uint64

func bundleCheckDigest(files map[string]string, entries []string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "entry\x00%s\x00", e)
	}
	for _, name := range names {
		fmt.Fprintf(h, "file\x00%s\x00%d\x00", name, len(files[name]))
		io.WriteString(h, files[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// build bundles entries against the copy and returns the errors. ok is
// false when the build could not run (no compile slot in time, deadline).
func (t *bundleTree) build(entries []string) ([]bundleProblem, bool) {
	if len(entries) == 0 {
		return nil, true
	}
	files := t.inputFiles()
	key := bundleCheckDigest(files, entries)
	now := time.Now()
	bundleCheckMemo.Lock()
	if e, ok := bundleCheckMemo.m[key]; ok && now.Sub(e.at) < bundleCheckMemoTTL {
		bundleCheckMemo.Unlock()
		return e.problems, true
	}
	bundleCheckMemo.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), bundleCheckTimeout)
	defer cancel()
	release, err := acquireCompileSlot(ctx)
	if err != nil {
		return nil, false
	}
	defer release()
	bundleCheckBuilds.Add(1)
	opts := browserBundleOptions(entries[0], t.staticRoot)
	opts.EntryPoints = entries
	opts.External = bundleCheckExternals
	opts.AbsWorkingDir = t.staticRoot
	// Several entries need an output directory; nothing is written
	// (Write: false) and no input lives there.
	opts.Outdir = filepath.Join(t.appDir, ".benmore-bundle-check")
	opts.Metafile = false
	opts.Sourcemap = esbuild.SourceMapNone
	opts.InputFiles = files
	// Shared modules go to shared chunks instead of into every entry's
	// output: the full check of 200 entries over 8 MB of source allocated
	// 430 MiB without it and 160 MiB with it. The runtime links each entry on
	// its own, so errors are taken from a build without splitting, run only
	// when the split build reports any (an error is never one splitting
	// alone produces).
	opts.Splitting = true
	result, err := buildAppSources(ctx, opts)
	if err == nil && len(result.Errors) > 0 {
		opts.Splitting = false
		result, err = buildAppSources(ctx, opts)
	}
	if err != nil {
		return nil, false
	}
	var problems []bundleProblem
	for _, m := range redactOutsideBuildMessages(result.Errors, t.staticRoot, t.staticRoot) {
		p := bundleProblem{text: m.Text,
			containment: m.PluginName == staticContainmentPluginName || strings.Contains(m.Text, errOutsideStatic.Error())}
		if m.Location != nil && m.Location.File != "" {
			file := filepath.FromSlash(m.Location.File)
			if !filepath.IsAbs(file) {
				file = filepath.Join(t.staticRoot, file)
			}
			p.file = t.rel(filepath.Clean(file))
			if p.file != "" && m.Location.Line > 0 {
				p.line, p.col = m.Location.Line, m.Location.Column+1
			}
		}
		problems = append(problems, p)
	}
	bundleCheckMemo.Lock()
	if len(bundleCheckMemo.m) >= bundleCheckMemoMax {
		for k, e := range bundleCheckMemo.m {
			if now.Sub(e.at) >= bundleCheckMemoTTL || len(bundleCheckMemo.m) >= bundleCheckMemoMax {
				delete(bundleCheckMemo.m, k)
			}
		}
	}
	bundleCheckMemo.m[key] = bundleCheckMemoEntry{problems: problems, at: now}
	bundleCheckMemo.Unlock()
	return problems, true
}

// bundleSourceChange reports whether a change to rel (app-relative) can change
// a browser bundle's build: a file under static/ a build reads.
func bundleSourceChange(rel string) bool {
	return strings.HasPrefix(rel, "static/") && bundleCheckContentExts[strings.ToLower(path.Ext(rel))]
}

// bundleRootConfig reports the app-root files every bundle's resolution reads.
func bundleRootConfig(rel string) bool {
	for _, name := range bundleCheckRootConfigs {
		if rel == name {
			return true
		}
	}
	return false
}

// bundleWriteRefusal is the write gate's bundle check: it builds the entries
// a write of content to rel affects, as the write leaves static/, and
// refuses errors located in rel (only imports outside static/ when the write
// is deferred). "" when nothing is refused or the tree cannot be judged.
func bundleWriteRefusal(appDir, rel, content string, deferred bool) string {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if appDir == "" || !bundleSourceChange(rel) {
		return ""
	}
	t, ok := loadBundleTree(appDir)
	if !ok {
		return ""
	}
	t.set(rel, &content)
	if len(t.entryPoints()) == 0 || !t.readContents() {
		return ""
	}
	problems, ok := t.build(t.affectedEntries(rel))
	if !ok {
		return ""
	}
	var own []bundleProblem
	for _, p := range problems {
		if p.file != rel || deferred && !p.containment {
			continue
		}
		own = append(own, p)
	}
	if len(own) == 0 {
		return ""
	}
	served := ""
	for _, ext := range bundleCheckEntryExts {
		if strings.HasSuffix(rel, ext) && !strings.HasSuffix(strings.ToLower(rel), ".d.ts") {
			served = " (/" + strings.TrimSuffix(rel, ext) + ".js)"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: the browser bundle%s cannot build with this file, so every page loading a bundle that includes it would get a module that throws instead:\n", rel, served)
	writeBundleProblems(&b, own)
	writeBundleHints(&b, own)
	b.WriteString("Fix the file and write it again.")
	return b.String()
}

var bundleUnresolvedRe = regexp.MustCompile(`^Could not resolve "([^"]*)"`)

// writeBundleHints adds what to do about each kind of problem listed.
func writeBundleHints(b *strings.Builder, problems []bundleProblem) {
	var containment, relative, bare, export bool
	for _, p := range problems {
		switch m := bundleUnresolvedRe.FindStringSubmatch(p.text); {
		case p.containment:
			containment = true
		case m != nil && (strings.HasPrefix(m[1], ".") || strings.HasPrefix(m[1], "/")):
			relative = true
		case m != nil:
			bare = true
		case strings.HasPrefix(p.text, "No matching export"):
			export = true
		}
	}
	if containment {
		b.WriteString("A bundle is public, so it may only import files inside static/: move what it needs into static/, or read it on the server (a flow) and fetch it.\n")
	}
	if relative {
		b.WriteString("An import must name a file the server has: push the imported file first, then the file that imports it.\n")
	}
	if bare {
		b.WriteString("Packages are not installed: only files inside static/ are bundled (bm and sdui come from the page's import map). Copy the module into static/ or import it by its full CDN URL (api(at:\"frontend\") cdn_imports). JSX elements import react/jsx-runtime, which no app provides: build markup with template strings.\n")
	}
	if export {
		b.WriteString("A named import must be exported by the module it names.\n")
	}
}

func writeBundleProblems(b *strings.Builder, problems []bundleProblem) {
	for i, p := range problems {
		if i == bundleCheckShown {
			fmt.Fprintf(b, "  ... and %d more\n", len(problems)-i)
			break
		}
		fmt.Fprintf(b, "  %s\n", p)
	}
}

// bundleDeleteRefusal refuses removing rel when that makes another file's
// bundle fail: it still imports rel. Errors that were there before the
// delete are not its doing.
func bundleDeleteRefusal(appDir, rel string) string {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if appDir == "" || !strings.HasPrefix(rel, "static/") {
		return ""
	}
	t, ok := loadBundleTree(appDir)
	if !ok || !t.names[t.abs(rel)] || len(t.entryPoints()) == 0 || !t.readContents() {
		return ""
	}
	var entries []string
	for _, e := range t.affectedEntries(rel) {
		if e != t.abs(rel) {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return ""
	}
	before, ok := t.build(entries)
	if !ok {
		return ""
	}
	t.set(rel, nil)
	after, ok := t.build(entries)
	if !ok {
		return ""
	}
	had := map[string]bool{}
	for _, p := range before {
		had[p.String()] = true
	}
	var caused []bundleProblem
	for _, p := range after {
		if !had[p.String()] {
			caused = append(caused, p)
		}
	}
	if len(caused) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to delete %s: other scripts still import it, and the browser bundles that include them could no longer build (their pages would get a module that throws):\n", rel)
	writeBundleProblems(&b, caused)
	b.WriteString("Remove or change those imports first (push the importing files), or delete the importing files first, then delete this file.")
	return b.String()
}

// bundleCheckFindings builds every entry (writtenPath "", a full check) or
// the entries a write of writtenPath affects, as static/ is now, and reports
// each build error on the file it is located in. skip names files already
// reported as unparsable, whose parse errors the build would repeat.
func bundleCheckFindings(dir, writtenPath string, skip map[string]bool) []CheckFinding {
	rel := filepath.ToSlash(filepath.Clean(writtenPath))
	if writtenPath != "" && !bundleSourceChange(rel) && !bundleRootConfig(rel) {
		return nil
	}
	t, ok := loadBundleTree(dir)
	if !ok || len(t.entryPoints()) == 0 || !t.readContents() {
		return nil
	}
	entries := t.entryPoints()
	if writtenPath != "" && bundleSourceChange(rel) {
		entries = t.affectedEntries(rel)
	}
	problems, ok := t.build(entries)
	if !ok {
		return nil
	}
	byFile := map[string][]bundleProblem{}
	var files []string
	for _, p := range problems {
		if skip[p.file] {
			continue
		}
		if _, seen := byFile[p.file]; !seen {
			files = append(files, p.file)
		}
		byFile[p.file] = append(byFile[p.file], p)
	}
	var findings []CheckFinding
	for _, file := range files {
		var b strings.Builder
		where := file
		if where == "" {
			where = "static/"
		}
		fmt.Fprintf(&b, "a browser bundle that includes %s cannot build, so its page gets a module that throws instead:\n", where)
		writeBundleProblems(&b, byFile[file])
		writeBundleHints(&b, byFile[file])
		findings = append(findings, CheckFinding{Severity: "error", Source: "bundle", File: file, Message: strings.TrimRight(b.String(), "\n")})
	}
	return findings
}
