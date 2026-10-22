//go:build !cli

package main

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// appMCPExecutionSourcesRuntime is the mcp.yaml `execution_sources` value that
// binds the execution digest to the files the runtime can load, execute or
// serve. Without it the digest covers the whole tree, as manifests reviewed
// before the field existed do; they keep validating that way until reviewed
// again, and `benmore mcp review` writes this form.
const appMCPExecutionSourcesRuntime = "runtime"

// Top-level files a loader reads by name (stageRuntimeConfig and the loaders
// it feeds, LoadSeeds for `reset-seed`, the favicon route, and the app's own
// tsconfig.json/package.json, which the captured browser/compute builds plant
// beside the sources). Root *.html files are pages (loadPagesFromSources).
var appMCPRuntimeRootFiles = map[string]bool{
	"app.yaml": true, "encrypted.yaml": true, "schema.prisma": true, "schema.sql": true, "schema.yaml": true,
	"hooks.yaml": true, "workflows.yaml": true, "cron.yaml": true, "flows.yaml": true, "validators.yaml": true,
	"admin.yaml": true, "computed.yaml": true, "retention.yaml": true, "head.html": true, "theme.css": true,
	"seeds.sql": true, "favicon.ico": true, "favicon.png": true, "tsconfig.json": true, "package.json": true,
	"mcp.yaml": true,
}

// Top-level directories the runtime reads from. static/ is served and bundled
// and flows/ is loaded whole; emails/ and templates/ are reached by a hook or
// flow `template:` value; the rest are enumerated by their loaders.
var appMCPRuntimeTrees = map[string]bool{
	"static": true, "flows": true, "partials": true, "layouts": true, "i18n": true, "migrations": true,
	"emails": true, "templates": true,
}

// appMCPEnumeratedTrees are read by listing their entries (or through the
// captured set), never by a free-form path, so files pull never writes
// (hidden directories) inside them are not read at runtime.
var appMCPEnumeratedTrees = map[string]bool{"partials": true, "layouts": true, "i18n": true, "migrations": true}

// appMCPSourceScope is the file set an execution digest binds. The zero value
// is the whole-tree form.
type appMCPSourceScope struct {
	runtime bool
	files   []string // declared source files outside the runtime trees
	trees   []string // declared source directories (whole subtree)
}

// appMCPScopeFor derives the scope a manifest's digest was made over. A
// pinned OpenAPI document (connections[].openapi) is runtime input wherever it
// lives, and so are the sibling files its relative $refs name, so its file and
// its directory are part of the set.
func appMCPScopeFor(m *AppMCPManifest) appMCPSourceScope {
	if m == nil || m.ExecutionSources != appMCPExecutionSourcesRuntime {
		return appMCPSourceScope{}
	}
	scope := appMCPSourceScope{runtime: true}
	for _, connection := range m.Connections {
		file := connection.OpenAPI
		if file == "" || !filepath.IsLocal(filepath.FromSlash(file)) {
			continue
		}
		scope.files = append(scope.files, file)
		// A root-level document's directory is the app root: its JSON/YAML
		// files (and those below it) are what its relative $refs can load.
		scope.trees = append(scope.trees, path.Dir(file))
	}
	return scope
}

// version is the Version recorded in the execution fingerprint, so the same
// bytes never hash alike under the two forms.
func (s appMCPSourceScope) version() int {
	if s.runtime {
		return 2
	}
	return 1
}

// excluded reports whether the walk skips p (a whole directory when isDir).
func (s appMCPSourceScope) excluded(p string, isDir bool) bool {
	if appMCPSourceExcluded(p, isDir) {
		return true
	}
	return s.runtime && !s.reads(p, isDir)
}

func (s appMCPSourceScope) reads(p string, isDir bool) bool {
	if s.declared(p, isDir) {
		return true
	}
	first, _, nested := strings.Cut(p, "/")
	name := pullFoldName(first)
	if !nested {
		if isDir {
			return appMCPRuntimeTrees[name]
		}
		return appMCPRuntimeRootFiles[name] || strings.HasSuffix(first, ".html")
	}
	if !appMCPRuntimeTrees[name] {
		return false
	}
	if appMCPEnumeratedTrees[name] {
		probe := p
		if isDir {
			probe += "/x" // a hidden directory denies what is inside it
		}
		return !pullDeniedPath(probe)
	}
	return true
}

// declared reports whether p is, or lies in, a declared source (a directory is
// kept when a declared path is somewhere below it). Inside a declared
// document's directory only JSON/YAML files that pull writes count: those are
// what a relative reference can load, and the directory may be docs/.
func (s appMCPSourceScope) declared(p string, isDir bool) bool {
	for _, file := range s.files {
		if p == file || isDir && strings.HasPrefix(file, p+"/") {
			return true
		}
	}
	for _, tree := range s.trees {
		if tree != "." {
			if isDir && strings.HasPrefix(tree, p+"/") {
				return true
			}
			if p != tree && !strings.HasPrefix(p, tree+"/") {
				continue
			}
		}
		if isDir {
			return !pullDeniedPath(p + "/x")
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json", ".yaml", ".yml":
			return !pullDeniedPath(p)
		}
	}
	return false
}

// appMCPCheckRuntimeRoot refuses a top-level entry that a case-insensitive
// file system would read as a runtime source under another spelling, and one
// of the wrong kind (a directory named like a config file, a file named like a
// source directory), which no loader accepts.
func appMCPCheckRuntimeRoot(p string, isDir bool) error {
	if strings.Contains(p, "/") {
		return nil
	}
	name := pullFoldName(p)
	switch {
	case appMCPRuntimeTrees[name]:
		if p != name {
			return fmt.Errorf("ambiguous authority configuration filename")
		}
		if !isDir {
			return fmt.Errorf("invalid execution source directory")
		}
	case appMCPRuntimeRootFiles[name]:
		if p != name {
			return fmt.Errorf("ambiguous authority configuration filename")
		}
		if isDir {
			return fmt.Errorf("invalid configuration source file")
		}
	}
	return nil
}
