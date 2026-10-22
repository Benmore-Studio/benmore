//go:build !cli

package main

// Build-time containment for esbuild bundles of app code.
//
// Browser bundles (bm_tsx_compile.go) are public and CDN-cached, and compute
// modules (compute.go) must stay pure functions of their inputs, so neither
// may read a file outside the app's static/ directory. Checking the bundled
// inputs after a successful build is not enough: a FAILED build is still
// served, as a module that throws esbuild's messages, and a parse error
// quotes the file it tried to read. Importing `../.benmore/server-secret` as
// JSON therefore published the secret inside the error text.
//
// staticContainmentPlugin refuses such files before esbuild reads them:
//   - at resolve time, a path-like import (relative or absolute) whose target
//     lies outside static/ (symlinks followed) is refused without touching it;
//   - at load time, any file esbuild resolved by other means (a bare package
//     specifier, a tsconfig path alias) is refused if it lies outside
//     static/, so its bytes are never loaded.
//
// redactOutsideBuildMessages is the second layer for failed builds: a message
// located in a file outside static/ (esbuild still reads tsconfig.json and
// package.json files up the directory tree while resolving) keeps no text,
// line or location. The post-build input checks stay as a third layer.

import (
	"errors"
	"path/filepath"
	"strings"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

const staticContainmentPluginName = "benmore-static-containment"

// errOutsideStatic is the refusal both builds report; callers and tests match
// "outside static/".
var errOutsideStatic = errors.New("refusing to read a file outside static/: bundles may only import files inside the app's static/ directory")

// outsideStaticBuildMessage replaces the text of a message located outside
// static/.
const outsideStaticBuildMessage = "a file outside static/ failed to build (details withheld); bundles may only use files inside the app's static/ directory"

// containmentRoot returns root with symlinks resolved, for comparisons.
func containmentRoot(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	if capturedCompilerFiles != nil {
		return abs
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

// realPathForContainment resolves path's symlinks without reading any file:
// the deepest existing ancestor is resolved and the missing rest appended.
func realPathForContainment(path string) string {
	path = filepath.Clean(path)
	if capturedCompilerFiles != nil {
		return path
	}
	rest := ""
	for p := path; ; {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// insideContainmentRoot reports whether path (symlinks followed) lies inside
// rootReal, a containmentRoot result.
func insideContainmentRoot(rootReal, path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	return pathWithinDir(rootReal, realPathForContainment(path))
}

// staticContainmentPlugin refuses every import that would read a file outside
// root (the app's static/ directory).
func staticContainmentPlugin(root string) esbuild.Plugin {
	rootReal := containmentRoot(root)
	return esbuild.Plugin{
		Name: staticContainmentPluginName,
		Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: ".*"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				if args.Namespace != "file" && args.Namespace != "" {
					return esbuild.OnResolveResult{}, nil
				}
				spec := args.Path
				if i := strings.IndexAny(spec, "?#"); i >= 0 {
					spec = spec[:i]
				}
				var target string
				switch {
				case filepath.IsAbs(spec):
					target = spec
				case spec == "." || spec == ".." || strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
					if args.ResolveDir == "" {
						return esbuild.OnResolveResult{}, errOutsideStatic
					}
					target = filepath.Join(args.ResolveDir, spec)
				default:
					// A bare specifier: esbuild resolves it, and the load
					// callback below refuses the file if it lies outside.
					return esbuild.OnResolveResult{}, nil
				}
				if !insideContainmentRoot(rootReal, target) {
					return esbuild.OnResolveResult{}, errOutsideStatic
				}
				return esbuild.OnResolveResult{}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				if args.Namespace != "file" {
					return esbuild.OnLoadResult{}, nil
				}
				if !insideContainmentRoot(rootReal, args.Path) {
					return esbuild.OnLoadResult{}, errOutsideStatic
				}
				// No contents: esbuild loads the file itself.
				return esbuild.OnLoadResult{}, nil
			})
		},
	}
}

// redactOutsideBuildMessages returns msgs with every message located in a
// file outside root stripped of its text, notes and location. workingDir is
// the build's AbsWorkingDir, against which esbuild reports relative paths.
func redactOutsideBuildMessages(msgs []esbuild.Message, root, workingDir string) []esbuild.Message {
	rootReal := containmentRoot(root)
	out := make([]esbuild.Message, 0, len(msgs))
	for _, m := range msgs {
		if m.Location != nil && m.Location.File != "" && !buildMessageFileInside(rootReal, m.Location.File, workingDir) {
			m = esbuild.Message{ID: m.ID, PluginName: m.PluginName, Text: outsideStaticBuildMessage}
		}
		out = append(out, m)
	}
	return out
}

func buildMessageFileInside(rootReal, file, workingDir string) bool {
	if !filepath.IsAbs(file) {
		file = filepath.Join(workingDir, file)
	}
	return insideContainmentRoot(rootReal, file)
}
