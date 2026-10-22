//go:build !cli

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
)

func appMCPComputeFixture(t *testing.T, files map[string]string) (*App, context.Context) {
	t.Helper()
	dir := t.TempDir()
	captured := make(map[string][]byte, len(files))
	hashes := make(map[string]string, len(files))
	for path, source := range files {
		writeTestFile(t, dir, path, source)
		body := []byte(source)
		captured[path] = body
		hashes[path] = hashBytesSHA256(body)
	}
	manifest := &AppMCPManifest{sourceHashes: hashes}
	app := &App{Dir: dir, MCP: manifest, sourceFiles: captured}
	ctx := context.WithValue(context.Background(), appMCPPrivateFlowKey{}, &appMCPPrivateFlow{app: app, manifest: manifest})
	return app, ctx
}

func TestAppMCPReviewedComputeUsesCapturedPackageMetadata(t *testing.T) {
	for _, warmCache := range []bool{false, true} {
		name := "cold"
		if warmCache {
			name = "ordinary-cache"
		}
		t.Run(name, func(t *testing.T) {
			app, ctx := appMCPComputeFixture(t, map[string]string{
				"static/entry.ts":                           `import { value } from "choice"; export function result() { return value; }`,
				"static/node_modules/choice/package.json":   `{"exports":{".":{"default":"./reviewed.ts"}}}`,
				"static/node_modules/choice/reviewed.ts":    `export const value = "reviewed";`,
				"static/node_modules/choice/alternative.ts": `export const value = "alternative";`,
			})
			writeTestFile(t, app.Dir, "static/node_modules/choice/package.json", `{"exports":{".":{"default":"./alternative.ts"}}}`)
			if warmCache {
				if _, err := CompileComputeModule(filepath.Join(app.Dir, "static/entry.ts"), filepath.Join(app.Dir, "static")); err != nil {
					t.Fatalf("populate ordinary compute cache: %v", err)
				}
			}
			if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
				t.Fatalf("private reviewed result = %#v, %v; want reviewed", got, err)
			}
		})
	}
}

func TestOrdinaryComputeUsesChangedPackageMetadata(t *testing.T) {
	app, _ := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":                           `import { value } from "choice"; export function result() { return value; }`,
		"static/node_modules/choice/package.json":   `{"exports":{".":{"default":"./reviewed.ts"}}}`,
		"static/node_modules/choice/reviewed.ts":    `export const value = "reviewed";`,
		"static/node_modules/choice/alternative.ts": `export const value = "alternative";`,
	})
	writeTestFile(t, app.Dir, "static/node_modules/choice/package.json", `{"exports":{".":{"default":"./alternative.ts"}}}`)
	program, err := CompileComputeModule(filepath.Join(app.Dir, "static/entry.ts"), filepath.Join(app.Dir, "static"))
	if err != nil {
		t.Fatalf("ordinary compile: %v", err)
	}
	if got, err := runComputeInVM(goja.New(), program, "result", "entry.ts", nil); err != nil || got != "alternative" {
		t.Fatalf("ordinary compiled result = %#v, %v; want alternative", got, err)
	}
	if got, err := RunCompute(app, "entry", "result", nil, time.Second); err != nil || got != "alternative" {
		t.Fatalf("ordinary runtime result = %#v, %v; want alternative", got, err)
	}
}

func TestAppMCPReviewedComputeUsesCapturedTSConfig(t *testing.T) {
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":       `import { value } from "@choice"; export function result() { return value; }`,
		"static/tsconfig.json":  `{"compilerOptions":{"baseUrl":".","paths":{"@choice":["reviewed.ts"]}}}`,
		"static/reviewed.ts":    `export const value = "reviewed";`,
		"static/alternative.ts": `export const value = "alternative";`,
	})
	writeTestFile(t, app.Dir, "static/tsconfig.json", `{"compilerOptions":{"baseUrl":".","paths":{"@choice":["alternative.ts"]}}}`)
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("private reviewed result = %#v, %v; want reviewed", got, err)
	}
}

func TestAppMCPReviewedComputeIgnoresLateHigherPrecedenceSource(t *testing.T) {
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":  `import { value } from "./choice"; export function result() { return value; }`,
		"static/choice.js": `export const value = "reviewed";`,
	})
	writeTestFile(t, app.Dir, "static/choice.ts", `export const value = "late";`)
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("private reviewed result = %#v, %v; want reviewed", got, err)
	}
}

// cancelDuringStagingContext triggers a real cancellation after staging starts.
// It makes the loop boundary deterministic without timing a filesystem race.
type cancelDuringStagingContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelDuringStagingContext) Err() error {
	c.checks++
	if c.checks == 5 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestAppMCPCompilerStagingCancelsAndCleansUp(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelDuringStagingContext{Context: parent, cancel: cancel}
	sources := map[string][]byte{"static/entry.js": []byte(`export const value = 1;`)}
	hashes := map[string]string{"static/entry.js": hashBytesSHA256(sources["static/entry.js"])}
	root, cleanup, err := stageAppCompilerSources(ctx, sources, hashes)
	if cleanup != nil {
		cleanup()
	}
	if !errors.Is(err, context.Canceled) || root != "" {
		t.Fatalf("staging = %q, %v; want canceled without a published tree", root, err)
	}
	files, err := os.ReadDir(scratch)
	if err != nil || len(files) != 0 {
		t.Fatalf("canceled staging leaked files: %v, %v", files, err)
	}
}

func TestAppMCPReviewedComputeIgnoresPackageShippedConfig(t *testing.T) {
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":                          `import {value} from "choice"; export function result() { return value; }`,
		"static/node_modules/choice/package.json":  `{"main":"index.js"}`,
		"static/node_modules/choice/index.js":      `export const value = "reviewed";`,
		"static/node_modules/choice/tsconfig.json": `{"extends":"missing-build-only-config"}`,
	})
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("ignored package config result = %#v, %v; want reviewed", got, err)
	}
}

func TestAppMCPCompilerCancellationAfterBuildStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	type outcome struct {
		result esbuild.BuildResult
		err    error
	}
	done := make(chan outcome, 1)
	body := strings.Repeat("void 0;\n", 250000)
	options := esbuild.BuildOptions{
		EntryPoints: []string{"captured-entry"}, Bundle: true, Write: false, LogLevel: esbuild.LogLevelSilent,
		Plugins: []esbuild.Plugin{{Name: "started-captured-fixture", Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: ".*"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: args.Path, Namespace: "captured-fixture"}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "captured-fixture"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				close(started)
				<-ctx.Done()
				return esbuild.OnLoadResult{Contents: &body, Loader: esbuild.LoaderJS}, nil
			})
		}}},
	}
	go func() { result, err := buildAppSources(ctx, options); done <- outcome{result, err} }()
	select {
	case <-started:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("compiler never started captured loading")
	}
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("build error = %v, want canceled", got.err)
		}
		canceled := false
		for _, message := range got.result.Errors {
			canceled = canceled || strings.Contains(message.Text, "build was canceled")
		}
		if !canceled {
			t.Fatalf("native compiler did not observe cancellation: %+v", got.result.Errors)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("started build did not finish cancellation")
	}
}
