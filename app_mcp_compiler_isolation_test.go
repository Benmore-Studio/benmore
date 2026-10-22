//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetCapturedBrowserModules drops compiled browser modules so a test that
// changes the compile environment compiles again.
func resetCapturedBrowserModules() {
	capturedBrowserModules.Lock()
	capturedBrowserModules.bodies, capturedBrowserModules.size = map[string][]byte{}, 0
	capturedBrowserModules.Unlock()
}

func appMCPCompilerBrowserBody(t *testing.T, app *App) string {
	t.Helper()
	resetCapturedBrowserModules()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/entry.js", nil)
	if !serveTSXIfPresent(recorder, request, app, "entry.js") {
		t.Fatal("serveTSXIfPresent did not handle the captured entry")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("captured browser compile status = %d, body: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func TestAppMCPCompilerIgnoresHostileAncestorMetadata(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts": `export const browserMarker = "reviewed-browser-body"; export function result() { return "reviewed-compute-value"; }`,
	})

	computeBefore, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second)
	if err != nil || computeBefore != "reviewed-compute-value" {
		t.Fatalf("reviewed compute before hostile metadata = %#v, %v", computeBefore, err)
	}
	bodyBefore := appMCPCompilerBrowserBody(t, app)
	if !strings.Contains(bodyBefore, "reviewed-browser-body") {
		t.Fatalf("reviewed browser body omitted its exact marker: %s", bodyBefore)
	}

	writeTestFile(t, tmp, "package.json", `{ malformed ancestor package metadata`)
	writeTestFile(t, tmp, "tsconfig.json", `{ malformed ancestor TypeScript metadata`)

	computeAfter, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second)
	if err != nil || computeAfter != "reviewed-compute-value" {
		t.Fatalf("reviewed compute with hostile ancestor metadata = %#v, %v; want reviewed-compute-value", computeAfter, err)
	}
	bodyAfter := appMCPCompilerBrowserBody(t, app)
	if bodyAfter != bodyBefore {
		t.Fatalf("reviewed browser body changed under hostile ancestor metadata\nbefore: %s\nafter:  %s", bodyBefore, bodyAfter)
	}
}

func TestAppMCPCompilerEscapedPathCandidateFallsBackToCapturedSource(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	writeTestFile(t, tmp, "outside/package.json", `{ malformed outside package metadata`)
	writeTestFile(t, tmp, "outside/index.ts", `export const value = "outside-poison";`)
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":      `import { value } from "@choice"; export function result() { return value; }`,
		"static/tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"@choice":["../../../outside","./reviewed.ts"]}}}`,
		"static/reviewed.ts":   `export const value = "reviewed-fallback";`,
	})

	got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second)
	if err != nil || got != "reviewed-fallback" {
		t.Fatalf("reviewed compute with escaped first candidate = %#v, %v; want reviewed-fallback", got, err)
	}
	body := appMCPCompilerBrowserBody(t, app)
	if !strings.Contains(body, "reviewed-fallback") || strings.Contains(body, "outside-poison") {
		t.Fatalf("captured browser body with escaped first candidate = %s; want reviewed fallback without outside poison", body)
	}
}

func TestAppMCPCompilerRejectsMalformedCapturedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    map[string]string
		fixDisk  string
		diskBody string
	}{
		{
			name: "tsconfig",
			files: map[string]string{
				"static/entry.ts":      `import { value } from "@choice"; export function result() { return value; }`,
				"static/tsconfig.json": `{ malformed captured tsconfig`,
				"static/reviewed.ts":   `export const value = "reviewed";`,
			},
			fixDisk:  "static/tsconfig.json",
			diskBody: `{"compilerOptions":{"baseUrl":".","paths":{"@choice":["reviewed.ts"]}}}`,
		},
		{
			name: "package",
			files: map[string]string{
				"static/entry.ts":                         `import { value } from "choice"; export function result() { return value; }`,
				"static/node_modules/choice/package.json": `{ malformed captured package metadata`,
				"static/node_modules/choice/index.ts":     `export const value = "reviewed";`,
			},
			fixDisk:  "static/node_modules/choice/package.json",
			diskBody: `{"main":"index.ts"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			app, ctx := appMCPComputeFixture(t, tc.files)
			writeTestFile(t, app.Dir, tc.fixDisk, tc.diskBody)

			if _, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err == nil {
				t.Fatal("compute accepted malformed captured compiler metadata")
			}
			body := appMCPCompilerBrowserBody(t, app)
			if !strings.Contains(body, "throw new Error(") {
				t.Fatalf("browser body did not throw for malformed captured compiler metadata: %s", body)
			}
		})
	}
}

func TestAppMCPCompilerSupportsCapturedBarePackageExtends(t *testing.T) {
	app, ctx := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts":                                 `import { value } from "@choice"; export function result() { return value; }`,
		"static/tsconfig.json":                            `{"extends":"choice-config"}`,
		"static/node_modules/choice-config/package.json":  `{"name":"choice-config","version":"1.0.0","tsconfig":"tsconfig.json"}`,
		"static/node_modules/choice-config/tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"@choice":["../../reviewed.ts"]}}}`,
		"static/reviewed.ts":                              `export const value = "reviewed-package-config";`,
	})

	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed-package-config" {
		t.Fatalf("reviewed compute with captured package extends = %#v, %v; want reviewed-package-config", got, err)
	}
	if got, err := RunCompute(app, "entry", "result", nil, time.Second); err != nil || got != "reviewed-package-config" {
		t.Fatalf("ordinary compute with package extends = %#v, %v; want reviewed-package-config", got, err)
	}
}

// /static/ is exempt from the request rate limit, so an unchanged reviewed
// generation must not restage its sources and start a compiler child for every
// request of the same module, sequential or concurrent.
func TestAppMCPCompilerBrowserModuleCompilesOncePerGeneration(t *testing.T) {
	resetCapturedBrowserModules()
	app, _ := appMCPComputeFixture(t, map[string]string{
		"static/entry.ts": `export const browserMarker = "compiled-once-" + "per-generation";`,
	})
	before := capturedCompilerRuns.Load()
	serve := func() string {
		recorder := httptest.NewRecorder()
		if !serveTSXIfPresent(recorder, httptest.NewRequest(http.MethodGet, "/static/entry.js", nil), app, "entry.js") || recorder.Code != http.StatusOK {
			t.Errorf("captured entry status = %d", recorder.Code)
		}
		return recorder.Body.String()
	}
	var wg sync.WaitGroup
	bodies := make([]string, 8)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bodies[i] = serve()
		}(i)
	}
	wg.Wait()
	bodies = append(bodies, serve(), serve())
	for _, body := range bodies {
		if body != bodies[0] || !strings.Contains(body, "compiled-once-") {
			t.Fatalf("captured bodies differ or lack the marker: %q vs %q", body, bodies[0])
		}
	}
	if runs := capturedCompilerRuns.Load() - before; runs != 1 {
		t.Fatalf("captured compiler children started = %d, want 1", runs)
	}
}
