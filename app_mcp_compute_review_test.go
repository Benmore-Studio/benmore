//go:build !cli

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestAppMCPReviewedComputeAcceptsExactColdCacheHashes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "static/entry.ts", `import { value } from "./dependency"; export function result() { return value; }`)
	writeTestFile(t, dir, "static/dependency.ts", `export const value = "reviewed";`)

	reviewed := map[string]string{}
	for _, path := range []string{"static/entry.ts", "static/dependency.ts"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		reviewed[path] = hashBytesSHA256(data)
	}

	program, err := compileComputeModule(filepath.Join(dir, "static/entry.ts"), filepath.Join(dir, "static"), reviewed)
	if err != nil {
		t.Fatalf("compile staged module: %v", err)
	}
	vm := goja.New()
	got, err := runComputeInVM(vm, program, "result", "entry.ts", nil)
	if err != nil || got != "reviewed" {
		t.Fatalf("reviewed module result = %#v, %v; want reviewed", got, err)
	}
}

func TestAppMCPReviewedComputeAcceptsRelativeAllowedRoot(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "static/entry.ts", `import { value } from "./dependency"; export function result() { return value; }`)
	writeTestFile(t, dir, "static/dependency.ts", `export const value = "reviewed";`)

	reviewed := map[string]string{}
	for _, path := range []string{"static/entry.ts", "static/dependency.ts"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		reviewed[path] = hashBytesSHA256(data)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeDir, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}

	program, err := compileComputeModule(filepath.Join(dir, "static/entry.ts"), filepath.Join(relativeDir, "static"), reviewed)
	if err != nil {
		t.Fatalf("compile with relative allowed root: %v", err)
	}
	got, err := runComputeInVM(goja.New(), program, "result", "entry.ts", nil)
	if err != nil || got != "reviewed" {
		t.Fatalf("relative-root module result = %#v, %v; want reviewed", got, err)
	}
}

func TestAppMCPReviewedComputeRejectsChangedSources(t *testing.T) {
	for _, changed := range []string{"static/entry.ts", "static/dependency.ts"} {
		for _, warmCache := range []bool{false, true} {
			t.Run(filepath.Base(changed)+map[bool]string{false: "/cold", true: "/ordinary-cache"}[warmCache], func(t *testing.T) {
				dir := t.TempDir()
				entry := filepath.Join(dir, "static/entry.ts")
				root := filepath.Join(dir, "static")
				writeTestFile(t, dir, "static/entry.ts", `import { value } from "./dependency"; export function result() { return value; }`)
				writeTestFile(t, dir, "static/dependency.ts", `export const value = "original";`)

				reviewed := map[string]string{}
				for _, path := range []string{"static/entry.ts", "static/dependency.ts"} {
					data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
					if err != nil {
						t.Fatal(err)
					}
					reviewed[path] = hashBytesSHA256(data)
				}
				writeTestFile(t, dir, changed, `export const value = "changed";`)
				if warmCache {
					if _, err := CompileComputeModule(entry, root); err != nil {
						t.Fatalf("populate unreviewed ordinary compute cache: %v", err)
					}
				}
				if _, err := compileComputeModule(entry, root, reviewed); err == nil {
					t.Fatalf("accepted changed %s with warmCache=%t", changed, warmCache)
				}
			})
		}
	}
}

func TestOrdinaryComputeModuleStillCompilesAndRuns(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "static/entry.ts")
	root := filepath.Join(dir, "static")
	writeTestFile(t, dir, "static/entry.ts", `import { value } from "./dependency"; export function result() { return value; }`)
	writeTestFile(t, dir, "static/dependency.ts", `export const value = "ordinary";`)

	program, err := CompileComputeModule(entry, root)
	if err != nil {
		t.Fatalf("ordinary compile: %v", err)
	}
	got, err := runComputeInVM(goja.New(), program, "result", "entry.ts", nil)
	if err != nil || got != "ordinary" {
		t.Fatalf("ordinary module result = %#v, %v; want ordinary", got, err)
	}
}

func TestAppMCPReviewedComputeContextUsesStagedGeneration(t *testing.T) {
	dir := t.TempDir()
	original := `export function result() { return "reviewed"; }`
	writeTestFile(t, dir, "static/entry.ts", original)
	manifest := &AppMCPManifest{sourceHashes: map[string]string{"static/entry.ts": hashBytesSHA256([]byte(original))}}
	app := &App{Dir: dir, MCP: manifest, sourceFiles: map[string][]byte{"static/entry.ts": []byte(original)}}
	ctx := context.WithValue(context.Background(), appMCPPrivateFlowKey{}, &appMCPPrivateFlow{app: app, manifest: manifest})
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("reviewed context: %#v %v", got, err)
	}
	writeTestFile(t, dir, "static/entry.ts", `export function result() { return "unreviewed"; }`)
	if got, err := RunCompute(app, "entry", "result", nil, time.Second); err != nil || got != "unreviewed" {
		t.Fatalf("ordinary changed context: %#v %v", got, err)
	}
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("private context failed to retain captured generation against ordinary cache: %#v %v", got, err)
	}
	writeTestFile(t, dir, "static/entry.ts", original)
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != "reviewed" {
		t.Fatalf("restored reviewed context: %#v %v", got, err)
	}
	app.MCP = &AppMCPManifest{sourceHashes: manifest.sourceHashes}
	if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err == nil || got != nil {
		t.Fatalf("replaced generation accepted: %#v %v", got, err)
	}
}

func TestAppMCPReviewedComputePreservesConflictingLoadedFingerprint(t *testing.T) {
	hashes := map[string]string{}
	path := filepath.Join(t.TempDir(), "dependency.ts")
	unreviewed := hashBytesSHA256([]byte("unreviewed entry bytes"))
	reviewed := hashBytesSHA256([]byte("reviewed dependency bytes"))
	if err := recordComputeSourceFingerprint(hashes, path, unreviewed); err != nil {
		t.Fatal(err)
	}
	if err := recordComputeSourceFingerprint(hashes, path, reviewed); err == nil {
		t.Fatal("alias collision erased an unreviewed compiled input")
	}
	if hashes[path] != unreviewed {
		t.Fatal("rejected collision changed earlier fingerprint")
	}
	if err := recordComputeSourceFingerprint(hashes, path, unreviewed); err != nil {
		t.Fatalf("same-byte alias rejected: %v", err)
	}
}
