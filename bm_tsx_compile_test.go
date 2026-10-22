//go:build !cli

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetTSXCache clears the process-wide compile cache so tests don't
// see each other's entries.
func resetTSXCache() {
	tsxCacheMu.Lock()
	tsxCache = map[string]*tsxCacheEntry{}
	tsxCacheMu.Unlock()
}

// touch sets a file's mtime to a fixed instant so the test controls
// freshness deterministically (avoids same-second mtime collisions).
func touch(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// TestCompileInvalidatesOnImportedModuleEdit is the regression test for
// the stale-bundle bug: editing an imported module (not the entry)
// must invalidate the cached compile. Pre-fix the cache keyed only on
// the entry's mtime, so this returned the stale first bundle.
func TestCompileInvalidatesOnImportedModuleEdit(t *testing.T) {
	resetTSXCache()
	dir := t.TempDir()

	entry := filepath.Join(dir, "app.tsx")
	dep := filepath.Join(dir, "boards.tsx")

	if err := os.WriteFile(dep, []byte(`export const label = "FIRST_VERSION";`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte(`import { label } from "./boards";`+"\n"+`console.log(label);`), 0o644); err != nil {
		t.Fatal(err)
	}

	t0 := time.Now().Add(-1 * time.Hour)
	touch(t, dep, t0)
	touch(t, entry, t0)

	first, err := compileTSXOrTS(entry, filepath.Dir(entry))
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	if !bytes.Contains(first, []byte("FIRST_VERSION")) {
		t.Fatalf("first bundle missing FIRST_VERSION:\n%s", first)
	}

	// Edit ONLY the imported module, leaving the entry's mtime untouched.
	if err := os.WriteFile(dep, []byte(`export const label = "SECOND_VERSION";`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, dep, t0.Add(10*time.Minute)) // entry stays at t0
	touch(t, entry, t0)

	second, err := compileTSXOrTS(entry, filepath.Dir(entry))
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if bytes.Contains(second, []byte("FIRST_VERSION")) || !bytes.Contains(second, []byte("SECOND_VERSION")) {
		t.Fatalf("stale bundle served after editing imported module - got:\n%s", second)
	}
}

// TestCompileCacheHitWhenUnchanged confirms we still serve from cache
// (no needless recompile) when nothing in the graph changed: the cached
// entry must be byte-identical and remain the same *instance*.
func TestCompileCacheHitWhenUnchanged(t *testing.T) {
	resetTSXCache()
	dir := t.TempDir()
	entry := filepath.Join(dir, "app.tsx")
	if err := os.WriteFile(entry, []byte(`console.log("hi");`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, entry, time.Now().Add(-time.Hour))

	if _, err := compileTSXOrTS(entry, filepath.Dir(entry)); err != nil {
		t.Fatalf("first compile: %v", err)
	}
	tsxCacheMu.RLock()
	firstEntry := tsxCache[entry]
	tsxCacheMu.RUnlock()
	if firstEntry == nil {
		t.Fatal("expected cache entry after first compile")
	}

	if _, err := compileTSXOrTS(entry, filepath.Dir(entry)); err != nil {
		t.Fatalf("second compile: %v", err)
	}
	tsxCacheMu.RLock()
	secondEntry := tsxCache[entry]
	tsxCacheMu.RUnlock()
	if firstEntry != secondEntry {
		t.Fatal("cache entry was replaced even though nothing changed (false invalidation)")
	}

	// The entry's tracked inputs should include the entry file itself.
	if _, ok := secondEntry.inputs[entry]; !ok {
		t.Fatalf("tracked inputs missing the entry file; got %v", secondEntry.inputs)
	}
}

// TestCompileInvalidatesOnEntryEdit keeps the original behavior honest:
// editing the entry still invalidates.
func TestCompileInvalidatesOnEntryEdit(t *testing.T) {
	resetTSXCache()
	dir := t.TempDir()
	entry := filepath.Join(dir, "app.tsx")
	if err := os.WriteFile(entry, []byte(`console.log("ALPHA");`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, entry, time.Now().Add(-time.Hour))
	first, _ := compileTSXOrTS(entry, filepath.Dir(entry))
	if !bytes.Contains(first, []byte("ALPHA")) {
		t.Fatalf("first bundle missing ALPHA:\n%s", first)
	}

	if err := os.WriteFile(entry, []byte(`console.log("BETA");`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, entry, time.Now().Add(-30*time.Minute))
	second, _ := compileTSXOrTS(entry, filepath.Dir(entry))
	if !bytes.Contains(second, []byte("BETA")) || bytes.Contains(second, []byte("ALPHA")) {
		t.Fatalf("entry edit not picked up - got:\n%s", second)
	}
}

// The compiled bundle is public (/static/app.js, cached by the CDN), so an
// import that reaches outside static/ must never inline that file into it.
func TestTSXBundleRefusesImportsOutsideStatic(t *testing.T) {
	app := t.TempDir()
	static := filepath.Join(app, "static")
	if err := os.MkdirAll(filepath.Join(static, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), []byte("STRIPE_KEY: TSX-LEAKED-SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "lib", "ok.ts"), []byte(`export const ok = "INSIDE-STATIC";`), 0o644); err != nil {
		t.Fatal(err)
	}
	leak := filepath.Join(static, "leak.tsx")
	if err := os.WriteFile(leak, []byte("import s from '../env.yaml' with { type: 'text' };\nconsole.log(s);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := compileTSXOrTS(leak, static)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "TSX-LEAKED-SECRET") || !strings.Contains(string(out), "outside static/") {
		t.Fatalf("bundle must refuse the import instead of inlining it:\n%s", out)
	}
	fine := filepath.Join(static, "fine.tsx")
	if err := os.WriteFile(fine, []byte("import { ok } from './lib/ok';\nconsole.log(ok);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = compileTSXOrTS(fine, static)
	if err != nil || !strings.Contains(string(out), "INSIDE-STATIC") {
		t.Fatalf("imports inside static/ must still bundle: %v\n%s", err, out)
	}
}

// A compile error in an imported module must clear as soon as that module is
// fixed. The failed build used to be cached against the entry file alone, so
// fixing the import kept serving the stale error until the entry was edited.
func TestTSXCompileErrorInImportClearsWhenImportIsFixed(t *testing.T) {
	resetTSXCache()
	dir := t.TempDir()
	entry := filepath.Join(dir, "app.tsx")
	dep := filepath.Join(dir, "board.tsx")
	if err := os.WriteFile(entry, []byte(`import { label } from "./board";`+"\n"+`console.log(label);`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dep, []byte(`export const label = ;`), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour)
	touch(t, entry, t0)
	touch(t, dep, t0)
	broken, err := compileTSXOrTS(entry, dir)
	if err != nil || !strings.Contains(string(broken), "[bm-tsx-compile]") {
		t.Fatalf("expected a compile-error module, got err=%v body=%s", err, broken)
	}
	if err := os.WriteFile(dep, []byte(`export const label = "FIXED_IMPORT";`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, dep, t0.Add(time.Minute))
	fixed, err := compileTSXOrTS(entry, dir)
	if err != nil || !strings.Contains(string(fixed), "FIXED_IMPORT") {
		t.Fatalf("fixing the imported file did not clear the cached error:\n%s", fixed)
	}
}

// An import that doesn't resolve yet names no file whose mtime can change, so
// a cached failure must expire on its own once the missing file appears.
func TestTSXUnresolvedImportErrorExpires(t *testing.T) {
	resetTSXCache()
	old := tsxErrorCacheTTL
	tsxErrorCacheTTL = 0
	t.Cleanup(func() { tsxErrorCacheTTL = old })
	dir := t.TempDir()
	entry := filepath.Join(dir, "app.tsx")
	if err := os.WriteFile(entry, []byte(`import { label } from "./later";`+"\n"+`console.log(label);`), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, _ := compileTSXOrTS(entry, dir); !strings.Contains(string(body), "[bm-tsx-compile]") {
		t.Fatalf("expected a compile-error module: %s", body)
	}
	if err := os.WriteFile(filepath.Join(dir, "later.tsx"), []byte(`export const label = "NOW_RESOLVED";`), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, _ := compileTSXOrTS(entry, dir); !strings.Contains(string(body), "NOW_RESOLVED") {
		t.Fatalf("creating the missing import did not clear the cached error:\n%s", body)
	}
}
