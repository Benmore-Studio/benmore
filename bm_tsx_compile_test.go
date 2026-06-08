//go:build !cli

package main

import (
	"bytes"
	"os"
	"path/filepath"
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

	first, err := compileTSXOrTS(entry)
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

	second, err := compileTSXOrTS(entry)
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if bytes.Contains(second, []byte("FIRST_VERSION")) || !bytes.Contains(second, []byte("SECOND_VERSION")) {
		t.Fatalf("stale bundle served after editing imported module — got:\n%s", second)
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

	if _, err := compileTSXOrTS(entry); err != nil {
		t.Fatalf("first compile: %v", err)
	}
	tsxCacheMu.RLock()
	firstEntry := tsxCache[entry]
	tsxCacheMu.RUnlock()
	if firstEntry == nil {
		t.Fatal("expected cache entry after first compile")
	}

	if _, err := compileTSXOrTS(entry); err != nil {
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
	first, _ := compileTSXOrTS(entry)
	if !bytes.Contains(first, []byte("ALPHA")) {
		t.Fatalf("first bundle missing ALPHA:\n%s", first)
	}

	if err := os.WriteFile(entry, []byte(`console.log("BETA");`), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, entry, time.Now().Add(-30*time.Minute))
	second, _ := compileTSXOrTS(entry)
	if !bytes.Contains(second, []byte("BETA")) || bytes.Contains(second, []byte("ALPHA")) {
		t.Fatalf("entry edit not picked up — got:\n%s", second)
	}
}
