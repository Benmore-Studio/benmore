//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Removing the Function global left every function's prototype chain
// pointing at the constructors; each of these compiled a string to code.
func TestComputeFunctionConstructorsUnreachable(t *testing.T) {
	app := writeComputeFixture(t, "ctor.ts", `
		function attempt(f: () => any): string {
			try { const r = f(); return 'escaped: ' + String(r); }
			catch (e: any) { return 'blocked'; }
		}
		export function arrow(): string { return attempt(() => (((() => 0) as any).constructor)('return 41 + 1')()); }
		export function proto(): string { return attempt(() => (Object.getPrototypeOf(function () {}) as any).constructor('return 1')()); }
		export function asyncCtor(): string { return attempt(() => ((async function () {}) as any).constructor('return 1')); }
		export function genCtor(): string { return attempt(() => ((function* () {}) as any).constructor('yield 1')().next().value); }
		export function redefine(): string {
			return attempt(() => { Object.defineProperty(Object.getPrototypeOf(() => 0), 'constructor', { value: 1 }); return 'redefined'; });
		}
		export function ordinary(): number { const f = (x: number) => x * 2; return [1, 2, 3].map(f).reduce((a, b) => a + b, 0); }
	`)
	for _, fn := range []string{"arrow", "proto", "asyncCtor", "genCtor", "redefine"} {
		got, err := RunCompute(app, "ctor", fn, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		if got != "blocked" {
			t.Fatalf("%s: function constructor reachable: %v", fn, got)
		}
	}
	if got, err := RunCompute(app, "ctor", "ordinary", nil, 0); err != nil || got != int64(12) {
		t.Fatalf("ordinary functions must still work: %v %v", got, err)
	}
}

func TestComputeConcurrencyIsBounded(t *testing.T) {
	app := writeComputeFixture(t, "one.ts", `export function one(): number { return 1; }`)
	if _, err := RunCompute(app, "one", "one", nil, 0); err != nil {
		t.Fatal(err)
	}
	// Occupy every slot, as abandoned timed-out goroutines would.
	held := 0
	for len(computeSlots) < cap(computeSlots) {
		computeSlots <- struct{}{}
		held++
	}
	_, err := RunCompute(app, "one", "one", nil, 100*time.Millisecond)
	for ; held > 0; held-- {
		<-computeSlots
	}
	if err == nil || !strings.Contains(err.Error(), "free compute slot") {
		t.Fatalf("want slot-wait timeout, got %v", err)
	}
	if got, err := RunCompute(app, "one", "one", nil, 0); err != nil || got != int64(1) {
		t.Fatalf("after slots free: %v %v", got, err)
	}
}

func TestFileStampDetectsRestoredMtimeEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.ts")
	if err := os.WriteFile(path, []byte("export const a = 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, ok := statFileStamp(path)
	if !ok {
		t.Skip("no ctime on this platform")
	}
	if before.trusted() {
		t.Fatal("a stamp taken right after a write must not be trusted")
	}
	info, _ := os.Stat(path)
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("export const a = 2;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, _ := statFileStamp(path)
	if before.sameFile(after) {
		t.Fatal("same-size edit with restored mtime must change the stamp (ctime)")
	}
	old := fileStamp{mtime: time.Now().Add(-time.Hour).UnixNano(), ctime: time.Now().Add(-time.Hour).UnixNano(), stamped: time.Now()}
	if !old.trusted() {
		t.Fatal("a stamp of a long-stable file should be trusted")
	}
}

func TestReviewedComputeProgramKey(t *testing.T) {
	a := reviewedComputeProgramKey("m", map[string]string{"static/m.ts": "h1", "static/x.ts": "h2"})
	if a != reviewedComputeProgramKey("m", map[string]string{"static/x.ts": "h2", "static/m.ts": "h1"}) {
		t.Fatal("key must not depend on map order")
	}
	for _, other := range []string{
		reviewedComputeProgramKey("n", map[string]string{"static/m.ts": "h1", "static/x.ts": "h2"}),
		reviewedComputeProgramKey("m", map[string]string{"static/m.ts": "h1", "static/x.ts": "h3"}),
		reviewedComputeProgramKey("m", map[string]string{"static/m.ts": "h1"}),
	} {
		if other == a {
			t.Fatal("module name, paths and hashes must all change the key")
		}
	}
}
