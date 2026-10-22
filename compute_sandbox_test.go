//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/dop251/goja"
)

// A compute module must not be able to import a file outside the app's
// static/ dir - the "pure function, no fs" sandbox depends on it. env.yaml
// (ENCRYPTION_KEY + every app secret) sits one level above static/; other
// tenants' files are further up. Before the fix, esbuild happily bundled
// them and RunCompute returned their bytes.
func TestComputeRejectsImportOutsideStatic(t *testing.T) {
	// (a) sibling of static/: env.yaml one level up.
	app := writeComputeFixture(t, "imp.ts",
		`import s from '../env.yaml' with { type: 'text' };`+"\n"+
			`export function f(): string { return s; }`)
	os.WriteFile(filepath.Join(app.Dir, "env.yaml"), []byte("ENCRYPTION_KEY: topsecret"), 0o644)
	if _, err := RunCompute(app, "imp", "f", nil, 0); err == nil {
		t.Fatal("expected import of ../env.yaml to be rejected")
	} else if !strings.Contains(err.Error(), "outside static/") {
		t.Fatalf("expected outside-static rejection, got: %v", err)
	}

	// (b) escape beyond the app dir entirely (cross-tenant on a shared FS).
	base := t.TempDir()
	os.WriteFile(filepath.Join(base, "victim.txt"), []byte("CROSS-TENANT"), 0o644)
	appDir := filepath.Join(base, "apps", "myapp")
	staticDir := filepath.Join(appDir, "static")
	os.MkdirAll(staticDir, 0o755)
	os.WriteFile(filepath.Join(staticDir, "esc.ts"), []byte(
		`import s from '../../../victim.txt' with { type: 'text' };`+"\n"+
			`export function f(): string { return s; }`), 0o644)
	if _, err := RunCompute(&App{Dir: appDir}, "esc", "f", nil, 0); err == nil {
		t.Fatal("expected import escaping the app dir to be rejected")
	} else if !strings.Contains(err.Error(), "outside static/") {
		t.Fatalf("expected outside-static rejection, got: %v", err)
	}

	// (c) a normal relative import INSIDE static/ still works.
	app2 := writeComputeFixture(t, "main.ts",
		`import { two } from './helper';`+"\n"+
			`export function f(): number { return two(); }`)
	os.WriteFile(filepath.Join(app2.Dir, "static", "helper.ts"),
		[]byte(`export function two(): number { return 2; }`), 0o644)
	if _, err := RunCompute(app2, "main", "f", nil, 0); err != nil {
		t.Fatalf("in-static import should compile: %v", err)
	}
}

// A compute result that json.Marshal cannot handle (a function value, a
// cyclic object) used to slip past the output-size cap and land a poison
// value in the flow's outputs. It must be rejected instead.
func TestComputeRejectsNonSerialisableResult(t *testing.T) {
	app := writeComputeFixture(t, "fn.ts",
		`export function f(): any { return { big: 'x'.repeat(20*1024*1024), fn: function(){} }; }`)
	if _, err := RunCompute(app, "fn", "f", nil, 0); err == nil {
		t.Fatal("expected non-serialisable oversized result to be rejected")
	} else if !strings.Contains(err.Error(), "not JSON-serialisable") && !strings.Contains(err.Error(), "too much data") {
		t.Fatalf("expected serialisability/size rejection, got: %v", err)
	}

	cyc := writeComputeFixture(t, "cyc.ts",
		`export function f(): any { const o: any = {a:1}; o.self = o; return o; }`)
	if _, err := RunCompute(cyc, "cyc", "f", nil, 0); err == nil {
		t.Fatal("expected cyclic result to be rejected")
	} else if !strings.Contains(err.Error(), "not JSON-serialisable") {
		t.Fatalf("expected serialisability rejection, got: %v", err)
	}
}

// vm.Interrupt does not fire inside a native Go call - notably regex
// matching. A catastrophic-backtracking regex must not hang the caller past
// the deadline; RunCompute bounds the wait and returns a timeout error.
func TestComputeNativeRegexBoundsCaller(t *testing.T) {
	// Lookahead forces goja onto the backtracking regexp2 engine (Go's RE2
	// is linear), where this pattern catastrophically backtracks.
	app := writeComputeFixture(t, "re.ts",
		`export function f(): boolean { return /^(?=(a+)+b)/.test('a'.repeat(40)); }`)
	start := time.Now()
	_, err := RunCompute(app, "re", "f", nil, 300*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("caller not bounded by deadline: waited %v", elapsed)
	}
}

// A backtracking match must end on its own, not only release the caller:
// otherwise every timed-out call leaves a goroutine spinning indefinitely.
func TestComputeRegexMatchesAreTimeBounded(t *testing.T) {
	if regexp2.DefaultMatchTimeout != computeRegexMatchTimeout {
		t.Fatalf("regexp2 match timeout = %v, want %v", regexp2.DefaultMatchTimeout, computeRegexMatchTimeout)
	}
	regexp2.DefaultMatchTimeout = 200 * time.Millisecond
	defer func() { regexp2.DefaultMatchTimeout = computeRegexMatchTimeout }()
	vm := goja.New()
	start := time.Now()
	v, err := vm.RunString(`/^(?=(a+)+b)/.test('a'.repeat(40))`)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("backtracking match ran %v despite the match timeout", elapsed)
	}
	if v.ToBoolean() {
		t.Fatal("timed-out match reported a match")
	}
}
