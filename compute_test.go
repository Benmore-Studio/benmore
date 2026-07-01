//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeComputeFixture(t *testing.T, name, body string) *App {
	t.Helper()
	dir := t.TempDir()
	staticDir := filepath.Join(dir, "static")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return &App{Dir: dir}
}

func TestCompute_PureFunction_RoundTrip(t *testing.T) {
	app := writeComputeFixture(t, "math.ts", `
		export function add(args: { a: number; b: number }): number {
			return args.a + args.b;
		}
	`)
	result, err := RunCompute(app, "math", "add", map[string]any{"a": 3, "b": 4}, 0)
	if err != nil {
		t.Fatalf("RunCompute: %v", err)
	}
	// goja returns int64 for integer-valued numbers.
	switch n := result.(type) {
	case int64:
		if n != 7 {
			t.Fatalf("expected 7, got %d", n)
		}
	case float64:
		if n != 7 {
			t.Fatalf("expected 7, got %v", n)
		}
	default:
		t.Fatalf("expected numeric, got %T = %v", result, result)
	}
}

func TestCompute_Iterative_IRRStyle(t *testing.T) {
	// Smoke-test something shaped like par-engine's IRR loop -
	// confirms goja handles arrays + iteration + Math.abs.
	app := writeComputeFixture(t, "irr.ts", `
		export function irr(args: { cashflows: number[]; precision?: number }): number {
			const cf = args.cashflows;
			const eps = args.precision ?? 1e-7;
			let lo = -0.99, hi = 10;
			for (let i = 0; i < 200; i++) {
				const mid = (lo + hi) / 2;
				let npv = 0;
				for (let y = 0; y < cf.length; y++) {
					npv += cf[y] / Math.pow(1 + mid, y);
				}
				if (Math.abs(npv) < eps) return mid * 100;
				if (npv > 0) lo = mid; else hi = mid;
			}
			return (lo + hi) / 2 * 100;
		}
	`)
	// Classic IRR test: -1000 upfront, +600 + +500 over 2 years → IRR ~6.4%
	result, err := RunCompute(app, "irr", "irr", map[string]any{"cashflows": []int{-1000, 600, 500}}, 0)
	if err != nil {
		t.Fatalf("RunCompute: %v", err)
	}
	f, ok := result.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T", result)
	}
	if f < 6.0 || f > 7.0 {
		t.Fatalf("IRR out of expected band (6-7%%), got %v", f)
	}
}

func TestCompute_ThrowSurface(t *testing.T) {
	app := writeComputeFixture(t, "fail.ts", `
		export function boom(): never {
			throw new Error('deliberate test failure');
		}
	`)
	_, err := RunCompute(app, "fail", "boom", nil, 0)
	if err == nil {
		t.Fatal("expected error from throwing function")
	}
	if !strings.Contains(err.Error(), "deliberate test failure") {
		t.Fatalf("expected error to surface the JS message, got: %v", err)
	}
}

func TestCompute_UnknownExport(t *testing.T) {
	app := writeComputeFixture(t, "mod.ts", `
		export function foo() { return 1; }
		export function bar() { return 2; }
	`)
	_, err := RunCompute(app, "mod", "baz", nil, 0)
	if err == nil {
		t.Fatal("expected error for missing export")
	}
	// Error should list available exports so the agent can fix the typo.
	if !strings.Contains(err.Error(), "foo") || !strings.Contains(err.Error(), "bar") {
		t.Fatalf("expected error to list available exports, got: %v", err)
	}
}

func TestCompute_Timeout(t *testing.T) {
	app := writeComputeFixture(t, "loop.ts", `
		export function spin(): never {
			while (true) {}
		}
	`)
	start := time.Now()
	_, err := RunCompute(app, "loop", "spin", nil, 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout in error, got: %v", err)
	}
	// Should bail close to the deadline - generous bound for CI noise.
	if elapsed > 2*time.Second {
		t.Fatalf("interrupt took too long: %v", elapsed)
	}
}

func TestCompute_NoEvalNoFetch(t *testing.T) {
	// The runtime strips eval + Function. fetch / setTimeout / require
	// don't exist in goja by default. Confirm they all throw.
	app := writeComputeFixture(t, "sandbox.ts", `
		export function tryEval(): string {
			try { (0, eval)('1+1'); return 'eval worked'; }
			catch (e: any) { return 'eval blocked: ' + (e.message || String(e)); }
		}
		export function tryFetch(): string {
			try { (fetch as any)('http://example.com'); return 'fetch worked'; }
			catch (e: any) { return 'fetch blocked: ' + (e.message || String(e)); }
		}
		export function tryRequire(): string {
			try { (require as any)('fs'); return 'require worked'; }
			catch (e: any) { return 'require blocked: ' + (e.message || String(e)); }
		}
	`)
	cases := []string{"tryEval", "tryFetch", "tryRequire"}
	for _, fn := range cases {
		result, err := RunCompute(app, "sandbox", fn, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		s, _ := result.(string)
		if !strings.Contains(s, "blocked") {
			t.Fatalf("%s: expected sandbox to block, got %q", fn, s)
		}
	}
}

func TestCompute_PathTraversalRejected(t *testing.T) {
	app := writeComputeFixture(t, "ok.ts", `export function x() { return 1; }`)
	// Try to escape static/ via ../
	_, err := RunCompute(app, "../etc/passwd", "x", nil, 0)
	if err == nil {
		t.Fatal("expected rejection of ../ path")
	}
}
