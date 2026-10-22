//go:build !cli

package main

import (
	"strings"
	"testing"
	"time"
)

// goja's built-ins walk a nested value by recursing in Go, and a Go stack
// overflow ends the whole process. A script that builds a structure far
// deeper than any real data (`for (...) a = [a]`) and returns it, or hands it
// to JSON.stringify, String()/join or flat(Infinity), must fail its step
// cleanly. The depth here (20000) is past the bound and well short of what
// overflows, so a missing guard shows as "no error", not as a dead test run.
func TestComputeBoundsNestingOfRecursiveBuiltins(t *testing.T) {
	const build = `function deep(n){ let a = []; for (let i = 0; i < n; i++) a = [a]; return a; }` + "\n"
	app := writeComputeFixture(t, "deep.ts", build+
		`export function returned(){ return deep(20000); }`+"\n"+
		`export function returnedObject(){ let o = {}; for (let i = 0; i < 20000; i++) o = {o: o}; return o; }`+"\n"+
		`export function stringified(){ return JSON.stringify(deep(20000)).length; }`+"\n"+
		`export function joined(){ return String(deep(20000)).length; }`+"\n"+
		`export function concatenated(){ return ('' + deep(20000)).length; }`+"\n"+
		`export function flattened(){ return deep(20000).flat(Infinity).length; }`+"\n"+
		`export function caught(){ try { JSON.stringify(deep(20000)); return 'no error'; } catch (e) { return e instanceof RangeError ? 'RangeError' : String(e); } }`+"\n")

	for fn, want := range map[string]string{
		"returned":       "nested more than 10000 levels deep",
		"returnedObject": "nested more than 10000 levels deep",
		"stringified":    "JSON.stringify: value nested more than 10000 levels deep",
		"joined":         "array nested more than 10000 levels deep",
		"concatenated":   "array nested more than 10000 levels deep",
		"flattened":      "flat: array nested more than 10000 levels deep",
	} {
		out, err := RunCompute(app, "deep", fn, nil, 20*time.Second)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error containing %q, got out=%.40v err=%v", fn, want, out, err)
		}
	}
	// The refusal is an ordinary RangeError the script can handle.
	if out, err := RunCompute(app, "deep", "caught", nil, 20*time.Second); err != nil || out != "RangeError" {
		t.Errorf("caught: out=%v err=%v", out, err)
	}

	// Args nested past the bound never reach the VM.
	var args any = map[string]any{}
	for i := 0; i < 20000; i++ {
		args = map[string]any{"a": []any{args}}
	}
	if _, err := RunCompute(app, "deep", "returned", args, 20*time.Second); err == nil || !strings.Contains(err.Error(), "input nested more than 10000 levels deep") {
		t.Errorf("deep args: err=%v", err)
	}
}

// Ordinary values behave exactly as before under the guards.
func TestComputeNestingGuardsKeepBuiltinSemantics(t *testing.T) {
	app := writeComputeFixture(t, "ok.ts", `
function deep(n){ let a = [1]; for (let i = 0; i < n; i++) a = [a, i]; return a; }
export function run(input) {
  const shared = { n: 1 };
  const cyclic: any = { name: 'c' }; cyclic.self = cyclic;
  let cycleError = '';
  try { JSON.stringify(cyclic); } catch (e) { cycleError = (e as Error).constructor.name; }
  return {
    json: JSON.stringify({ a: [1, { b: [2, 3] }], d: new Date(0), u: undefined }),
    pretty: JSON.stringify({ a: [1] }, null, 2),
    replaced: JSON.stringify({ a: 1, b: 2 }, (k, v) => (k === 'b' ? undefined : v)),
    picked: JSON.stringify({ b: 2, a: 1, c: 3 }, ['a', 'b']),
    shared: JSON.stringify([shared, shared, { again: shared }]),
    echoed: JSON.stringify(input),
    cycleError,
    joined: [1, [2, [3, [4]]], 'x'].join('-'),
    str: String([1, [2, [3]]]),
    tmpl: `+"`${[1, [2]]}`"+`,
    locale: [1, [2]].toLocaleString(),
    flat1: [1, [2, [3, [4]]]].flat(),
    flatAll: [1, [2, [3, [4]]]].flat(Infinity),
    flat2: [1, [2, [3, [4]]]].flat(2),
    deepJoin: String(deep(3000)).length,
    deepJSON: JSON.stringify(deep(3000)).length,
    deepFlat: deep(3000).flat(Infinity).length,
    names: [Array.prototype.join.length >= 0, typeof JSON.stringify],
  };
}`)
	// One key per object: a Go map handed to the VM has no fixed key order.
	input := map[string]any{"rows": []any{map[string]any{"tags": []any{"a", "b"}}}}
	out, err := RunCompute(app, "ok", "run", input, 20*time.Second)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := out.(map[string]any)
	want := map[string]any{
		"json":       `{"a":[1,{"b":[2,3]}],"d":"1970-01-01T00:00:00.000Z"}`,
		"pretty":     "{\n  \"a\": [\n    1\n  ]\n}",
		"replaced":   `{"a":1}`,
		"picked":     `{"a":1,"b":2}`,
		"shared":     `[{"n":1},{"n":1},{"again":{"n":1}}]`,
		"echoed":     `{"rows":[{"tags":["a","b"]}]}`,
		"cycleError": "TypeError",
		"joined":     "1-2,3,4-x",
		"str":        "1,2,3",
		"tmpl":       "1,2",
		"locale":     "1,2",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	for k, n := range map[string]int{"flat1": 3, "flatAll": 4, "flat2": 4} {
		if arr, _ := got[k].([]any); len(arr) != n {
			t.Errorf("%s = %#v, want %d elements", k, got[k], n)
		}
	}
	for _, k := range []string{"deepJoin", "deepJSON", "deepFlat"} {
		if n, _ := got[k].(int64); n <= 0 {
			t.Errorf("%s = %#v, want a positive length (3000 levels is within the bound)", k, got[k])
		}
	}
}

// A getter that throws while the result is converted is script code running
// outside any JS try frame; goja reports it as a Go panic, which used to end
// the app process from the compute goroutine.
func TestComputeResultConversionPanicFailsTheStep(t *testing.T) {
	app := writeComputeFixture(t, "getter.ts",
		`export function f(){ return { get x(){ throw new Error('boom') } }; }`)
	if _, err := RunCompute(app, "getter", "f", nil, 5*time.Second); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want a step error naming the thrown error, got %v", err)
	}
}
