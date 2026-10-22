//go:build !cli

package main

import (
	"strings"
	"testing"
	"time"
)

func TestAppMCPCompilerPrivateAndOrdinaryNativeFidelity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		files         map[string]string
		want          any
		browserMarker string
	}{
		{
			name: "legacy decorators",
			files: map[string]string{
				"static/tsconfig.json": `{"compilerOptions":{"experimentalDecorators":true}}`,
				"static/entry.ts": `function answer(_target: object, _key: string, descriptor: PropertyDescriptor) {
					descriptor.value = () => 42;
				}
				class Choice { @answer value() { return 0; } }
				export function result() { return new Choice().value(); }`,
			},
			want: int64(42),
		},
		{
			name: "jsx import source",
			files: map[string]string{
				"static/tsconfig.json":                        `{"compilerOptions":{"jsx":"react-jsx","jsxImportSource":"renderer"}}`,
				"static/entry.tsx":                            `export function result() { return <choice />; }`,
				"static/node_modules/renderer/jsx-runtime.js": `export function jsx() { return "native-jsx"; } export { jsx as jsxs };`,
			},
			want:          "native-jsx",
			browserMarker: "native-jsx",
		},
		{
			name: "mixed import and require share package state",
			files: map[string]string{
				"static/entry.ts": `import { state } from "choice";
				const required = require("choice");
				export function result() { state.value = 42; return required.state.value; }`,
				"static/node_modules/choice/package.json": `{"module":"esm.js","main":"cjs.js"}`,
				"static/node_modules/choice/esm.js":       `export const state = { value: 0 };`,
				"static/node_modules/choice/cjs.js":       `exports.state = { value: 0 };`,
			},
			want: int64(42),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			app, ctx := appMCPComputeFixture(t, tc.files)
			if got, err := RunComputeContext(ctx, app, "entry", "result", nil, time.Second); err != nil || got != tc.want {
				t.Fatalf("private compute = %#v, %v; want %#v", got, err, tc.want)
			}
			if got, err := RunCompute(app, "entry", "result", nil, time.Second); err != nil || got != tc.want {
				t.Fatalf("ordinary compute = %#v, %v; want %#v", got, err, tc.want)
			}
			if tc.browserMarker != "" {
				for _, browser := range []struct {
					name string
					app  *App
				}{
					{name: "private", app: app},
					{name: "ordinary", app: &App{Dir: app.Dir}},
				} {
					body := appMCPCompilerBrowserBody(t, browser.app)
					if !strings.Contains(body, tc.browserMarker) || strings.Contains(body, "throw new Error(") {
						t.Fatalf("%s browser body omitted the compiled renderer or threw: %s", browser.name, body)
					}
				}
			}
		})
	}
}
