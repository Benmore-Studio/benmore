//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TypeScript source and `run: compute` modules are never served from
// /static; browser bundles and assets still are, and the compute module
// still runs.
func TestStaticDoesNotServeSourceOrComputeModules(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	write := func(rel, content string) {
		p := filepath.Join(app.Dir, "static", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("server/pushsign.ts", "export function sign() { return 'SERVER-ONLY-MARKER'; }\n")
	write("app.tsx", "export const ui = 'BROWSER-MARKER';\n")
	write("logo.txt", "asset")
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "sign.yaml"), []byte(`on:
  request:
    method: GET
    path: /api/sign
jobs:
  sign:
    steps:
      - id: s
        run: compute
        with:
          module: server/pushsign
          function: sign
      - run: respond
        with:
          status: 200
          body: '${{ steps.s.outputs }}'
`))
	if err != nil {
		t.Fatal(err)
	}
	app.Flows = flows
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		serveStaticAsset(w, r, app, false, strings.TrimPrefix(path, "/static/"))
		return w.Code, w.Body.String()
	}
	for _, path := range []string{"/static/server/pushsign.ts", "/static/app.tsx", "/static/server/pushsign.js"} {
		if code, body := get(path); code != http.StatusNotFound || strings.Contains(body, "MARKER") {
			t.Errorf("%s served: %d %q", path, code, body)
		}
	}
	if code, body := get("/static/app.js"); code != http.StatusOK || !strings.Contains(body, "BROWSER-MARKER") {
		t.Errorf("browser bundle not served: %d %q", code, body)
	}
	if code, _ := get("/static/logo.txt"); code != http.StatusOK {
		t.Errorf("asset not served: %d", code)
	}
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flows[0], rr, httptest.NewRequest(http.MethodGet, "/api/sign", nil))
	if !strings.Contains(rr.Body.String(), "SERVER-ONLY-MARKER") {
		t.Errorf("compute module no longer runs: %d %s", rr.Code, rr.Body.String())
	}
}

// A compute module's helpers are server code too. Only the entry module was
// blocked, so a key in a helper it imports was served compiled (round-2
// review, 2026-10-23). Browser modules beside it, and a browser module that
// shares nothing with the compute module, are still served.
func TestStaticDoesNotServeComputeModuleImports(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	write := func(rel, content string) {
		p := filepath.Join(app.Dir, "static", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("server/main.ts", "import { KEY } from './key';\nimport { fmt } from '../lib/format';\nexport function sign() { return fmt(KEY); }\n")
	write("server/key.ts", "export const KEY = 'HELPER-SECRET-MARKER';\n")
	write("server/legacy.js", "export const OLD = 'PLAIN-JS-MARKER';\n")
	write("lib/format.ts", "export const fmt = (s: string) => s + '!';\n")
	write("app.tsx", "export const ui = 'BROWSER-MARKER';\n")
	write("server/public-widget.ts", "export const w = 'WIDGET-MARKER';\n")
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "sign.yaml"), []byte(`on:
  request:
    method: GET
    path: /api/sign
jobs:
  sign:
    steps:
      - id: s
        run: compute
        with:
          module: server/main
          function: sign
      - run: respond
        with:
          status: 200
          body: '${{ steps.s.outputs }}'
`))
	if err != nil {
		t.Fatal(err)
	}
	app.Flows = flows
	get := func(path string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		serveStaticAsset(w, r, app, false, strings.TrimPrefix(path, "/static/"))
		return w.Code, w.Body.String()
	}
	for _, path := range []string{"/static/server/main.js", "/static/server/key.js", "/static/lib/format.js"} {
		if code, body := get(path); code != http.StatusNotFound || strings.Contains(body, "MARKER") {
			t.Errorf("%s (imported by the compute module) served: %d %q", path, code, body)
		}
	}
	for path, marker := range map[string]string{"/static/app.js": "BROWSER-MARKER", "/static/server/public-widget.js": "WIDGET-MARKER", "/static/server/legacy.js": "PLAIN-JS-MARKER"} {
		if code, body := get(path); code != http.StatusOK || !strings.Contains(body, marker) {
			t.Errorf("%s not served: %d %q", path, code, body)
		}
	}

	// A compute module that does not compile has no known import graph:
	// its directory is refused, other directories are not.
	write("server/main.ts", "import { KEY } from './key';\nexport function sign( { return KEY; }\n")
	if code, body := get("/static/server/key.js"); code != http.StatusNotFound || strings.Contains(body, "MARKER") {
		t.Errorf("helper of a broken compute module served: %d %q", code, body)
	}
	if code, body := get("/static/app.js"); code != http.StatusOK || !strings.Contains(body, "BROWSER-MARKER") {
		t.Errorf("browser bundle not served while a compute module is broken: %d %q", code, body)
	}
}
