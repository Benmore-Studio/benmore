//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCDNTestFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func cdnTestDirectives(t *testing.T, dir string) map[string]string {
	t.Helper()
	refreshCDNSources(dir)
	return pageCSPDirectives(&App{Dir: dir})
}

func fields(s string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.Fields(s) {
		out[f] = true
	}
	return out
}

var allCDNOrigins = []string{"https://unpkg.com", "https://cdn.jsdelivr.net", "https://esm.sh", "https://cdn.skypack.dev"}

func assertCDNOrigins(t *testing.T, d map[string]string, want ...string) {
	t.Helper()
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
	}
	script, connect := fields(d["script_src"]), fields(d["connect_src"])
	for _, o := range allCDNOrigins {
		if script[o] != wanted[o] || connect[o] != wanted[o] {
			t.Errorf("%s: want allowed=%v, script-src=%q connect-src=%q", o, wanted[o], d["script_src"], d["connect_src"])
		}
	}
}

// An app that names no CDN gets none; mentions in places that are never
// served (tests, docs, root Markdown, type declarations, hidden dirs,
// uploads) do not count.
func TestPageCSPNoCDNWithoutSourceReference(t *testing.T) {
	dir := t.TempDir()
	writeCDNTestFile(t, dir, "static/index.html", `<script type="module" src="/static/app.js"></script><script src="/_internal/chart.js"></script>`)
	writeCDNTestFile(t, dir, "static/app.tsx", `import bm from 'bm'; console.log(bm)`)
	writeCDNTestFile(t, dir, "tests/e2e.yaml", `get: "https://unpkg.com/x"`)
	writeCDNTestFile(t, dir, "docs/notes.txt", `https://esm.sh/react`)
	writeCDNTestFile(t, dir, "AGENTS.md", `import from https://cdn.skypack.dev`)
	writeCDNTestFile(t, dir, "src/bm.d.ts", `/** Leaflet: unpkg.com */ declare module 'sdui' {}`)
	writeCDNTestFile(t, dir, ".benmore/state", `https://cdn.jsdelivr.net`)
	writeCDNTestFile(t, dir, "uploads/a.html", `<script src="https://cdn.jsdelivr.net/x.js"></script>`)
	writeCDNTestFile(t, dir, "static/node_modules/x/index.js", `https://esm.sh/x`)
	writeCDNTestFile(t, dir, "static/logo.png", `https://unpkg.com/`)
	d := cdnTestDirectives(t, dir)
	assertCDNOrigins(t, d)
	if strings.Contains(d["script_src"]+d["style_src"]+d["img_src"], "leaflet") {
		t.Errorf("no sdui import, but Leaflet is allowed: %v", d)
	}
}

// Each host is allowed exactly when served source names it: a TSX import,
// an HTML script tag, an SSR page at the app root, a partial, a flow.
func TestPageCSPAllowsReferencedCDNOnly(t *testing.T) {
	cases := []struct {
		rel, body string
		want      []string
	}{
		{"static/app.tsx", `import { h } from 'https://esm.sh/preact@10.23.2'`, []string{"https://esm.sh"}},
		{"static/index.html", `<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>`, []string{"https://cdn.jsdelivr.net"}},
		{"api-docs.html", `<script src="//cdn.jsdelivr.net/npm/redoc"></script>`, []string{"https://cdn.jsdelivr.net"}},
		{"partials/head.html", `<script src="HTTPS://UNPKG.COM/htmx.org"></script>`, []string{"https://unpkg.com"}},
		{"flows/page.yaml", `respond: '<script src="https://cdn.skypack.dev/x"></script>'`, []string{"https://cdn.skypack.dev"}},
		{"static/lib/pdf.ts", "const base = `https://cdn.jsdelivr.net/npm/pdfjs-dist@${V}`", []string{"https://cdn.jsdelivr.net"}},
		{"static/data.json", `{"u":"https:\/\/esm.sh\/x"}`, []string{"https://esm.sh"}},
		// Not the CDN hosts.
		{"static/app.ts", `fetch('https://fastly.jsdelivr.net/x'); run('build-esm.sh'); 'esm.shop'; 'unpkg.community'`, nil},
	}
	for _, c := range cases {
		dir := t.TempDir()
		writeCDNTestFile(t, dir, c.rel, c.body)
		t.Run(c.rel, func(t *testing.T) { assertCDNOrigins(t, cdnTestDirectives(t, dir), c.want...) })
	}
}

// An app importing sdui gets the exact Leaflet files its Map loads, not the
// unpkg origin.
func TestPageCSPSDUIGetsOnlyLeafletFiles(t *testing.T) {
	for _, src := range []string{
		`import { Map } from 'sdui'`,
		`const S = await import("sdui")`,
		`<script type="module">import * as S from '/_internal/sdui.js'</script>`,
	} {
		dir := t.TempDir()
		writeCDNTestFile(t, dir, "static/app.tsx", src)
		d := cdnTestDirectives(t, dir)
		assertCDNOrigins(t, d)
		if !fields(d["script_src"])[sduiLeafletJS] || !fields(d["style_src"])[sduiLeafletCSS] || !fields(d["img_src"])[sduiLeafletImages] {
			t.Errorf("%s: Leaflet files not allowed: %v", src, d)
		}
	}
	// With unpkg already allowed, the file entry is redundant in script-src.
	dir := t.TempDir()
	writeCDNTestFile(t, dir, "static/app.tsx", `import { Map } from 'sdui'; import x from 'https://unpkg.com/x'`)
	d := cdnTestDirectives(t, dir)
	if fields(d["script_src"])[sduiLeafletJS] || !fields(d["script_src"])["https://unpkg.com"] || !fields(d["style_src"])[sduiLeafletCSS] {
		t.Errorf("unexpected Leaflet entries: %v", d)
	}
}

// The app.yaml csp: block still widens the policy on its own.
func TestPageCSPExplicitCSPStillAppended(t *testing.T) {
	dir := t.TempDir()
	writeCDNTestFile(t, dir, "static/index.html", `<p>hi</p>`)
	refreshCDNSources(dir)
	d := pageCSPDirectives(&App{Dir: dir, Design: &DesignConfig{CSP: map[string]string{"script_src": "https://esm.sh", "connect_src": "https://esm.sh"}}})
	assertCDNOrigins(t, d, "https://esm.sh")
}

// A reference split across the scanner's read chunks is still found.
func TestPageCSPReferenceAcrossChunkBoundary(t *testing.T) {
	for _, offset := range []int{-20, -9, -1, 0, 1, cdnScanOverlap - 1, cdnScanOverlap, cdnScanOverlap + 1} {
		dir := t.TempDir()
		pad := strings.Repeat("x", cdnScanChunk+cdnScanOverlap+1+offset)
		writeCDNTestFile(t, dir, "static/big.js", pad+";'https://esm.sh/x';")
		assertCDNOrigins(t, cdnTestDirectives(t, dir), "https://esm.sh")
	}
	// A host-character neighbour across the boundary still disqualifies.
	dir := t.TempDir()
	pad := strings.Repeat("x", cdnScanChunk+1)
	writeCDNTestFile(t, dir, "static/big.js", pad+"esm.sh;")
	assertCDNOrigins(t, cdnTestDirectives(t, dir))
}

// Edits are picked up: a new reference is allowed, a removed one dropped.
func TestPageCSPFollowsSourceEdits(t *testing.T) {
	dir := t.TempDir()
	writeCDNTestFile(t, dir, "static/app.tsx", `console.log(1)`)
	assertCDNOrigins(t, cdnTestDirectives(t, dir))
	writeCDNTestFile(t, dir, "static/views/chart.tsx", `import c from 'https://esm.sh/chart.js'`)
	assertCDNOrigins(t, cdnTestDirectives(t, dir), "https://esm.sh")
	if err := os.Remove(filepath.Join(dir, "static/views/chart.tsx")); err != nil {
		t.Fatal(err)
	}
	assertCDNOrigins(t, cdnTestDirectives(t, dir))
}

// Until the first scan finishes, and for an app whose source cannot be
// read, the page CSP keeps every CDN (the policy before the narrowing).
func TestPageCSPFallsBackToEveryCDN(t *testing.T) {
	assertCDNOrigins(t, pageCSPDirectives(nil), allCDNOrigins...)
	missing := filepath.Join(t.TempDir(), "gone")
	assertCDNOrigins(t, cdnTestDirectives(t, missing), allCDNOrigins...)

	dir := t.TempDir()
	writeCDNTestFile(t, dir, "static/index.html", `<p>no cdn</p>`)
	app := &App{Dir: dir}
	assertCDNOrigins(t, pageCSPDirectives(app), allCDNOrigins...) // first call: scan starts in the background
	deadline := time.Now().Add(5 * time.Second)
	for {
		d := pageCSPDirectives(app)
		if !strings.Contains(d["script_src"], "https://unpkg.com") {
			assertCDNOrigins(t, d)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background scan never narrowed the policy: %v", d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The scan stops reading a file once every flag is set and skips binary
// media without opening it.
func TestCDNScanSkipRules(t *testing.T) {
	for rel, skip := range map[string]bool{
		"static/a.png": true, "static/a.svg": false, "static/a.wasm": false, "src/bm.d.ts": true,
		"README.md": true, "static/README.md": false, "env.yaml": true, "data.db-wal": true, "static/x.json": false,
	} {
		if got := cdnScanSkipFile(rel, filepath.Base(rel)); got != skip {
			t.Errorf("cdnScanSkipFile(%s) = %v, want %v", rel, got, skip)
		}
	}
	for rel, skip := range map[string]bool{
		"tests": true, "docs": true, "migrations": true, "uploads": true, ".git": true, ".benmore": true,
		"static": false, "partials": false, "static/docs": false, "static/tests": false, "static/node_modules": true,
	} {
		if got := cdnScanSkipDir(rel, filepath.Base(rel)); got != skip {
			t.Errorf("cdnScanSkipDir(%s) = %v, want %v", rel, got, skip)
		}
	}
}
