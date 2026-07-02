//go:build !cli

package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// versionStaticAssets is the auto-versioning transform that closes the
// "I just edited the file but Cloudflare caches it immutable for a
// year" footgun. The behavior contract:
//
//   1. /static/*.css and /static/*.js refs in HTML get ?v=<content-hash>
//      appended, derived from the file's bytes on disk (the .js hash covers
//      the .tsx/.ts/.jsx source tree it's JIT-compiled from)
//   2. URLs that already have a query string are NOT rewritten
//      (idempotent against re-rendering; respects explicit versions)
//   3. URLs whose files don't exist on disk are NOT rewritten
//      (a real 404 should still surface, not a fake versioned URL)
//   4. /_internal/* and other prefixes are NOT rewritten (framework
//      libraries are versioned by the binary, not per-app)
//
// Each test corresponds to one bullet above so a regression in any
// single property fails a specific test rather than the whole suite.

// vQueryRe extracts the emitted ?v=<hash> token for a given asset.
var vQueryRe = regexp.MustCompile(`\?v=([0-9a-zA-Z]+)`)

func TestVersionStaticAssetsRewritesCSSAndJS(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"styles.css", "app.tsx"} {
		if err := os.WriteFile(filepath.Join(staticDir, name), []byte("/* v1 */"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	html := []byte(`<link rel="stylesheet" href="/static/styles.css"><script src="/static/app.js"></script>`)
	out := string(versionStaticAssets(html, app))

	// Both refs get a content-hash ?v= token (the .js version derives from the
	// app.tsx source it compiles from).
	if !regexp.MustCompile(`href="/static/styles\.css\?v=[0-9a-f]{12}"`).MatchString(out) {
		t.Errorf("CSS not content-versioned: %s", out)
	}
	if !regexp.MustCompile(`src="/static/app\.js\?v=[0-9a-f]{12}"`).MatchString(out) {
		t.Errorf("JS not content-versioned: %s", out)
	}

	// Determinism: same content → same version on a second call.
	out2 := string(versionStaticAssets(html, app))
	if out != out2 {
		t.Errorf("version not stable for unchanged content:\n%s\n%s", out, out2)
	}

	// Content change → version change (the whole point: a revert that restores
	// different bytes must bust the cache, regardless of mtime).
	before := vQueryRe.FindString(out)
	if err := os.WriteFile(filepath.Join(staticDir, "styles.css"), []byte("/* v2 - different */"), 0644); err != nil {
		t.Fatal(err)
	}
	after := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	if before == after {
		t.Errorf("CSS version did not change after content changed (both %q)", before)
	}
}

func TestVersionStaticAssetsReversionsFrameworkOwnedURLs(t *testing.T) {
	// The framework owns the `?v=<hash>` it emits and replaces a stale one with
	// the current hash. Non-`v` query strings are author intent and stay
	// untouched. (Pre-2.7.31 a stale ?v=42 was preserved, creating permanent
	// dead zones the agent worked around by manually bumping v=2→3→5→6→7.)
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "styles.css"), []byte("body{}"), 0644)

	html := []byte(`<link href="/static/styles.css?v=42"><link href="/static/styles.css?hash=abc">`)
	out := string(versionStaticAssets(html, app))

	// Stale framework-owned ?v=42 is re-owned with the content hash.
	if strings.Contains(out, `?v=42`) {
		t.Errorf("stale ?v=42 leaked through: %s", out)
	}
	if !regexp.MustCompile(`href="/static/styles\.css\?v=[0-9a-f]{12}"`).MatchString(out) {
		t.Errorf("stale ?v=42 should be re-versioned to the content hash: %s", out)
	}
	// Author-owned query strings stay untouched.
	if !strings.Contains(out, `href="/static/styles.css?hash=abc"`) {
		t.Errorf("explicit ?hash=abc should be preserved: %s", out)
	}
}

func TestVersionStaticAssetsSkipsMissingFiles(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	// No file written - /static/ghost.css does NOT exist on disk.

	html := []byte(`<link href="/static/ghost.css">`)
	out := string(versionStaticAssets(html, app))

	if out != string(html) {
		t.Errorf("missing file should be left untouched, got: %s", out)
	}
}

func TestVersionStaticAssetsLeavesInternalAndOtherPrefixesAlone(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	html := []byte(`<script src="/_internal/htmx.js"></script><img src="/uploads/foo.png"><link href="https://cdn.example.com/style.css">`)
	out := string(versionStaticAssets(html, app))

	if out != string(html) {
		t.Errorf("non-/static/ URLs should be untouched, got: %s", out)
	}
}

func TestVersionStaticAssetsHandlesSingleQuotes(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "main.css"), []byte("body{}"), 0644)

	html := []byte(`<link href='/static/main.css'>`)
	out := string(versionStaticAssets(html, app))

	if !regexp.MustCompile(`href='/static/main\.css\?v=[0-9a-f]{12}'`).MatchString(out) {
		t.Errorf("single-quoted attr not content-versioned: %s", out)
	}
}

func TestVersionStaticAssetsJSVersionTracksSourceTree(t *testing.T) {
	// /static/app.js is JIT-compiled from app.tsx + its imports. Editing ANY
	// source file (entry OR a non-entry sibling) changes the compiled bundle,
	// so the .js ?v= must change too - the version is content-addressed over
	// the whole source tree, not just the entry file.
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "app.tsx"), []byte("import './huddle';"), 0644)
	os.WriteFile(filepath.Join(staticDir, "huddle.tsx"), []byte("export const v = 1"), 0644)

	html := []byte(`<script src="/static/app.js"></script>`)
	before := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	if before == "" {
		t.Fatal("app.js got no ?v= token")
	}
	// Edit a NON-entry sibling import: the bundle changes, so must the version.
	// Different length so the (mtime,size,count) memo key changes regardless of
	// the filesystem's mtime resolution.
	os.WriteFile(filepath.Join(staticDir, "huddle.tsx"), []byte("export const v = 2 // edited longer"), 0644)
	after := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	if before == after {
		t.Errorf("editing a sibling source did not bump the .js version (both %q)", before)
	}
}

func TestVersionStaticAssetsJSVersionIgnoresStaleCompiledBundle(t *testing.T) {
	// The framework's embedded esbuild writes the compiled bundle back to disk
	// as app.js for fast-path serves. Hashing the SOURCE tree means a freshly-
	// edited sibling busts the cache even though the on-disk app.js is
	// unchanged - the mtime-era bug was returning the stale .js mtime so CF
	// kept serving the cached bundle.
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "app.js"), []byte("/* compiled */"), 0644)
	os.WriteFile(filepath.Join(staticDir, "app.tsx"), []byte("import './notes';"), 0644)
	os.WriteFile(filepath.Join(staticDir, "notes.tsx"), []byte("export const v = 1"), 0644)

	html := []byte(`<script src="/static/app.js"></script>`)
	before := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	// Sibling edit only; on-disk app.js untouched.
	os.WriteFile(filepath.Join(staticDir, "notes.tsx"), []byte("export const v = 2 // changed"), 0644)
	after := vQueryRe.FindString(string(versionStaticAssets(html, app)))
	if before == "" || before == after {
		t.Errorf("sibling edit should bust the version despite a stale on-disk app.js (before=%q after=%q)", before, after)
	}
}

func TestVersionStaticAssetsIsIdempotentOnTwoPasses(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "x.css"), []byte(""), 0644)

	html := []byte(`<link href="/static/x.css">`)
	once := versionStaticAssets(html, app)
	twice := versionStaticAssets(once, app)

	if string(once) != string(twice) {
		t.Errorf("second pass changed output:\n  once : %s\n  twice: %s", once, twice)
	}
}

func TestTryServeHTMLFileInjectsDevReloadClientInDevMode(t *testing.T) {
	app := &App{Dir: t.TempDir(), DevMode: true, Design: featuresForStaticHTMLTest(false, false)}
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(staticDir, "index.html")
	if err := os.WriteFile(indexPath, []byte(`<!doctype html><html><body><h1>Dev</h1></body></html>`), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	if !tryServeHTMLFile(rr, httptest.NewRequest("GET", "/", nil), app, indexPath) {
		t.Fatal("expected HTML file to be served")
	}
	body := rr.Body.String()
	if !strings.Contains(body, `id="bm-dev-reload-client"`) {
		t.Fatalf("dev reload script not injected: %s", body)
	}
	if !strings.Contains(body, `new EventSource('/sse/events')`) {
		t.Fatalf("dev reload script missing SSE client: %s", body)
	}
}

func TestTryServeHTMLFileSkipsDevReloadClientInProduction(t *testing.T) {
	app := &App{Dir: t.TempDir(), Design: featuresForStaticHTMLTest(false, false)}
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(staticDir, "index.html")
	if err := os.WriteFile(indexPath, []byte(`<!doctype html><html><body><h1>Prod</h1></body></html>`), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	if !tryServeHTMLFile(rr, httptest.NewRequest("GET", "/", nil), app, indexPath) {
		t.Fatal("expected HTML file to be served")
	}
	if strings.Contains(rr.Body.String(), `bm-dev-reload-client`) {
		t.Fatalf("production page should not include dev reload client: %s", rr.Body.String())
	}
}

func TestTryServeHTMLFileInjectsDevReloadClientInTestingMode(t *testing.T) {
	app := &App{Dir: t.TempDir(), Design: featuresForStaticHTMLTest(true, false)}
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(staticDir, "index.html")
	if err := os.WriteFile(indexPath, []byte(`<!doctype html><html><body><h1>Testing</h1></body></html>`), 0644); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	if !tryServeHTMLFile(rr, httptest.NewRequest("GET", "/", nil), app, indexPath) {
		t.Fatal("expected HTML file to be served")
	}
	if !strings.Contains(rr.Body.String(), `id="bm-dev-reload-client"`) {
		t.Fatalf("testing page should include dev reload client: %s", rr.Body.String())
	}
}

func TestWrapLayoutInjectsDevReloadClientForTemplatePages(t *testing.T) {
	devApp := &App{Dir: t.TempDir(), DevMode: true, Design: featuresForStaticHTMLTest(false, false)}
	if body := WrapLayout("<main>Dev</main>", "Dev", devApp, nil); !strings.Contains(body, `__bmDevReloadClient`) {
		t.Fatalf("template dev page should include reload client: %s", body)
	}

	prodApp := &App{Dir: t.TempDir(), Design: featuresForStaticHTMLTest(false, false)}
	if body := WrapLayout("<main>Prod</main>", "Prod", prodApp, nil); strings.Contains(body, `__bmDevReloadClient`) {
		t.Fatalf("template production page should not include reload client: %s", body)
	}
}

func TestInjectDevReloadClientIsIdempotent(t *testing.T) {
	html := []byte(`<!doctype html><html><body></body></html>`)
	once := injectDevReloadClient(html)
	twice := injectDevReloadClient(once)

	if string(once) != string(twice) {
		t.Fatalf("second injection changed output:\nonce: %s\ntwice: %s", once, twice)
	}
}

func featuresForStaticHTMLTest(testingEnabled, analyticsEnabled bool) *DesignConfig {
	return &DesignConfig{
		Features: &FeaturesConfig{
			Testing:   &testingEnabled,
			Analytics: &analyticsEnabled,
		},
	}
}
