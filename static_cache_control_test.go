//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func staticCacheTestApp(t *testing.T) (*App, string) {
	t.Helper()
	app := &App{Dir: t.TempDir()}
	static := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(static, 0o755); err != nil {
		t.Fatal(err)
	}
	return app, static
}

func serveStaticForTest(app *App, rel, target string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	serveStaticAsset(rec, req, app, false, rel)
	return rec
}

// A replaced logo must show without renaming it: only the URL served HTML
// carries for the current bytes is immutable; every other spelling
// revalidates against a content ETag.
func TestStaticAssetCachedImmutableOnlyWhenVersioned(t *testing.T) {
	app, static := staticCacheTestApp(t)
	logo := filepath.Join(static, "logo.png")
	if err := os.WriteFile(logo, []byte("old logo"), 0o644); err != nil {
		t.Fatal(err)
	}
	ver, ok := assetContentVersion(static, "logo.png")
	if !ok {
		t.Fatal("no content version for an existing file")
	}
	serve := func(target string, header http.Header) *httptest.ResponseRecorder {
		return serveStaticForTest(app, "logo.png", target, header)
	}
	plain := serve("/static/logo.png", nil)
	if got := plain.Header().Get("Cache-Control"); got != "public, no-cache" {
		t.Fatalf("unversioned Cache-Control = %q", got)
	}
	if got := plain.Header().Get("ETag"); got != `"`+ver+`"` {
		t.Fatalf("ETag = %q, want the content version %q", got, ver)
	}
	if got := serve("/static/logo.png?v="+ver, nil).Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("current-version Cache-Control = %q", got)
	}
	// A stale or hand-written version, an extra parameter or another query
	// names bytes this response may not hold: never pinned for a year.
	for _, target := range []string{"/static/logo.png?v=2", "/static/logo.png?v=" + ver + "&x=1", "/static/logo.png?w=200", "/static/logo.png?v="} {
		if got := serve(target, nil).Header().Get("Cache-Control"); got != "public, no-cache" {
			t.Fatalf("%s Cache-Control = %q", target, got)
		}
	}
	// Unchanged: a revalidation is a 304, by ETag or by date.
	if rec := serve("/static/logo.png", http.Header{"If-None-Match": {`"` + ver + `"`}}); rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged ETag revalidation = %d", rec.Code)
	}
	lastModified := plain.Header().Get("Last-Modified")
	if rec := serve("/static/logo.png", http.Header{"If-Modified-Since": {lastModified}}); rec.Code != http.StatusNotModified {
		t.Fatalf("unchanged date revalidation = %d", rec.Code)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(logo, []byte("new logo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(logo, later, later); err != nil {
		t.Fatal(err)
	}
	if rec := serve("/static/logo.png", http.Header{"If-None-Match": {`"` + ver + `"`}}); rec.Code != http.StatusOK || rec.Body.String() != "new logo" {
		t.Fatalf("replaced logo revalidation = %d %q", rec.Code, rec.Body.String())
	}
	// The old version's URL now serves new bytes, so it must not be pinned.
	if got := serve("/static/logo.png?v="+ver, nil).Header().Get("Cache-Control"); got != "public, no-cache" {
		t.Fatalf("stale version after replacement Cache-Control = %q", got)
	}
}

// A promote rewrites every file with a new mtime; unchanged bytes keep their
// ETag, so a revalidation is still a 304.
func TestStaticAssetETagFollowsContentNotMtime(t *testing.T) {
	app, static := staticCacheTestApp(t)
	css := filepath.Join(static, "styles.css")
	if err := os.WriteFile(css, []byte("body{color:red}"), 0o644); err != nil {
		t.Fatal(err)
	}
	etag := serveStaticForTest(app, "styles.css", "/static/styles.css", nil).Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on a static file")
	}
	later := time.Now().Add(time.Hour)
	if err := os.WriteFile(css, []byte("body{color:red}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(css, later, later); err != nil {
		t.Fatal(err)
	}
	if rec := serveStaticForTest(app, "styles.css", "/static/styles.css", http.Header{"If-None-Match": {etag}}); rec.Code != http.StatusNotModified {
		t.Fatalf("rewritten identical stylesheet revalidation = %d", rec.Code)
	}
}

// A plain .js file is versioned with the static/ tree it may import from,
// the same value served HTML writes for it.
func TestStaticScriptImmutableOnlyForCurrentTreeVersion(t *testing.T) {
	app, static := staticCacheTestApp(t)
	if err := os.WriteFile(filepath.Join(static, "site.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := string(versionStaticAssets([]byte(`<script src="/static/site.js"></script>`), app))
	i := strings.Index(out, "?v=")
	if i < 0 {
		t.Fatalf("script reference not versioned: %s", out)
	}
	target := out[strings.Index(out, `"`)+1 : strings.LastIndex(out, `"`)]
	if got := serveStaticForTest(app, "site.js", target, nil).Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("%s Cache-Control = %q", target, got)
	}
	// Another file in the tree changed: the old URL is no longer current.
	if err := os.WriteFile(filepath.Join(static, "data.json"), []byte(`{"a":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := serveStaticForTest(app, "site.js", target, nil).Header().Get("Cache-Control"); got != "public, no-cache" {
		t.Fatalf("stale tree version Cache-Control = %q", got)
	}
}

// The uncached tree walk that confirms a .js URL's version runs only for a
// request naming the version pages currently emit; any other ?v= is answered
// from the cached tree version without walking static/.
func TestStaticScriptForeignVersionDoesNotWalkTree(t *testing.T) {
	app, static := staticCacheTestApp(t)
	for i := 0; i < 50; i++ {
		if err := os.WriteFile(filepath.Join(static, fmt.Sprintf("part%02d.js", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Production keeps the tree version for a second; tests default to 0.
	staticTreeVersionTTL = time.Hour
	t.Cleanup(func() { staticTreeVersionTTL = 0 })
	invalidateStaticTreeVersion(app.Dir)
	before := staticTreeWalks.Load()
	for i := 0; i < 20; i++ {
		rec := serveStaticForTest(app, "part00.js", fmt.Sprintf("/static/part00.js?v=bogus%d", i), nil)
		if got := rec.Header().Get("Cache-Control"); got != "public, no-cache" {
			t.Fatalf("foreign ?v= Cache-Control = %q", got)
		}
	}
	if walks := staticTreeWalks.Load() - before; walks > 1 {
		t.Fatalf("20 requests with an invented ?v= walked static/ %d times, want at most the 1 cached walk", walks)
	}
}

// poster, og:image content and srcset candidates get the same ?v= as
// href/src, and the PWA manifest's icon does too.
func TestFrameworkStaticReferencesCarryVersion(t *testing.T) {
	app, static := staticCacheTestApp(t)
	for name, body := range map[string]string{"intro.jpg": "poster", "og.png": "og", "a.png": "1x", "b.png": "2x", "icon-512.png": "icon"} {
		if err := os.WriteFile(filepath.Join(static, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	version := func(rel string) string {
		v, ok := assetContentVersion(static, rel)
		if !ok {
			t.Fatalf("no version for %s", rel)
		}
		return v
	}
	html := `<video poster="/static/intro.jpg"></video><meta property="og:image" content="/static/og.png">` +
		`<img srcset="/static/a.png 1x, /static/b.png?v=old 2x, https://cdn.example/c.png 3x" src="/static/a.png">` +
		`<meta name="description" content="see /static/og.png">`
	out := string(versionStaticAssets([]byte(html), app))
	for _, want := range []string{
		`poster="/static/intro.jpg?v=` + version("intro.jpg") + `"`,
		`content="/static/og.png?v=` + version("og.png") + `"`,
		`srcset="/static/a.png?v=` + version("a.png") + ` 1x, /static/b.png?v=` + version("b.png") + ` 2x, https://cdn.example/c.png 3x"`,
		`src="/static/a.png?v=` + version("a.png") + `"`,
		`content="see /static/og.png"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in\n%s", want, out)
		}
	}
	if again := string(versionStaticAssets([]byte(out), app)); again != out {
		t.Fatalf("versioning is not idempotent:\n%s\n%s", out, again)
	}

	app.Design = &DesignConfig{PWA: map[string]string{"icon": "/static/icon-512.png"}}
	var manifest struct {
		Icons []struct {
			Src string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal([]byte(GenerateManifest(app)), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Icons) == 0 || manifest.Icons[0].Src != "/static/icon-512.png?v="+version("icon-512.png") {
		t.Fatalf("manifest icon not versioned: %+v", manifest.Icons)
	}
}

// A link out of static/ is not served, so it gets no version either (and its
// target's hash never reaches a page).
func TestStaticAssetVersionRefusesLinkOutOfStatic(t *testing.T) {
	app, static := staticCacheTestApp(t)
	secret := filepath.Join(app.Dir, "env.yaml")
	if err := os.WriteFile(secret, []byte("KEY: value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(static, "logo.png")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, ok := assetContentVersion(static, "logo.png"); ok {
		t.Fatal("a link out of static/ got a content version")
	}
	html := `<img src="/static/logo.png">`
	if out := string(versionStaticAssets([]byte(html), app)); out != html {
		t.Fatalf("link out of static/ was versioned: %s", out)
	}
}
