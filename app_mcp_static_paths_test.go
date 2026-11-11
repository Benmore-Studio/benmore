//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const (
	staticImmutableCC  = "public, max-age=31536000, immutable"
	staticRevalidateCC = "private, no-cache, must-revalidate"
)

// reviewedStaticApp loads sources as the reviewed generation of an app whose
// mcp.yaml binds them, the state a `create_app` or `benmore new` starter is in.
func reviewedStaticApp(t *testing.T, sources map[string]string) *App {
	t.Helper()
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	for name, source := range sources {
		writeTestFile(t, app.Dir, name, source)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAndReloadStaticApp(t, app)
	return app
}

// reviewAndReloadStaticApp reviews the files on disk and publishes them as the
// app's next generation, as a reviewed push followed by its reload does.
func reviewAndReloadStaticApp(t *testing.T, app *App) {
	t.Helper()
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if appMCPManifestSnapshot(app) == nil {
		t.Fatal("fixture did not load a reviewed manifest")
	}
}

func staticGET(mux http.Handler, target string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// pageAssetVersion returns the ?v= a served page carries for asset.
func pageAssetVersion(t *testing.T, page, asset string) string {
	t.Helper()
	m := regexp.MustCompile(regexp.QuoteMeta(asset) + `\?v=([0-9a-zA-Z]+)`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("page carries no ?v= for %s:\n%s", asset, page)
	}
	return m[1]
}

var staticPathsSources = map[string]string{
	"static/index.html":                  `<!doctype html><html><head><include src="partials/head.html" /></head><body>home<script type="module" src="/static/app.js"></script><script src="/static/assets/x.js"></script></body></html>`,
	"static/guide/index.html":            `<!doctype html><html><head><include src="partials/head.html" /></head><body>guide-index</body></html>`,
	"static/about.html":                  `<!doctype html><html><head><include src="partials/head.html" /></head><body>about-page</body></html>`,
	"static/partials/head.html":          `<meta name="generation" content="reviewed-head"><link rel="stylesheet" href="/static/styles.css"><link rel="icon" href="/static/favicon.svg">`,
	"static/app.tsx":                     `import { label } from "./lib/label"; console.log(label);`,
	"static/lib/label.ts":                `export const label = "reviewed-bundle";`,
	"static/styles.css":                  "body { color: #111; } /* reviewed-css */\n",
	"static/assets/x.js":                 "console.log('reviewed-asset-js');\n",
	"static/assets/x.css":                ".x { color: red; } /* reviewed-asset-css */\n",
	"static/favicon.svg":                 `<svg xmlns="http://www.w3.org/2000/svg"><!-- reviewed-icon --></svg>`,
	"static/hello.txt":                   "reviewed-text\n",
	"static/.well-known/assetlinks.json": `[{"reviewed":"assetlinks"}]` + "\n",
}

// A copied Vite, Next export or CRA build references its files from the URL
// root (/assets/app.js). With a reviewed mcp.yaml loaded those requests
// answered 404: only .html candidates were looked up in the captured source.
// They are served from the same captured bytes as /static/<path>, with the
// same headers, and never from the directory on disk.
func TestReviewedAppServesRootRelativeStaticFilesFromCapture(t *testing.T) {
	app := reviewedStaticApp(t, staticPathsSources)
	// The directory changes after the review; none of this may be served.
	for name := range staticPathsSources {
		writeTestFile(t, app.Dir, name, "unreviewed replacement of "+name)
	}
	writeTestFile(t, app.Dir, "static/late.css", ".late {}")
	mux := buildAppMux(app, false, "https://fixture.example.com")

	for _, rel := range []string{"assets/x.js", "assets/x.css", "styles.css", "favicon.svg", "hello.txt", ".well-known/assetlinks.json"} {
		want := staticPathsSources["static/"+rel]
		root := staticGET(mux, "/"+rel)
		under := staticGET(mux, "/static/"+rel)
		if root.Code != http.StatusOK || root.Body.String() != want {
			t.Errorf("GET /%s = %d %q, want the captured bytes %q", rel, root.Code, root.Body.String(), want)
			continue
		}
		if under.Code != http.StatusOK || under.Body.String() != root.Body.String() {
			t.Errorf("GET /static/%s = %d %q, want the bytes /%s serves", rel, under.Code, under.Body.String(), rel)
		}
		for _, h := range []string{"Content-Type", "ETag", "Cache-Control", "CDN-Cache-Control"} {
			if root.Header().Get(h) != under.Header().Get(h) {
				t.Errorf("/%s %s = %q, /static/%s has %q", rel, h, root.Header().Get(h), rel, under.Header().Get(h))
			}
		}
		etag := root.Header().Get("ETag")
		if etag == "" || root.Header().Get("Cache-Control") != staticRevalidateCC || root.Header().Get("CDN-Cache-Control") != "no-store" {
			t.Errorf("/%s ETag %q Cache-Control %q CDN %q, want a validator and the revalidated answer", rel, etag, root.Header().Get("Cache-Control"), root.Header().Get("CDN-Cache-Control"))
		}
		if again := staticGET(mux, "/"+rel, "If-None-Match", etag); again.Code != http.StatusNotModified {
			t.Errorf("conditional GET /%s = %d, want 304", rel, again.Code)
		}
	}

	// Not in the reviewed generation, source rather than a browser asset, or
	// outside static/: still not served from the root.
	for _, path := range []string{
		"/late.css",          // written after the review
		"/assets/missing.js", // never existed
		"/app.tsx",           // script source, refused under /static/ too
		"/lib/label.ts",      // script source
		"/app.js",            // compiled bundles are served under /static/ only
		"/schema.sql",        // captured, but not under static/
		"/mcp.yaml",          // app root
	} {
		rec := staticGET(mux, path)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s = 200 %q, want it not served", path, rec.Body.String())
		}
		for _, leak := range []string{"unreviewed", "CREATE TABLE", "reviewed-bundle", "contract_digest", ".late"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("GET %s leaked %q: %s", path, leak, rec.Body.String())
			}
		}
	}

	// HTML keeps its own path forms, includes expanded from the capture.
	for path, marker := range map[string]string{
		"/": "home", "/index.html": "home", "/about": "about-page", "/about.html": "about-page",
		"/guide/": "guide-index", "/guide/index.html": "guide-index",
	} {
		rec := staticGET(mux, path, "Accept", "text/html")
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, marker) || !strings.Contains(body, "reviewed-head") || strings.Contains(body, "<include") || strings.Contains(body, "unreviewed") {
			t.Errorf("GET %s = %d, want the reviewed page with its include expanded: %s", path, rec.Code, body)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", path, rec.Header().Get("Cache-Control"))
		}
	}
	// A client-side route still falls back to the reviewed index page; a
	// missing asset never does.
	if rec := staticGET(mux, "/some/client/route", "Accept", "text/html"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "home") {
		t.Errorf("client route fallback = %d %s", rec.Code, rec.Body.String())
	}
	if rec := staticGET(mux, "/assets/missing.js", "Accept", "text/html"); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset = %d, want 404", rec.Code)
	}
}

// A /static/ URL whose ?v= is the version the page carries names the captured
// bytes, so it is cached for a year; every other spelling keeps the
// revalidated answer. The page's version comes from the captured source, so
// an edit on disk changes neither the URL nor the bytes behind it, and a new
// generation gets new URLs.
func TestReviewedAppCachesStaticURLsThatNameCapturedBytes(t *testing.T) {
	app := reviewedStaticApp(t, staticPathsSources)
	mux := buildAppMux(app, false, "https://fixture.example.com")
	page := staticGET(mux, "/", "Accept", "text/html").Body.String()
	versions := map[string]string{}
	for _, asset := range []string{"/static/app.js", "/static/styles.css", "/static/assets/x.js", "/static/favicon.svg"} {
		versions[asset] = pageAssetVersion(t, page, asset)
	}
	if versions["/static/app.js"] != versions["/static/assets/x.js"] {
		t.Errorf("script versions differ: %v", versions)
	}
	bodies := map[string]string{}
	check := func(mux http.Handler, target, wantCC string) *httptest.ResponseRecorder {
		t.Helper()
		rec := staticGET(mux, target)
		if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
			t.Errorf("GET %s = %d ETag %q", target, rec.Code, rec.Header().Get("ETag"))
		}
		if got := rec.Header().Get("Cache-Control"); got != wantCC {
			t.Errorf("GET %s Cache-Control = %q, want %q", target, got, wantCC)
		}
		cdn := rec.Header().Get("CDN-Cache-Control")
		if wantCC == staticImmutableCC && cdn != "" || wantCC == staticRevalidateCC && cdn != "no-store" {
			t.Errorf("GET %s CDN-Cache-Control = %q with Cache-Control %q", target, cdn, wantCC)
		}
		return rec
	}
	for asset, v := range versions {
		rec := check(mux, asset+"?v="+v, staticImmutableCC)
		bodies[asset] = rec.Body.String()
		check(mux, asset, staticRevalidateCC)
		check(mux, asset+"?v=000000000000", staticRevalidateCC)
		check(mux, asset+"?v="+v+"&a=1", staticRevalidateCC)
		check(mux, asset+"?a=1&v="+v, staticRevalidateCC)
		check(mux, asset+"?x="+v, staticRevalidateCC)
		// The stored copy still validates.
		if again := staticGET(mux, asset+"?v="+v, "If-None-Match", rec.Header().Get("ETag")); again.Code != http.StatusNotModified {
			t.Errorf("conditional GET %s = %d, want 304", asset, again.Code)
		}
	}
	if !strings.Contains(bodies["/static/app.js"], "reviewed-bundle") || bodies["/static/styles.css"] != staticPathsSources["static/styles.css"] {
		t.Fatalf("versioned URLs did not serve the captured source: %q", bodies)
	}
	// A file's own content hash is not a script's version: scripts are
	// versioned by everything they may bundle.
	if own := strings.Trim(staticGET(mux, "/static/assets/x.js").Header().Get("ETag"), `"`); len(own) >= 12 {
		check(mux, "/static/assets/x.js?v="+own[:12], staticRevalidateCC)
	}

	// Edits on disk without a reload: the page names the same URLs, and they
	// still answer with the captured bytes.
	writeTestFile(t, app.Dir, "static/styles.css", "body { color: #222; } /* edited-on-disk */\n")
	writeTestFile(t, app.Dir, "static/lib/label.ts", `export const label = "edited-on-disk";`)
	writeTestFile(t, app.Dir, "static/assets/x.js", "console.log('edited-on-disk');\n")
	invalidateStaticTreeVersion(app.Dir)
	edited := staticGET(mux, "/", "Accept", "text/html").Body.String()
	for asset, v := range versions {
		if got := pageAssetVersion(t, edited, asset); got != v {
			t.Errorf("%s version changed with the directory: %s -> %s", asset, v, got)
		}
		rec := check(mux, asset+"?v="+v, staticImmutableCC)
		if rec.Body.String() != bodies[asset] || strings.Contains(rec.Body.String(), "edited-on-disk") {
			t.Errorf("GET %s?v=%s changed with the directory: %q", asset, v, rec.Body.String())
		}
	}

	// The next reviewed generation: new URLs for what changed, and the old
	// URLs no longer claim to be immutable.
	reviewAndReloadStaticApp(t, app)
	mux = buildAppMux(app, false, "https://fixture.example.com")
	next := staticGET(mux, "/", "Accept", "text/html").Body.String()
	for _, asset := range []string{"/static/app.js", "/static/styles.css", "/static/assets/x.js"} {
		old, v := versions[asset], pageAssetVersion(t, next, asset)
		if v == old {
			t.Errorf("%s kept version %s across a generation that changed it", asset, v)
			continue
		}
		rec := check(mux, asset+"?v="+v, staticImmutableCC)
		if !strings.Contains(rec.Body.String(), "edited-on-disk") {
			t.Errorf("GET %s?v=%s did not serve the new generation: %q", asset, v, rec.Body.String())
		}
		stale := check(mux, asset+"?v="+old, staticRevalidateCC)
		if stale.Body.String() != rec.Body.String() {
			t.Errorf("GET %s with the old version served other bytes than the current generation", asset)
		}
	}
	// An unchanged file keeps its URL and its bytes.
	if v := pageAssetVersion(t, next, "/static/favicon.svg"); v != versions["/static/favicon.svg"] {
		t.Errorf("unchanged favicon.svg changed version: %s -> %s", versions["/static/favicon.svg"], v)
	}
}

// A bundle that does not build is served as a module that throws; that answer
// is never cached for a year, whatever ?v= says.
func TestReviewedAppNeverCachesAFailedBundle(t *testing.T) {
	app := reviewedStaticApp(t, map[string]string{
		"static/index.html": `<!doctype html><html><head></head><body><script type="module" src="/static/app.js"></script></body></html>`,
		"static/app.tsx":    `import { gone } from "./lib/gone"; console.log(gone);`,
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	v := pageAssetVersion(t, staticGET(mux, "/", "Accept", "text/html").Body.String(), "/static/app.js")
	rec := staticGET(mux, "/static/app.js?v="+v)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "[bm-tsx-compile]") {
		t.Fatalf("failed bundle = %d %q, want the module that throws", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != staticRevalidateCC {
		t.Errorf("failed bundle Cache-Control = %q, want %q", got, staticRevalidateCC)
	}
}

// The version a page carries is bound to the generation that is serving: a
// manifest whose source set carries no version (or whose recorded digest is
// not the digest of the bytes) never yields an immutable answer.
func TestCapturedStaticVersionRequiresTheServedBytes(t *testing.T) {
	app := reviewedStaticApp(t, staticPathsSources)
	mux := buildAppMux(app, false, "https://fixture.example.com")
	page := staticGET(mux, "/", "Accept", "text/html").Body.String()
	v := pageAssetVersion(t, page, "/static/assets/x.js")

	// Same manifest, other bytes under the script's name: the digest recorded
	// for the generation no longer describes what would be sent.
	app.mu.Lock()
	swapped := make(map[string][]byte, len(app.sourceFiles))
	for name, data := range app.sourceFiles {
		swapped[name] = data
	}
	swapped["static/assets/x.js"] = []byte("console.log('not the reviewed bytes');\n")
	original := app.sourceFiles
	app.sourceFiles = swapped
	app.mu.Unlock()
	if rec := staticGET(mux, "/static/assets/x.js?v="+v); rec.Header().Get("Cache-Control") != staticRevalidateCC {
		t.Errorf("bytes outside the generation: Cache-Control = %q, want %q", rec.Header().Get("Cache-Control"), staticRevalidateCC)
	}
	app.mu.Lock()
	app.sourceFiles = original
	app.mu.Unlock()
	if rec := staticGET(mux, "/static/assets/x.js?v="+v); rec.Header().Get("Cache-Control") != staticImmutableCC {
		t.Errorf("restored generation: Cache-Control = %q, want %q", rec.Header().Get("Cache-Control"), staticImmutableCC)
	}

	// A hand-built manifest with digests but no version (older tests, tools).
	bare := &App{Dir: app.Dir, MCP: &AppMCPManifest{sourceHashes: app.MCP.sourceHashes}, sourceFiles: original}
	if got := string(versionStaticAssets([]byte(`<script src="/static/assets/x.js"></script>`), bare)); strings.Contains(got, "?v=") {
		t.Errorf("a generation without a version versioned a script: %s", got)
	}
	if got := string(versionStaticAssets([]byte(`<link href="/static/styles.css">`), bare)); !strings.Contains(got, "/static/styles.css?v=") {
		t.Errorf("a captured stylesheet lost its content version: %s", got)
	}
	// References the generation does not hold are left as written.
	for _, ref := range []string{"/static/late.css", "/static/nope.js", "/static/../static/styles.css", "/static/../theme.css"} {
		in := `<link href="` + ref + `">`
		if got := string(versionStaticAssets([]byte(in), app)); got != in {
			t.Errorf("versioned a reference outside the generation: %s", got)
		}
	}
}

// A reload whose source no longer matches the review turns the connector off
// and the app serves its directory again: pages go back to naming the
// directory's bytes, with the headers of an app without a manifest.
func TestReviewedAppWithAStaleReviewServesTheDirectory(t *testing.T) {
	app := reviewedStaticApp(t, staticPathsSources)
	mux := buildAppMux(app, false, "https://fixture.example.com")
	captured := pageAssetVersion(t, staticGET(mux, "/", "Accept", "text/html").Body.String(), "/static/styles.css")

	writeTestFile(t, app.Dir, "static/styles.css", "body { color: #333; } /* edited-after-review */\n")
	config, err := loadServedRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if appMCPManifestSnapshot(app) != nil {
		t.Fatal("a stale review stayed loaded")
	}
	mux = buildAppMux(app, false, "https://fixture.example.com")
	current := pageAssetVersion(t, staticGET(mux, "/", "Accept", "text/html").Body.String(), "/static/styles.css")
	if current == captured {
		t.Fatalf("page still names the superseded generation: %s", current)
	}
	for target, wantCC := range map[string]string{
		"/static/styles.css?v=" + current:  staticImmutableCC,
		"/static/styles.css?v=" + captured: "public, no-cache",
		"/static/styles.css":               "public, no-cache",
		"/styles.css":                      "",
	} {
		rec := staticGET(mux, target)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "edited-after-review") {
			t.Errorf("GET %s = %d %q, want the directory's bytes", target, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != wantCC {
			t.Errorf("GET %s Cache-Control = %q, want %q", target, got, wantCC)
		}
	}
}

// Without mcp.yaml nothing changes: files come from the directory, the root
// alias sends no cache headers, and only the page's own ?v= is immutable.
func TestOrdinaryAppStaticServingIsUnchanged(t *testing.T) {
	app, _ := auditApp(t)
	for name, source := range staticPathsSources {
		writeTestFile(t, app.Dir, name, source)
	}
	mux := buildAppMux(app, false, "https://fixture.example.com")
	page := staticGET(mux, "/", "Accept", "text/html").Body.String()
	if !strings.Contains(page, "reviewed-head") || strings.Contains(page, "<include") {
		t.Fatalf("page did not expand its include: %s", page)
	}
	want := func(target, cc, cdn, body string) {
		t.Helper()
		rec := staticGET(mux, target)
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != cc || rec.Header().Get("CDN-Cache-Control") != cdn {
			t.Errorf("GET %s = %d Cache-Control %q CDN %q, want 200 %q %q", target, rec.Code, rec.Header().Get("Cache-Control"), rec.Header().Get("CDN-Cache-Control"), cc, cdn)
		}
		if body != "" && !strings.Contains(rec.Body.String(), body) {
			t.Errorf("GET %s body %q, want it to contain %q", target, rec.Body.String(), body)
		}
	}
	js, css := pageAssetVersion(t, page, "/static/app.js"), pageAssetVersion(t, page, "/static/styles.css")
	want("/static/app.js?v="+js, staticImmutableCC, "", "reviewed-bundle")
	want("/static/app.js", staticRevalidateCC, "no-store", "reviewed-bundle")
	want("/static/app.js?v=000000000000", staticRevalidateCC, "no-store", "reviewed-bundle")
	want("/static/styles.css?v="+css, staticImmutableCC, "", "reviewed-css")
	want("/static/styles.css", "public, no-cache", "", "reviewed-css")
	want("/static/styles.css?v=000000000000", "public, no-cache", "", "reviewed-css")
	want("/static/assets/x.js?v="+js, staticImmutableCC, "", "reviewed-asset-js")
	want("/static/assets/x.js", "public, no-cache", "", "reviewed-asset-js")
	want("/assets/x.js", "", "", "reviewed-asset-js")
	want("/assets/x.css", "", "", "reviewed-asset-css")
	want("/styles.css", "", "", "reviewed-css")
	want("/hello.txt", "", "", "reviewed-text")

	// The directory is what is served: an edit shows on the next request and
	// moves the page's version.
	writeTestFile(t, app.Dir, "static/styles.css", "body { color: #222; } /* edited-on-disk */\n")
	want("/styles.css", "", "", "edited-on-disk")
	want("/static/styles.css", "public, no-cache", "", "edited-on-disk")
	want("/static/styles.css?v="+css, "public, no-cache", "", "edited-on-disk")
	if next := pageAssetVersion(t, staticGET(mux, "/", "Accept", "text/html").Body.String(), "/static/styles.css"); next == css {
		t.Errorf("stylesheet version did not follow the directory: %s", next)
	}
	if rec := staticGET(mux, "/assets/missing.js"); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset = %d, want 404", rec.Code)
	}
}
