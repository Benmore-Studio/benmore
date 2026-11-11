//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The app these tests serve: a browser entry with a module it imports, a
// `run: compute` module with a helper it imports, a compute module written as
// plain JavaScript, a JSX file, and ordinary assets. Every source file holds
// a marker no response may carry unless the file is a browser asset.
var sourceFormsFiles = map[string]string{
	"static/index.html":      `<!doctype html><html><head></head><body>HOME-PAGE<script type="module" src="/static/app.js"></script></body></html>`,
	"static/app.tsx":         "import { label } from './lib/label';\nexport const ui = label; // ENTRY-SOURCE-MARKER\n",
	"static/lib/label.ts":    "export const label = 'BROWSER-BUNDLE-TEXT'; // LABEL-SOURCE-MARKER\n",
	"static/widget.jsx":      "export const W = 'JSX-SOURCE-MARKER';\n",
	"static/server/sign.ts":  "import { KEY } from './key';\nexport function sign() { return 'signed:' + KEY; } // SIGN-SOURCE-MARKER\n",
	"static/server/key.ts":   "export const KEY = 'SERVER-SECRET-MARKER';\n",
	"static/server/plain.js": "export function run() { return 'PLAINJS-SERVER-MARKER'; }\n",
	"static/assets/x.js":     "console.log('ordinary-asset-js');\n",
	"static/styles.css":      "body { color: #111; } /* ordinary-asset-css */\n",
	"static/hello.txt":       "ordinary-asset-text\n",
	"flows/sign.yaml": `on:
  request:
    method: GET
    path: /api/sign
jobs:
  sign:
    steps:
      - id: s
        run: compute
        with:
          module: server/sign
          function: sign
      - id: p
        run: compute
        with:
          module: server/plain
          function: run
      - run: respond
        with:
          status: 200
          body: '${{ steps.s.outputs }}'
`,
}

// sourceFormsApp is an app without mcp.yaml that serves sourceFormsFiles from
// its directory, behind the whole app mux.
func sourceFormsApp(t *testing.T) (*App, http.Handler) {
	t.Helper()
	app, _ := auditApp(t)
	for name, body := range sourceFormsFiles {
		writeTestFile(t, app.Dir, name, body)
	}
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "sign.yaml"), []byte(sourceFormsFiles["flows/sign.yaml"]))
	if err != nil {
		t.Fatal(err)
	}
	app.Flows = flows
	return app, buildAppMux(app, false, "https://fixture.example.com")
}

func sourceFormsDo(h http.Handler, method, target string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// sourceFormsSpellings are the ways one static/-relative path can be written
// in a URL and still name the same file to the handlers: query strings, a
// trailing slash, percent-encoded dots, slashes and letters, and upper case.
func sourceFormsSpellings(rel string) map[string]string {
	dot := strings.LastIndex(rel, ".")
	stem, ext := rel[:dot], rel[dot:]
	last := rel[len(rel)-1]
	forms := map[string]string{
		"as written":     rel,
		"trailing slash": rel + "/",
		"?download":      rel + "?download=1",
		"?v=":            rel + "?v=0123456789ab",
		"%2e dot":        stem + "%2e" + ext[1:],
		"%2E dot":        stem + "%2E" + ext[1:],
		"encoded letter": rel[:len(rel)-1] + fmt.Sprintf("%%%02x", last),
		"upper-case ext": stem + strings.ToUpper(ext),
	}
	if slash := strings.Index(rel, "/"); slash >= 0 {
		forms["%2f slash"] = rel[:slash] + "%2f" + rel[slash+1:]
		forms["%2F slash"] = rel[:slash] + "%2F" + rel[slash+1:]
	}
	return forms
}

// Script source and `run: compute` modules under static/ are refused at
// /static/<path>. The same files answered 200 at the URL root (/app.tsx,
// /server/key.ts), the alias copied frontends use for /assets/x.js: the root
// form never asked. Every spelling of both forms now gets the one answer.
func TestStaticSourceIsRefusedAtEveryURLForm(t *testing.T) {
	_, mux := sourceFormsApp(t)
	refused := []string{
		"app.tsx", "lib/label.ts", "widget.jsx", // script source
		"server/sign.ts", "server/key.ts", // a compute module and its helper, as source
		"server/sign.js", "server/key.js", // the same two under their compiled names
		"server/plain.js", // a compute module written as JavaScript
	}
	for _, rel := range refused {
		// What /static/<rel> answers is the reference: a plain 404 that says
		// nothing about the file.
		want := sourceFormsDo(mux, http.MethodGet, "/static/"+rel)
		if want.Code != http.StatusNotFound || want.Body.String() != "404 page not found\n" || want.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET /static/%s = %d %q (Cache-Control %q), want the plain no-store 404", rel, want.Code, want.Body.String(), want.Header().Get("Cache-Control"))
		}
		for name, spelled := range sourceFormsSpellings(rel) {
			if name == "upper-case ext" && (rel == "server/sign.js" || rel == "server/key.js") {
				// Only a lower-case .js URL is compiled and no file has this
				// name, so the spelling names nothing: a miss, covered with
				// the other folds below.
				continue
			}
			for _, prefix := range []string{"/static/", "/"} {
				target := prefix + spelled
				for _, attempt := range []struct {
					method string
					header []string
				}{
					{http.MethodGet, nil},
					{http.MethodHead, nil},
					{http.MethodGet, []string{"Range", "bytes=0-15"}},
					{http.MethodGet, []string{"Accept", "text/html"}},
					{http.MethodGet, []string{"If-None-Match", `"x"`, "If-Modified-Since", "Mon, 02 Jan 2006 15:04:05 GMT"}},
				} {
					got := sourceFormsDo(mux, attempt.method, target, attempt.header...)
					if got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
						t.Errorf("%s %s %v (%s) = %d %q %v\nwant what /static/%s answers: %d %q %v",
							attempt.method, target, attempt.header, name, got.Code, got.Body.String(), got.Header(), rel, want.Code, want.Body.String(), want.Header())
					}
				}
			}
		}
	}
}

// Spellings that name the same file only where the file system says so (a
// case-insensitive one opens server/key.ts as SERVER/KEY.TS, and folds the
// long s U+017F to s), and path shapes the mux or the handlers rewrite. None
// may return the file, whatever the file system; where a spelling names no
// file at all the answer is the ordinary 404 of that URL form.
func TestStaticSourceIsNotServedUnderFoldedOrRewrittenPaths(t *testing.T) {
	_, mux := sourceFormsApp(t)
	const longS = "%C5%BF" // U+017F, which folds to "s"
	targets := []string{
		// case and Unicode folds of source files
		"APP.TSX", "App.Tsx", "app.t" + longS + "x", "LIB/label.ts", "lib/LABEL.TS", "lib/label.t" + longS,
		"WIDGET.JSX", "widget.j" + longS + "x", "SERVER/key.ts", "server/KEY.TS", longS + "erver/key.t" + longS,
		// the compiled names of a compute module and its helper, folded
		"SERVER/sign.js", "server/SIGN.js", "SERVER/key.js", "server/Key.js", "Server/Sign.js",
		longS + "erver/key.js", "server/" + longS + "ign.js", "server/sign.JS", "server/key.JS",
		// a compute module written as JavaScript, folded
		"SERVER/plain.js", "server/PLAIN.js", "server/plain.JS", longS + "erver/plain.js",
		// path shapes
		"server//key.ts", "server/./key.ts", "x/../server/key.ts", "server/%2e%2e/server/key.ts",
		"server%5ckey.ts", "server/key.ts%00", "server/key.ts.", "server/key.ts%20", "server/key.ts/index.html",
		"server/key.ts/..namedfork/data", "app.tsx/", "app.tsx//", "./app.tsx",
	}
	for _, spelled := range targets {
		for _, prefix := range []string{"/static/", "/"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				target := prefix + spelled
				got := sourceFormsDo(mux, method, target, "Accept", "*/*")
				// A redirect to the clean path is the mux's answer to // and
				// dot segments; follow it once.
				if loc := got.Header().Get("Location"); got.Code/100 == 3 && loc != "" {
					got = sourceFormsDo(mux, method, loc, "Accept", "*/*")
				}
				// A spelling that names no file may fall back to the app's
				// own index.html like any client route; nothing else is a 200.
				body := got.Body.String()
				page := got.Code == http.StatusOK && strings.Contains(body, "HOME-PAGE")
				if strings.Contains(body, "MARKER") || ((got.Code == http.StatusOK || got.Code == http.StatusPartialContent) && !page) {
					t.Errorf("%s %s = %d, body %q: source served", method, target, got.Code, body)
				}
			}
		}
	}
}

// A compute module that does not compile has no import graph, so its whole
// directory is refused, and a failed build is served as a module that quotes
// the source line it stopped at. Both held only for the spelling on disk:
// under another one the directory and the module were different paths.
func TestBrokenComputeModuleIsRefusedUnderFoldedNames(t *testing.T) {
	app, mux := sourceFormsApp(t)
	writeTestFile(t, app.Dir, "static/server/sign.ts", "import { KEY } from './key';\nexport function sign( { return KEY; } // BROKEN-SIGN-MARKER\n")
	writeTestFile(t, app.Dir, "static/toplevel.ts", "export function run( { return 'BROKEN-TOPLEVEL-MARKER'; }\n")
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "top.yaml"), []byte(`on:
  request:
    method: GET
    path: /api/top
jobs:
  top:
    steps:
      - id: t
        run: compute
        with:
          module: toplevel
          function: run
`))
	if err != nil {
		t.Fatal(err)
	}
	app.Flows = append(app.Flows, flows...)
	invalidateStaticTreeVersion(app.Dir)
	const longS = "%C5%BF"
	for _, spelled := range []string{
		"server/key.js", "SERVER/key.js", "server/KEY.js", "Server/Key.js", longS + "erver/key.js", // the broken module's directory
		"server/sign.js", "SERVER/sign.js", "server/SIGN.js", "server/" + longS + "ign.js",
		"toplevel.js", "TOPLEVEL.js", "TopLevel.js", "toplevel.ts", "TOPLEVEL.TS", // a broken module directly under static/
	} {
		for _, prefix := range []string{"/static/", "/"} {
			got := sourceFormsDo(mux, http.MethodGet, prefix+spelled)
			if got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), "MARKER") || strings.Contains(got.Body.String(), "bm-tsx-compile") {
				t.Errorf("GET %s%s = %d %q: a broken compute module's source or build message was served", prefix, spelled, got.Code, got.Body.String())
			}
		}
	}
	// Browser code elsewhere is still compiled and served.
	if got := sourceFormsDo(mux, http.MethodGet, "/static/app.js"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "BROWSER-BUNDLE-TEXT") {
		t.Errorf("GET /static/app.js = %d %q, want the bundle while a compute module is broken", got.Code, got.Body.String())
	}
}

// The refusal reads only the extension for source files, so it must fold the
// way a case-insensitive file system does: such a system opens app.ts for a
// request spelled app.TS or app.tſ.
func TestStaticServerSourceExtensionFolds(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	for _, name := range []string{
		"app.ts", "app.TS", "app.Ts", "app.tſ", "app.tsx", "app.TSX", "app.tſx", "x/y.mts", "x/y.MTS", "x/y.mTſ",
		"x/y.cts", "x/y.CtS", "w.jsx", "w.JSX", "w.jſx", "/lead/slash.ts", "dir.ts/",
	} {
		if !staticServerSource(app, name) {
			t.Errorf("staticServerSource(%q) = false, want script source refused", name)
		}
	}
	for _, name := range []string{"app.js", "app.JS", "app.mjs", "x.css", "x.tsv", "x.ts.html", "ts", "x.tsx.map", "x.json", "notes.txt", ""} {
		if staticServerSource(app, name) {
			t.Errorf("staticServerSource(%q) = true in an app with no compute module", name)
		}
	}
}

// Compiled output and ordinary assets are served exactly as before, at both
// forms: the bundle only under /static/, files with no cache headers at the
// root, and the SPA fallback for routes that are not files.
func TestStaticAssetsAndCompiledOutputStayServed(t *testing.T) {
	_, mux := sourceFormsApp(t)
	type want struct {
		code                  int
		body, contentType, cc string
		etag                  bool
	}
	for target, w := range map[string]want{
		"/static/app.js":             {code: 200, body: "BROWSER-BUNDLE-TEXT", contentType: "application/javascript; charset=utf-8", cc: "private, no-cache, must-revalidate", etag: true},
		"/static/lib/label.js":       {code: 200, body: "BROWSER-BUNDLE-TEXT", contentType: "application/javascript; charset=utf-8", cc: "private, no-cache, must-revalidate", etag: true},
		"/static/assets/x.js":        {code: 200, body: "ordinary-asset-js", contentType: "text/javascript; charset=utf-8", cc: "public, no-cache", etag: true},
		"/static/styles.css":         {code: 200, body: "ordinary-asset-css", contentType: "text/css; charset=utf-8", cc: "public, no-cache", etag: true},
		"/static/hello.txt":          {code: 200, body: "ordinary-asset-text", contentType: "text/plain; charset=utf-8", cc: "public, no-cache", etag: true},
		"/assets/x.js":               {code: 200, body: "ordinary-asset-js", contentType: "text/javascript; charset=utf-8"},
		"/assets/x.js?v=1":           {code: 200, body: "ordinary-asset-js", contentType: "text/javascript; charset=utf-8"},
		"/styles.css":                {code: 200, body: "ordinary-asset-css", contentType: "text/css; charset=utf-8"},
		"/hello.txt":                 {code: 200, body: "ordinary-asset-text", contentType: "text/plain; charset=utf-8"},
		"/hello.txt/":                {code: 200, body: "ordinary-asset-text", contentType: "text/plain; charset=utf-8"},
		"/assets%2fx.js":             {code: 200, body: "ordinary-asset-js", contentType: "text/javascript; charset=utf-8"},
		"/":                          {code: 200, body: "HOME-PAGE", contentType: "text/html; charset=utf-8", cc: "no-store"},
		"/index.html":                {code: 200, body: "HOME-PAGE", contentType: "text/html; charset=utf-8", cc: "no-store"},
		"/some/client/route":         {code: 200, body: "HOME-PAGE", contentType: "text/html; charset=utf-8", cc: "no-store"},
		"/app.js":                    {code: 404, body: "Page not found", contentType: "text/html; charset=utf-8"},
		"/lib/label.js":              {code: 404, body: "Page not found", contentType: "text/html; charset=utf-8"},
		"/assets/missing.js":         {code: 404, body: "Page not found", contentType: "text/html; charset=utf-8"},
		"/static/assets/missing.js":  {code: 404, body: "404 page not found", contentType: "text/plain; charset=utf-8", cc: "no-store"},
		"/static/assets/missing.css": {code: 404, body: "404 page not found", contentType: "text/plain; charset=utf-8", cc: "no-store"},
	} {
		got := sourceFormsDo(mux, http.MethodGet, target, "Accept", "text/html")
		if got.Code != w.code || !strings.Contains(got.Body.String(), w.body) || got.Header().Get("Content-Type") != w.contentType {
			t.Errorf("GET %s = %d %s %q, want %d %s containing %q", target, got.Code, got.Header().Get("Content-Type"), got.Body.String(), w.code, w.contentType, w.body)
		}
		if w.code == 200 || w.cc != "" {
			if cc := got.Header().Get("Cache-Control"); cc != w.cc {
				t.Errorf("GET %s Cache-Control = %q, want %q", target, cc, w.cc)
			}
		}
		if hasTag := got.Header().Get("ETag") != ""; w.code == 200 && hasTag != w.etag {
			t.Errorf("GET %s ETag = %q, want one: %v", target, got.Header().Get("ETag"), w.etag)
		}
		if strings.Contains(got.Body.String(), "SERVER") || strings.Contains(got.Body.String(), "SOURCE-MARKER") {
			t.Errorf("GET %s carries source text: %q", target, got.Body.String())
		}
	}
	// HEAD and byte ranges of an asset, at both forms.
	for _, target := range []string{"/static/hello.txt", "/hello.txt"} {
		if got := sourceFormsDo(mux, http.MethodHead, target); got.Code != http.StatusOK || got.Header().Get("Content-Length") != "20" {
			t.Errorf("HEAD %s = %d Content-Length %q, want 200 and 20", target, got.Code, got.Header().Get("Content-Length"))
		}
		if got := sourceFormsDo(mux, http.MethodGet, target, "Range", "bytes=0-7"); got.Code != http.StatusPartialContent || got.Body.String() != "ordinary" {
			t.Errorf("GET %s Range = %d %q, want 206 %q", target, got.Code, got.Body.String(), "ordinary")
		}
	}
	// The compute modules still run; what a flow answers with is the app's own choice.
	if got := sourceFormsDo(mux, http.MethodGet, "/api/sign"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "signed:SERVER-SECRET-MARKER") {
		t.Errorf("GET /api/sign = %d %q, want the compute module's output", got.Code, got.Body.String())
	}
}

// A link inside static/ gives a source file a second name. The name asked for
// passes the check on the request (notes.txt, page.html); the file it
// resolves to must not.
func TestStaticSourceIsNotServedThroughALinkInsideStatic(t *testing.T) {
	app, mux := sourceFormsApp(t)
	static := filepath.Join(app.Dir, "static")
	for link, target := range map[string]string{
		"notes.txt": "server/key.ts", "page.html": "app.tsx", "assets/k.css": "../server/key.ts", "alias.css": "styles.css",
	} {
		if err := os.Symlink(target, filepath.Join(static, filepath.FromSlash(link))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	for _, target := range []string{
		"/static/notes.txt", "/notes.txt", "/static/page.html", "/page.html", "/page", "/static/assets/k.css", "/assets/k.css",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			got := sourceFormsDo(mux, method, target, "Accept", "text/html")
			if got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), "MARKER") {
				t.Errorf("%s %s = %d %q: a link to source was served", method, target, got.Code, got.Body.String())
			}
		}
	}
	// A link to an ordinary asset is still served at both forms.
	for _, target := range []string{"/static/alias.css", "/alias.css"} {
		if got := sourceFormsDo(mux, http.MethodGet, target); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "ordinary-asset-css") {
			t.Errorf("GET %s = %d %q, want the linked stylesheet", target, got.Code, got.Body.String())
		}
	}
	// At /static/ the refused link answers what any refused path answers.
	want := sourceFormsDo(mux, http.MethodGet, "/static/server/key.ts")
	for _, target := range []string{"/static/notes.txt", "/notes.txt", "/assets/k.css"} {
		got := sourceFormsDo(mux, http.MethodGet, target)
		if got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
			t.Errorf("GET %s = %d %q %v, want the refusal /static/server/key.ts gets: %q %v", target, got.Code, got.Body.String(), got.Header(), want.Body.String(), want.Header())
		}
	}
}

// With a reviewed mcp.yaml loaded the app serves its captured source. The
// root form gives the same answer as /static/ for script source there too.
func TestReviewedAppRefusesSourceAtTheRootLikeStatic(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	for name, body := range sourceFormsFiles {
		if strings.HasPrefix(name, "flows/") || strings.HasPrefix(name, "static/server/") {
			continue // the fixture manifest reviews no flow
		}
		writeTestFile(t, app.Dir, name, body)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
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
	mux := buildAppMux(app, false, "https://fixture.example.com")
	for _, rel := range []string{"app.tsx", "lib/label.ts", "widget.jsx"} {
		want := sourceFormsDo(mux, http.MethodGet, "/static/"+rel)
		if want.Code != http.StatusNotFound || want.Body.String() != "404 page not found\n" {
			t.Fatalf("GET /static/%s = %d %q, want the plain 404", rel, want.Code, want.Body.String())
		}
		for name, spelled := range sourceFormsSpellings(rel) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				got := sourceFormsDo(mux, method, "/"+spelled, "Accept", "text/html")
				if got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
					t.Errorf("%s /%s (%s) = %d %q %v\nwant what /static/%s answers: %d %q %v",
						method, spelled, name, got.Code, got.Body.String(), got.Header(), rel, want.Code, want.Body.String(), want.Header())
				}
			}
		}
	}
	if got := sourceFormsDo(mux, http.MethodGet, "/static/app.js"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "BROWSER-BUNDLE-TEXT") {
		t.Errorf("GET /static/app.js = %d %q, want the compiled bundle", got.Code, got.Body.String())
	}
	if got := sourceFormsDo(mux, http.MethodGet, "/static/styles.css"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "ordinary-asset-css") {
		t.Errorf("GET /static/styles.css = %d %q, want the stylesheet", got.Code, got.Body.String())
	}
	if got := sourceFormsDo(mux, http.MethodGet, "/", "Accept", "text/html"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "HOME-PAGE") {
		t.Errorf("GET / = %d, want the page", got.Code)
	}
}

// pwa.service_worker serves a static/ file at /sw.js on the grounds that the
// file is public at /static/ anyway. A `run: compute` module is not, so
// naming one there serves the generated worker instead.
func TestServiceWorkerNeverServesAComputeModule(t *testing.T) {
	app, _ := sourceFormsApp(t)
	app.Design = &DesignConfig{PWA: map[string]string{"service_worker": "/static/server/plain.js"}, SEO: map[string]string{"site_name": "X"}}
	if body, _ := serveSW(t, app); strings.Contains(body, "MARKER") || body != GenerateServiceWorker(app) {
		t.Errorf("/sw.js served the compute module:\n%s", body)
	}
	app.Design.PWA["service_worker"] = "/static/assets/x.js"
	if body, _ := serveSW(t, app); !strings.Contains(body, "ordinary-asset-js") {
		t.Errorf("/sw.js did not serve the app's own worker:\n%s", body)
	}
}
