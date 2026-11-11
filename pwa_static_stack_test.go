//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// `pwa:` promised an installable, offline-capable app with zero setup, but
// only the SSR shell carried the manifest link and the worker registration:
// the default TSX stack's static/*.html pages got neither. The generated
// worker's offline mode precached page routes that are all served no-store,
// so it stored nothing and its fallback resolved to nothing. These tests pin
// the static-page wiring, an offline fallback that works without ever
// storing a page, the manifest icon type and the theme color.

func pwaStaticTestApp(t *testing.T, pwa map[string]string, page string) *App {
	t.Helper()
	app := &App{Dir: t.TempDir(), Design: &DesignConfig{PWA: pwa, SEO: map[string]string{"site_name": "Events"}}}
	static := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(static, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "dashboard.html"), []byte(page), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "favicon.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	return app
}

func servePWAStaticPage(t *testing.T, app *App) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	if !serveStaticHTML(rec, req, app) || rec.Code != http.StatusOK {
		t.Fatalf("/dashboard not served: %d", rec.Code)
	}
	return rec.Body.String()
}

const pwaPlainPage = "<!DOCTYPE html><html><head><title>Dashboard</title></head><body><div id=\"root\"></div></body></html>"

var pwaFrontConfig = map[string]string{
	"name": "Events", "short_name": "Events", "icon": "/static/favicon.svg",
	"theme_color": "#18181b", "background_color": "#ffffff", "offline": "true",
}

func TestStaticHTMLPageGetsPWAWiringWhenConfigured(t *testing.T) {
	body := servePWAStaticPage(t, pwaStaticTestApp(t, pwaFrontConfig, pwaPlainPage))
	head := body[:strings.Index(body, "</head>")]
	for _, want := range []string{
		`<link rel="manifest" href="/manifest.json">`,
		`<meta name="theme-color" content="#18181b">`,
		`<script src="/_internal/pwa.js" defer></script>`,
		`<meta name="apple-mobile-web-app-title" content="Events">`,
	} {
		if strings.Count(body, want) != 1 || !strings.Contains(head, want) {
			t.Fatalf("static page lacks %s once in <head>:\n%s", want, body)
		}
	}
	// The registration is a same-origin script (script-src 'self'), so it
	// does not depend on the CSP allowing inline scripts.
	if strings.Contains(body, "serviceWorker.register") {
		t.Fatalf("worker registration is inline:\n%s", body)
	}

	// An app without a pwa: section gets none of it, even though a site
	// name alone serves a manifest: no worker is registered on its pages.
	off := servePWAStaticPage(t, pwaStaticTestApp(t, nil, pwaPlainPage))
	for _, absent := range []string{`rel="manifest"`, "/_internal/pwa.js", `name="theme-color"`} {
		if strings.Contains(off, absent) {
			t.Fatalf("page of an app without pwa: carries %s:\n%s", absent, off)
		}
	}
}

func TestStaticHTMLPageKeepsItsOwnPWATags(t *testing.T) {
	page := `<html><head><link rel="manifest" href="/static/app.webmanifest"><meta name="theme-color" content="#123456"></head><body></body></html>`
	body := servePWAStaticPage(t, pwaStaticTestApp(t, pwaFrontConfig, page))
	if strings.Count(body, `rel="manifest"`) != 1 || strings.Contains(body, `href="/manifest.json"`) {
		t.Fatalf("page's own manifest link duplicated or replaced:\n%s", body)
	}
	if strings.Count(body, `name="theme-color"`) != 1 || !strings.Contains(body, `content="#123456"`) {
		t.Fatalf("page's own theme-color duplicated or replaced:\n%s", body)
	}
	if !strings.Contains(body, `<script src="/_internal/pwa.js" defer></script>`) {
		t.Fatalf("worker registration missing:\n%s", body)
	}

	// A page that registers a worker itself is left to do so.
	own := `<html><head><script type="module">navigator.serviceWorker.register('/sw.js')</script></head><body></body></html>`
	if body := servePWAStaticPage(t, pwaStaticTestApp(t, pwaFrontConfig, own)); strings.Contains(body, "/_internal/pwa.js") {
		t.Fatalf("second registration injected:\n%s", body)
	}
}

func TestPWARegistrationAndOfflineRoutes(t *testing.T) {
	app := pwaStaticTestApp(t, pwaFrontConfig, pwaPlainPage)
	mux := http.NewServeMux()
	RegisterPWARoutes(mux, app)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		return rec
	}
	js := get("/_internal/pwa.js")
	if ct := js.Header().Get("Content-Type"); ct != "application/javascript" || !strings.Contains(js.Body.String(), "navigator.serviceWorker.register('/sw.js')") {
		t.Fatalf("/_internal/pwa.js: %s\n%s", ct, js.Body.String())
	}
	off := get(pwaOfflinePath)
	page := off.Body.String()
	if !strings.HasPrefix(off.Header().Get("Content-Type"), "text/html") || off.Header().Get("Set-Cookie") != "" ||
		strings.Contains(off.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("offline page headers: %v", off.Header())
	}
	for _, want := range []string{"<title>Events - Offline</title>", `<meta name="theme-color" content="#18181b">`, "background:#ffffff", `<a href="">`} {
		if !strings.Contains(page, want) {
			t.Fatalf("offline page lacks %s:\n%s", want, page)
		}
	}
	// No script and no CSRF token: it needs neither, and a cached copy
	// outlives every session.
	if strings.Contains(page, "<script") || strings.Contains(page, "csrf") {
		t.Fatalf("offline page carries script or token:\n%s", page)
	}
	// Author-controlled text is escaped; a color that is not hex is ignored.
	app.Design.PWA = map[string]string{"name": `<b>"x"</b>`, "background_color": "red;}body{display:none", "offline": "true"}
	page = get(pwaOfflinePath).Body.String()
	if strings.Contains(page, "<b>") || strings.Contains(page, "display:none") {
		t.Fatalf("offline page interpolates raw config:\n%s", page)
	}

	// An app-provided offline page is served as written.
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "offline.html"), []byte("<h1>Mine</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.Design.PWA = map[string]string{"offline": "true", "offline_page": "/static/offline.html"}
	if got := get(pwaOfflinePath).Body.String(); got != "<h1>Mine</h1>" {
		t.Fatalf("offline_page not served: %q", got)
	}
	// It must stay inside static/ and be .html; otherwise the generated page.
	if err := os.WriteFile(filepath.Join(app.Dir, "secret.html"), []byte("outside static"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(app.Dir, "secret.html"), filepath.Join(app.Dir, "static", "link.html")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"/static/../secret.html", "../secret.html", "/static/link.html", "/static/app.js"} {
		app.Design.PWA = map[string]string{"offline": "true", "offline_page": v}
		if got := get(pwaOfflinePath).Body.String(); !strings.Contains(got, "You're offline") {
			t.Fatalf("offline_page %q: served %q, want the generated page", v, got)
		}
	}
}

func TestManifestIconTypeFromExtension(t *testing.T) {
	type icon struct {
		Src   string `json:"src"`
		Sizes string `json:"sizes"`
		Type  string `json:"type"`
	}
	icons := func(app *App) []icon {
		var m struct {
			Icons []icon `json:"icons"`
		}
		if err := json.Unmarshal([]byte(GenerateManifest(app)), &m); err != nil {
			t.Fatal(err)
		}
		return m.Icons
	}
	app := pwaStaticTestApp(t, map[string]string{"icon": "/static/favicon.svg"}, pwaPlainPage)
	got := icons(app)
	if len(got) != 1 || got[0].Type != "image/svg+xml" || got[0].Sizes != "any" || !strings.HasPrefix(got[0].Src, "/static/favicon.svg?v=") {
		t.Fatalf("svg icon: %+v", got)
	}
	for ext, typ := range map[string]string{".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg"} {
		app.Design.PWA = map[string]string{"icon": "/static/icon-512" + ext}
		// The icon must be a file the app has: a missing one gives way to the
		// favicon (pwa_icon.go, TestManifestIconFallsBackToAFileTheAppHas).
		if err := os.WriteFile(filepath.Join(app.Dir, "static", "icon-512"+ext), []byte("icon"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := icons(app)
		if len(got) != 2 || got[0].Type != typ || got[0].Sizes != "192x192" || got[1].Type != typ || got[1].Sizes != "512x512" {
			t.Fatalf("%s icon: %+v", ext, got)
		}
	}
}

func TestThemeColorFollowsPWAConfig(t *testing.T) {
	themeMeta := regexp.MustCompile(`<meta name="theme-color" content="([^"]*)">`)
	manifestTheme := func(app *App) string {
		var m struct {
			Theme string `json:"theme_color"`
		}
		if err := json.Unmarshal([]byte(GenerateManifest(app)), &m); err != nil {
			t.Fatal(err)
		}
		return m.Theme
	}
	for _, c := range []struct {
		pwa   map[string]string
		brand string
		want  string
	}{
		{map[string]string{"theme_color": "#18181b"}, "#2563eb", "#18181b"},
		{map[string]string{"name": "x"}, "#2563eb", "#2563eb"},
		{map[string]string{"name": "x"}, "", "#09090b"},
	} {
		app := &App{Design: &DesignConfig{PWA: c.pwa, Colors: map[string]string{}}}
		if c.brand != "" {
			app.Design.Colors["_brand"] = c.brand
		}
		html := WrapLayout("<p>hi</p>", "T", app, nil)
		m := themeMeta.FindAllStringSubmatch(html, -1)
		if len(m) != 1 || m[0][1] != c.want {
			t.Fatalf("pwa=%v brand=%q: theme-color metas %v, want one %s", c.pwa, c.brand, m, c.want)
		}
		if c.want != "#09090b" && manifestTheme(app) != c.want {
			t.Fatalf("pwa=%v brand=%q: manifest theme_color %q", c.pwa, c.brand, manifestTheme(app))
		}
	}
}

// swHarness runs the generated worker against fake browser primitives:
// caches, fetch (online or offline, with per-path responses) and the
// install/activate/fetch events.
const swHarness = `
var handlers = {};
var ORIGIN = 'https://app.test';
var self = {
  location: { origin: ORIGIN },
  addEventListener: function (t, fn) { handlers[t] = fn; },
  skipWaiting: function () {},
  clients: { claim: function () {} },
};
function URL(u, base) {
  var m = /^(https?:\/\/[^\/?#]+)?([^?#]*)(\?[^#]*)?/.exec(String(u));
  this.origin = m[1] || (base ? new URL(base).origin : ORIGIN);
  this.pathname = m[2] || '/';
  this.search = m[3] || '';
  this.href = this.origin + this.pathname + this.search;
  var q = this.search.slice(1).split('&');
  this.searchParams = { has: function (k) { return q.some(function (p) { return p.split('=')[0] === k; }); } };
}
function Request(u, init) {
  init = init || {};
  this.url = new URL(u, ORIGIN).href;
  this.method = init.method || 'GET';
  this.mode = init.mode || 'cors';
  this.credentials = init.credentials || 'same-origin';
}
function Headers(h) { this.m = {}; for (var k in (h || {})) this.m[k.toLowerCase()] = h[k]; }
Headers.prototype.get = function (k) { var v = this.m[k.toLowerCase()]; return v === undefined ? null : v; };
function Response(status, headers, body) {
  this.status = status; this.ok = status >= 200 && status < 300; this.type = 'basic';
  this.redirected = false; this.headers = new Headers(headers); this.body = body;
}
Response.prototype.clone = function () { return new Response(this.status, this.headers.m, this.body); };
Response.error = function () { var r = new Response(0, {}, null); r.type = 'error'; r.ok = false; return r; };
var online = true, routes = {}, fetched = [];
function fetch(req) {
  if (typeof req === 'string') req = new Request(req);
  fetched.push({ url: req.url, credentials: req.credentials });
  if (!online) return Promise.reject(new TypeError('Failed to fetch'));
  var u = new URL(req.url), r = routes[u.pathname + u.search] || routes[u.pathname];
  return Promise.resolve(r ? new Response(r[0], r[1], r[2]) : new Response(404, {}, 'not found'));
}
var cacheStore = {};
function key(req) { return typeof req === 'string' ? new URL(req, ORIGIN).href : req.url; }
function openCache(n) {
  var c = cacheStore[n] = cacheStore[n] || {};
  return {
    put: function (req, res) { c[key(req)] = res; return Promise.resolve(); },
    match: function (req) { return Promise.resolve(c[key(req)]); },
    keys: function () { return Promise.resolve(Object.keys(c).map(function (k) { return new Request(k); })); },
    delete: function (req) { var had = key(req) in c; delete c[key(req)]; return Promise.resolve(had); },
  };
}
var caches = {
  open: function (n) { return Promise.resolve(openCache(n)); },
  match: function (req) {
    for (var n in cacheStore) if (cacheStore[n][key(req)]) return Promise.resolve(cacheStore[n][key(req)]);
    return Promise.resolve(undefined);
  },
  keys: function () { return Promise.resolve(Object.keys(cacheStore)); },
  delete: function (n) { var had = n in cacheStore; delete cacheStore[n]; return Promise.resolve(had); },
};
var out;
function lifecycle(type) {
  var ps = [];
  out = undefined;
  handlers[type]({ waitUntil: function (p) { ps.push(p); } });
  Promise.all(ps).then(function () { out = { ok: true }; }, function (e) { out = { rejected: String(e) }; });
}
function navigate(path, mode) {
  var responded = null, ps = [];
  out = undefined;
  if (handlers.fetch) handlers.fetch({
    request: new Request(path, { mode: mode || 'navigate' }),
    respondWith: function (p) { responded = Promise.resolve(p); },
    waitUntil: function (p) { ps.push(p); },
  });
  if (!responded) { out = { passthrough: true }; return; }
  responded.then(function (r) { out = { status: r ? r.status : -1, body: r ? r.body : null, type: r ? r.type : null }; },
    function (e) { out = { rejected: String(e) }; });
}
function cached() {
  var all = [];
  for (var n in cacheStore) for (var k in cacheStore[n]) all.push(n + ' ' + k.replace(ORIGIN, ''));
  return all.sort();
}
`

type swResult struct {
	Out struct {
		OK          bool   `json:"ok"`
		Rejected    string `json:"rejected"`
		Passthrough bool   `json:"passthrough"`
		Status      int    `json:"status"`
		Body        string `json:"body"`
		Type        string `json:"type"`
	} `json:"out"`
	Cached  []string `json:"cached"`
	Fetched []struct {
		URL         string `json:"url"`
		Credentials string `json:"credentials"`
	} `json:"fetched"`
}

func swVM(t *testing.T, app *App) *goja.Runtime {
	t.Helper()
	vm := goja.New()
	if _, err := vm.RunString(swHarness); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(GenerateServiceWorker(app)); err != nil {
		t.Fatalf("generated worker does not run: %v", err)
	}
	return vm
}

// swStep runs one statement, lets its promises settle (goja runs promise
// jobs when a script returns) and reads the outcome with a second script.
func swStep(t *testing.T, vm *goja.Runtime, js string) swResult {
	t.Helper()
	if _, err := vm.RunString("fetched = [];\n" + js); err != nil {
		t.Fatalf("%s: %v", js, err)
	}
	v, err := vm.RunString(`JSON.stringify({out: out, cached: cached(), fetched: fetched})`)
	if err != nil {
		t.Fatal(err)
	}
	var r swResult
	if err := json.Unmarshal([]byte(v.String()), &r); err != nil {
		t.Fatalf("%v: %s", err, v.String())
	}
	return r
}

func TestOfflineServiceWorkerServesPrecachedOfflinePage(t *testing.T) {
	app := &App{Design: &DesignConfig{PWA: map[string]string{"offline": "true"}}, Pages: map[string]*Page{
		"/pricing": {}, "/dashboard": {Auth: "required"},
	}}
	vm := swVM(t, app)
	// The offline page is fetched without cookies and stored even when its
	// headers say no-store; no page route is fetched at install.
	swStep(t, vm, `routes['`+pwaOfflinePath+`'] = [200, {'Cache-Control': 'no-store', 'Content-Type': 'text/html'}, 'OFFLINE PAGE'];
cacheStore['benmore-v1'] = {'https://app.test/dashboard': new Response(200, {}, 'old signed-in page')};`)
	r := swStep(t, vm, `lifecycle('install')`)
	if !r.Out.OK || len(r.Fetched) != 1 || r.Fetched[0].URL != "https://app.test"+pwaOfflinePath || r.Fetched[0].Credentials != "omit" {
		t.Fatalf("install: %+v", r)
	}
	if r = swStep(t, vm, `lifecycle('activate')`); !r.Out.OK || strings.Join(r.Cached, ",") != "benmore-v3 "+pwaOfflinePath {
		t.Fatalf("after activate the cache holds %v, want only the offline page", r.Cached)
	}

	// Signed-in pages come from the network and are never stored, whatever
	// their headers say.
	r = swStep(t, vm, `routes['/dashboard'] = [200, {'Cache-Control': 'no-store'}, 'alice dashboard'];
routes['/pricing'] = [200, {'Cache-Control': 'public, max-age=600'}, 'pricing'];
navigate('/dashboard'); navigate('/pricing');`)
	if r.Out.Body != "pricing" || len(r.Fetched) != 2 || strings.Join(r.Cached, ",") != "benmore-v3 "+pwaOfflinePath {
		t.Fatalf("online navigation: %+v", r)
	}

	// Offline, every navigation gets the offline page, never a stored page.
	for _, p := range []string{"/dashboard", "/pricing", "/events/7"} {
		r = swStep(t, vm, `online = false; navigate('`+p+`')`)
		if r.Out.Status != 200 || r.Out.Body != "OFFLINE PAGE" {
			t.Fatalf("offline %s: %+v", p, r.Out)
		}
	}

	// Static assets: stored only when shareable; a versioned URL is served
	// from the cache, an unversioned one from the network while online.
	swStep(t, vm, `online = true;
routes['/static/app.js?v=aaa'] = [200, {'Cache-Control': 'public, max-age=31536000, immutable'}, 'bundle a'];
routes['/static/app.js?v=bbb'] = [200, {'Cache-Control': 'public, max-age=31536000, immutable'}, 'bundle b'];
routes['/static/logo.png'] = [200, {'Cache-Control': 'public, no-cache'}, 'logo 1'];
routes['/static/me.json'] = [200, {'Cache-Control': 'private, no-store'}, 'mine'];
routes['/uploads/private/a.png'] = [200, {}, 'private upload'];
routes['/api/tasks'] = [200, {}, '[]'];`)
	swStep(t, vm, `navigate('/static/app.js?v=aaa', 'no-cors'); navigate('/static/logo.png', 'no-cors'); navigate('/static/me.json', 'cors')`)
	for _, p := range []string{"/uploads/private/a.png", "/api/tasks"} {
		if r = swStep(t, vm, `navigate('`+p+`', 'cors')`); !r.Out.Passthrough {
			t.Fatalf("%s handled by the worker: %+v", p, r.Out)
		}
	}
	r = swStep(t, vm, `navigate('/static/app.js?v=aaa', 'no-cors')`)
	if r.Out.Body != "bundle a" || len(r.Fetched) != 0 {
		t.Fatalf("versioned asset not served from cache: %+v", r)
	}
	r = swStep(t, vm, `routes['/static/logo.png'][2] = 'logo 2'; navigate('/static/logo.png', 'no-cors')`)
	if r.Out.Body != "logo 2" || len(r.Fetched) != 1 {
		t.Fatalf("unversioned asset not fetched first: %+v", r)
	}
	// A new version replaces the old one.
	r = swStep(t, vm, `navigate('/static/app.js?v=bbb', 'no-cors')`)
	want := []string{"benmore-v3 " + pwaOfflinePath, "benmore-v3 /static/app.js?v=bbb", "benmore-v3 /static/logo.png"}
	if strings.Join(r.Cached, ",") != strings.Join(want, ",") {
		t.Fatalf("cache holds %v, want %v", r.Cached, want)
	}
	r = swStep(t, vm, `online = false; navigate('/static/logo.png', 'no-cors')`)
	if r.Out.Body != "logo 2" {
		t.Fatalf("offline asset: %+v", r.Out)
	}
	r = swStep(t, vm, `navigate('/static/me.json', 'cors')`)
	if r.Out.Body == "mine" {
		t.Fatalf("no-store asset served from the cache: %+v", r.Out)
	}
}

func TestServiceWorkerWithoutOfflineHandlesNoFetches(t *testing.T) {
	vm := swVM(t, &App{Design: &DesignConfig{PWA: map[string]string{"name": "x"}}})
	if r := swStep(t, vm, `navigate('/dashboard')`); !r.Out.Passthrough {
		t.Fatalf("worker without offline answered a navigation: %+v", r.Out)
	}
}

// Through the whole app mux and its security headers: the page carries the
// wiring, its CSP admits the same-origin registration script, and the
// offline page is answered without a cookie even to a signed-in browser.
func TestPWAStaticStackThroughAppMux(t *testing.T) {
	app := pwaStaticTestApp(t, pwaFrontConfig, pwaPlainPage)
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(app.Dir, "data.db"), app.Dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app.DB, app.SessionDuration, app.Stop = db, time.Hour, make(chan struct{})
	t.Cleanup(app.Shutdown)
	h := securityHeaders(buildAppMux(app, false, "https://events.test"), false, app)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://events.test"+path, nil)
		req.Header.Set("Accept", "text/html")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "signed-in-visitor"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d\n%s", path, rec.Code, rec.Body.String())
		}
		return rec
	}
	page := get("/dashboard")
	if body := page.Body.String(); !strings.Contains(body, `<script src="/_internal/pwa.js" defer></script>`) || !strings.Contains(body, `<link rel="manifest" href="/manifest.json">`) {
		t.Fatalf("/dashboard lacks PWA wiring:\n%s", body)
	}
	csp := page.Header().Get("Content-Security-Policy")
	if !regexp.MustCompile(`(^|; )script-src 'self'`).MatchString(csp) {
		t.Fatalf("page CSP does not admit same-origin scripts: %s", csp)
	}
	if js := get("/_internal/pwa.js").Body.String(); !strings.Contains(js, "register('/sw.js')") {
		t.Fatalf("/_internal/pwa.js: %s", js)
	}
	off := get(pwaOfflinePath)
	if off.Header().Get("Set-Cookie") != "" || !strings.Contains(off.Body.String(), "You're offline") {
		t.Fatalf("offline page: %v\n%s", off.Header(), off.Body.String())
	}
	if sw := get("/sw.js").Body.String(); !strings.Contains(sw, "'"+pwaOfflinePath+"'") {
		t.Fatalf("/sw.js lacks the offline page:\n%s", sw)
	}
}

// Like the worker, a reviewed app's offline page comes from the reviewed
// source, never from later disk edits.
func TestOfflinePageServesReviewedCapturedSource(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "app.yaml", "site_name: X\npwa:\n  offline: true\n  offline_page: /static/offline.html\n")
	writeTestFile(t, app.Dir, "static/offline.html", "<h1>reviewed</h1>")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "static/offline.html", "<h1>unreviewed</h1>")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	buildAppMux(app, false, "https://fixture.example.com").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, pwaOfflinePath, nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "<h1>reviewed</h1>" {
		t.Fatalf("reviewed app served %d %q at %s, want the captured reviewed page", rec.Code, rec.Body.String(), pwaOfflinePath)
	}
}
