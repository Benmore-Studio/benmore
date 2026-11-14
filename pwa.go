//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// PWA manifest and service worker generation.
// Configured via app.yaml:
//
//   pwa:
//     name: "My App"
//     short_name: "MyApp"
//     icon: "/static/icon-512.png"      # default; absent, the manifest lists seo.favicon or static/favicon.svg
//     theme_color: "#000000"
//     background_color: "#000000"
//     offline: true                     # offline fallback page + asset cache (see GenerateServiceWorker)
//     offline_page: "/static/offline.html"  # optional: the app's own offline page
//     service_worker: "/static/sw.js"   # optional: serve the app's own worker at /sw.js
//
// The SSR shell and every static/*.html page of an app with a `pwa:` section
// carry the manifest link, the theme color and /_internal/pwa.js, which
// registers /sw.js (injectPWATags).

// GenerateManifest creates a web app manifest from app config.
func GenerateManifest(app *App) string {
	name := "App"
	shortName := ""
	// pwa.icon, else seo.favicon, else /static/icon-512.png; a /static/ choice
	// the app does not have gives way to one it has (pwa_icon.go).
	icon := manifestIconFor(app)
	themeColor := "#000000"
	bgColor := "#000000"
	startURL := "/"
	display := "standalone"

	if app.Design != nil {
		// From PWA config
		if n := app.Design.PWA["name"]; n != "" {
			name = n
		} else if n := app.Design.SEO["site_name"]; n != "" {
			name = n
		}
		if s := app.Design.PWA["short_name"]; s != "" {
			shortName = s
		}
		if t := pwaThemeColor(app); t != "" {
			themeColor = t
		}
		if b := app.Design.PWA["background_color"]; b != "" {
			bgColor = b
		}
		if s := app.Design.PWA["start_url"]; s != "" {
			startURL = s
		}
		if d := app.Design.PWA["display"]; d != "" {
			display = d
		}
	}
	if shortName == "" {
		shortName = name
	}
	// An unversioned /static/ icon revalidates on every use; with its ?v= a
	// replaced icon reaches installed apps without being renamed.
	icon = versionedStaticURL(app, icon)

	manifest := map[string]any{
		"name":             name,
		"short_name":       shortName,
		"start_url":        startURL,
		"display":          display,
		"theme_color":      themeColor,
		"background_color": bgColor,
		"icons":            manifestIcons(icon),
	}

	// Optional: description
	if app.Design != nil {
		if d := app.Design.SEO["description"]; d != "" {
			manifest["description"] = d
		}
	}

	data, _ := json.MarshalIndent(manifest, "", "  ")
	return string(data)
}

// pwaThemeColor is the browser UI color pages and the manifest declare:
// pwa.theme_color, else the brand color, else "" (the caller's default).
func pwaThemeColor(app *App) string {
	if app == nil || app.Design == nil {
		return ""
	}
	if t := strings.TrimSpace(app.Design.PWA["theme_color"]); t != "" {
		return t
	}
	return strings.TrimSpace(app.Design.Colors["_brand"])
}

// manifestIconTypes maps an icon file extension to its MIME type.
var manifestIconTypes = map[string]string{
	".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".avif": "image/avif", ".ico": "image/x-icon",
}

// manifestIcons declares the app icon with the type its extension names. An
// SVG scales to any size, so it is one entry with sizes "any"; it used to be
// declared as a 192x192 and a 512x512 PNG, which browsers check against the
// file. A raster icon keeps the two sizes installability asks for; an
// unknown extension leaves the type out so the browser reads the file.
func manifestIcons(src string) []map[string]any {
	p := src
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	ext := strings.ToLower(path.Ext(p))
	if ext == ".svg" {
		return []map[string]any{{"src": src, "sizes": "any", "type": "image/svg+xml"}}
	}
	icons := []map[string]any{{"src": src, "sizes": "192x192"}, {"src": src, "sizes": "512x512"}}
	if typ, ok := manifestIconTypes[ext]; ok {
		for _, icon := range icons {
			icon["type"] = typ
		}
	}
	return icons
}

// pwaOfflinePath serves the offline page: the generated worker precaches it
// and answers a navigation with it when the network fails.
const pwaOfflinePath = "/_internal/offline.html"

// pwaRegisterPath is the same-origin script that registers /sw.js. A script
// file rather than an inline one, so registration keeps working under a CSP
// without 'unsafe-inline'.
const pwaRegisterPath = "/_internal/pwa.js"

// pwaRegisterJS registers the worker once the page has loaded.
const pwaRegisterJS = `(function () {
  if (!('serviceWorker' in navigator)) return;
  function register() { navigator.serviceWorker.register('/sw.js').catch(function () {}); }
  if (document.readyState === 'complete') register(); else window.addEventListener('load', register);
})();
`

// pwaCacheName names the generated worker's cache. Activation deletes every
// cache with another name, so a new name purges what earlier workers stored:
// v1 cached signed-in pages, v2 answered unversioned assets from the cache
// first (a changed file stayed stale).
const pwaCacheName = "benmore-v3"

// pwaOfflineEnabled reports `pwa.offline: true` (yes/on/1 too).
func pwaOfflineEnabled(app *App) bool {
	if app == nil || app.Design == nil {
		return false
	}
	v, ok := canonicalAuthFlag(app.Design.PWA["offline"])
	return ok && v == "true"
}

// GenerateServiceWorker creates the worker served at /sw.js.
//
// With pwa.offline it gives the app an offline fallback without storing any
// page. A worker's cache outlives the login session, and every page the
// framework serves is no-store (it carries a CSRF token and may be rendered
// for the signed-in visitor), so:
//   - a navigation always goes to the network. When the network fails the
//     worker answers with the offline page (pwaOfflinePath), precached at
//     install without credentials. That page is generated from app.yaml (or
//     is the static file pwa.offline_page names), anonymous and token-free,
//     so it is stored whatever its headers say.
//   - /static/ files and the embedded Tailwind runtime are stored only when
//     the response is shareable: not no-store or private, no Vary on Cookie
//     or Authorization, no Set-Cookie, not redirected, not a signed URL. A
//     versioned URL (the ?v= served HTML carries) names fixed bytes, so it is
//     answered from the cache and older versions of the same file are
//     dropped; an unversioned URL is fetched first and the stored copy is
//     used only offline.
//   - nothing else (API, uploads, real-time, other origins) is handled.
//
// The old offline mode precached the public page routes and fell back to "/".
// Every page is no-store, so it stored nothing and the fallback was empty.
func GenerateServiceWorker(app *App) string {
	sw := strings.ReplaceAll(swBaseJS, "__CACHE__", pwaCacheName)
	if pwaOfflineEnabled(app) {
		sw += strings.ReplaceAll(swOfflineJS, "__OFFLINE_URL__", pwaOfflinePath)
	}
	return sw
}

const swBaseJS = `// Benmore Go Service Worker
var CACHE = '__CACHE__';

// Clean old caches
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(names) {
      return Promise.all(
        names.filter(function(n) { return n !== CACHE; }).map(function(n) { return caches.delete(n); })
      );
    })
  );
  self.clients.claim();
});
`

const swOfflineJS = `
var OFFLINE_URL = '__OFFLINE_URL__';

// Only shareable static files are stored: a page may have been rendered for
// the signed-in visitor, and the cache outlives the session.
function cacheable(url, response) {
  if (!response || !response.ok || response.type !== 'basic' || response.redirected) return false;
  var cc = (response.headers.get('Cache-Control') || '').toLowerCase();
  if (cc.indexOf('no-store') >= 0 || cc.indexOf('private') >= 0) return false;
  var vary = (response.headers.get('Vary') || '').toLowerCase();
  if (vary.indexOf('cookie') >= 0 || vary.indexOf('authorization') >= 0 || vary === '*') return false;
  if (response.headers.get('Set-Cookie')) return false;
  if (url.searchParams.has('sig')) return false;
  return isAsset(url);
}

function isAsset(url) {
  return url.pathname.indexOf('/static/') === 0 || url.pathname === '/_internal/tailwind.js';
}

// The offline page is anonymous and carries no token: fetched without
// cookies and stored whatever its headers say.
function storeOfflinePage() {
  return fetch(new Request(OFFLINE_URL, {credentials: 'omit'})).then(function(response) {
    if (!response.ok || response.type !== 'basic' || response.redirected) return;
    return caches.open(CACHE).then(function(cache) { return cache.put(OFFLINE_URL, response); });
  });
}

self.addEventListener('install', function(e) {
  e.waitUntil(storeOfflinePage().catch(function() {}));
  self.skipWaiting();
});

function offlinePage() {
  return caches.open(CACHE).then(function(cache) { return cache.match(OFFLINE_URL); }).then(function(r) {
    return r || Response.error();
  });
}

// Stores a shareable response; a new ?v= of a file replaces the older ones.
function store(request, url, response) {
  if (!cacheable(url, response)) return;
  var copy = response.clone();
  caches.open(CACHE).then(function(cache) {
    var stale = url.searchParams.has('v') ? cache.keys().then(function(keys) {
      return Promise.all(keys.filter(function(k) {
        var u = new URL(k.url);
        return u.pathname === url.pathname && u.search !== url.search;
      }).map(function(k) { return cache.delete(k); }));
    }) : Promise.resolve();
    return stale.then(function() { return cache.put(request, copy); });
  }).catch(function() {});
}

function fromNetwork(request, url) {
  return fetch(request).then(function(response) {
    store(request, url, response);
    return response;
  });
}

self.addEventListener('fetch', function(e) {
  var request = e.request;
  if (request.method !== 'GET') return;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    // Pages come only from the network. Offline, the offline page.
    e.respondWith(fetch(request).catch(offlinePage));
    e.waitUntil(caches.open(CACHE).then(function(cache) { return cache.match(OFFLINE_URL); }).then(function(r) {
      if (!r) return storeOfflinePage();
    }).catch(function() {}));
    return;
  }
  if (!isAsset(url) || url.searchParams.has('sig')) return;

  var cached = caches.open(CACHE).then(function(cache) { return cache.match(request); });
  if (url.searchParams.has('v')) {
    // A versioned URL names fixed bytes.
    e.respondWith(cached.then(function(r) { return r || fromNetwork(request, url); }));
    return;
  }
  // An unversioned file may change: network first, the stored copy offline.
  e.respondWith(fromNetwork(request, url).catch(function() {
    return cached.then(function(r) { return r || Response.error(); });
  }));
});
`

// appPWAStaticFile opens the static/ file an app.yaml `pwa:` key names
// (`service_worker`, `offline_page`) when it ends in ext, or ok=false to use
// the generated one.
//
// /sw.js is reserved: the framework registers it before any app route, so an
// app that shipped static/sw.js could never serve it there, and a worker
// served from /static/sw.js only controls /static/. Offline-first apps were
// silently left with the generated worker (no fetch handler unless
// pwa.offline is set), which cannot open the app with no connection.
//
// Opt-in only: an app without the key gets exactly the generated file it
// got before. The file must be inside the app's static/ directory
// (symlink-safe, via openServableFile); anything else falls back to the
// generated one rather than breaking a registered worker with a 404. The
// file is already public at /static/..., so serving it at /sw.js or
// /_internal/offline.html exposes nothing new.
func appPWAStaticFile(app *App, key, ext string) (*servableFile, bool) {
	rel, ok := appPWAStaticRel(app, key, ext)
	if !ok {
		return nil, false
	}
	file, _, ok := openStaticAsset(app, filepath.Join(app.Dir, "static", filepath.FromSlash(rel)))
	return file, ok
}

func appPWAStaticRel(app *App, key, ext string) (string, bool) {
	if app == nil || app.Design == nil || app.Dir == "" {
		return "", false
	}
	raw := strings.TrimSpace(app.Design.PWA[key])
	if raw == "" {
		return "", false
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(raw, "/"), "static/")
	if rel == "" || !strings.HasSuffix(strings.ToLower(rel), ext) {
		return "", false
	}
	// "Already public at /static/" holds only for what /static/ serves: a
	// `run: compute` module named here gets the generated file instead.
	if staticServerSource(app, rel) {
		return "", false
	}
	return rel, true
}

// appPWAStaticCaptured returns the configured file from the source captured
// with a reviewed mcp.yaml. Like serveStaticAsset, a reviewed app never
// serves later disk bytes: a worker edited after review (a refused reload
// leaves it on disk) would otherwise control every page of the origin. The
// path must stay inside static/, since the capture also holds other trees.
func appPWAStaticCaptured(app *App, key, ext string) ([]byte, bool) {
	rel, ok := appPWAStaticRel(app, key, ext)
	if !ok {
		return nil, false
	}
	name := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return nil, false
	}
	data, err := app.readSourceFile(filepath.Join("static", name))
	return data, err == nil
}

// serviceWorkerSource is the body served at /sw.js: the app's own worker when
// configured and readable, else the generated one.
func serviceWorkerSource(app *App) string {
	if appMCPManifestSnapshot(app) != nil {
		if b, ok := appPWAStaticCaptured(app, "service_worker", ".js"); ok {
			return string(b)
		}
	} else if file, ok := appPWAStaticFile(app, "service_worker", ".js"); ok {
		defer file.Close()
		if b, err := io.ReadAll(file); err == nil {
			return string(b)
		}
		return GenerateServiceWorker(app)
	}
	if app != nil && app.Design != nil && strings.TrimSpace(app.Design.PWA["service_worker"]) != "" {
		// Once per app and value: /sw.js is fetched on every page load.
		key := app.Dir + "\x00" + app.Design.PWA["service_worker"]
		if _, seen := swFallbackLogged.LoadOrStore(key, true); !seen {
			log.Printf("pwa: service_worker %q is not a .js file inside static/ (with mcp.yaml: inside its reviewed source); serving the generated worker",
				app.Design.PWA["service_worker"])
		}
	}
	return GenerateServiceWorker(app)
}

var swFallbackLogged sync.Map

// offlinePageSource is the body served at pwaOfflinePath: the static/ .html
// file pwa.offline_page names, else a page generated from app.yaml.
func offlinePageSource(app *App) []byte {
	if appMCPManifestSnapshot(app) != nil {
		if b, ok := appPWAStaticCaptured(app, "offline_page", ".html"); ok {
			return b
		}
	} else if file, ok := appPWAStaticFile(app, "offline_page", ".html"); ok {
		defer file.Close()
		if b, err := io.ReadAll(file); err == nil {
			return b
		}
	}
	return []byte(generateOfflinePage(app))
}

var hexColorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// hexColorIsDark reports a #rgb/#rrggbb color too dark for dark text.
func hexColorIsDark(c string) bool {
	h := strings.TrimPrefix(c, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return false
	}
	r, g, b := float64(v>>16&0xff), float64(v>>8&0xff), float64(v&0xff)
	return 0.299*r+0.587*g+0.114*b < 128
}

// generateOfflinePage is the default offline page: the app's name and
// colors, a link that retries the address the visitor asked for (the worker
// serves this page in its place, so href="" is that address), and no script
// or CSRF token, so a stored copy depends on nobody's session. A background
// color that is not #rgb/#rrggbb is ignored, since it lands in CSS.
func generateOfflinePage(app *App) string {
	name := html.EscapeString(pwaAppName(app))
	bg, fg := "#ffffff", "#18181b"
	if app != nil && app.Design != nil {
		if c := strings.TrimSpace(app.Design.PWA["background_color"]); hexColorRe.MatchString(c) {
			bg = c
			if hexColorIsDark(c) {
				fg = "#fafafa"
			}
		}
	}
	theme := ""
	if c := pwaThemeColor(app); c != "" {
		theme = `<meta name="theme-color" content="` + html.EscapeString(c) + `">`
	}
	return `<!DOCTYPE html>
<html lang="` + html.EscapeString(getLang(app)) + `">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
` + theme + `
<title>` + name + ` - Offline</title>
<style>
html,body{margin:0;height:100%;background:` + bg + `;color:` + fg + `;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
main{box-sizing:border-box;min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;padding:24px;text-align:center}
h1{margin:0;font-size:1.25rem}
p{margin:0 0 12px;opacity:.75;max-width:28rem}
a{color:inherit;border:1px solid currentColor;border-radius:8px;padding:10px 20px;text-decoration:none}
</style>
</head>
<body><main>
<h1>You're offline</h1>
<p>` + name + ` needs a connection for this page. Check your network and try again.</p>
<a href="">Try again</a>
</main></body>
</html>
`
}

// pwaConfigured reports an explicit `pwa:` section. IsPWAEnabled also serves
// a manifest for apps with only a site name or brand color; a static page
// registers a worker only when the app asked for one.
func pwaConfigured(app *App) bool {
	design := app.designConfig()
	return design != nil && len(design.PWA) > 0
}

var (
	pageManifestLinkRe = regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']?\s*manifest\b`)
	pageThemeColorRe   = regexp.MustCompile(`(?is)<meta\b[^>]*\bname\s*=\s*["']?\s*theme-color\b`)
)

// pwaRegisterScriptTag loads pwaRegisterPath. Same-origin, so it runs under
// the page CSP's script-src 'self'.
const pwaRegisterScriptTag = `<script src="` + pwaRegisterPath + `" defer></script>`

// injectPWATags gives a static/*.html page of an app with a `pwa:` section
// the wiring the SSR shell carries (layout.go): the manifest link and
// home-screen meta tags, the theme color and the script that registers
// /sw.js. The default TSX stack's pages had none of it, so `pwa:` made them
// neither installable nor offline-capable. Each part is skipped when the
// page already declares it (its own manifest link, a theme-color meta, a
// serviceWorker.register call), so a page that wires PWA itself is kept.
func injectPWATags(page []byte, app *App) []byte {
	if !pwaConfigured(app) {
		return page
	}
	var chunk strings.Builder
	if !pageManifestLinkRe.Match(page) {
		chunk.WriteString(PWAMetaTags(app))
	}
	if !pageThemeColorRe.Match(page) {
		if c := pwaThemeColor(app); c != "" {
			chunk.WriteString(`<meta name="theme-color" content="` + html.EscapeString(c) + `">`)
		}
	}
	if !bytes.Contains(page, []byte(pwaRegisterPath)) && !bytes.Contains(page, []byte("serviceWorker.register")) {
		chunk.WriteString(pwaRegisterScriptTag)
	}
	if chunk.Len() == 0 {
		return page
	}
	return insertInHead(page, []byte(chunk.String()+"\n"))
}

// IsPWAEnabled checks if the app should serve a web app manifest.
//
// Historically this required an explicit `pwa:` section in app.yaml.
// That created a silent failure mode for the builder's "Open on phone"
// flow: apps without pwa: set couldn't be installed as home-screen apps
// because the manifest route wasn't registered. Now we auto-enable PWA
// for any app that has enough design metadata to generate a sensible
// manifest - a site name or a brand color is enough. Explicit pwa:
// sections still take precedence via GenerateManifest's fallback chain.
func IsPWAEnabled(app *App) bool {
	if app.Design == nil {
		return false
	}
	if len(app.Design.PWA) > 0 {
		return true
	}
	// Auto-enable if we have enough design context to generate a
	// reasonable default manifest.
	if app.Design.SEO["site_name"] != "" {
		return true
	}
	if app.Design.Colors["_brand"] != "" {
		return true
	}
	return false
}

// pwaAppName is the home-screen name: pwa.name, else seo.site_name, else "App".
func pwaAppName(app *App) string {
	if app != nil && app.Design != nil {
		if n := strings.TrimSpace(app.Design.PWA["name"]); n != "" {
			return n
		}
		if n := strings.TrimSpace(app.Design.SEO["site_name"]); n != "" {
			return n
		}
	}
	return "App"
}

// PWAMetaTags returns the HTML meta tags for PWA support.
func PWAMetaTags(app *App) string {
	if !IsPWAEnabled(app) {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(`<link rel="manifest" href="/manifest.json">`)
	sb.WriteString(`<meta name="mobile-web-app-capable" content="yes">`)
	sb.WriteString(`<meta name="apple-mobile-web-app-capable" content="yes">`)
	sb.WriteString(`<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">`)

	sb.WriteString(`<meta name="apple-mobile-web-app-title" content="` + html.EscapeString(pwaAppName(app)) + `">`)

	icon := app.Design.PWA["icon"]
	if icon == "" {
		icon = app.Design.SEO["favicon"]
	}
	if icon != "" {
		sb.WriteString(`<link rel="apple-touch-icon" href="` + html.EscapeString(icon) + `">`)
	}

	return sb.String()
}

// RegisterPWARoutes adds the manifest, the service worker, the script that
// registers it and the offline page.
func RegisterPWARoutes(mux appRouteRegistrar, app *App) {
	if !IsPWAEnabled(app) {
		return
	}

	mux.HandleFunc("GET /manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/manifest+json")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write([]byte(GenerateManifest(app)))
	})

	mux.HandleFunc("GET /sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write([]byte(serviceWorkerSource(app)))
	})

	mux.HandleFunc("GET "+pwaRegisterPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write([]byte(pwaRegisterJS))
	})

	// The worker stores this page and shows it to whoever is offline on the
	// device, so it never reads the session and carries no token.
	mux.HandleFunc("GET "+pwaOfflinePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(offlinePageSource(app))
	})
}
