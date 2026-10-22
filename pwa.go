//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
)

// PWA manifest and service worker generation.
// Configured via app.yaml:
//
//   pwa:
//     name: "My App"
//     short_name: "MyApp"
//     icon: "/static/icon-512.png"
//     theme_color: "#000000"
//     background_color: "#000000"
//     offline: true
//     service_worker: "/static/sw.js"   # optional: serve the app's own worker at /sw.js

// GenerateManifest creates a web app manifest from app config.
func GenerateManifest(app *App) string {
	name := "App"
	shortName := ""
	icon := "/static/icon-512.png"
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
		if i := app.Design.PWA["icon"]; i != "" {
			icon = i
		} else if i := app.Design.SEO["favicon"]; i != "" {
			icon = i
		}
		if t := app.Design.PWA["theme_color"]; t != "" {
			themeColor = t
		} else if b := app.Design.Colors["_brand"]; b != "" {
			themeColor = b
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

	manifest := map[string]any{
		"name":             name,
		"short_name":       shortName,
		"start_url":        startURL,
		"display":          display,
		"theme_color":      themeColor,
		"background_color": bgColor,
		"icons": []map[string]any{
			{"src": icon, "sizes": "192x192", "type": "image/png"},
			{"src": icon, "sizes": "512x512", "type": "image/png"},
		},
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

// GenerateServiceWorker creates a service worker for offline caching.
func GenerateServiceWorker(app *App) string {
	// Determine cache strategy
	// v2: the v1 worker cached signed-in pages; activation deletes every cache
	// whose name differs, so the rename purges what earlier visitors hold.
	cacheName := "benmore-v2"
	offlineEnabled := false

	if app.Design != nil {
		if app.Design.PWA["offline"] == "true" {
			offlineEnabled = true
		}
	}

	// Build list of routes to precache
	var precache []string
	precache = append(precache, "/")
	for route, p := range app.Pages {
		// Skip auth-required, typed (login/signup), and gated pages - they redirect and break cache.addAll()
		if p.Type != "" || p.Auth == "required" || p.Require != "" {
			continue
		}
		precache = append(precache, route)
	}
	precache = append(precache, "/_internal/tailwind.js")

	precacheJSON, _ := json.Marshal(precache)

	offlineStrategy := ""
	if offlineEnabled {
		// A service worker cache outlives the login session, so it must only
		// ever hold anonymous, shareable responses: precaching fetches
		// without cookies, and a runtime response is stored only when it
		// says nothing personal (no no-store / private / Vary: Cookie /
		// Set-Cookie), was not redirected (a login bounce), and is either a
		// static asset (public routes come only from the anonymous precache). Any other page
		// is network-only, so a signed-in page is never replayed to the next
		// person on the device after logout.
		offlineStrategy = fmt.Sprintf(`
var PUBLIC_ROUTES = %s;

function cacheable(url, response, runtime) {
  if (!response.ok || response.type !== 'basic' || response.redirected) return false;
  var cc = (response.headers.get('Cache-Control') || '').toLowerCase();
  if (cc.indexOf('no-store') >= 0 || cc.indexOf('private') >= 0) return false;
  var vary = (response.headers.get('Vary') || '').toLowerCase();
  if (vary.indexOf('cookie') >= 0 || vary.indexOf('authorization') >= 0 || vary === '*') return false;
  if (response.headers.get('Set-Cookie')) return false;
  var p = url.pathname;
  if (p.indexOf('/uploads/private/') === 0 || p.indexOf('/auth') === 0 || p.indexOf('/oauth') === 0 || url.searchParams.has('sig')) return false;
  if (p.indexOf('/static/') === 0 || p === '/_internal/tailwind.js') return true;
  // A page route may have been rendered for the signed-in visitor: only the
  // anonymous precache stores one.
  return !runtime && PUBLIC_ROUTES.indexOf(p) >= 0;
}

// Precache on install, anonymously (credentials omitted)
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open('%s').then(function(cache) {
      return Promise.all(PUBLIC_ROUTES.map(function(route) {
        return fetch(new Request(route, {credentials: 'omit'})).then(function(response) {
          if (cacheable(new URL(route, self.location.origin), response)) return cache.put(route, response);
        }).catch(function() {});
      }));
    })
  );
  self.skipWaiting();
});

// Serve from cache, fall back to network
self.addEventListener('fetch', function(e) {
  // Skip non-GET and API requests
  if (e.request.method !== 'GET') return;
  var url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/_internal/fetch')) return;

  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;
      return fetch(e.request).then(function(response) {
        if (cacheable(url, response, true)) {
          var clone = response.clone();
          caches.open('%s').then(function(cache) { cache.put(e.request, clone); });
        }
        return response;
      }).catch(function() {
        // Offline fallback
        if (e.request.mode === 'navigate') {
          return caches.match('/');
        }
      });
    })
  );
});`, string(precacheJSON), cacheName, cacheName)
	}

	return fmt.Sprintf(`// Benmore Go Service Worker
var CACHE = '%s';

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
%s
`, cacheName, offlineStrategy)
}

// appServiceWorkerFile opens the app's own service worker
// when app.yaml opts in with `pwa.service_worker`, or ok=false to use the
// generated one.
//
// /sw.js is reserved: the framework registers it before any app route, so an
// app that shipped static/sw.js could never serve it there, and a worker
// served from /static/sw.js only controls /static/. Offline-first apps were
// silently left with the generated worker (no fetch handler unless
// pwa.offline is set), which cannot open the app with no connection.
//
// Opt-in only: an app without the key gets exactly the generated worker it
// got before. The file must be a .js file inside the app's static/ directory
// (symlink-safe, via openServableFile); anything else falls back to the
// generated worker rather than breaking a registered worker with a 404. The
// file is already public at /static/..., so serving it at /sw.js exposes
// nothing new.
func appServiceWorkerFile(app *App) (*servableFile, bool) {
	rel, ok := appServiceWorkerRel(app)
	if !ok {
		return nil, false
	}
	staticRoot := filepath.Join(app.Dir, "static")
	return openServableFile(staticRoot, filepath.Join(staticRoot, filepath.FromSlash(rel)))
}

func appServiceWorkerRel(app *App) (string, bool) {
	if app == nil || app.Design == nil || app.Dir == "" {
		return "", false
	}
	raw := strings.TrimSpace(app.Design.PWA["service_worker"])
	if raw == "" {
		return "", false
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(raw, "/"), "static/")
	if rel == "" || !strings.HasSuffix(strings.ToLower(rel), ".js") {
		return "", false
	}
	return rel, true
}

// appServiceWorkerCaptured returns the configured worker from the source
// captured with a reviewed mcp.yaml. Like serveStaticAsset, a reviewed app
// never serves later disk bytes: a worker edited after review (a refused
// reload leaves it on disk) would otherwise control every page of the origin.
// The path must stay inside static/, since the capture also holds other trees.
func appServiceWorkerCaptured(app *App) ([]byte, bool) {
	rel, ok := appServiceWorkerRel(app)
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
		if b, ok := appServiceWorkerCaptured(app); ok {
			return string(b)
		}
	} else if file, ok := appServiceWorkerFile(app); ok {
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

	name := "App"
	if app.Design.PWA["name"] != "" {
		name = app.Design.PWA["name"]
	} else if app.Design.SEO["site_name"] != "" {
		name = app.Design.SEO["site_name"]
	}
	sb.WriteString(fmt.Sprintf(`<meta name="apple-mobile-web-app-title" content="%s">`, name))

	icon := app.Design.PWA["icon"]
	if icon == "" {
		icon = app.Design.SEO["favicon"]
	}
	if icon != "" {
		sb.WriteString(fmt.Sprintf(`<link rel="apple-touch-icon" href="%s">`, icon))
	}

	return sb.String()
}

// RegisterPWARoutes adds manifest.json and service worker endpoints.
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
}
