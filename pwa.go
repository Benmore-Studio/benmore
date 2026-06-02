//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	cacheName := "benmore-v1"
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
		// Skip auth-required, typed (login/signup), and gated pages — they redirect and break cache.addAll()
		if p.Type != "" || p.Auth == "required" || p.Require != "" {
			continue
		}
		precache = append(precache, route)
	}
	precache = append(precache, "/_internal/tailwind.js")

	precacheJSON, _ := json.Marshal(precache)

	offlineStrategy := ""
	if offlineEnabled {
		offlineStrategy = fmt.Sprintf(`
// Precache on install
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open('%s').then(function(cache) {
      return cache.addAll(%s);
    })
  );
  self.skipWaiting();
});

// Serve from cache, fall back to network
self.addEventListener('fetch', function(e) {
  // Skip non-GET and API requests
  if (e.request.method !== 'GET') return;
  var url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/_internal/fetch')) return;

  e.respondWith(
    caches.match(e.request).then(function(cached) {
      if (cached) return cached;
      return fetch(e.request).then(function(response) {
        if (response.ok) {
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
});`, cacheName, string(precacheJSON), cacheName)
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

// IsPWAEnabled checks if the app should serve a web app manifest.
//
// Historically this required an explicit `pwa:` section in app.yaml.
// That created a silent failure mode for the builder's "Open on phone"
// flow: apps without pwa: set couldn't be installed as home-screen apps
// because the manifest route wasn't registered. Now we auto-enable PWA
// for any app that has enough design metadata to generate a sensible
// manifest — a site name or a brand color is enough. Explicit pwa:
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
func RegisterPWARoutes(mux *http.ServeMux, app *App) {
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
		w.Write([]byte(GenerateServiceWorker(app)))
	})
}
