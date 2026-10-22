//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The offline service worker cache outlives the login session. It used to
// cache every non-/api GET (signed-in pages, private uploads) and precache
// with the visitor's cookies, then answer cache-first, so the next person on
// the device saw the previous user's pages after logout.
func TestOfflineServiceWorkerOnlyCachesAnonymousResponses(t *testing.T) {
	app := &App{Design: &DesignConfig{PWA: map[string]string{"offline": "true"}}, Pages: map[string]*Page{
		"/pricing":   {},
		"/dashboard": {Auth: "required"},
	}}
	sw := GenerateServiceWorker(app)
	for _, want := range []string{
		"credentials: 'omit'", "no-store", "private", "redirected", "/uploads/private/", "PUBLIC_ROUTES",
	} {
		if !strings.Contains(sw, want) {
			t.Fatalf("service worker lacks %q guard:\n%s", want, sw)
		}
	}
	if strings.Contains(sw, "if (response.ok) {") {
		t.Fatalf("service worker still caches every ok response")
	}
	// Browsers that already hold the old worker's cache still have the
	// signed-in pages in "benmore-v1"; the activate handler only deletes
	// caches whose name differs, so the name must change with the fix.
	if strings.Contains(sw, "'benmore-v1'") {
		t.Fatalf("cache name unchanged: existing visitors keep the pre-fix cache of signed-in pages")
	}
	// A runtime response is stored only for static assets: a page route,
	// even a public one, may have been rendered for the signed-in visitor,
	// and /_internal/ also serves admin-only developer artifacts.
	if strings.Contains(sw, "PUBLIC_ROUTES.indexOf(p) >= 0 || p.indexOf('/static/')") ||
		strings.Contains(sw, "p.indexOf('/_internal/') === 0") {
		t.Fatalf("runtime caching still admits page routes or every /_internal/ path:\n%s", sw)
	}
	if !strings.Contains(sw, `"/pricing"`) || strings.Contains(sw, `"/dashboard"`) {
		t.Fatalf("precache list wrong:\n%s", sw)
	}
}
