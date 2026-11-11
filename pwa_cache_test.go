//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The offline service worker cache outlives the login session. It used to
// cache every non-/api GET (signed-in pages, private uploads) and precache
// with the visitor's cookies, then answer cache-first, so the next person on
// the device saw the previous user's pages after logout. The worker now
// stores no page at all (TestOfflineServiceWorkerServesPrecachedOfflinePage
// runs it): navigations fall back to the anonymous offline page.
func TestOfflineServiceWorkerOnlyCachesAnonymousResponses(t *testing.T) {
	app := &App{Design: &DesignConfig{PWA: map[string]string{"offline": "true"}}, Pages: map[string]*Page{
		"/pricing":   {},
		"/dashboard": {Auth: "required"},
	}}
	sw := GenerateServiceWorker(app)
	for _, want := range []string{
		"credentials: 'omit'", "no-store", "private", "redirected", "Set-Cookie", "has('sig')", "OFFLINE_URL",
	} {
		if !strings.Contains(sw, want) {
			t.Fatalf("service worker lacks %q guard:\n%s", want, sw)
		}
	}
	if strings.Contains(sw, "if (response.ok) {") {
		t.Fatalf("service worker still caches every ok response")
	}
	// Browsers that already hold an old worker's cache still have what it
	// stored ("benmore-v1": signed-in pages; "benmore-v2": unversioned
	// assets answered cache-first); the activate handler only deletes
	// caches whose name differs, so the name must change with each fix.
	if strings.Contains(sw, "'benmore-v1'") || strings.Contains(sw, "'benmore-v2'") {
		t.Fatalf("cache name unchanged: existing visitors keep a pre-fix cache")
	}
	// A runtime response is stored only for static assets: a page route,
	// even a public one, may have been rendered for the signed-in visitor,
	// and /_internal/ also serves admin-only developer artifacts. No page
	// route is precached either.
	if strings.Contains(sw, "p.indexOf('/_internal/') === 0") || strings.Contains(sw, `"/pricing"`) || strings.Contains(sw, `"/dashboard"`) {
		t.Fatalf("worker caches page routes or every /_internal/ path:\n%s", sw)
	}
}
