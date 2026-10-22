//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Hosted apps run behind the router on a loopback port, so robots.txt told
// crawlers the sitemap was at http://localhost:<port>, and a TSX/static app's
// generated sitemap was empty even when it shipped static/sitemap.xml.
func TestSEOFilesUseTheAppsOwnFilesAndPublicOrigin(t *testing.T) {
	get := func(t *testing.T, app *App, path, host string) string {
		t.Helper()
		mux := buildAppMux(app, true, "http://localhost:9999")
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		return rec.Body.String()
	}

	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: SEO fixture\n")
	writeTestFile(t, dir, "static/index.html", "<!doctype html><title>x</title>")
	writeTestFile(t, dir, "static/sitemap.xml", `<?xml version="1.0"?><urlset><url><loc>https://www.example.test/</loc></url></urlset>`)
	writeTestFile(t, dir, "static/robots.txt", "User-agent: *\nAllow: /\nSitemap: https://www.example.test/sitemap.xml\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if body := get(t, app, "/sitemap.xml", "www.example.test"); !strings.Contains(body, "<loc>https://www.example.test/</loc>") {
		t.Fatalf("app's own sitemap not served: %s", body)
	}
	if body := get(t, app, "/robots.txt", "www.example.test"); body != "User-agent: *\nAllow: /\nSitemap: https://www.example.test/sitemap.xml\n" {
		t.Fatalf("app's own robots.txt not served: %q", body)
	}

	// Without its own files, generated links use the vetted request host
	// (dev mode here; the platform router in hosted apps), never localhost.
	dir2 := t.TempDir()
	writeTestFile(t, dir2, "app.yaml", "name: SEO fixture two\n")
	writeTestFile(t, dir2, "static/index.html", "<!doctype html><title>x</title>")
	app2, err := loadApp(dir2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app2.Shutdown)
	app2.DevMode = true
	robots := get(t, app2, "/robots.txt", "www.example.test")
	if strings.Contains(robots, "localhost") || !strings.Contains(robots, "Sitemap: http://www.example.test/sitemap.xml") {
		t.Fatalf("robots.txt sitemap line: %q", robots)
	}

	// A configured seo.url still wins.
	app2.Design.SEO = map[string]string{"url": "https://configured.example.test/"}
	if robots := get(t, app2, "/robots.txt", "www.example.test"); !strings.Contains(robots, "Sitemap: https://configured.example.test/sitemap.xml") {
		t.Fatalf("seo.url ignored: %q", robots)
	}
}
