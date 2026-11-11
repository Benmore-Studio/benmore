//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A hosted dev instance (<sub>-dev.benmore.ai) holds an unfinished build, so it
// asks search engines not to index anything it serves; prod and the framework
// edition are unchanged. The signal is a header on every response, never a
// robots.txt Disallow (a blocked crawler cannot see the noindex).
func TestDevInstanceAsksSearchEnginesNotToIndex(t *testing.T) {
	newApp := func(t *testing.T, files map[string]string) http.Handler {
		t.Helper()
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", "name: Noindex fixture\n")
		writeTestFile(t, dir, "static/index.html", "<!doctype html><title>x</title>")
		writeTestFile(t, dir, "static/logo.svg", `<svg xmlns="http://www.w3.org/2000/svg"/>`)
		for name, body := range files {
			writeTestFile(t, dir, name, body)
		}
		app, err := loadApp(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(app.Shutdown)
		return wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false)
	}
	get := func(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "notes-ab12cd-dev.benmore.ai"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	paths := []string{"/", "/static/logo.svg", "/robots.txt", "/sitemap.xml", "/api/no-such-route"}

	t.Run("dev instance", func(t *testing.T) {
		t.Setenv("BENMORE_APP_NAME", "notes-ab12cd-dev")
		h := newApp(t, nil)
		for _, path := range paths {
			if got := get(t, h, path).Header().Get("X-Robots-Tag"); got != devInstanceRobotsTag {
				t.Errorf("%s: X-Robots-Tag = %q, want %q", path, got, devInstanceRobotsTag)
			}
		}
		robots := get(t, h, "/robots.txt").Body.String()
		if strings.Contains(robots, "Sitemap:") {
			t.Errorf("dev robots.txt advertises a sitemap:\n%s", robots)
		}
		if !strings.Contains(robots, "User-agent: *\nAllow: /\n") || strings.Contains(robots, "Disallow") {
			t.Errorf("dev robots.txt must keep crawling allowed so the noindex is seen:\n%s", robots)
		}
	})

	for _, tc := range []struct{ name, appName string }{
		{"prod instance", "notes-ab12cd"},
		{"framework edition", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BENMORE_APP_NAME", tc.appName)
			h := newApp(t, nil)
			for _, path := range paths {
				if got := get(t, h, path).Header().Get("X-Robots-Tag"); got != "" {
					t.Errorf("%s: X-Robots-Tag = %q, want none", path, got)
				}
			}
			if robots := get(t, h, "/robots.txt").Body.String(); !strings.Contains(robots, "Sitemap: ") {
				t.Errorf("robots.txt lost its sitemap line:\n%s", robots)
			}
		})
	}

	t.Run("an app's own robots.txt is served as written on dev", func(t *testing.T) {
		t.Setenv("BENMORE_APP_NAME", "notes-ab12cd-dev")
		own := "User-agent: *\nAllow: /\nSitemap: https://www.example.test/sitemap.xml\n"
		h := newApp(t, map[string]string{"static/robots.txt": own})
		rec := get(t, h, "/robots.txt")
		if rec.Body.String() != own {
			t.Errorf("own robots.txt changed: %q", rec.Body.String())
		}
		if got := rec.Header().Get("X-Robots-Tag"); got != devInstanceRobotsTag {
			t.Errorf("X-Robots-Tag = %q", got)
		}
	})
}

func TestDevInstanceRobotsHeaderYieldsToTheHandler(t *testing.T) {
	t.Setenv("BENMORE_APP_NAME", "notes-ab12cd-dev")
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noai")
	}), false, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Robots-Tag"); got != "noai" {
		t.Fatalf("X-Robots-Tag = %q, want the handler's own value", got)
	}
}

func TestGeneratedRobotsUnchangedOutsideDev(t *testing.T) {
	base := "https://notes-ab12cd.benmore.ai"
	if got := generateRobotsFor(base, false); got != GenerateRobots(base) {
		t.Fatalf("prod robots.txt changed:\n%s", got)
	}
	dev := generateRobotsFor(base, true)
	if want := strings.Replace(GenerateRobots(base), "Sitemap: "+base+"/sitemap.xml\n", "", 1); dev != want {
		t.Fatalf("dev robots.txt should only drop the Sitemap line:\n got %q\nwant %q", dev, want)
	}
}
