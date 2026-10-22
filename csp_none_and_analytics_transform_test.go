//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFrameAncestorsNoneReplacesDefaultsAndFailsClosed(t *testing.T) {
	for _, value := range []string{"'none'", " 'none' https://example.com", "'NONE' https://example.com"} {
		t.Run(value, func(t *testing.T) {
			app := &App{Design: &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}, CSP: map[string]string{"frame_ancestors": value}}}
			w := httptest.NewRecorder()
			applySecurityHeaders(w, false, app)
			csp := w.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "frame-ancestors 'self'") {
				t.Fatalf("frame policy did not replace defaults: %q", csp)
			}
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("X-Frame-Options = %q, want DENY", got)
			}
		})
	}

	app := &App{Design: &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}, CSP: map[string]string{"frame_ancestors": "https://embed.example"}}}
	w := httptest.NewRecorder()
	applySecurityHeaders(w, false, app)
	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("origin allowlist kept X-Frame-Options %q", got)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "https://embed.example") {
		t.Fatal("origin allowlist was lost")
	}
}

func TestAnalyticsOptOutAddsNoTransformOnlyToHTMLAndPreservesCachePolicy(t *testing.T) {
	analyticsOff := false
	for _, tc := range []struct {
		name          string
		analyticsOff  bool
		contentType   string
		cacheControl  string
		wantTransform bool
	}{
		{name: "html opt-out", analyticsOff: true, contentType: "text/html; charset=utf-8", cacheControl: "no-store, must-revalidate", wantTransform: true},
		{name: "json opt-out", analyticsOff: true, contentType: "application/json", cacheControl: "no-store"},
		{name: "html default-on", analyticsOff: false, contentType: "text/html", cacheControl: "no-store"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			features := &FeaturesConfig{}
			if tc.analyticsOff {
				features.Analytics = &analyticsOff
			}
			app := &App{Design: &DesignConfig{Features: features, Auth: map[string]string{}, SEO: map[string]string{}}}
			h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Cache-Control", tc.cacheControl)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html>response</html>"))
			}), false, app)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			cc := strings.ToLower(w.Header().Get("Cache-Control"))
			if got := strings.Contains(cc, "no-transform"); got != tc.wantTransform {
				t.Fatalf("Cache-Control = %q; no-transform=%v, want %v", cc, got, tc.wantTransform)
			}
			if !strings.Contains(cc, "no-store") {
				t.Fatalf("Cache-Control lost no-store: %q", cc)
			}
		})
	}
}

func TestAnalyticsOptOutCoversStaticServerRenderedAndAuthHTML(t *testing.T) {
	analyticsOff := false
	app := &App{
		Dir:    t.TempDir(),
		Paths:  DiscoverAuthPaths(nil),
		Design: &DesignConfig{Features: &FeaturesConfig{Analytics: &analyticsOff}, Auth: map[string]string{}, SEO: map[string]string{}},
	}
	cases := []struct {
		name string
		run  http.HandlerFunc
	}{
		{name: "static html", run: func(w http.ResponseWriter, r *http.Request) {
			serveHTMLBytes(w, r, app, []byte("<!doctype html><main>static</main>"))
		}},
		{name: "raw server page", run: func(w http.ResponseWriter, r *http.Request) {
			servePage(w, r, app, &Page{Route: "/raw", Engine: "raw", RawHTML: "<!doctype html><main>raw</main>"}, false)
		}},
		{name: "gotmpl server page", run: func(w http.ResponseWriter, r *http.Request) {
			servePage(w, r, app, &Page{Route: "/rendered", RawHTML: "---\nengine: gotmpl\n---\n<main>rendered</main>"}, false)
		}},
		{name: "password change page", run: func(w http.ResponseWriter, r *http.Request) { renderPasswordChange(w, r, app, "", http.StatusOK) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := securityHeaders(tc.run, false, app)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code < http.StatusOK || w.Code >= http.StatusMultipleChoices {
				t.Fatalf("HTML renderer status = %d body=%q", w.Code, w.Body.String())
			}
			cc := strings.ToLower(w.Header().Get("Cache-Control"))
			if !strings.Contains(cc, "no-store") || !strings.Contains(cc, "no-transform") {
				t.Fatalf("HTML Cache-Control = %q, want no-store + no-transform", cc)
			}
		})
	}
}

func TestAnalyticsOptOutAddsNoTransformBeforeHTMLFlush(t *testing.T) {
	analyticsOff := false
	app := &App{Design: &DesignConfig{Features: &FeaturesConfig{Analytics: &analyticsOff}, Auth: map[string]string{}, SEO: map[string]string{}}}
	for _, tc := range []struct {
		name        string
		contentType string
	}{
		{name: "html", contentType: "text/html; charset=utf-8"},
		{name: "json", contentType: "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Cache-Control", "no-store")
				f, ok := w.(http.Flusher)
				if !ok {
					t.Fatal("analytics response wrapper removed http.Flusher")
				}
				f.Flush()
				_, _ = w.Write([]byte("body"))
			}), false, app)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream", nil))
			got := strings.Contains(strings.ToLower(w.Header().Get("Cache-Control")), "no-transform")
			if want := tc.contentType == "text/html; charset=utf-8"; got != want {
				t.Fatalf("Cache-Control = %q; no-transform=%v, want %v", w.Header().Get("Cache-Control"), got, want)
			}
			if !strings.Contains(strings.ToLower(w.Header().Get("Cache-Control")), "no-store") {
				t.Fatalf("flush lost no-store: %q", w.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestAppYAMLFrameAncestorsNoneMustStandAlone(t *testing.T) {
	for _, content := range []string{
		"site_name: x\ncsp:\n  frame_ancestors: \"'none'\"\n",
		"site_name: x\ncsp:\n  frame_ancestors: \"https://embed.example https://preview.example\"\n",
	} {
		if msg := validateAppYAML(content); msg != "" {
			t.Errorf("valid frame_ancestors refused: %s", msg)
		}
	}
	for _, content := range []string{
		"site_name: x\ncsp:\n  frame_ancestors: \"'none' https://embed.example\"\n",
		"site_name: x\ncsp:\n  frame_ancestors: \"'NONE'\"\n",
	} {
		if msg := validateAppYAML(content); !strings.Contains(msg, "standalone value") {
			t.Errorf("invalid frame_ancestors accepted or wrong diagnostic: %q", msg)
		}
	}
}
