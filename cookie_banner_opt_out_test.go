//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A page can drop the consent banner (an embedded player) without turning
// analytics off for the whole app.
func TestPageCookieBannerOptOut(t *testing.T) {
	on := true
	app := &App{
		Dir:    t.TempDir(),
		Paths:  DiscoverAuthPaths(nil),
		Design: &DesignConfig{Features: &FeaturesConfig{Analytics: &on}, Auth: map[string]string{}, SEO: map[string]string{}},
	}
	serve := func(page string) string {
		rec := httptest.NewRecorder()
		serveHTMLBytes(rec, httptest.NewRequest("GET", "/embed", nil), app, []byte(page))
		return rec.Body.String()
	}
	if body := serve("<!doctype html><html><head></head><body><main>player</main></body></html>"); !strings.Contains(body, `id="bm-cookie"`) {
		t.Fatal("control: an ordinary page must carry the banner")
	}
	for _, meta := range []string{
		`<meta name="bm-cookie-banner" content="off">`,
		`<META content='OFF' name='bm-cookie-banner' />`,
	} {
		body := serve("<!doctype html><html><head>" + meta + "</head><body><main>player</main></body></html>")
		if strings.Contains(body, `id="bm-cookie"`) {
			t.Fatalf("%s: banner still injected", meta)
		}
		if !strings.Contains(body, "/api/_analytics") {
			t.Fatalf("%s: the opt-out must not drop the analytics beacon", meta)
		}
	}
	if !strings.Contains(serve(`<html><head><meta name="bm-cookie-banner" content="on"></head><body></body></html>`), `id="bm-cookie"`) {
		t.Fatal("content other than off must keep the banner")
	}
}
