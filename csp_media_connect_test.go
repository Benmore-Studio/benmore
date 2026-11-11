//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// B16: pages could not fetch() an upload or a signed link - the media CDN
// was in img-src and media-src but not connect-src, so
// `fetch(await bm.signedUrl(...))` failed unless the app added csp.connect_src.
// connect-src now lists that one origin, never a wildcard.
func TestPageCSPConnectSrcAllowsMediaCDN(t *testing.T) {
	cfg := testMediaConfig(t)
	cfg.CDNDomain = "media.example.test"
	withPlatformMedia(t, cfg)

	rec := httptest.NewRecorder()
	applySecurityHeaders(rec, nil, false, &App{Dir: t.TempDir()})
	csp := rec.Header().Get("Content-Security-Policy")
	connect := ""
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "connect-src ") {
			connect = d
		}
	}
	if !strings.Contains(" "+connect+" ", " https://media.example.test ") {
		t.Fatalf("connect-src %q lacks the media CDN origin", connect)
	}
	for _, tok := range strings.Fields(connect) {
		if strings.Contains(tok, "*") || tok == "https:" {
			t.Fatalf("connect-src %q opened more than the media origin", connect)
		}
	}

	// Without a media CDN (local-disk uploads are same-origin) nothing changes.
	withPlatformMedia(t, nil)
	if got := pageCSPDirectives(&App{Dir: t.TempDir()})["connect_src"]; strings.Contains(got, "media.example.test") {
		t.Fatalf("connect-src %q kept the media origin with no CDN configured", got)
	}
}
