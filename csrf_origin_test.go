package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSRFOriginGate covers round-2 #2: the origin gate must block a cross-site
// request (so a lifted unbound token can't be replayed cross-site), including
// the absent-Origin case via Sec-Fetch-Site.
func TestCSRFOriginGate(t *testing.T) {
	if serverSecret == "" {
		serverSecret = generateToken(32)
	}
	tok := authMintCSRFToken("") // unbound token, as minted for pages/_csrf
	newReq := func(set func(*http.Request)) *http.Request {
		r := httptest.NewRequest("POST", "http://app.example/api/x", strings.NewReader("_csrf="+tok))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Host = "app.example"
		set(r)
		return r
	}
	cases := []struct {
		name string
		set  func(*http.Request)
		want bool
	}{
		{"same-origin Origin", func(r *http.Request) { r.Header.Set("Origin", "http://app.example") }, true},
		{"cross-origin Origin", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, false},
		{"no Origin, sec-fetch same-origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }, true},
		{"no Origin, sec-fetch cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, false},
		{"no Origin, sec-fetch same-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, false},
		{"no Origin, no sec-fetch (native client)", func(r *http.Request) {}, true},
	}
	for _, c := range cases {
		if got := validateCSRF(newReq(c.set)); got != c.want {
			t.Errorf("%s: validateCSRF = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSecurityLinkBaseURL covers round-2 #5: credential links must not be built
// from the request Host when an operator origin is configured.
func TestSecurityLinkBaseURL(t *testing.T) {
	r := httptest.NewRequest("POST", "http://attacker.example/forgot", nil)
	r.Host = "attacker.example"
	app := &App{Design: &DesignConfig{SEO: map[string]string{"url": "https://app.real"}}}
	if got := securityLinkBaseURL(app, r); got != "https://app.real" {
		t.Fatalf("with seo.url: got %q, want https://app.real (not the request Host)", got)
	}
}
