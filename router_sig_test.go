//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const routerSigTestSecret = "0123456789abcdef0123456789abcdef-tenant-b"

// signedFromRouter builds the request a router would send tenant B.
func signedFromRouter(t *testing.T, secret, ip string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/forgot-password", nil)
	r.Host = "shop.benmore.ai"
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", ip+", 127.0.0.1")
	r.Header.Set("X-Benmore-App", "shop")
	signRouterHeaders(r.Header, r.Method, r.Host, ip, secret)
	return r
}

func withRouterSigApp(t *testing.T, requireSig string) {
	t.Helper()
	old := serverSecret
	serverSecret = routerSigTestSecret
	t.Setenv("BENMORE_REQUIRE_ROUTER_SIG", requireSig)
	t.Setenv("BENMORE_TRUST_PROXY", "")
	t.Cleanup(func() { serverSecret = old; routerSigNow = time.Now })
}

func TestRouterMarkerRequiresSignatureWhenFlagged(t *testing.T) {
	withRouterSigApp(t, "1")

	good := signedFromRouter(t, routerSigTestSecret, "203.0.113.7")
	if !routerMarkerTrusted(good) || resolveClientIP(good, true) != "203.0.113.7" {
		t.Fatal("a correctly signed router request was refused")
	}

	forged := httptest.NewRequest("GET", "/", nil)
	forged.RemoteAddr = "127.0.0.1:5000"
	forged.Host = "evil.example"
	forged.Header.Set("X-Benmore-App", "shop")
	forged.Header.Set("X-Forwarded-For", "9.9.9.9")
	if routerMarkerTrusted(forged) || resolveClientIP(forged, true) != "127.0.0.1" {
		t.Fatal("unsigned marker trusted with the flag on")
	}
	if routerVettedHost(forged) {
		t.Fatal("unsigned marker vouched for a Host with the flag on")
	}

	// Signed by another tenant's secret (what a neighbor could compute).
	wrong := signedFromRouter(t, "another-tenants-secret-0123456789abcdef", "203.0.113.7")
	if routerMarkerTrusted(wrong) {
		t.Fatal("signature from a different secret accepted")
	}
}

func TestRouterSignatureBindsFields(t *testing.T) {
	withRouterSigApp(t, "1")
	base := time.Now()
	routerSigNow = func() time.Time { return base }

	mutate := map[string]func(*http.Request){
		"ip":     func(r *http.Request) { r.Header.Set("X-Forwarded-For", "198.51.100.1, 127.0.0.1") },
		"host":   func(r *http.Request) { r.Host = "evil.example" },
		"scheme": func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
		"method": func(r *http.Request) { r.Method = "GET" },
	}
	for name, f := range mutate {
		r := signedFromRouter(t, routerSigTestSecret, "203.0.113.7")
		f(r)
		if routerMarkerTrusted(r) {
			t.Fatalf("signature survived a changed %s", name)
		}
	}

	// Expiry: outside the window either way is refused; inside is accepted.
	r := signedFromRouter(t, routerSigTestSecret, "203.0.113.7")
	routerSigNow = func() time.Time { return base.Add(29 * time.Second) }
	if !routerMarkerTrusted(r) {
		t.Fatal("fresh signature refused")
	}
	routerSigNow = func() time.Time { return base.Add(31 * time.Second) }
	if routerMarkerTrusted(r) {
		t.Fatal("expired signature accepted")
	}
	routerSigNow = func() time.Time { return base.Add(-31 * time.Second) }
	if routerMarkerTrusted(r) {
		t.Fatal("future-dated signature accepted")
	}
	// A malformed timestamp is refused, not an error.
	routerSigNow = func() time.Time { return base }
	r.Header.Set(routerSigTimeHeader, "soon")
	if routerMarkerTrusted(r) {
		t.Fatal("garbage timestamp accepted")
	}
}

// With BENMORE_REQUIRE_ROUTER_SIG unset (or set to anything but an explicit
// off), an unsigned marker is refused: another tenant reaching this app's
// loopback port must not choose the client address it is rate-limited as.
func TestRouterMarkerRequiresSignatureByDefault(t *testing.T) {
	for _, v := range []string{"", "maybe"} {
		withRouterSigApp(t, v)
		if v == "" {
			os.Unsetenv("BENMORE_REQUIRE_ROUTER_SIG")
		}
		forged := httptest.NewRequest("GET", "/", nil)
		forged.RemoteAddr = "127.0.0.1:5000"
		forged.Header.Set("X-Benmore-App", "shop")
		forged.Header.Set("X-Forwarded-For", "9.9.9.9")
		if routerMarkerTrusted(forged) || resolveClientIP(forged, true) != "127.0.0.1" {
			t.Fatalf("BENMORE_REQUIRE_ROUTER_SIG=%q: unsigned marker trusted", v)
		}
		good := signedFromRouter(t, routerSigTestSecret, "203.0.113.7")
		if !routerMarkerTrusted(good) || resolveClientIP(good, true) != "203.0.113.7" {
			t.Fatalf("BENMORE_REQUIRE_ROUTER_SIG=%q: signed router request refused", v)
		}
	}
}

func TestRouterMarkerLegacyWhenFlagOff(t *testing.T) {
	withRouterSigApp(t, "0")
	legacy := httptest.NewRequest("GET", "/", nil)
	legacy.RemoteAddr = "127.0.0.1:5000"
	legacy.Header.Set("X-Benmore-App", "shop")
	legacy.Header.Set("X-Forwarded-For", "203.0.113.7, 127.0.0.1")
	if !routerMarkerTrusted(legacy) || resolveClientIP(legacy, true) != "203.0.113.7" {
		t.Fatal("unsigned marker refused with the flag off (old router rollout)")
	}
	// Still never from a non-loopback peer, signed or not.
	remote := signedFromRouter(t, routerSigTestSecret, "203.0.113.7")
	remote.RemoteAddr = "10.0.0.8:5000"
	if routerMarkerTrusted(remote) {
		t.Fatal("non-loopback peer trusted")
	}
	// A short (ephemeral) app secret can never verify, so the flag refuses.
	serverSecret = strings.Repeat("x", 8)
	t.Setenv("BENMORE_REQUIRE_ROUTER_SIG", "true")
	if routerMarkerTrusted(signedFromRouter(t, routerSigTestSecret, "203.0.113.7")) {
		t.Fatal("verified against a short secret")
	}
}
