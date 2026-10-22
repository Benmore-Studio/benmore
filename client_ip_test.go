//go:build !cli

package main

import (
	"net/http/httptest"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	// These cases exercise the hop walk; the router signature itself (now
	// required by default) is covered in router_sig_test.go.
	t.Setenv("BENMORE_REQUIRE_ROUTER_SIG", "0")
	type req struct {
		remote, xff, cf, real, app string
	}
	resolve := func(q req, trustRouter bool) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = q.remote
		for h, v := range map[string]string{"X-Forwarded-For": q.xff, "CF-Connecting-IP": q.cf, "X-Real-IP": q.real, "X-Benmore-App": q.app} {
			if v != "" {
				r.Header.Set(h, v)
			}
		}
		return resolveClientIP(r, trustRouter)
	}
	cases := []struct {
		name        string
		trustProxy  string
		trustRouter bool
		q           req
		want        string
	}{
		// A direct client never chooses its own address.
		{"direct forged headers", "", true, req{remote: "198.51.100.20:4000", xff: "1.2.3.4", cf: "5.6.7.8", real: "9.9.9.9", app: "shop"}, "198.51.100.20"},
		{"direct forged headers framework", "", false, req{remote: "198.51.100.20:4000", xff: "1.2.3.4", cf: "5.6.7.8", app: "shop"}, "198.51.100.20"},
		// Cloudflare's edge asserts the visitor.
		{"cloudflare peer", "", false, req{remote: "104.16.0.5:443", cf: "203.0.113.7", xff: "6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		{"cloudflare peer v6", "", true, req{remote: "[2606:4700::1]:443", cf: "2001:db8::7"}, "2001:db8::7"},
		{"cloudflare peer without header", "", false, req{remote: "104.16.0.5:443", xff: "6.6.6.6, 203.0.113.7"}, "203.0.113.7"},
		// Platform router: it writes the first hop, the proxy appends its peer.
		{"router marker", "", true, req{remote: "127.0.0.1:5000", xff: "203.0.113.7, 104.16.0.5", app: "shop"}, "203.0.113.7"},
		{"router marker bad xff", "", true, req{remote: "127.0.0.1:5000", xff: "not-an-ip", app: "shop"}, "127.0.0.1"},
		{"router marker ignored in framework", "", false, req{remote: "127.0.0.1:5000", xff: "203.0.113.7", cf: "5.6.7.8", app: "shop"}, "127.0.0.1"},
		{"router marker needs loopback", "", true, req{remote: "10.0.0.8:5000", xff: "203.0.113.7", app: "shop"}, "10.0.0.8"},
		{"unmarked loopback", "", true, req{remote: "127.0.0.1:5000", xff: "203.0.113.7"}, "127.0.0.1"},
		// Operator-declared proxies: walk from the right.
		{"nginx append", "1", false, req{remote: "127.0.0.1:5000", xff: "6.6.6.6, 198.51.100.9"}, "198.51.100.9"},
		{"nginx forged cloudflare hop", "1", false, req{remote: "127.0.0.1:5000", xff: "104.16.0.5, 198.51.100.66", cf: "1.1.1.1"}, "198.51.100.66"},
		{"cloudflare then nginx", "1", false, req{remote: "127.0.0.1:5000", xff: "6.6.6.6, 198.51.100.9, 104.16.0.5", cf: "198.51.100.9"}, "198.51.100.9"},
		{"private load balancer", "true", false, req{remote: "10.1.2.3:5000", xff: "198.51.100.9, 10.1.2.4"}, "198.51.100.9"},
		{"cidr list", "10.0.0.0/8", false, req{remote: "10.1.2.3:5000", xff: "198.51.100.9"}, "198.51.100.9"},
		{"cidr list other peer", "10.0.0.0/8", false, req{remote: "172.16.0.1:5000", xff: "198.51.100.9"}, "172.16.0.1"},
		{"hop with port", "1", false, req{remote: "127.0.0.1:5000", xff: "[2001:db8::9]:443"}, "2001:db8::9"},
		{"x-real-ip", "1", false, req{remote: "127.0.0.1:5000", real: "198.51.100.9"}, "198.51.100.9"},
		{"x-real-ip untrusted peer", "", false, req{remote: "127.0.0.1:5000", real: "198.51.100.9"}, "127.0.0.1"},
		{"garbage hop stops the walk", "1", false, req{remote: "127.0.0.1:5000", xff: "198.51.100.9, unknown"}, "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("BENMORE_TRUST_PROXY", c.trustProxy)
			if got := resolve(c.q, c.trustRouter); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
