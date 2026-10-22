package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The markdown limiter keys on the resolved client address, not the TCP
// peer: behind a proxy every request shares one peer, and keying on it put
// all clients into a single bucket (one client exhausting it locked out
// everyone else).
func TestMarkdownRateLimitKeysOnResolvedClient(t *testing.T) {
	t.Cleanup(resetMarkdownRateLimiters)
	mux := http.NewServeMux()
	registerMarkdownRoutes(mux)

	// A Cloudflare edge address: clientIP believes CF-Connecting-IP from it.
	const edge = "173.245.48.10:443"
	post := func(client string) int {
		req := httptest.NewRequest("POST", "/_internal/markdown", strings.NewReader(`{"text":"hi"}`))
		req.RemoteAddr = edge
		req.Header.Set("CF-Connecting-IP", client)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	limited := false
	for i := 0; i < mdMarkdownRateLimit+10; i++ {
		if post("198.51.100.1") == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("first client was never rate-limited")
	}
	if code := post("198.51.100.2"); code != http.StatusOK {
		t.Fatalf("a different client behind the same proxy got %d; buckets must be per client", code)
	}
}
