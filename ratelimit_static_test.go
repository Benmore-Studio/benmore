//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRateLimitMiddleware_SkipsStatic locks the fix for "I keep hitting
// the rate limit just clicking around": static asset / internal-lib
// requests must NOT count against the budget, while real API requests do.
func TestRateLimitMiddleware_SkipsStatic(t *testing.T) {
	// Budget of 3 per window so the test is fast + deterministic.
	rl := NewRateLimiter(3, time.Minute)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := RateLimitMiddleware(rl, ok)

	hit := func(path string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "1.2.3.4:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// 50 static-asset requests: none should ever 429.
	for i := 0; i < 50; i++ {
		for _, p := range []string{"/static/app.js", "/_internal/bm.js", "/static/styles.css", "/favicon.ico"} {
			if code := hit(p); code == http.StatusTooManyRequests {
				t.Fatalf("static path %s was rate-limited (429) — must be exempt", p)
			}
		}
	}

	// API requests DO count: 3 allowed, 4th blocked (budget = 3).
	for i := 0; i < 3; i++ {
		if code := hit("/api/orders"); code != 200 {
			t.Fatalf("API request %d should be allowed, got %d", i+1, code)
		}
	}
	if code := hit("/api/orders"); code != http.StatusTooManyRequests {
		t.Fatalf("4th API request should be 429, got %d", code)
	}
}
