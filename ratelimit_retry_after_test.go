//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A refusal says how long to wait, and is flagged as the first of its window
// exactly once, so callers can log a bucket running dry without logging every
// request.
func TestRateLimiterCheck_RetryAfterAndFirstDenial(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	for i := 0; i < 2; i++ {
		if ok, retry, first := rl.Check("k"); !ok || retry != 0 || first {
			t.Fatalf("request %d: allowed=%v retry=%v first=%v, want allowed with no retry", i+1, ok, retry, first)
		}
	}
	ok, retry, first := rl.Check("k")
	if ok || !first {
		t.Fatalf("3rd request: allowed=%v first=%v, want refused and first", ok, first)
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry %v, want within (0, 1m]", retry)
	}
	if _, _, first := rl.Check("k"); first {
		t.Fatal("second refusal in the same window must not be flagged first")
	}
	if !rl.Allow("other") {
		t.Fatal("a different key has its own budget")
	}
}

func TestRateLimiterCheck_SharedMode(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "rl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stop := make(chan struct{})
	defer close(stop)
	rl := NewSharedRateLimiter(db, 1, time.Minute, stop)
	if ok, _, _ := rl.Check("k"); !ok {
		t.Fatal("first request refused")
	}
	ok, retry, first := rl.Check("k")
	if ok || !first || retry <= 0 || retry > time.Minute {
		t.Fatalf("2nd request: allowed=%v first=%v retry=%v, want refused, first, retry in (0,1m]", ok, first, retry)
	}
	if _, _, first := rl.Check("k"); first {
		t.Fatal("second refusal in the same window must not be flagged first")
	}
}

func TestRateLimitMiddleware_SetsRetryAfter(t *testing.T) {
	h := RateLimitMiddleware(NewRateLimiter(1, time.Minute), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/x", nil)
		req.RemoteAddr = "198.51.100.9:1111"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(); rec.Code != 200 || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("allowed request: code %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	rec := send()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	if n, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || n < 1 || n > 60 {
		t.Fatalf("Retry-After %q, want 1..60", rec.Header().Get("Retry-After"))
	}
}
