//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a simple per-IP token bucket rate limiter.
// In single-instance mode, uses in-memory tracking (fast, zero overhead).
// In cluster mode (BENMORE_CLUSTER=true), uses SQLite for cross-instance consistency.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // requests per window
	window   time.Duration // time window
	// Shared mode fields (cluster)
	db     *sql.DB // non-nil = shared mode via SQLite
}

type visitor struct {
	tokens    int
	lastReset time.Time
}

// NewRateLimiter creates an in-memory rate limiter. Default: 60 requests per minute per IP.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
	// Cleanup stale entries every 5 minutes
	safeGo("rateLimit.cleanup1", func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.cleanup()
		}
	})
	return rl
}

// NewSharedRateLimiter creates a SQLite-backed rate limiter for cluster mode.
// Uses the _benmore_rate_limits table for cross-instance consistency.
func NewSharedRateLimiter(db *sql.DB, rate int, window time.Duration) *RateLimiter {
	EnsureRateLimitsTable(db)
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		db:       db,
	}
	// Cleanup stale entries every 5 minutes
	safeGo("rateLimit.cleanup2", func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.cleanupShared()
		}
	})
	return rl
}

// EnsureRateLimitsTable creates the shared rate limits table for cluster mode.
func EnsureRateLimitsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_rate_limits (
		key TEXT PRIMARY KEY,
		count INTEGER NOT NULL DEFAULT 0,
		window_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
}

// Allow checks if a request from this key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	if rl.db != nil {
		return rl.allowShared(key)
	}
	return rl.allowLocal(key)
}

// allowLocal is the fast in-memory path for single-instance mode.
func (rl *RateLimiter) allowLocal(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists || time.Since(v.lastReset) > rl.window {
		rl.visitors[key] = &visitor{tokens: rl.rate - 1, lastReset: time.Now()}
		return true
	}

	if v.tokens <= 0 {
		return false
	}

	v.tokens--
	return true
}

// allowShared uses SQLite for cross-instance rate limiting.
// Atomic: uses INSERT OR REPLACE with window check in a single transaction.
func (rl *RateLimiter) allowShared(key string) bool {
	windowSec := int(rl.window.Seconds())

	// Atomic check-and-increment using SQLite's UPSERT.
	// If the window has expired, reset the counter. Otherwise, increment.
	result, err := rl.db.Exec(`
		INSERT INTO _benmore_rate_limits (key, count, window_start)
		VALUES (?, 1, datetime('now'))
		ON CONFLICT(key) DO UPDATE SET
			count = CASE
				WHEN (julianday('now') - julianday(window_start)) * 86400 > ?
				THEN 1
				ELSE count + 1
			END,
			window_start = CASE
				WHEN (julianday('now') - julianday(window_start)) * 86400 > ?
				THEN datetime('now')
				ELSE window_start
			END
	`, key, windowSec, windowSec)
	if err != nil {
		// On error, fail open (allow the request)
		return true
	}

	// Check if the request was allowed by reading the current count
	_ = result
	var count int
	err = rl.db.QueryRow("SELECT count FROM _benmore_rate_limits WHERE key = ?", key).Scan(&count)
	if err != nil {
		return true // fail open
	}

	return count <= rl.rate
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-2 * rl.window)
	for ip, v := range rl.visitors {
		if v.lastReset.Before(cutoff) {
			delete(rl.visitors, ip)
		}
	}
}

func (rl *RateLimiter) cleanupShared() {
	if rl.db == nil {
		return
	}
	windowSec := int(rl.window.Seconds()) * 2
	rl.db.Exec(
		"DELETE FROM _benmore_rate_limits WHERE (julianday('now') - julianday(window_start)) * 86400 > ?",
		windowSec,
	)
}

// RateLimitMiddleware wraps an HTTP handler with rate limiting.
// Uses user ID when authenticated (Bearer or cookie), falls back to IP for anonymous.
func RateLimitMiddleware(rl *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't count static asset / internal-library serving against the
		// rate limit. A single page load fires 10-30 of these (the compiled
		// JS bundle, styles.css, /_internal/bm.js, fonts, images, favicon),
		// so counting them made normal click-through browsing trip the API
		// limit within ~5 page navigations — exactly the "I keep hitting the
		// rate limit just clicking around" symptom. isStaticPath covers
		// /static/, /_internal/, /uploads/ + common asset extensions (the
		// same filter the request log uses).
		if isStaticPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Prefer user-based rate limiting when authenticated
		key := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			key = "user:" + strings.TrimPrefix(auth, "Bearer ")
		}
		if key == "" {
			if cookie, err := r.Cookie("_benmore_session"); err == nil {
				key = "session:" + cookie.Value
			}
		}
		if key == "" {
			// Use RemoteAddr only — do not trust X-Forwarded-For as it can be spoofed.
			// If behind a trusted reverse proxy, configure the proxy to set a trusted header.
			key = r.RemoteAddr
		}

		if !rl.Allow(key) {
			http.Error(w, "Rate limit exceeded. Try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// StrictRateLimiter for auth endpoints (5 requests per minute).
func AuthRateLimiter() *RateLimiter {
	return NewRateLimiter(5, time.Minute)
}

// SharedAuthRateLimiter creates a SQLite-backed auth rate limiter for cluster mode.
func SharedAuthRateLimiter(db *sql.DB) *RateLimiter {
	return NewSharedRateLimiter(db, 5, time.Minute)
}
