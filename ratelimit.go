//go:build !cli

package main

import (
	"database/sql"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// realtimeMaxVisitors bounds the in-memory visitor map. H-17: the map
// was previously unbounded, so a flood of distinct keys (one per spoofed
// credential / source IP) could grow it without limit and exhaust memory
// before the 5-minute cleanup ran. When the cap is reached we evict the
// stalest entry so the map can never exceed this size. Sized generously
// so legitimate per-IP traffic on a busy single instance never trips it.
const realtimeMaxVisitors = 50000

// RateLimiter implements a simple per-IP token bucket rate limiter.
// In single-instance mode, uses in-memory tracking (fast, zero overhead).
// In cluster mode (BENMORE_CLUSTER=true), uses SQLite for cross-instance consistency.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // requests per window
	window   time.Duration // time window
	// Shared mode fields (cluster)
	db *sql.DB // non-nil = shared mode via SQLite
}

type visitor struct {
	tokens    int
	lastReset time.Time
	// denied is set by the first refusal in the current window, so a caller
	// can log a bucket running dry once per window instead of once per request.
	denied bool
}

// NewRateLimiter creates a process-lifetime in-memory rate limiter (the
// cleanup goroutine never exits). Use for package-level limiters that live
// as long as the process. For a limiter re-created on every hot reload
// (inside buildAppMux / wrapMiddleware / a Register* func) use
// NewRateLimiterStoppable(..., app.Stop) so cleanup is reclaimed on reload
// instead of leaking a goroutine + visitor map per push.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return newRateLimiter(rate, window, nil)
}

// NewRateLimiterStoppable is NewRateLimiter whose cleanup goroutine exits
// when stop is closed. Pass app.Stop for per-app/per-reload limiters.
func NewRateLimiterStoppable(rate int, window time.Duration, stop <-chan struct{}) *RateLimiter {
	return newRateLimiter(rate, window, stop)
}

func newRateLimiter(rate int, window time.Duration, stop <-chan struct{}) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
	// Cleanup stale entries every 5 minutes. A nil stop channel blocks
	// forever in the select - exactly the process-lifetime case.
	safeGo("rateLimit.cleanup", func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	})
	return rl
}

// NewSharedRateLimiter creates a SQLite-backed rate limiter for cluster mode.
// Uses the _benmore_rate_limits table for cross-instance consistency. `stop`
// (typically app.Stop) reclaims the cleanup goroutine on hot reload - without
// it, wrapMiddleware leaked one cleanup goroutine per reload. Pass nil for a
// process-lifetime limiter.
func NewSharedRateLimiter(db *sql.DB, rate int, window time.Duration, stop <-chan struct{}) *RateLimiter {
	EnsureRateLimitsTable(db)
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		db:       db,
	}
	// Cleanup stale entries every 5 minutes, until stop is closed.
	safeGo("rateLimit.cleanup2", func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				rl.cleanupShared()
			}
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
	ok, _, _ := rl.Check(key)
	return ok
}

// Check is Allow plus what a refusal needs: how long until this key's window
// resets (for a Retry-After header) and whether this is the first refusal in
// the window (to log a bucket running dry once, not once per request). Both
// are zero values when the request is allowed. Counting is identical to Allow.
func (rl *RateLimiter) Check(key string) (allowed bool, retryAfter time.Duration, firstDenial bool) {
	if rl.db != nil {
		return rl.checkShared(key)
	}
	return rl.checkLocal(key)
}

// checkLocal is the fast in-memory path for single-instance mode.
func (rl *RateLimiter) checkLocal(key string) (bool, time.Duration, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	if !exists || time.Since(v.lastReset) > rl.window {
		// H-17: bound the visitor map. Before inserting a brand-new key,
		// enforce the size cap by evicting the stalest entry. Invariant:
		// len(rl.visitors) never exceeds realtimeMaxVisitors, so a flood
		// of distinct keys cannot drive unbounded memory growth between
		// cleanup ticks.
		if !exists && len(rl.visitors) >= realtimeMaxVisitors {
			rl.evictStalestLocked()
		}
		rl.visitors[key] = &visitor{tokens: rl.rate - 1, lastReset: time.Now()}
		return true, 0, false
	}

	if v.tokens <= 0 {
		first := !v.denied
		v.denied = true
		return false, rl.window - time.Since(v.lastReset), first
	}

	v.tokens--
	return true, 0, false
}

// checkShared uses SQLite for cross-instance rate limiting.
// Atomic: uses INSERT OR REPLACE with window check in a single transaction.
func (rl *RateLimiter) checkShared(key string) (bool, time.Duration, bool) {
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
		return true, 0, false
	}

	// Check if the request was allowed by reading the current count
	_ = result
	var count int
	var elapsed float64
	err = rl.db.QueryRow(
		"SELECT count, (julianday('now') - julianday(window_start)) * 86400 FROM _benmore_rate_limits WHERE key = ?", key,
	).Scan(&count, &elapsed)
	if err != nil {
		return true, 0, false // fail open
	}
	if count <= rl.rate {
		return true, 0, false
	}
	// Every request increments the shared counter, so rate+1 is the first
	// refusal of the window.
	return false, rl.window - time.Duration(elapsed*float64(time.Second)), count == rl.rate+1
}

// setRetryAfter writes a Retry-After header in whole seconds, rounded up and
// never below 1, so a client that waits exactly that long lands in a fresh
// window rather than one more refusal.
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
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

// evictStalestLocked removes the single least-recently-reset visitor.
// Caller MUST hold rl.mu. Used as the overflow valve when the map hits
// realtimeMaxVisitors (H-17): O(n) but only runs at the cap, which a
// healthy instance never reaches.
// evictStalestLocked frees headroom when the visitor map hits the cap. It
// evicts a BATCH (~10%) per call rather than a single stalest entry, so it does
// not run a full O(n) scan on EVERY insert during a distinct-key flood - which
// would turn the H-17 memory-DoS defense into a CPU/lock-contention DoS (the
// scan runs under rl.mu, serializing all Allow callers). Batching amortizes the
// scan to ~O(1) per insert: one pass frees room for the next ~N/10 inserts.
func (rl *RateLimiter) evictStalestLocked() {
	target := len(rl.visitors)/10 + 1 // free ~10% so the next ~N/10 inserts skip this
	cutoff := time.Now().Add(-rl.window)
	removed := 0
	// First pass: drop genuinely stale entries (expired windows = real garbage).
	for k, v := range rl.visitors {
		if v.lastReset.Before(cutoff) {
			delete(rl.visitors, k)
			removed++
		}
	}
	// If stale entries didn't free enough (e.g. a burst of all-fresh keys),
	// drop arbitrary entries until the target is met. Map iteration order is
	// randomized, so this is an unbiased sample - fine for flood garbage.
	for k := range rl.visitors {
		if removed >= target {
			break
		}
		delete(rl.visitors, k)
		removed++
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
		// limit within ~5 page navigations - exactly the "I keep hitting the
		// rate limit just clicking around" symptom. isStaticPath covers
		// /static/, /_internal/, /uploads/ + common asset extensions (the
		// same filter the request log uses).
		if isStaticPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// H-17: NEVER key the bucket on the raw, attacker-supplied
		// bearer/session value. This middleware runs before (and without
		// access to app.DB for) token validation, so it cannot tell a
		// real principal from a forged one. Keying on the raw credential
		// let an attacker mint a fresh bucket per request simply by
		// sending a random Bearer token each time - bypassing the anon
		// limit entirely and growing the visitor map without bound.
		//
		// The only principal we can RESOLVE without trusting unvalidated
		// input is the source IP, so we always key on the host here.
		// Per-user fairness for *validated* principals is enforced
		// downstream where the session is actually authenticated; this
		// budget is the fail-closed anti-abuse floor. RemoteAddr (not
		// X-Forwarded-For, which is spoofable) is authoritative.
		//
		// Key on the HOST only, never the ip:PORT pair: RemoteAddr's
		// ephemeral port differs every TCP connection, so keying on the
		// whole thing gave a connection that reconnects per request its
		// own fresh bucket. SplitHostPort drops the port; fall back to the
		// raw value if it has no port.
		key := "ip:" + rateLimitClientHost(r)

		if ok, retry, _ := rl.Check(key); !ok {
			setRetryAfter(w, retry)
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
// nil stop = process-lifetime cleanup (callers that live for the whole process).
func SharedAuthRateLimiter(db *sql.DB) *RateLimiter {
	return NewSharedRateLimiter(db, 5, time.Minute, nil)
}

// rateLimitClientHost returns the host to key per-client limits on: the
// client address resolved from trusted peers only (client_ip.go). Apps run
// behind the platform router, whose loopback RemoteAddr would otherwise pool
// every visitor of an app into one bucket.
func rateLimitClientHost(r *http.Request) string {
	return clientIP(r)
}
