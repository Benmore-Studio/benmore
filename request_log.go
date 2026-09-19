//go:build !cli

package main

// Per-app HTTP request logging. Every app automatically gets a
// _benmore_request_log table that records the last 5000 requests.
// The dashboard surfaces this as the "Runtime" tab - the equivalent
// of DigitalOcean's runtime logs.
//
// The middleware wraps the app's mux handler and records method, path,
// status code, response time, client IP, and authenticated user (if any).
// Static assets (JS/CSS/images/fonts) are excluded to keep noise down.
//
// The ring buffer is enforced lazily - every 100 inserts we prune
// anything beyond the cap. This keeps write overhead near zero
// while still bounding table size.

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const requestLogCap = 5000

// requestLogSem caps concurrent request-log insert goroutines process-wide.
// The log write is fire-and-forget; under a burst against a write-contended
// SQLite the old goroutine-per-request pattern let those goroutines (each
// blocked in the busy handler) accumulate without bound. The semaphore bounds
// them; when full, the log line is dropped (best-effort, by design).
var requestLogSem = make(chan struct{}, 16)

// EnsureRequestLogTable creates the per-app request log table.
func EnsureRequestLogTable(db *sql.DB) {
	if db == nil {
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_request_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		status INTEGER NOT NULL,
		duration_ms INTEGER NOT NULL,
		ip TEXT DEFAULT '',
		user_id TEXT DEFAULT '',
		user_agent TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	// Add error column for 500-level details. Without this, agents
	// debugging via get_request_logs see status codes but not what
	// actually broke - they end up stripping their schema down to
	// nothing trying to fix invisible errors. Idempotent ALTER.
	db.Exec(`ALTER TABLE _benmore_request_log ADD COLUMN error TEXT DEFAULT ''`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_request_log_time ON _benmore_request_log(created_at DESC)`)
}

// requestLogMiddleware wraps an http.Handler and logs every request
// to the app's _benmore_request_log table. Static assets are skipped.
func requestLogMiddleware(app *App, next http.Handler) http.Handler {
	if app == nil || app.DB == nil {
		return next
	}
	EnsureRequestLogTable(app.DB)

	var insertCount int64

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip static assets, internal endpoints, security scans, and favicon
		if isStaticPath(path) || r.UserAgent() == "BenmoreSecurityScanner/1.0" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rw := &statusCapture{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		dur := time.Since(start).Milliseconds()

		// Extract user info from the session (best-effort, non-blocking)
		userID := ""
		if sess := getSession(app, r); sess != nil {
			if sess.Email != "" {
				userID = sess.Email
			} else {
				userID = fmt.Sprintf("user:%d", sess.UserID)
			}
		}

		ip := clientIP(r)
		ua := r.UserAgent()
		if len(ua) > 200 {
			ua = ua[:200]
		}

		// Capture the error context handlers set via the
		// X-Benmore-Error response header (production hides the
		// error from the user, but the request log keeps it so the
		// agent can see what broke). The header is stripped from the
		// outgoing response below so it never reaches the client.
		errorDetail := w.Header().Get("X-Benmore-Error")
		if errorDetail != "" {
			w.Header().Del("X-Benmore-Error")
		}

		// Async insert - don't block the response. Bounded by requestLogSem so
		// a burst can't spawn unbounded goroutines stacked behind the SQLite
		// write lock; if the cap is reached the line is dropped (best-effort).
		method, status, ua2, err2 := r.Method, rw.status, ua, errorDetail
		select {
		case requestLogSem <- struct{}{}:
			go func() {
				defer func() { <-requestLogSem }()
				app.DB.Exec(
					"INSERT INTO _benmore_request_log (method, path, status, duration_ms, ip, user_id, user_agent, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
					method, path, status, dur, ip, userID, ua2, err2,
				)
				// Lazy prune every 100 inserts. atomic - this counter is
				// shared across all the concurrent insert goroutines (the old
				// plain insertCount++ was a data race).
				if atomic.AddInt64(&insertCount, 1)%100 == 0 {
					app.DB.Exec(fmt.Sprintf(
						"DELETE FROM _benmore_request_log WHERE id NOT IN (SELECT id FROM _benmore_request_log ORDER BY id DESC LIMIT %d)",
						requestLogCap,
					))
				}
			}()
		default:
			// log-write backpressure: drop this line rather than pile up.
		}
	})
}

// statusCapture wraps ResponseWriter to capture the status code.
type statusCapture struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader records the status code and forwards to the underlying
// writer EXACTLY ONCE. Net/http's protocol enforcement logs
// `http: superfluous response.WriteHeader call from …` on every
// duplicate call; pre-2.7.31 we forwarded unconditionally, so any
// handler that wrote a 4xx and then bubbled to an outer error-mapper
// that also called WriteHeader logged a noisy "superfluous" warning
// from THIS function on every failed outbound `api` step. The capture
// itself doesn't care about extra calls - we already have the first
// status - so dropping the second forward is harmless and silences
// the log spam.
func (sc *statusCapture) WriteHeader(code int) {
	if sc.wrote {
		return
	}
	sc.status = code
	sc.wrote = true
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Write(b []byte) (int, error) {
	if !sc.wrote {
		// Default-200 path: net/http will call WriteHeader(200) for us
		// on the first Write, so mark wrote=true to keep dedupe semantics
		// consistent.
		sc.status = http.StatusOK
		sc.wrote = true
	}
	return sc.ResponseWriter.Write(b)
}

// Flush passes through to the underlying writer when it supports
// Flusher. Without this, statusCapture silently swallows flushes -
// which is fatal for SSE since the handler writes a frame then calls
// Flush() to ship it. Manifested as 0-byte responses on /sse/events
// despite headers + body being written.
func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.NewResponseController find the underlying conn so
// the SSE handler can clear the server's WriteTimeout for its long-lived
// stream. Without Unwrap, SetWriteDeadline returns ErrNotSupported and
// the connection still gets cut at 30s.
func (sc *statusCapture) Unwrap() http.ResponseWriter {
	return sc.ResponseWriter
}

// Hijack passes through to the underlying ResponseWriter so the /ws
// WebSocket upgrade can hijack the raw TCP connection. Without this,
// the type assertion `w.(http.Hijacker)` inside wsUpgrade fails on
// the statusCapture wrapper and the upgrade returns 400 - even though
// the request was a perfectly valid RFC 6455 handshake. Same silent
// pattern that broke Flush before Flush was added above.
func (sc *statusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sc.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// isStaticPath returns true for paths that shouldn't be logged.
func isStaticPath(path string) bool {
	if strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/_internal/") ||
		strings.HasPrefix(path, "/uploads/") ||
		path == "/api/_analytics" ||
		// Long-lived streaming connections: their "duration" is the
		// connection lifetime (often minutes), not request latency, so
		// logging them wrecks the Performance tab's percentiles +
		// slowest-pages (e.g. /sse/events showing 117319ms). Skip them.
		path == "/sse/events" || strings.HasPrefix(path, "/sse/") ||
		path == "/ws" {
		return true
	}
	// Security scanner user-agent - filter out our own probes
	// The scanner runs from localhost, but we
	// can't easily pass UA through. Instead, skip requests from
	// the server's own IP hitting known probe patterns.

	// Common static file extensions
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
