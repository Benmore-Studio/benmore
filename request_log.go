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
// Writes are batched: the middleware hands each line to a buffered channel
// and one writer goroutine per app inserts everything queued in a single
// transaction every requestLogFlushInterval (or sooner once
// requestLogBatchMax lines are waiting). The previous design ran one
// INSERT transaction per request on up to 16 concurrent goroutines, each
// holding a pool connection while it queued on SQLite's single write lock
// (up to the 10s busy timeout) - log writes competed with the app's own
// writes for the lock and the pool. When the buffer is full a line is
// dropped and counted (best-effort, by design); the count is logged.
//
// The ring buffer is enforced after each batch once requestLogPruneEvery
// lines have been written since the last prune, keeping the newest
// requestLogCap rows.

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	requestLogCap           = 5000
	requestLogBuffer        = 2048
	requestLogBatchMax      = 500
	requestLogFlushInterval = time.Second
	requestLogPruneEvery    = 100
	// requestLogPathMax caps the logged path. Any visitor chooses it (up to
	// the 64 KiB front-door header cap, 1 MiB on a bare `benmore serve`),
	// and it is held for every buffered line and every one of the
	// requestLogCap rows in the app's own, storage-capped database.
	requestLogPathMax = 2048
)

// requestLogTruncate cuts s to at most n bytes without splitting a UTF-8
// rune.
func requestLogTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// requestLogEntry is one buffered _benmore_request_log row.
type requestLogEntry struct {
	method, path   string
	status         int
	durationMS     int64
	ip, userID, ua string
	errorDetail    string
	requestID      string
}

// requestLogWriter owns one app's request-log channel and writer goroutine.
type requestLogWriter struct {
	db         *sql.DB
	ch         chan requestLogEntry
	keepRows   int
	dropped    atomic.Int64
	reported   int64 // dropped count already logged (writer goroutine only)
	sincePrune int
}

func newRequestLogWriter(db *sql.DB, buffer, capRows int) *requestLogWriter {
	return &requestLogWriter{db: db, ch: make(chan requestLogEntry, buffer), keepRows: capRows}
}

// enqueue never blocks the request: a full buffer drops the line.
func (w *requestLogWriter) enqueue(e requestLogEntry) {
	select {
	case w.ch <- e:
	default:
		w.dropped.Add(1)
	}
}

// run drains the channel until stop closes, then flushes what is queued.
func (w *requestLogWriter) run(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	batch := make([]requestLogEntry, 0, requestLogBatchMax)
	for {
		select {
		case <-stop:
			batch = w.drain(batch)
			w.flush(batch)
			return
		case e := <-w.ch:
			batch = append(batch, e)
			if len(batch) >= requestLogBatchMax {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			batch = w.drain(batch)
			w.flush(batch)
			batch = batch[:0]
		}
	}
}

// drain moves every currently queued entry into batch without blocking.
func (w *requestLogWriter) drain(batch []requestLogEntry) []requestLogEntry {
	for {
		select {
		case e := <-w.ch:
			batch = append(batch, e)
		default:
			return batch
		}
	}
}

// flush writes batch in one transaction and prunes when due. Failures drop
// the batch (and are counted): the log is best-effort and must never retry
// into a write-contended database.
func (w *requestLogWriter) flush(batch []requestLogEntry) {
	if d := w.dropped.Load(); d != w.reported {
		log.Printf("request-log: dropped %d line(s) (buffer full or write failed)", d-w.reported)
		w.reported = d
	}
	if len(batch) == 0 {
		return
	}
	if err := w.insertBatch(batch); err != nil {
		w.dropped.Add(int64(len(batch)))
		return
	}
	w.sincePrune += len(batch)
	if w.sincePrune >= requestLogPruneEvery {
		w.sincePrune = 0
		pruneRingTable(w.db, "_benmore_request_log", w.keepRows)
	}
}

func (w *requestLogWriter) insertBatch(batch []requestLogEntry) error {
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO _benmore_request_log (method, path, status, duration_ms, ip, user_id, user_agent, error, request_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range batch {
		if _, err := stmt.Exec(e.method, e.path, e.status, e.durationMS, e.ip, e.userID, e.ua, e.errorDetail, e.requestID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// pruneRingTable keeps the newest keep rows of an AUTOINCREMENT ring table.
// The old `id NOT IN (SELECT id ... ORDER BY id DESC LIMIT N)` built an
// N-row temp b-tree and probed it for every row on each prune; this finds
// the boundary id with one index seek and range-deletes below it. When the
// table holds keep rows or fewer the subquery is NULL and nothing matches.
// table is a framework constant, never request input.
func pruneRingTable(db *sql.DB, table string, keep int) {
	_, _ = db.Exec(fmt.Sprintf(
		"DELETE FROM %s WHERE id <= (SELECT id FROM %s ORDER BY id DESC LIMIT 1 OFFSET ?)",
		table, table), keep)
}

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
	// The id a server error's answer carries (X-Request-Id, server_error.go),
	// so a caller's quoted id finds this row. Empty for other requests.
	db.Exec(`ALTER TABLE _benmore_request_log ADD COLUMN request_id TEXT DEFAULT ''`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_request_log_time ON _benmore_request_log(created_at DESC)`)
}

// requestLogMiddleware wraps an http.Handler and logs every request
// to the app's _benmore_request_log table. Static assets are skipped.
func requestLogMiddleware(app *App, next http.Handler) http.Handler {
	if app == nil || app.DB == nil {
		return next
	}
	EnsureRequestLogTable(app.DB)

	// One writer per middleware instance, tracked like the app's other
	// workers so Shutdown waits for its final flush before the DB closes. A
	// hot reload rebuilds the middleware after closing the previous
	// app.Stop, so the old writer flushes and exits while the new one runs
	// on the fresh channel.
	writer := newRequestLogWriter(app.DB, requestLogBuffer, requestLogCap)
	app.startWorker("request_log.writer", func(stop <-chan struct{}) {
		writer.run(stop, requestLogFlushInterval)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip static assets, internal endpoints, the platform scanner's own
		// probes (proven by a signed marker, never by User-Agent alone), and
		// favicon
		if isStaticPath(path) || platformScanRequest(app, r) {
			next.ServeHTTP(w, r)
			return
		}
		path = requestLogTruncate(path, requestLogPathMax)

		start := time.Now()
		rw := &statusCapture{ResponseWriter: w, status: 200}
		slot := &requestLogSlot{}
		logged := r.WithContext(context.WithValue(r.Context(), requestLogErrorKey{}, slot))
		logLine := func(status int) {
			dur := time.Since(start).Milliseconds()
			errorDetail, requestID := slot.read()

			userID := requestLogUser(app, r)

			ip := clientIP(r)
			ua := r.UserAgent()
			if len(ua) > 200 {
				ua = ua[:200]
			}

			// Hand off to the batch writer - never blocks the response; a full
			// buffer drops (and counts) the line.
			writer.enqueue(requestLogEntry{
				method: r.Method, path: path, status: status, durationMS: dur,
				ip: ip, userID: userID, ua: ua, errorDetail: errorDetail, requestID: requestID,
			})
		}
		// A handler panic unwinds past this middleware to recoverMiddleware,
		// which answers 500 and logs the stack. The request still gets its
		// log line, with the panic as its error and a request id on the
		// answer; http.ErrAbortHandler is a deliberate abort, not a fault.
		defer func() {
			if rec := recover(); rec != nil {
				if rec != http.ErrAbortHandler {
					id := recordRequestError(logged, fmt.Sprintf("panic: %v", rec))
					if !rw.wrote {
						rw.Header().Set(requestIDHeader, id)
					}
					logLine(http.StatusInternalServerError)
				}
				panic(rec)
			}
		}()
		next.ServeHTTP(rw, logged)
		logLine(rw.status)
	})
}

// requestLogErrorKey carries the request log's per-request slot (a
// *requestLogSlot) to the handler. Production hides a failure's detail from
// the user, but the request log keeps it so the agent can see what broke. It
// used to travel in an X-Benmore-Error response header that the log stripped
// only after the headers had been written, so the detail reached the client;
// the slot keeps it server-side.
type requestLogErrorKey struct{}

// requestLogSlot is what a handler hands the request log about its own
// request: the error detail and the request id its error answer carried
// (server_error.go). Locked because a handler may record from a goroutine
// other than the one that serves the request.
type requestLogSlot struct {
	mu        sync.Mutex
	err       string
	requestID string
}

func (s *requestLogSlot) read() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err, s.requestID
}

func requestLogSlotFor(r *http.Request) *requestLogSlot {
	slot, _ := r.Context().Value(requestLogErrorKey{}).(*requestLogSlot)
	return slot
}

// setRequestLogError records detail as the error of r's request log line. A
// no-op for a request the log skips. Runtime handlers answering a server
// error go through serverError (server_error.go), which bounds and redacts
// the detail before it lands here.
func setRequestLogError(r *http.Request, detail string) {
	if slot := requestLogSlotFor(r); slot != nil {
		slot.mu.Lock()
		slot.err = detail
		slot.mu.Unlock()
	}
}

// requestLogUser names the request's user for the log line. It is the one
// place the request log reads the session (best-effort; "" when anonymous),
// so a per-request session cache can be wired in here alone.
func requestLogUser(app *App, r *http.Request) string {
	sess := getSession(app, r)
	if sess == nil {
		return ""
	}
	if sess.Email != "" {
		return sess.Email
	}
	return fmt.Sprintf("user:%d", sess.UserID)
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
