//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Per-address budgets for anonymous callers were keyed on values a client
// can change for free. The PDF route and lock acquisition used RemoteAddr
// whole, source port included, so every new connection got a fresh budget
// (and behind the router, where the peer is loopback, the client's address
// was not in the key at all). The recording beacon and the markdown service
// keyed a single IPv6 address, which a client holding a /64 rotates on every
// request. All key the resolved client address by its rate bucket now.
func TestAnonymousBudgetsKeyTheClientRateBucket(t *testing.T) {
	// One host opening a new connection for every request.
	reconnecting := func(i int) string { return fmt.Sprintf("198.51.100.7:%d", 40000+i) }
	// One IPv6 subscriber walking through its own /64.
	rotating := func(i int) string { return fmt.Sprintf("[2001:db8:5:9::%x]:443", i+1) }
	// A different subscriber: must not be caught in the first one's budget.
	const neighbour = "[2001:db8:5:a::1]:443"

	// exhaust sends budget requests from addr(i), then one more, and returns
	// the status of that last one and of a neighbour's first request.
	exhaust := func(h http.Handler, method, path string, budget int, addr func(int) string) (last, other int) {
		send := func(remote string) int {
			r := httptest.NewRequest(method, path, strings.NewReader("{}"))
			r.RemoteAddr = remote
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
		for i := 0; i <= budget; i++ {
			last = send(addr(i))
		}
		return last, send(neighbour)
	}
	check := func(t *testing.T, what string, last, other int) {
		t.Helper()
		if last != http.StatusTooManyRequests {
			t.Errorf("%s: the request past the budget answered %d, want 429", what, last)
		}
		if other == http.StatusTooManyRequests {
			t.Errorf("%s: another client was refused on the first client's budget", what)
		}
	}
	newApp := func(t *testing.T) *App {
		dir := t.TempDir()
		db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)")
		EnsureLocksTable(db)
		return &App{Dir: dir, DB: db, Stop: make(chan struct{}), DevMode: true, Pages: map[string]*Page{}}
	}

	for name, addr := range map[string]func(int) string{"a new connection per request": reconnecting, "a new address in one /64 per request": rotating} {
		t.Run("pdf/"+name, func(t *testing.T) {
			previous := pdfLimiter
			pdfLimiter = NewRateLimiter(3, time.Minute)
			t.Cleanup(func() { pdfLimiter = previous })
			mux := http.NewServeMux()
			RegisterPDFRoutes(mux, newApp(t))
			last, other := exhaust(mux, http.MethodGet, "/pdf/missing", 3, addr)
			check(t, "GET /pdf", last, other)
		})
		t.Run("lock/"+name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerLockTables(mux, newApp(t), []string{"notes"})
			last, other := exhaust(mux, http.MethodPost, "/api/notes/1/lock", 30, addr)
			check(t, "POST /api/notes/1/lock", last, other)
		})
	}
	t.Run("recording beacon", func(t *testing.T) {
		mux := http.NewServeMux()
		RegisterRecordingRoutes(mux, newApp(t))
		last, other := exhaust(mux, http.MethodPost, "/_internal/recording", recordingBeaconsPerMinute, rotating)
		check(t, "POST /_internal/recording", last, other)
	})
	t.Run("markdown", func(t *testing.T) {
		rl := NewRateLimiter(3, time.Minute)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !markdownRateLimited(w, r, rl, "single") {
				w.WriteHeader(http.StatusOK)
			}
		})
		last, other := exhaust(h, http.MethodPost, "/_internal/markdown", 3, rotating)
		check(t, "POST /_internal/markdown", last, other)
	})
}
