//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func requestLogTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db")+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	EnsureRequestLogTable(db)
	return db
}

func rlCountRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A burst of lines is written by one goroutine in batches, and everything
// queued before stop is flushed on the way out.
func TestRequestLogWriterBatchesAndFlushesOnStop(t *testing.T) {
	db := requestLogTestDB(t)
	w := newRequestLogWriter(db, 2048, 100000)
	for i := 0; i < 1200; i++ {
		w.enqueue(requestLogEntry{method: "GET", path: "/p", status: 200, durationMS: 1})
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { w.run(stop, time.Hour); close(done) }() // ticker never fires: batches come from size + stop
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not exit on stop")
	}
	if got := rlCountRows(t, db, "_benmore_request_log"); got != 1200 {
		t.Fatalf("rows = %d, want 1200", got)
	}
	if w.dropped.Load() != 0 {
		t.Fatalf("dropped %d", w.dropped.Load())
	}
}

func TestRequestLogWriterDropsWhenBufferFull(t *testing.T) {
	db := requestLogTestDB(t)
	w := newRequestLogWriter(db, 3, 100)
	for i := 0; i < 10; i++ {
		w.enqueue(requestLogEntry{method: "GET", path: "/p", status: 200})
	}
	if got := w.dropped.Load(); got != 7 {
		t.Fatalf("dropped = %d, want 7 (buffer of 3, writer not draining)", got)
	}
}

// The ring prune keeps exactly the newest rows and is a no-op below the cap.
func TestPruneRingTableKeepsNewest(t *testing.T) {
	db := requestLogTestDB(t)
	for i := 0; i < 30; i++ {
		if _, err := db.Exec(`INSERT INTO _benmore_request_log (method, path, status, duration_ms) VALUES ('GET', '/', 200, ?)`, i); err != nil {
			t.Fatal(err)
		}
	}
	pruneRingTable(db, "_benmore_request_log", 50)
	if got := rlCountRows(t, db, "_benmore_request_log"); got != 30 {
		t.Fatalf("prune below cap deleted rows: %d left", got)
	}
	pruneRingTable(db, "_benmore_request_log", 10)
	var n, minID, maxID int
	if err := db.QueryRow(`SELECT COUNT(*), MIN(id), MAX(id) FROM _benmore_request_log`).Scan(&n, &minID, &maxID); err != nil {
		t.Fatal(err)
	}
	if n != 10 || minID != 21 || maxID != 30 {
		t.Fatalf("after prune: n=%d ids %d..%d, want 10 rows 21..30", n, minID, maxID)
	}
}

func TestRequestLogWriterPrunesToCap(t *testing.T) {
	db := requestLogTestDB(t)
	w := newRequestLogWriter(db, 4096, 150)
	for i := 0; i < 1000; i++ {
		w.enqueue(requestLogEntry{method: "GET", path: "/p", status: 200})
	}
	stop := make(chan struct{})
	close(stop)
	w.run(stop, time.Hour)
	if got := rlCountRows(t, db, "_benmore_request_log"); got != 150 {
		t.Fatalf("rows = %d, want the 150-row cap", got)
	}
}

// End to end through the middleware: the request is logged once the app's
// workers stop, without a goroutine per request.
func TestRequestLogMiddlewareWritesThroughWriter(t *testing.T) {
	db := requestLogTestDB(t)
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	h := requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setRequestLogError(r, "boom detail")
		w.WriteHeader(http.StatusTeapot)
	}))
	for i := 0; i < 5; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/things", nil))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/static/app.js", nil)) // skipped
	close(app.Stop)
	app.workerWG.Wait()
	var n, status int
	var errDetail string
	if err := db.QueryRow(`SELECT COUNT(*), MAX(status), MAX(error) FROM _benmore_request_log WHERE path = '/api/things' AND method = 'POST'`).Scan(&n, &status, &errDetail); err != nil {
		t.Fatal(err)
	}
	if n != 5 || status != http.StatusTeapot || errDetail != "boom detail" {
		t.Fatalf("logged n=%d status=%d error=%q", n, status, errDetail)
	}
	if got := rlCountRows(t, db, "_benmore_request_log"); got != 5 {
		t.Fatalf("static path logged: %d rows", got)
	}
}

// The logged path is visitor-chosen and is kept for every buffered line and
// every ring row in the app's storage-capped database, so it is capped
// (rune-safe) instead of stored at the full header-limited length.
func TestRequestLogCapsVisitorPathLength(t *testing.T) {
	db := requestLogTestDB(t)
	app := &App{Dir: t.TempDir(), DB: db, Stop: make(chan struct{})}
	h := requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	long := "/x" + strings.Repeat("é", 30000) // 60 KB, two-byte runes
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Path = long
	h.ServeHTTP(httptest.NewRecorder(), r)
	close(app.Stop)
	app.workerWG.Wait()
	var maxLen int
	var stored string
	if err := db.QueryRow(`SELECT MAX(length(CAST(path AS BLOB))) FROM _benmore_request_log`).Scan(&maxLen); err != nil {
		t.Fatal(err)
	}
	if maxLen > requestLogPathMax {
		t.Fatalf("logged path is %d bytes, want at most %d", maxLen, requestLogPathMax)
	}
	if err := db.QueryRow(`SELECT path FROM _benmore_request_log WHERE path LIKE '/x%'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(stored) || !strings.HasPrefix(long, stored) {
		t.Fatalf("truncated path is not a rune-safe prefix (len %d)", len(stored))
	}
}
