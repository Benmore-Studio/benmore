//go:build !cli

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitErrorGroupCount(t *testing.T, app *App, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := app.DB.QueryRow("SELECT COALESCE(SUM(count),0) FROM _benmore_error_groups").Scan(&n); err == nil && n == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("reporter did not persist %d occurrences", want)
}

func reportingPanicHandler(http.ResponseWriter, *http.Request) { panic("test crash") }

func TestErrorReportRequestFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		handler     http.HandlerFunc
		level, kind string
		count       int
	}{
		{"panic", reportingPanicHandler, "fatal", "server", 1},
		{"raw", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusInternalServerError) }, "error", "http5xx", 1},
		{"busy", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "busy", http.StatusServiceUnavailable) }, "", "", 0},
		{"full", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "full", http.StatusInsufficientStorage) }, "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := errorGroupsFixture(t)
			t.Cleanup(func() { close(app.Stop); app.workerWG.Wait() })
			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/test/{id}", tc.handler)
			h := recoverMiddleware(requestLogMiddleware(app, mux))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/api/test/123?secret=no", nil))
			waitErrorGroupCount(t, app, tc.count)
			if tc.count == 0 {
				return
			}
			var level, kind, sample, id string
			if err := app.DB.QueryRow("SELECT level,kind,sample,last_request_id FROM _benmore_error_groups").Scan(&level, &kind, &sample, &id); err != nil {
				t.Fatal(err)
			}
			if level != tc.level || kind != tc.kind {
				t.Fatalf("level=%s kind=%s", level, kind)
			}
			if strings.Contains(sample, "secret=no") {
				t.Fatal("query string escaped into sample")
			}
			if tc.name == "panic" {
				if id == "" || id != w.Header().Get(requestIDHeader) {
					t.Fatalf("correlation id=%s header=%s", id, w.Header().Get(requestIDHeader))
				}
				if !strings.Contains(sample, "reportingPanicHandler") {
					t.Fatalf("panicking frame missing: %s", sample)
				}
			}
		})
	}
}

func TestErrorReportFunnelAndWorkerPanic(t *testing.T) {
	app := errorGroupsFixture(t)
	t.Cleanup(func() { close(app.Stop); app.workerWG.Wait() })
	h := requestLogMiddleware(app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverErrorJSON(w, r, app, "read", errors.New("upstream bearer abcdefghijkl failed for jane@example.com"), "Failed")
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/read", nil))
	waitErrorGroupCount(t, app, 1)
	var sample string
	if err := app.DB.QueryRow("SELECT sample FROM _benmore_error_groups").Scan(&sample); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sample, "abcdefghijkl") || strings.Contains(sample, "jane@example.com") {
		t.Fatalf("unscrubbed: %s", sample)
	}
	if !strings.Contains(sample, w.Header().Get(requestIDHeader)) {
		t.Fatal("request id lost")
	}
	<-app.startWorker("failing.worker", func(<-chan struct{}) { panic("worker crash") })
	waitErrorGroupCount(t, app, 2)
	var n int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_error_groups WHERE level='fatal' AND sample LIKE '%failing.worker%'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("worker count=%d err=%v", n, err)
	}
}

func TestErrorReportSentryRuntimeAndReservedTags(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	ev := scrubErrorEvent(app, errorEvent{Source: "server", Kind: "server", Message: "failure", RequestID: "0123456789abcdef0123456789abcdef", Tags: map[string]string{"source": "other", "request_id": "forged", "group_key": "forged", "custom": "ok"}})
	event := errorSentryEvent(app, ev, time.Now())
	tags := event["tags"].(map[string]string)
	if tags["source"] != "server" || tags["request_id"] != ev.RequestID || len(tags["group_key"]) != 64 || tags["custom"] != "ok" {
		t.Fatalf("reserved tags: %#v", tags)
	}
	contexts, ok := event["contexts"].(map[string]any)
	if !ok || contexts["runtime"].(map[string]string)["name"] != "go" || contexts["os"].(map[string]string)["name"] == "" {
		t.Fatalf("missing runtime context: %#v", contexts)
	}
}

type wrappedReportingError struct{ error }

func (e *wrappedReportingError) Unwrap() error { return e.error }

func TestErrorReportReloadRenewsWorker(t *testing.T) {
	app := errorGroupsFixture(t)
	t.Cleanup(func() { stopReportingTest(app) })
	first := app.getErrorReporter()
	reportError(app, errorEvent{Message: "reload failure", Source: "server", Kind: "server"})
	flushReportingTest(t, app)
	close(app.Stop)
	<-first.done
	app.mu.Lock()
	app.Stop = make(chan struct{})
	app.mu.Unlock()
	second := app.getErrorReporter()
	if first == second {
		t.Fatal("reload reused stopped reporter")
	}
	reportError(app, errorEvent{Message: "reload failure", Source: "server", Kind: "server"})
	flushReportingTest(t, app)
	// Without a configured sink, neither occurrence consumes a delivery claim.
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE count=2 AND unforwarded=2", 1)
}

func TestErrorReportCompileDeduplicatesContent(t *testing.T) {
	app := errorGroupsFixture(t)
	t.Cleanup(func() { stopReportingTest(app) })
	root := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "broken.tsx")
	if err := os.WriteFile(file, []byte("export const broken = ;"), 0644); err != nil {
		t.Fatal(err)
	}
	serve := func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/static/broken.js", nil)
		if !serveTSXIfPresent(w, r, app, "broken.js") || !strings.Contains(w.Body.String(), "throw new Error") {
			t.Fatalf("missing throwing module: %s", w.Body.String())
		}
		flushReportingTest(t, app)
	}
	serve()
	serve()
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='compile' AND count=1", 1)
	// A changed input with the same diagnostic is a new failing content version.
	if err := os.WriteFile(file, []byte("export const broken = ; // changed"), 0644); err != nil {
		t.Fatal(err)
	}
	src := resolveTSXSource(app.Dir, "broken.js")
	tsxCacheMu.Lock()
	delete(tsxCache, src)
	tsxCacheMu.Unlock()
	serve()
	assertCount(t, app, "SELECT count(*) FROM _benmore_error_groups WHERE kind='compile' AND count=2", 1)
}

// Browser reports may fill only half the queue, so a beacon flood cannot
// crowd out server failures (review errors-a F4).
func TestErrorQueueKeepsRoomForServerEvents(t *testing.T) {
	app := errorGroupsFixture(t)
	defer close(app.Stop)
	r := &errorReporter{app: app, queue: make(chan errorEvent, 8), done: make(chan struct{})}
	g := &errorReporterGeneration{stop: app.Stop, reporter: r}
	g.once.Do(func() {})
	app.errorReporter = g
	for i := 0; i < 20; i++ {
		reportError(app, errorEvent{clientBody: &clientErrorBody{Message: "flood"}})
	}
	if len(r.queue) != 4 {
		t.Fatalf("browser reports queued %d of 8 slots", len(r.queue))
	}
	for i := 0; i < 4; i++ {
		reportError(app, errorEvent{Source: "server", Message: "real failure"})
	}
	if len(r.queue) != 8 {
		t.Fatalf("server events were refused: %d queued", len(r.queue))
	}
}
