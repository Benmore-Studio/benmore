//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// useHealthCgroup points the health memory reader at root ("" = no cgroup)
// for the test.
func useHealthCgroup(t *testing.T, root string) {
	t.Helper()
	prev := healthCgroupFS
	healthCgroupFS = func() (cgroupFS, bool) { return cgroupFS{root: root}, root != "" }
	t.Cleanup(func() { healthCgroupFS = prev })
}

func shortenHealthProbe(t *testing.T, timeout time.Duration) {
	t.Helper()
	prev := healthDBProbeTimeout
	healthDBProbeTimeout = timeout
	t.Cleanup(func() { healthDBProbeTimeout = prev })
}

// expireHealthReadiness ends the app's cache window so the next read
// measures again.
func expireHealthReadiness(app *App) {
	app.healthReadiness.mu.Lock()
	app.healthReadiness.last.at = time.Time{}
	app.healthReadiness.mu.Unlock()
}

func testHealthGet(t *testing.T, app *App, target, sess string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if sess != "" {
		req = authedRequest(http.MethodGet, target, "", sess)
	}
	rec := httptest.NewRecorder()
	healthHandler(app).ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s: Cache-Control %q", target, rec.Header().Get("Cache-Control"))
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %d %s: %v", target, rec.Code, rec.Body.String(), err)
	}
	return rec.Code, body
}

func healthBodyKeys(body map[string]any) string {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestParseMemoryPressure(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		name, in   string
		some, full *float64
	}{
		{"idle", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", f(0), f(0)},
		{"throttled", "some avg10=91.31 avg60=88.02 avg300=70.10 total=123456789\nfull avg10=63.50 avg60=60.00 avg300=41.25 total=98765432\n", f(91.31), f(63.5)},
		{"no full line", "some avg10=1.50 avg60=0.40 avg300=0.10 total=10\n", f(1.5), nil},
		{"malformed values", "some avg10=lots avg60=0.00\nfull avg10=-3 avg60=0.00\n", nil, nil},
		{"out of range", "full avg10=100.01 avg60=0.00\n", nil, nil},
		{"other lines", "partial avg10=50.00\n\n", nil, nil},
		{"empty", "", nil, nil},
	}
	same := func(a, b *float64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	for _, tc := range cases {
		got := parseMemoryPressure([]byte(tc.in))
		if !same(got.some, tc.some) || !same(got.full, tc.full) {
			t.Errorf("%s: some=%v full=%v", tc.name, got.some, got.full)
		}
	}
}

// The probe must be a plain read: under WAL it succeeds while another
// connection holds the write lock. A probe that began a transaction would
// run BEGIN IMMEDIATE (the app DSN's _txlock=immediate) and wait on the busy
// timeout, past its deadline.
func TestHealthDBProbeIsAPlainReadAWriterDoesNotBlock(t *testing.T) {
	app, _ := auditApp(t)
	useHealthCgroup(t, "")
	ctx := context.Background()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO notes (user_id, title) VALUES (1, 'held by a writer')`); err != nil {
		t.Fatal(err)
	}

	// Control: the write lock really is held.
	other, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=0&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if otx, err := other.BeginTx(ctx, nil); err == nil {
		otx.Rollback()
		t.Fatal("a second BEGIN IMMEDIATE succeeded: the test's writer holds no write lock")
	} else if !strings.Contains(err.Error(), "locked") && !strings.Contains(err.Error(), "busy") {
		t.Fatalf("second writer: %v", err)
	}

	if p := probeHealthDB(app.DB); p.Status != healthProbeOK && p.Status != healthProbeSlow {
		t.Fatalf("probe under a held write lock: %+v", p)
	}
	code, body := testHealthGet(t, app, "/health?deep=1", "")
	if code != http.StatusOK || body["ready"] != true || body["status"] != "healthy" {
		t.Fatalf("deep health under a held write lock: %d %v", code, body)
	}
}

func TestHealthDeepAnswers503WhenTheDatabaseStalls(t *testing.T) {
	app, _ := auditApp(t)
	useHealthCgroup(t, "")
	shortenHealthProbe(t, 100*time.Millisecond)
	var measured atomic.Int32
	app.healthReadiness.measure = func(db *sql.DB) healthReadiness {
		measured.Add(1)
		return measureHealthReadiness(db)
	}
	// Every pool connection busy, as when stuck requests hold them all.
	app.DB.SetMaxOpenConns(1)
	held, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	code, body := testHealthGet(t, app, "/health?deep=1", "")
	if took := time.Since(start); took > healthDeepBudget {
		t.Fatalf("deep check took %s with a stalled pool", took)
	}
	if code != http.StatusServiceUnavailable || body["reason"] != "database_timeout" || body["ready"] != false || body["status"] != "unhealthy" {
		t.Fatalf("stalled pool: %d %v", code, body)
	}
	if healthBodyKeys(body) != "instance_id,ready,reason,reload_generation,status,version" {
		t.Fatalf("not-ready body keys %s", healthBodyKeys(body))
	}
	// Inside the window the result is reused: no second probe.
	if code, _ := testHealthGet(t, app, "/health?deep=1", ""); code != http.StatusServiceUnavailable || measured.Load() != 1 {
		t.Fatalf("second deep check: %d after %d probes", code, measured.Load())
	}

	held.Close()
	expireHealthReadiness(app)
	if code, body := testHealthGet(t, app, "/health?deep=1", ""); code != http.StatusOK || body["ready"] != true {
		t.Fatalf("released pool: %d %v", code, body)
	}

	// A failing (not slow) database is database_error.
	broken, _ := auditApp(t)
	broken.DB.Close()
	if code, body := testHealthGet(t, broken, "/health?deep=1", ""); code != http.StatusServiceUnavailable || body["reason"] != "database_error" {
		t.Fatalf("closed database: %d %v", code, body)
	}
}

func TestHealthReportsMemoryAndDeepAnswers503UnderPressure(t *testing.T) {
	app, _ := auditApp(t)
	root := t.TempDir()
	useHealthCgroup(t, root)
	writeProcSelfCgroup(t, root, "0::"+testDevUnitCgroup+"\n")
	writeCgroupFiles(t, root, testDevUnitCgroup, map[string]string{
		"memory.current":  "398458880\n", // 380 MiB
		"memory.high":     "402653184\n", // 384 MiB
		"memory.max":      "536870912\n",
		"memory.pressure": "some avg10=88.10 avg60=80.00 avg300=60.00 total=1\nfull avg10=41.70 avg60=35.00 avg300=20.00 total=1\n",
	})

	code, body := testHealthGet(t, app, "/health?deep=1", "")
	if code != http.StatusServiceUnavailable || body["reason"] != "memory_pressure" {
		t.Fatalf("deep check under pressure: %d %v", code, body)
	}

	// Plain /health keeps its contract: the restart verification and the
	// release tooling wait for 200 "healthy" with exactly these fields.
	code, body = testHealthGet(t, app, "/health", "")
	if code != http.StatusOK || body["status"] != "healthy" || healthBodyKeys(body) != "instance_id,reload_generation,status,version" {
		t.Fatalf("plain health under pressure: %d %v", code, body)
	}

	sess := seedAdminSession(t, app)
	code, body = testHealthGet(t, app, "/health", sess)
	checks, _ := body["checks"].(map[string]any)
	memory, _ := checks["memory"].(map[string]any)
	probe, _ := checks["db_probe"].(map[string]any)
	if code != http.StatusOK || body["status"] != "healthy" || memory == nil || probe == nil {
		t.Fatalf("admin health: %d %v", code, body)
	}
	if memory["status"] != "pressure" || memory["current_bytes"] != float64(398458880) || memory["limit_bytes"] != float64(402653184) ||
		memory["limit_file"] != "memory.high" || memory["used_percent"] != 99.0 || memory["pressure_full_avg10"] != 41.7 || memory["pressure_some_avg10"] != 88.1 {
		t.Fatalf("checks.memory %v", memory)
	}
	if probe["status"] != healthProbeOK || probe["latency"] == "" {
		t.Fatalf("checks.db_probe %v", probe)
	}

	writeCgroupFiles(t, root, testDevUnitCgroup, map[string]string{
		"memory.pressure": "some avg10=2.00 avg60=1.00 avg300=0.50 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n",
	})
	expireHealthReadiness(app)
	if code, body := testHealthGet(t, app, "/health?deep=1", ""); code != http.StatusOK || body["ready"] != true || body["checks"] != nil {
		t.Fatalf("deep check after the pressure passed: %d %v", code, body)
	}
}

func TestHealthReadinessCacheMeasuresOncePerWindow(t *testing.T) {
	var c healthReadinessCache
	var calls atomic.Int32
	release := make(chan struct{})
	c.measure = func(*sql.DB) healthReadiness {
		calls.Add(1)
		<-release
		return healthReadiness{DB: healthDBProbe{Status: healthProbeOK}}
	}
	var wg sync.WaitGroup
	results := make(chan healthReadiness, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- c.read(context.Background(), nil)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	close(results)
	for r := range results {
		if r.DB.Status != healthProbeOK {
			t.Fatalf("a caller got %+v", r)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d concurrent callers took %d measurements, want 1", 8, n)
	}
	c.read(context.Background(), nil)
	if n := calls.Load(); n != 1 {
		t.Fatalf("a read inside the window measured again (%d)", n)
	}
	c.mu.Lock()
	c.last.at = time.Now().Add(-healthReadinessTTL)
	c.mu.Unlock()
	c.read(context.Background(), nil)
	if n := calls.Load(); n != 2 {
		t.Fatalf("a read after the window did not measure (%d)", n)
	}
}

// A measurement stuck where the deadline cannot reach (SQLite's busy
// handler) must not hold a deep check past its budget, nor start a second
// measurement while it runs.
func TestHealthReadinessCallerStopsWaitingAtItsDeadline(t *testing.T) {
	var c healthReadinessCache
	var calls atomic.Int32
	release := make(chan struct{})
	c.measure = func(*sql.DB) healthReadiness {
		calls.Add(1)
		<-release
		return healthReadiness{DB: healthDBProbe{Status: healthProbeOK}}
	}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		got := c.read(ctx, nil)
		cancel()
		if got.DB.Status != healthProbeTimeout || got.notReadyReason() != "database_timeout" {
			t.Fatalf("caller past its deadline got %+v", got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d measurements while one was stuck, want 1", n)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.read(context.Background(), nil); got.DB.Status == healthProbeOK {
			if n := calls.Load(); n != 1 {
				t.Fatalf("%d measurements, want the finished one reused", n)
			}
			return
		}
	}
	t.Fatal("the finished measurement was never stored")
}

func TestHealthMemoryAbsentWithoutACgroup(t *testing.T) {
	useHealthCgroup(t, "")
	if m := readHealthMemory(); m != nil {
		t.Fatalf("memory without a cgroup: %+v", m)
	}
	root := t.TempDir()
	useHealthCgroup(t, root)
	writeProcSelfCgroup(t, root, "0::/\n") // a host's root cgroup: no files
	if m := readHealthMemory(); m != nil {
		t.Fatalf("memory on a root cgroup without files: %+v", m)
	}
}
