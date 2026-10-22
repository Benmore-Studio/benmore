//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hotpathDB(t *testing.T, dsnSuffix string) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL"+dsnSuffix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

// --- query deadline -------------------------------------------------------

func withTestQueryDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	queryDeadline() // resolve the Once first
	prev := queryDeadlineValue
	queryDeadlineValue = d
	t.Cleanup(func() { queryDeadlineValue = prev })
}

const runawayQuery = `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c`

func TestQueryRowsInterruptsRunawayStatement(t *testing.T) {
	db, _ := hotpathDB(t, "")
	withTestQueryDeadline(t, 150*time.Millisecond)
	start := time.Now()
	_, err := QueryRows(db, runawayQuery)
	if err == nil {
		t.Fatal("unbounded statement completed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("statement ran %s past a 150ms deadline", elapsed)
	}
	// The pool connection is usable afterwards.
	if rows, err := QueryRows(db, "SELECT 1 AS one"); err != nil || len(rows) != 1 {
		t.Fatalf("pool unusable after interrupt: %v", err)
	}
}

// An endless row stream is cut off at the deadline: every step after the first
// row still sees it (firstStepContext).
func TestQueryRowsStopsEndlessRowStream(t *testing.T) {
	db, _ := hotpathDB(t, "")
	withTestQueryDeadline(t, 100*time.Millisecond)
	start := time.Now()
	_, err := QueryRows(db, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c`)
	if err == nil {
		t.Fatal("endless row stream completed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("row stream ran %s past a 100ms deadline", elapsed)
	}
}

// The deadline also interrupts a step that runs long AFTER the first row has
// arrived: the first match comes at once, the second would take billions of
// loop steps. Up to go-sqlite3 v1.14.50 such a step ran to its end (the scan
// stepped synchronously after the first row).
func TestQueryRowsInterruptsSlowStepAfterFirstRow(t *testing.T) {
	db, _ := hotpathDB(t, "")
	withTestQueryDeadline(t, 150*time.Millisecond)
	start := time.Now()
	rows, err := QueryRows(db, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c WHERE x = 1 OR x = 30000000000`)
	if err == nil {
		t.Fatalf("statement completed with %d rows", len(rows))
	}
	if !(errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "interrupt")) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("second step ran %s past a 150ms deadline", elapsed)
	}
	// The pool connection is usable afterwards.
	if rows, err := QueryRows(db, "SELECT 1 AS one"); err != nil || len(rows) != 1 {
		t.Fatalf("pool unusable after interrupt: %v", err)
	}
}

func TestQueryRowsContextHonorsCallerCancel(t *testing.T) {
	db, _ := hotpathDB(t, "")
	withTestQueryDeadline(t, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := QueryRowsContext(ctx, db, runawayQuery)
	if err == nil || !(errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "interrupt")) {
		t.Fatalf("err = %v, want a cancellation", err)
	}
}

func TestQueryDeadlineDisabledAndParsing(t *testing.T) {
	cases := map[string]time.Duration{"": 10 * time.Second, "30": 30 * time.Second, "2m": 2 * time.Minute, "0": 0}
	for raw, want := range cases {
		if got, ok := parseQueryDeadline(raw); !ok || got != want {
			t.Errorf("parseQueryDeadline(%q) = %s,%v want %s", raw, got, ok, want)
		}
	}
	if _, ok := parseQueryDeadline("soon"); ok {
		t.Error("garbage accepted")
	}
	withTestQueryDeadline(t, 0)
	ctx, cancel := withQueryDeadline(context.Background())
	defer cancel()
	if _, has := ctx.Deadline(); has {
		t.Fatal("disabled deadline still set one")
	}
}

// Transactions are not given the default deadline (interrupting a write in
// an explicit transaction would roll the whole transaction back).
func TestQueryRowsInsideTransactionHasNoDefaultDeadline(t *testing.T) {
	db, _ := hotpathDB(t, "")
	withTestQueryDeadline(t, time.Nanosecond)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if rows, err := queryRowsWith(tx, "SELECT 1 AS one"); err != nil || len(rows) != 1 {
		t.Fatalf("tx query hit the default deadline: %v", err)
	}
}

// --- scanRows buffer reuse --------------------------------------------------

func TestScanRowsReusedBufferKeepsRowsIndependent(t *testing.T) {
	db, _ := hotpathDB(t, "")
	crudScopeMustExec(t, db, `CREATE TABLE t (id INTEGER PRIMARY KEY, tag TEXT, blob BLOB, done BOOLEAN)`)
	crudScopeMustExec(t, db, `INSERT INTO t VALUES (1, 'first', x'0102', 1), (2, NULL, NULL, 0), (3, 'third', x'03', NULL)`)
	rows, err := QueryRows(db, `SELECT * FROM t ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0]["tag"] != "first" || rows[1]["tag"] != nil || rows[2]["tag"] != "third" {
		t.Fatalf("tags leaked across rows: %v %v %v", rows[0]["tag"], rows[1]["tag"], rows[2]["tag"])
	}
	if rows[0]["blob"] != "\x01\x02" || rows[1]["blob"] != nil || rows[2]["blob"] != "\x03" {
		t.Fatalf("blobs leaked across rows: %q %v %q", rows[0]["blob"], rows[1]["blob"], rows[2]["blob"])
	}
	if rows[0]["done"] != true || rows[1]["done"] != false || rows[2]["done"] != nil {
		t.Fatalf("bool coercion: %v %v %v", rows[0]["done"], rows[1]["done"], rows[2]["done"])
	}
}

// --- pool sizing -------------------------------------------------------------

func TestAppDBPoolLimits(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	hosted := resolveAppDBPoolLimits(true, env(nil))
	if hosted.maxOpen != 10 || hosted.maxIdle != 2 || hosted.idleTimeout != 2*time.Minute || hosted.maxLifetime != 30*time.Minute || hosted.cacheKiB != 16000 {
		t.Fatalf("hosted defaults = %+v", hosted)
	}
	self := resolveAppDBPoolLimits(false, env(nil))
	if self.maxOpen != 25 || self.maxIdle != 10 || self.idleTimeout != 0 || self.maxLifetime != 30*time.Minute || self.cacheKiB != 64000 {
		t.Fatalf("self-hosted defaults changed: %+v", self)
	}
	over := resolveAppDBPoolLimits(true, env(map[string]string{
		"BENMORE_DB_MAX_OPEN": "4", "BENMORE_DB_MAX_IDLE": "9", "BENMORE_DB_IDLE_TIMEOUT": "30s", "BENMORE_DB_CACHE_KIB": "8000", "BENMORE_DB_MAX_LIFETIME": "0",
	}))
	if over.maxOpen != 4 || over.maxIdle != 4 || over.idleTimeout != 30*time.Second || over.maxLifetime != 0 || over.cacheKiB != 8000 {
		t.Fatalf("overrides = %+v (idle must not exceed open)", over)
	}
	bad := resolveAppDBPoolLimits(true, env(map[string]string{"BENMORE_DB_MAX_OPEN": "-3", "BENMORE_DB_CACHE_KIB": "lots", "BENMORE_DB_IDLE_TIMEOUT": "x", "BENMORE_DB_MAX_LIFETIME": "soon"}))
	if bad != hosted {
		t.Fatalf("malformed overrides applied: %+v", bad)
	}
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	t.Setenv("BENMORE_DB_CACHE_KIB", "")
	if dsn := sqliteAppDSN("/x/data.db", t.TempDir()); !strings.Contains(dsn, "_cache_size=-16000&") {
		t.Fatalf("hosted DSN cache: %s", dsn)
	}
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	if dsn := sqliteAppDSN("/x/data.db", t.TempDir()); !strings.Contains(dsn, "_cache_size=-64000&") {
		t.Fatalf("self-hosted DSN cache: %s", dsn)
	}
}

// A busy pool used to keep its connections forever, and with them every
// authorizer callback registered on them. The pool now recycles a connection
// after its lifetime even while it is in steady use.
func TestAppDBPoolRecyclesBusyConnections(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	l := resolveAppDBPoolLimits(true, func(string) string { return "" })
	l.maxLifetime = 50 * time.Millisecond
	applyAppDBPoolLimits(db, l)
	deadline := time.Now().Add(5 * time.Second)
	for db.Stats().MaxLifetimeClosed == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no connection was recycled while the pool stayed busy: %+v", db.Stats())
		}
		if _, err := db.Exec("SELECT 1"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- column metadata cache -------------------------------------------------

// A column added by ANOTHER connection (another process in production) is
// visible on the next list request: the cache is keyed on the schema cookie.
func TestCachedTableColumnsSeesOutOfBandDDL(t *testing.T) {
	db, path := hotpathDB(t, "")
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
	first, err := cachedTableColumns(db, "notes")
	if err != nil || len(first) != 2 {
		t.Fatalf("cols = %v %v", first, err)
	}
	other, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	crudScopeMustExec(t, other, `ALTER TABLE notes ADD COLUMN priority INTEGER`)
	cols, err := cachedTableColumns(db, "notes")
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 3 || cols[2].Name != "priority" {
		t.Fatalf("stale columns after DDL: %v", cols)
	}
	// Callers get a copy: mutating it does not poison the cache.
	cols[0].Name = "mutated"
	again, _ := cachedTableColumns(db, "notes")
	if again[0].Name != "id" {
		t.Fatal("cache returned a shared slice")
	}
}

// --- locks cleanup -----------------------------------------------------------

// With nothing expired the 10-second sweep must not queue for the write lock:
// it returns promptly even while another connection holds it.
func TestCleanupExpiredLocksSkipsWriteLockWhenNothingExpired(t *testing.T) {
	db, path := hotpathDB(t, "&_busy_timeout=3000")
	EnsureLocksTable(db)
	crudScopeMustExec(t, db, `INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('notes', '1', 1, 'a@x', datetime('now', '+1 hour'))`)

	writer, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	conn, err := writer.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	cleanupExpiredLocks(db)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("no-op cleanup waited %s on the write lock", elapsed)
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}

	// Expired rows are still removed, live ones kept.
	crudScopeMustExec(t, db, `INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('notes', '2', 1, 'a@x', datetime('now', '-1 minute'))`)
	cleanupExpiredLocks(db)
	var left string
	if err := db.QueryRow(`SELECT group_concat(row_id) FROM _benmore_locks`).Scan(&left); err != nil || left != "1" {
		t.Fatalf("locks left = %q (%v), want only the live lock", left, err)
	}
}

// --- deep offset cap ---------------------------------------------------------

func TestDeepOffsetPaginationIsRefused(t *testing.T) {
	req := func(q string) *http.Request { return httptest.NewRequest(http.MethodGet, "/api/notes?"+q, nil) }
	if msg := apiOffsetTooDeepError(req("page=2001&per_page=50")); msg != "" {
		t.Fatalf("offset of exactly the cap refused: %s", msg)
	}
	if msg := apiOffsetTooDeepError(req("page=2002&per_page=50")); !strings.Contains(msg, "?cursor=") {
		t.Fatalf("deep offset not refused with a cursor pointer: %q", msg)
	}
	if msg := apiOffsetTooDeepError(req("page=99999999999&per_page=500")); msg == "" {
		t.Fatal("overflowing page accepted")
	}
	if msg := apiOffsetTooDeepError(req("per_page=500")); msg != "" {
		t.Fatal("request without ?page= refused")
	}

	// Through the list endpoint: a 400 with guidance, not a table walk.
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"read": "everyone"}}},
		Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title", Type: "TEXT"}}}},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?page=5000&per_page=500", bob, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "cursor") {
		t.Fatalf("deep page: %d %s", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?page=2&per_page=50", bob, nil); rec.Code != http.StatusOK {
		t.Fatalf("shallow page: %d %s", rec.Code, rec.Body.String())
	}
}

// --- audit log ----------------------------------------------------------------

func TestAuditLogIndexesAndOptionalRetention(t *testing.T) {
	db, _ := hotpathDB(t, "")
	EnsureAuditLogTable(db)
	for _, idx := range []string{"idx_audit_log_row", "idx_audit_log_user", "idx_audit_log_time"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s missing", idx)
		}
	}
	if plan := queryPlan(t, db, `SELECT * FROM _benmore_audit_log WHERE table_name = ? AND row_id = ? ORDER BY id DESC`, "notes", "1"); !strings.Contains(plan, "idx_audit_log_row") {
		t.Fatalf("row history plan:\n%s", plan)
	}

	// Retention is off unless configured, and refuses tiny TTLs.
	if auditRetentionTTL("") != 0 || auditRetentionTTL("1h") != 0 || auditRetentionTTL("400d") != 400*24*time.Hour {
		t.Fatal("auditRetentionTTL parsing")
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for i, ts := range []string{"2025-01-01 00:00:00", "2025-06-01 00:00:00", "2026-10-01 00:00:00"} {
		if _, err := db.Exec(`INSERT INTO _benmore_audit_log (id, action, table_name, row_id, created_at) VALUES (?, 'update', 'notes', '1', ?)`, i+1, ts); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	// Shipper configured but it has only shipped id 1: id 2 is old but unshipped.
	ensureAuditShipperCursor(db)
	crudScopeMustExec(t, db, `UPDATE `+auditShipperCursorTable+` SET last_shipped_id = 1 WHERE id = 1`)
	n, err := sweepAuditLog(db, 180*24*time.Hour, true, now, stop)
	if err != nil || n != 1 {
		t.Fatalf("shipper-gated sweep deleted %d (%v), want 1", n, err)
	}
	// Without the shipper both old rows go; the recent one stays.
	n, err = sweepAuditLog(db, 180*24*time.Hour, false, now, stop)
	if err != nil || n != 1 {
		t.Fatalf("sweep deleted %d (%v), want 1", n, err)
	}
	var left int
	_ = db.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log`).Scan(&left)
	if left != 1 {
		t.Fatalf("rows left = %d, want the recent row only", left)
	}
}
