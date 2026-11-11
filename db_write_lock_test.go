//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedLog collects log output written from several goroutines (the
// watchdog logs from a timer).
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureWriteLockLog(t *testing.T) *lockedLog {
	t.Helper()
	out := &lockedLog{}
	old := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(old) })
	return out
}

// openWriteLockTestDB opens a served-driver pool the way an app does, with a
// short busy timeout so contention tests do not wait 10s.
func openWriteLockTestDB(t *testing.T, driverName string, busyMS int) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	dsn := path + "?_journal_mode=WAL&_txlock=immediate&_busy_timeout=" + strconv.Itoa(busyMS)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	return db
}

func writeLockTestRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A read-only transaction used to take the write lock (mattn ignores
// TxOptions.ReadOnly under _txlock=immediate), so the connector preflight on
// every reload queued behind, and blocked, every writer.
func TestReadOnlyTransactionDoesNotTakeTheWriteLock(t *testing.T) {
	db := openWriteLockTestDB(t, "sqlite3_benmore", 5000)
	ro, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := ro.QueryRow("SELECT COUNT(*) FROM t").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Exec("INSERT INTO t (v) VALUES ('from read-only')"); err == nil {
		t.Fatal("a read-only transaction wrote")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	w, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("writer blocked by a read-only transaction: %v", err)
	}
	if _, err := w.Exec("INSERT INTO t (v) VALUES ('writer')"); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("writer waited %s behind a read-only transaction", waited)
	}
	// The read-only transaction keeps its snapshot.
	if err := ro.QueryRow("SELECT COUNT(*) FROM t").Scan(&n); err != nil || n != 0 {
		t.Fatalf("snapshot read = %d, %v; want 0", n, err)
	}
	if err := ro.Commit(); err != nil {
		t.Fatal(err)
	}
	// query_only is restored before the connection goes back to the pool.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("INSERT INTO t (v) VALUES ('after')"); err != nil {
		t.Fatalf("connection stayed read-only after the transaction: %v", err)
	}
}

// A request that finds the database locked names who holds it.
func TestDatabaseLockedNamesTheHolder(t *testing.T) {
	out := captureWriteLockLog(t)
	db := openWriteLockTestDB(t, "sqlite3_benmore", 200)
	holder, err := db.BeginTx(withWriteTxLabel(context.Background(), "flow:slow_payroll"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()

	_, err = db.BeginTx(withWriteTxLabel(context.Background(), "cron:digest"), nil)
	if !isSQLiteBusy(err) || err.Error() != "database is locked" {
		t.Fatalf("second writer err = %v; want the unchanged SQLITE_BUSY error", err)
	}
	logged := out.String()
	for _, want := range []string{"database is locked: cron:digest", "by flow:slow_payroll", "data.db"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log %q does not contain %q", logged, want)
		}
	}
	if !regexp.MustCompile(`write lock held \d`).MatchString(logged) {
		t.Fatalf("log %q does not say how long the lock was held", logged)
	}
}

// Without a tracked holder in this process the log says so instead of
// guessing.
func TestDatabaseLockedOutsideThisProcessSaysSo(t *testing.T) {
	out := captureWriteLockLog(t)
	db := openWriteLockTestDB(t, "sqlite3_benmore", 200)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A manual BEGIN is not a database/sql transaction: untracked, like a
	// writer in another process.
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if _, err := db.Exec("INSERT INTO t (v) VALUES ('x')"); !isSQLiteBusy(err) {
		t.Fatalf("insert err = %v; want SQLITE_BUSY", err)
	}
	if logged := out.String(); !strings.Contains(logged, "no tracked write transaction in this process holds it") {
		t.Fatalf("log %q", logged)
	}
}

// A write transaction past BENMORE_DB_WRITE_TX_LIMIT is rolled back by the
// watchdog, which frees the lock for other writers even while its owner is
// still away (a slow outbound call, or a leaked *sql.Tx). Its later
// statements, prepared ones included, and its Commit fail instead of running
// in autocommit.
func TestWriteTransactionTimeLimitRollsBackAndFreesTheLock(t *testing.T) {
	t.Setenv("BENMORE_DB_WRITE_TX_LIMIT", "300ms")
	out := captureWriteLockLog(t)
	db := openWriteLockTestDB(t, "sqlite3_benmore", 5000)

	stuck, err := db.BeginTx(withWriteTxLabel(context.Background(), "flow:stuck_payment"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stuck.Exec("INSERT INTO t (v) VALUES ('before the limit')"); err != nil {
		t.Fatal(err)
	}
	prepared, err := stuck.Prepare("INSERT INTO t (v) VALUES (?)")
	if err != nil {
		t.Fatal(err)
	}

	// Another writer gets the lock once the limit passes, without the stuck
	// owner doing anything.
	start := time.Now()
	other, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("writer still blocked after the limit: %v", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("writer waited %s; the limit is 300ms", waited)
	}
	if _, err := other.Exec("INSERT INTO t (v) VALUES ('other')"); err != nil {
		t.Fatal(err)
	}
	if err := other.Commit(); err != nil {
		t.Fatal(err)
	}

	if _, err := stuck.Exec("INSERT INTO t (v) VALUES ('after the limit')"); !errors.Is(err, errWriteTxExpired) {
		t.Fatalf("statement after expiry err = %v; want errWriteTxExpired", err)
	}
	if _, err := prepared.Exec("prepared after the limit"); !errors.Is(err, errWriteTxExpired) {
		t.Fatalf("prepared statement after expiry err = %v; want errWriteTxExpired", err)
	}
	if err := stuck.Commit(); !errors.Is(err, errWriteTxExpired) {
		t.Fatalf("commit after expiry err = %v; want errWriteTxExpired", err)
	}
	var vals []string
	rows, err := db.Query("SELECT v FROM t ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var v string
		rows.Scan(&v)
		vals = append(vals, v)
	}
	rows.Close()
	if strings.Join(vals, ",") != "other" {
		t.Fatalf("rows = %v; want only the other writer's row (the expired transaction rolled back whole)", vals)
	}
	if logged := out.String(); !strings.Contains(logged, "write transaction by flow:stuck_payment held the write lock") || !strings.Contains(logged, "rolling it back") {
		t.Fatalf("log %q does not name the rolled-back holder", logged)
	}
	// The connection is usable again once its owner finished the transaction.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("INSERT INTO t (v) VALUES ('reused')"); err != nil {
		t.Fatal(err)
	}
	if n := writeLockTestRows(t, db); n != 2 {
		t.Fatalf("rows = %d; want 2", n)
	}
}

// Migrations, imports and other maintenance mark themselves long and are
// never cut off; neither is anything on the maintenance driver.
func TestLongAndMaintenanceWriteTransactionsHaveNoLimit(t *testing.T) {
	t.Setenv("BENMORE_DB_WRITE_TX_LIMIT", "100ms")
	for _, tc := range []struct {
		name   string
		driver string
		ctx    context.Context
	}{
		{"long", "sqlite3_benmore", withLongWriteTx(context.Background(), "schema migration")},
		{"maintenance", sqliteMaintenanceDriver, context.Background()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openWriteLockTestDB(t, tc.driver, 5000)
			tx, err := db.BeginTx(tc.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec("INSERT INTO t (v) VALUES ('kept')"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(400 * time.Millisecond)
			if _, err := tx.Exec("INSERT INTO t (v) VALUES ('kept too')"); err != nil {
				t.Fatalf("long transaction cut off: %v", err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if n := writeLockTestRows(t, db); n != 2 {
				t.Fatalf("rows = %d; want 2", n)
			}
		})
	}
}

// A hold longer than BENMORE_DB_WRITE_TX_WARN is logged with its holder.
func TestSlowWriteLockHoldIsLogged(t *testing.T) {
	t.Setenv("BENMORE_DB_WRITE_TX_WARN", "50ms")
	out := captureWriteLockLog(t)
	db := openWriteLockTestDB(t, "sqlite3_benmore", 5000)
	tx, err := db.BeginTx(withWriteTxLabel(context.Background(), "job:recompute"), nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if logged := out.String(); !strings.Contains(logged, "write lock on data.db held") || !strings.Contains(logged, "by job:recompute") {
		t.Fatalf("log %q", logged)
	}
	// A fast transaction is not logged; an unlabelled one is named by its caller.
	before := out.String()
	tx, err = db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if out.String() != before {
		t.Fatalf("fast transaction logged: %q", strings.TrimPrefix(out.String(), before))
	}
}

func TestUnlabelledWriteTxIsNamedByItsCaller(t *testing.T) {
	if got := writeTxLabel(context.Background()); !strings.Contains(got, "TestUnlabelledWriteTxIsNamedByItsCaller (db_write_lock_test.go:") {
		t.Fatalf("label = %q", got)
	}
}

// The protections live in the driver, so they cover every transaction only
// while the framework drivers are the wrapped ones, and code that needs the
// driver connection must unwrap it rather than assert the mattn type (the
// assertion fails on a wrapped connection).
func TestFrameworkDriversWrapEveryConnection(t *testing.T) {
	for _, name := range []string{"sqlite3_benmore", sqliteMaintenanceDriver} {
		db := openWriteLockTestDB(t, name, 1000)
		if _, ok := db.Driver().(*benmoreDriver); !ok {
			t.Fatalf("%s driver is %T", name, db.Driver())
		}
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		err = conn.Raw(func(raw any) error {
			if _, ok := raw.(*benmoreConn); !ok {
				t.Fatalf("%s connection is %T", name, raw)
			}
			if _, ok := sqliteConnOf(raw); !ok {
				t.Fatal("sqliteConnOf cannot unwrap the connection")
			}
			return nil
		})
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	direct := regexp.MustCompile(`\.\(\*sqlite3\.SQLiteConn\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f == "db_write_lock.go" || f == "db_write_lock_test.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if direct.Match(src) {
			t.Errorf("%s asserts .(*sqlite3.SQLiteConn); use sqliteConnOf or mustSQLiteConn (db_write_lock.go)", f)
		}
	}
}
