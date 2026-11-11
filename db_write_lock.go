//go:build !cli

package main

// Write-lock discipline for the framework SQLite drivers (sqlite3_benmore and
// sqlite3_benmore_maintenance).
//
// SQLite allows one writer per database file. App pools open with
// _txlock=immediate, so every transaction takes that write lock at BEGIN.
// Before this file, three things let one slow holder freeze a whole app and
// leave no trace of who it was (2026-10: an app's "database is locked" storms
// and blank screens after sign-in, 15 to 40 minutes at a time):
//
//   - mattn ignores TxOptions.ReadOnly, so "read-only" transactions (the
//     connector lifecycle preflight on every load and reload, transfer and
//     artifact reads) also took the write lock;
//   - nothing said who held the lock when a request failed with
//     "database is locked";
//   - nothing bounded how long a transaction could hold it. A transaction kept
//     open by a slow outbound call inside a flow, a slow upload into the
//     streaming ingest, or a leaked *sql.Tx held it until the call returned or
//     the process restarted.
//
// The drivers now wrap each connection (benmoreConn):
//
//   - A read-only transaction runs as BEGIN DEFERRED with query_only on, so it
//     reads a snapshot without taking the write lock and cannot write.
//   - A write transaction on a connection opened with _txlock=immediate or
//     exclusive holds the file's write lock from BEGIN to its end; the file's
//     dbWriteLock records it with a label: the context's (withWriteTxLabel) or
//     the calling framework function. Any statement or BEGIN that fails with
//     SQLITE_BUSY logs who holds the lock and for how long, or that no tracked
//     transaction in this process does (rate-limited per file). A release
//     after more than BENMORE_DB_WRITE_TX_WARN (2s) logs the hold.
//   - On the served driver a write transaction has a time limit,
//     BENMORE_DB_WRITE_TX_LIMIT (60s; 0 or off disables). When it passes, a
//     watchdog rolls the transaction back, which frees the lock. The
//     transaction stays attached to its connection: its later statements and
//     its Commit fail with errWriteTxExpired, so its remaining writes can never
//     run in autocommit and commit half of it. Schema migrations, table
//     rebuilds, imports, key rotation and trigger installs mark their context
//     with withLongWriteTx and have no limit; the maintenance driver has none.
//     Manual BEGIN statements (reset/seed, WAL capture, connector reads) are
//     not transactions database/sql knows about and are not limited.
//
// Code that needs the driver's own connection (RegisterAuthorizer, Backup,
// RegisterFunc) unwraps it with sqliteConnOf / mustSQLiteConn; a guard test
// refuses a direct `.(*sqlite3.SQLiteConn)` assertion elsewhere.

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	defaultWriteTxLimit = 60 * time.Second
	defaultWriteTxWarn  = 2 * time.Second
	// At most one contention line per database file in this window; the
	// next line counts the ones it suppressed.
	writeLockNoteInterval = 5 * time.Second
)

// errWriteTxExpired matches (errors.Is) every statement error and the Commit
// error of a write transaction the watchdog rolled back.
var errWriteTxExpired = errors.New("database write transaction rolled back: it held the write lock past BENMORE_DB_WRITE_TX_LIMIT")

type writeTxExpiredError struct {
	label string
	limit time.Duration
}

func (e *writeTxExpiredError) Error() string {
	return fmt.Sprintf("database write transaction by %s rolled back: it held the write lock longer than %s (BENMORE_DB_WRITE_TX_LIMIT)", e.label, e.limit)
}

func (e *writeTxExpiredError) Is(target error) bool { return target == errWriteTxExpired }

// ---- settings ----

// writeTxLimitSetting is the time limit for a write transaction on the served
// driver. BENMORE_DB_WRITE_TX_LIMIT is a Go duration; 0, off or none disables
// it. 60s bounds a stuck holder to a minute, stays under Cloudflare's 100s
// response cutoff, and leaves room for a transactional flow that makes one
// outbound call at run: api's default 30s timeout.
func writeTxLimitSetting() time.Duration {
	return durationSetting("BENMORE_DB_WRITE_TX_LIMIT", defaultWriteTxLimit)
}

// writeTxWarnSetting is the hold after which a released write lock is logged.
func writeTxWarnSetting() time.Duration {
	return durationSetting("BENMORE_DB_WRITE_TX_WARN", defaultWriteTxWarn)
}

var warnedDurationSettings sync.Map

func durationSetting(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	switch strings.ToLower(raw) {
	case "":
		return fallback
	case "0", "off", "none", "false":
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		if _, seen := warnedDurationSettings.LoadOrStore(name+"="+raw, true); !seen {
			log.Printf("db: %s=%q is not a Go duration (like 45s or 2m); using %s", name, raw, fallback)
		}
		return fallback
	}
	return d
}

// ---- context labels and limits ----

type writeTxLabelKey struct{}
type writeTxLimitKey struct{}

// withWriteTxLabel names the work behind a write transaction begun with ctx,
// for the holder logs ("flow:payroll_calc", "cron:digest").
func withWriteTxLabel(ctx context.Context, label string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, writeTxLabelKey{}, label)
}

// withLongWriteTx marks a write transaction that may legitimately hold the
// write lock longer than BENMORE_DB_WRITE_TX_LIMIT: schema migrations, table
// rebuilds, imports, key rotation, trigger installs and backfills. It has no
// time limit; it is still labelled and logged.
func withLongWriteTx(ctx context.Context, label string) context.Context {
	return context.WithValue(withWriteTxLabel(ctx, label), writeTxLimitKey{}, time.Duration(0))
}

func writeTxLimitFor(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(writeTxLimitKey{}).(time.Duration); ok {
		return d
	}
	return writeTxLimitSetting()
}

// writeTxLabel is the context's label, else the first framework function on
// the stack outside database/sql and this file ("handleCreate
// (crud_create.go:379)"), so an unlabelled transaction is still named.
func writeTxLabel(ctx context.Context) string {
	if ctx != nil {
		if label, ok := ctx.Value(writeTxLabelKey{}).(string); ok && label != "" {
			return label
		}
	}
	var pcs [32]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if strings.HasPrefix(f.Function, frameworkFuncPrefix) && filepath.Base(f.File) != "db_write_lock.go" {
			return strings.TrimPrefix(f.Function, frameworkFuncPrefix) + " (" + filepath.Base(f.File) + ":" + strconv.Itoa(f.Line) + ")"
		}
		if !more {
			return "unlabelled transaction"
		}
	}
}

// frameworkFuncPrefix is this package's prefix in runtime function names:
// "main." in the binary, the module path in a test binary.
var frameworkFuncPrefix = frameworkPackagePrefix()

func frameworkPackagePrefix() string {
	pc, _, _, _ := runtime.Caller(0)
	name := runtime.FuncForPC(pc).Name()
	return name[:strings.LastIndex(name, ".")+1]
}

// ---- who holds each file's write lock ----

// dbWriteLock records this process's tracked write transaction on one file.
type dbWriteLock struct {
	file string

	mu         sync.Mutex
	holder     *benmoreWriteTx
	lastNote   time.Time
	suppressed int
}

var dbWriteLocks sync.Map // database file -> *dbWriteLock

func dbWriteLockFor(file string) *dbWriteLock {
	if l, ok := dbWriteLocks.Load(file); ok {
		return l.(*dbWriteLock)
	}
	l, _ := dbWriteLocks.LoadOrStore(file, &dbWriteLock{file: file})
	return l.(*dbWriteLock)
}

func (l *dbWriteLock) hold(t *benmoreWriteTx) {
	l.mu.Lock()
	l.holder = t
	l.mu.Unlock()
}

// release clears t as the holder and logs a hold longer than the warn setting.
func (l *dbWriteLock) release(t *benmoreWriteTx) {
	l.mu.Lock()
	if l.holder == t {
		l.holder = nil
	}
	l.mu.Unlock()
	if warn := writeTxWarnSetting(); warn > 0 {
		if held := time.Since(t.start); held >= warn {
			log.Printf("db: write lock on %s held %s by %s", filepath.Base(l.file), held.Round(time.Millisecond), t.label)
		}
	}
}

// noteContention logs a statement or BEGIN that met the lock, naming the
// holder when it is a tracked transaction in this process.
func (l *dbWriteLock) noteContention(victim, what string) {
	l.mu.Lock()
	now := time.Now()
	if !l.lastNote.IsZero() && now.Sub(l.lastNote) < writeLockNoteInterval {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	holder, suppressed := l.holder, l.suppressed
	l.lastNote, l.suppressed = now, 0
	var label string
	var since time.Time
	if holder != nil {
		label, since = holder.label, holder.start
	}
	l.mu.Unlock()

	msg := "db: database is locked: " + victim + " " + what + " on " + filepath.Base(l.file)
	if holder != nil {
		msg += "; write lock held " + time.Since(since).Round(time.Millisecond).String() + " by " + label
	} else {
		msg += "; no tracked write transaction in this process holds it (another process, a single write statement or a manual BEGIN)"
	}
	if suppressed > 0 {
		msg += fmt.Sprintf(" (%d similar suppressed)", suppressed)
	}
	log.Print(msg)
}

// ---- driver and connection wrappers ----

// benmoreDriver opens wrapped connections. limited is false for the
// maintenance driver: no time limit on databases that are not being served.
type benmoreDriver struct {
	*sqlite3.SQLiteDriver
	limited bool
}

func (d *benmoreDriver) Open(dsn string) (driver.Conn, error) {
	conn, err := d.SQLiteDriver.Open(dsn)
	if err != nil {
		return nil, err
	}
	sc, ok := conn.(*sqlite3.SQLiteConn)
	if !ok {
		return conn, nil
	}
	c := &benmoreConn{SQLiteConn: sc, limited: d.limited}
	file := sc.GetFilename("main")
	if file != "" {
		c.lock = dbWriteLockFor(file)
		c.tracked = sqliteDSNTxLock(dsn) != "deferred"
	}
	// The connection's default authorizer (app_sql_guard.go). The served
	// driver's ConnectHook has applied the storage ceiling by now.
	benmoreConnsByDriverConn.Store(sc, c)
	c.installDefaultAuthorizer(d.limited && effectiveDBStorageLimit(canonicalDBPath(file)) > 0)
	return c, nil
}

// sqliteDSNTxLock reads the DSN's _txlock the way mattn does (default
// deferred).
func sqliteDSNTxLock(dsn string) string {
	_, query, ok := strings.Cut(dsn, "?")
	if !ok {
		return "deferred"
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		return "deferred"
	}
	if v := strings.ToLower(params.Get("_txlock")); v != "" {
		return v
	}
	return "deferred"
}

// benmoreConn is a framework connection. gate serializes statements with the
// watchdog, so its ROLLBACK never interleaves with a running statement.
type benmoreConn struct {
	*sqlite3.SQLiteConn
	lock *dbWriteLock // nil for a database with no file (in-memory)
	// tracked: BEGIN takes the write lock (_txlock immediate or exclusive),
	// so a write transaction is the file's holder from BEGIN to its end.
	tracked bool
	limited bool

	gate sync.Mutex
	tx   *benmoreWriteTx // the open tracked write transaction, guarded by gate
	// stmtCtx, when set, bounds every statement that came without a deadline of
	// its own (bindStatementContext). Guarded by gate.
	stmtCtx context.Context
	// appSQL is the scope of the app-authored statement being compiled
	// (app_sql_guard.go); set and cleared under gate. ceiling: the default
	// authorizer also guards the storage-ceiling pragmas.
	appSQL  *appSQLScope
	ceiling atomic.Bool
}

// bindStatementContext makes statements on this connection that carry no
// deadline of their own (tx.Exec, tx.Query: the shared migration code) run under
// ctx, so ctx's end interrupts them. A migration dry run holds the write lock
// and runs tenant SQL through that code; its time bound has to hold for every
// statement, or one slow statement keeps every writer of the app waiting.
func (c *benmoreConn) bindStatementContext(ctx context.Context) {
	c.gate.Lock()
	c.stmtCtx = ctx
	c.gate.Unlock()
}

// statementContext is ctx, or the bound context when ctx has no way to end.
// Caller holds c.gate.
func (c *benmoreConn) statementContext(ctx context.Context) context.Context {
	if c.stmtCtx != nil && ctx.Done() == nil {
		return c.stmtCtx
	}
	return ctx
}

// sqliteConnOf returns the driver connection behind a database/sql Raw value.
func sqliteConnOf(raw any) (*sqlite3.SQLiteConn, bool) {
	switch c := raw.(type) {
	case *benmoreConn:
		return c.SQLiteConn, true
	case *sqlite3.SQLiteConn:
		return c, true
	}
	return nil, false
}

// mustSQLiteConn is sqliteConnOf for code that only runs on SQLite pools; it
// panics like the bare type assertion it replaces.
func mustSQLiteConn(raw any) *sqlite3.SQLiteConn {
	c, ok := sqliteConnOf(raw)
	if !ok {
		panic(fmt.Sprintf("not a SQLite connection: %T", raw))
	}
	return c
}

// enter takes the gate for one statement, refusing it when the connection's
// write transaction was rolled back by the watchdog.
func (c *benmoreConn) enter() error {
	c.gate.Lock()
	if t := c.tx; t != nil && t.expired.Load() {
		c.gate.Unlock()
		return t.expiredError()
	}
	return nil
}

func (c *benmoreConn) noteIfBusy(ctx context.Context, err error, what string) {
	if c.lock == nil || !isSQLiteBusy(err) {
		return
	}
	c.lock.noteContention(writeTxLabel(ctx), what)
}

func isSQLiteBusy(err error) bool {
	var se sqlite3.Error
	return errors.As(err, &se) && se.Code == sqlite3.ErrBusy
}

func (c *benmoreConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.enter(); err != nil {
		return nil, err
	}
	query, scope, err := c.beginAppSQL(query)
	if err != nil {
		c.gate.Unlock()
		return nil, err
	}
	res, err := c.SQLiteConn.ExecContext(c.statementContext(ctx), query, args)
	err = c.endAppSQL(scope, err)
	c.gate.Unlock()
	if err != nil {
		c.noteIfBusy(ctx, err, "could not write")
	}
	return res, err
}

func (c *benmoreConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.enter(); err != nil {
		return nil, err
	}
	query, scope, err := c.beginAppSQL(query)
	if err != nil {
		c.gate.Unlock()
		return nil, err
	}
	rows, err := c.SQLiteConn.QueryContext(c.statementContext(ctx), query, args)
	err = c.endAppSQL(scope, err)
	c.gate.Unlock()
	if err != nil {
		c.noteIfBusy(ctx, err, "could not run a query")
	}
	return rows, err
}

func (c *benmoreConn) Exec(query string, args []driver.Value) (driver.Result, error) {
	return c.ExecContext(context.Background(), query, valuesToNamed(args))
}

func (c *benmoreConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	return c.QueryContext(context.Background(), query, valuesToNamed(args))
}

func valuesToNamed(args []driver.Value) []driver.NamedValue {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return named
}

func (c *benmoreConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := c.enter(); err != nil {
		return nil, err
	}
	query, scope, err := c.beginAppSQL(query)
	if err != nil {
		c.gate.Unlock()
		return nil, err
	}
	stmt, err := c.SQLiteConn.PrepareContext(ctx, query)
	err = c.endAppSQL(scope, err)
	c.gate.Unlock()
	if err != nil {
		return nil, err
	}
	if s, ok := stmt.(*sqlite3.SQLiteStmt); ok {
		return &benmoreStmt{SQLiteStmt: s, c: c}, nil
	}
	return stmt, nil
}

func (c *benmoreConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *benmoreConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *benmoreConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.ReadOnly {
		return c.beginReadOnly(ctx)
	}
	if err := c.enter(); err != nil {
		return nil, err
	}
	inner, err := c.SQLiteConn.BeginTx(ctx, opts)
	if err != nil {
		c.gate.Unlock()
		c.noteIfBusy(ctx, err, "could not begin a write transaction")
		return nil, err
	}
	if !c.tracked || c.lock == nil {
		c.gate.Unlock()
		return inner, nil
	}
	t := &benmoreWriteTx{c: c, inner: inner, label: writeTxLabel(ctx), start: time.Now()}
	c.tx = t
	c.lock.hold(t)
	c.gate.Unlock()
	if c.limited {
		if limit := writeTxLimitFor(ctx); limit > 0 {
			t.limit = limit
			t.timer = time.AfterFunc(limit, func() { c.expire(t) })
		}
	}
	return t, nil
}

func (c *benmoreConn) Close() error {
	c.gate.Lock()
	if t := c.tx; t != nil {
		c.finishLocked(t)
	}
	c.gate.Unlock()
	benmoreConnsByDriverConn.Delete(c.SQLiteConn)
	return c.SQLiteConn.Close()
}

// finishLocked ends t's bookkeeping: stops the watchdog, clears the holder
// once and detaches t from the connection. Caller holds c.gate.
func (c *benmoreConn) finishLocked(t *benmoreWriteTx) {
	if t.timer != nil {
		t.timer.Stop()
	}
	if !t.released {
		t.released = true
		c.lock.release(t)
	}
	if c.tx == t {
		c.tx = nil
	}
	t.done = true
}

// expire is the watchdog: it rolls back a write transaction that outlived its
// limit, which frees the lock. The transaction stays attached to the
// connection, so its later statements and its Commit fail instead of running
// outside it.
func (c *benmoreConn) expire(t *benmoreWriteTx) {
	t.expired.Store(true)
	log.Printf("db: write transaction by %s held the write lock on %s for %s (limit %s, BENMORE_DB_WRITE_TX_LIMIT); rolling it back so other requests can write",
		t.label, filepath.Base(c.lock.file), time.Since(t.start).Round(time.Millisecond), t.limit)
	c.gate.Lock()
	defer c.gate.Unlock()
	if c.tx != t || t.done || t.rolledBack {
		return
	}
	if err := t.inner.Rollback(); err != nil {
		log.Printf("db: rolling back the expired write transaction by %s failed: %v", t.label, err)
	}
	t.rolledBack = true
	if !t.released {
		t.released = true
		c.lock.release(t)
	}
}

// benmoreWriteTx is a tracked write transaction.
type benmoreWriteTx struct {
	c     *benmoreConn
	inner driver.Tx
	label string
	start time.Time
	limit time.Duration
	timer *time.Timer

	expired atomic.Bool
	// Guarded by c.gate.
	rolledBack, released, done bool
}

func (t *benmoreWriteTx) expiredError() error {
	return &writeTxExpiredError{label: t.label, limit: t.limit}
}

func (t *benmoreWriteTx) Commit() error {
	c := t.c
	c.gate.Lock()
	defer c.gate.Unlock()
	if t.done {
		// Its connection was closed under it; SQLite rolled it back.
		return errors.New("sqlite: transaction already ended: its connection was closed")
	}
	if t.expired.Load() {
		if !t.rolledBack {
			t.inner.Rollback()
			t.rolledBack = true
		}
		c.finishLocked(t)
		return t.expiredError()
	}
	err := t.inner.Commit()
	c.finishLocked(t)
	return err
}

func (t *benmoreWriteTx) Rollback() error {
	c := t.c
	c.gate.Lock()
	defer c.gate.Unlock()
	if t.done {
		return nil
	}
	var err error
	if !t.rolledBack {
		err = t.inner.Rollback()
		t.rolledBack = true
	}
	c.finishLocked(t)
	return err
}

// beginReadOnly starts a deferred transaction with query_only on: a snapshot
// read that never takes the write lock and cannot write.
func (c *benmoreConn) beginReadOnly(ctx context.Context) (driver.Tx, error) {
	if err := c.enter(); err != nil {
		return nil, err
	}
	defer c.gate.Unlock()
	already, err := sqliteQueryOnly(ctx, c.SQLiteConn)
	if err != nil {
		return nil, err
	}
	if !already {
		if _, err := c.SQLiteConn.ExecContext(ctx, "PRAGMA query_only = 1", nil); err != nil {
			return nil, err
		}
	}
	if _, err := c.SQLiteConn.ExecContext(ctx, "BEGIN DEFERRED", nil); err != nil {
		if !already {
			c.SQLiteConn.ExecContext(context.Background(), "PRAGMA query_only = 0", nil)
		}
		return nil, err
	}
	return &benmoreReadTx{c: c, restore: !already}, nil
}

func sqliteQueryOnly(ctx context.Context, conn *sqlite3.SQLiteConn) (bool, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA query_only", nil)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	dest := make([]driver.Value, 1)
	if err := rows.Next(dest); err != nil {
		return false, err
	}
	v, _ := dest[0].(int64)
	return v != 0, nil
}

// benmoreReadTx is a read-only transaction.
type benmoreReadTx struct {
	c       *benmoreConn
	restore bool
	done    bool
}

func (t *benmoreReadTx) end(stmt string) error {
	c := t.c
	c.gate.Lock()
	defer c.gate.Unlock()
	if t.done {
		return nil
	}
	t.done = true
	_, err := c.SQLiteConn.ExecContext(context.Background(), stmt, nil)
	if err != nil && stmt == "COMMIT" {
		// As mattn does: database/sql treats the transaction as finished.
		c.SQLiteConn.ExecContext(context.Background(), "ROLLBACK", nil)
	}
	if t.restore {
		if _, rerr := c.SQLiteConn.ExecContext(context.Background(), "PRAGMA query_only = 0", nil); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

func (t *benmoreReadTx) Commit() error   { return t.end("COMMIT") }
func (t *benmoreReadTx) Rollback() error { return t.end("ROLLBACK") }

// benmoreStmt gates a prepared statement like a direct one, so a statement
// prepared before the watchdog fired cannot run after it.
type benmoreStmt struct {
	*sqlite3.SQLiteStmt
	c *benmoreConn
}

func (s *benmoreStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := s.c.enter(); err != nil {
		return nil, err
	}
	res, err := s.SQLiteStmt.ExecContext(ctx, args)
	s.c.gate.Unlock()
	if err != nil {
		s.c.noteIfBusy(ctx, err, "could not write")
	}
	return res, err
}

func (s *benmoreStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if err := s.c.enter(); err != nil {
		return nil, err
	}
	rows, err := s.SQLiteStmt.QueryContext(ctx, args)
	s.c.gate.Unlock()
	if err != nil {
		s.c.noteIfBusy(ctx, err, "could not run a query")
	}
	return rows, err
}

func (s *benmoreStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), valuesToNamed(args))
}

func (s *benmoreStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), valuesToNamed(args))
}
