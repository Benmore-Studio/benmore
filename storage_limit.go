//go:build !cli

package main

// Database storage ceiling, enforced by SQLite itself.
//
// Hosted apps share one disk, and an app can grow its data.db through many
// doors: auto-CRUD, flows, `sql write:true`, SQL-restore imports, hooks,
// jobs, framework bookkeeping. A per-endpoint size check covers only the
// doors that call it. Instead, every connection the framework driver
// (sqlite3_benmore) opens to a database with a registered limit gets
//
//	PRAGMA max_page_count = limit / page_size
//
// in its ConnectHook (encryption.go), so any write that would extend the
// file past the limit fails inside SQLite with SQLITE_FULL, whichever code
// path issued it. SQLite rolls back the failing statement (and, when it has
// to, the whole transaction) and the file stays consistent; reads, deletes
// and writes that fit in pages freed by earlier deletes keep working.
//
// The SQLite ceiling sits above the plan limit (storageCeilingHeadroom): the
// plan limit itself is the pre-flight refusal on creates, bootstrap and
// imports (checkStorageCap), while the ceiling only bounds the shared disk. At
// the plan limit new data is refused politely and sign-ins, sessions, jobs and
// migrations keep working; only runaway growth past the headroom hits
// SQLITE_FULL.
//
// max_page_count is a per-connection setting that SQLite never lowers below
// the database's current page count. A database already larger than its
// limit is therefore frozen at its current size rather than refused: it can
// shrink and reuse freed space, but it cannot grow.
//
// Only platform builds register limits (storage_cap.go, from the owner's
// plan); a self-hosted or framework-edition database has none and is never
// capped.

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mattn/go-sqlite3"
)

// dbStorageLimits maps canonical database paths to their byte limit. A stored
// 0 records an explicit "no limit" (the platform's own app, an operator
// override) and is distinct from an absent entry, which leaves any plan
// pre-flight check (checkStorageCap) on its own default.
var dbStorageLimits sync.Map

// processStorageLimit applies to every framework-driver connection whose file
// has no entry of its own. Only a hosted tenant process sets it: the one
// database it opens is its app database, whatever path DATABASE_URL gives it.
var processStorageLimit atomic.Int64

// dbStorageFrozenLogged throttles the "already over its limit" line to once
// per database per process; the pool opens many connections.
var dbStorageFrozenLogged sync.Map

// setDBStorageLimit registers the byte limit for one database file. limit <= 0
// records that the database is explicitly unlimited.
func setDBStorageLimit(dbPath string, limit int64) {
	key := canonicalDBPath(dbPath)
	if key == "" {
		return
	}
	if limit < 0 {
		limit = 0
	}
	dbStorageLimits.Store(key, limit)
}

// registeredDBStorageLimit returns the registered limit for dbPath and whether
// one was registered (a registered 0 means unlimited).
func registeredDBStorageLimit(dbPath string) (int64, bool) {
	if dbPath == "" {
		return 0, false
	}
	if v, ok := dbStorageLimits.Load(canonicalDBPath(dbPath)); ok {
		return v.(int64), true
	}
	return 0, false
}

// effectiveDBStorageLimit is the limit a connection to canonicalPath enforces:
// its own registration, else the process default. 0 means unlimited.
func effectiveDBStorageLimit(canonicalPath string) int64 {
	if canonicalPath == "" {
		return 0
	}
	if v, ok := dbStorageLimits.Load(canonicalPath); ok {
		return v.(int64)
	}
	return processStorageLimit.Load()
}

// applyDBStorageLimit runs in the driver ConnectHook. It fails the connection
// rather than hand out one that could write past the limit.
func applyDBStorageLimit(conn *sqlite3.SQLiteConn, canonicalPath string) error {
	limit := effectiveDBStorageLimit(canonicalPath)
	if limit <= 0 {
		return nil
	}
	pageSize, err := sqliteConnInt(conn, "PRAGMA page_size")
	if err != nil {
		return fmt.Errorf("storage limit: read page size: %w", err)
	}
	if pageSize <= 0 {
		pageSize = 4096
	}
	ceiling := limit + storageCeilingHeadroom(limit)
	pages := storagePageBudget(ceiling, pageSize)
	// The pragma answers with the maximum it actually set: never below the
	// current page count.
	set, err := sqliteConnInt(conn, fmt.Sprintf("PRAGMA max_page_count = %d", pages))
	if err != nil {
		return fmt.Errorf("storage limit: %w", err)
	}
	if set > pages {
		if _, seen := dbStorageFrozenLogged.LoadOrStore(canonicalPath, true); !seen {
			log.Printf("STORAGE LIMIT: %s is %s, over its %s limit - it cannot grow; reads, deletes and writes into freed space continue",
				filepath.Base(filepath.Dir(canonicalPath)), humanBytesShort(set*pageSize), humanBytesShort(limit))
		}
	}
	// TEMP tables live in a file of their own (go-sqlite3 ignores the
	// _temp_store DSN option, so SQLite's default file-backed temp store is
	// what runs), which the main ceiling does not count. Bound it per
	// connection; the file is deleted when the connection closes.
	tempPageSize, err := sqliteConnInt(conn, "PRAGMA temp.page_size")
	if err != nil {
		return fmt.Errorf("storage limit: read temp page size: %w", err)
	}
	if tempPageSize <= 0 {
		tempPageSize = 4096
	}
	tempBudget := storageTempSchemaMaxBytes
	if ceiling < tempBudget {
		tempBudget = ceiling
	}
	if _, err := sqliteConnInt(conn, fmt.Sprintf("PRAGMA temp.max_page_count = %d", storagePageBudget(tempBudget, tempPageSize))); err != nil {
		return fmt.Errorf("storage limit: bound temp schema: %w", err)
	}
	// App SQL runs on this connection (flow and hook SQL, sql write:true), so
	// it must not be able to set the pragmas above back up.
	conn.RegisterAuthorizer(authorizeStorageCeiling)
	return nil
}

// storageTempSchemaMaxBytes bounds one connection's TEMP tables. The
// framework keeps no data in them; an app's scratch tables get 64 MiB.
const storageTempSchemaMaxBytes int64 = 64 << 20

// storagePageBudget converts a byte budget to a max_page_count value.
func storagePageBudget(bytes, pageSize int64) int64 {
	pages := bytes / pageSize
	if pages < 1 {
		pages = 1
	}
	if pages > 0xfffffffe {
		pages = 0xfffffffe
	}
	return pages
}

// storageCeilingPragmas would lift or reset the ceiling if app SQL could set
// them: max_page_count directly (main or temp), page_size together with a
// rebuild, and temp_store / temp_store_directory by reopening the temp schema
// without its bound.
var storageCeilingPragmas = map[string]bool{
	"max_page_count":       true,
	"page_size":            true,
	"temp_store":           true,
	"temp_store_directory": true,
}

// authorizeStorageCeiling is the default authorizer of a connection with a
// storage ceiling: it refuses to SET a storage-ceiling pragma on any schema
// and allows everything else, including reading those pragmas. The
// table-valued pragma_* forms of these take no value, so they can only read.
func authorizeStorageCeiling(action int, arg1, arg2, database string) int {
	if action == sqlite3.SQLITE_PRAGMA && arg2 != "" && storageCeilingPragmas[strings.ToLower(arg1)] {
		return sqlite3.SQLITE_DENY
	}
	return sqlite3.SQLITE_OK
}

// restoreConnAuthorizer ends a caller's temporary authorizer (read-only
// queries, app resets) and puts back the connection's default: the storage
// ceiling guard when its database has a limit, none otherwise. Clearing the
// authorizer with nil would let later app SQL on the pooled connection lift
// the ceiling.
func restoreConnAuthorizer(conn *sqlite3.SQLiteConn) {
	if conn == nil {
		return
	}
	if effectiveDBStorageLimit(canonicalDBPath(conn.GetFilename("main"))) > 0 {
		conn.RegisterAuthorizer(authorizeStorageCeiling)
		return
	}
	conn.RegisterAuthorizer(nil)
}

// storageCeilingHeadroom is how far past its plan limit a database may grow
// before SQLite refuses writes: a quarter of the limit, at least 64 MiB. Tests
// replace it to reach the ceiling with small databases.
var storageCeilingHeadroom = func(limit int64) int64 {
	if h := limit / 4; h > 64<<20 {
		return h
	}
	return 64 << 20
}

// sqliteConnInt runs a single-value PRAGMA on a raw driver connection. The
// statement only executes when its row is read, so the row is always read.
func sqliteConnInt(conn *sqlite3.SQLiteConn, query string) (int64, error) {
	rows, err := conn.Query(query, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	dest := make([]driver.Value, len(rows.Columns()))
	if len(dest) == 0 {
		return 0, fmt.Errorf("%s returned no columns", query)
	}
	if err := rows.Next(dest); err != nil {
		if err == io.EOF {
			return 0, fmt.Errorf("%s returned no row", query)
		}
		return 0, err
	}
	switch v := dest[0].(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	}
	return 0, fmt.Errorf("%s returned %T", query, dest[0])
}

// isStorageFullError reports SQLITE_FULL: the database reached its storage
// limit, or the disk itself is full.
func isStorageFullError(err error) bool {
	if err == nil {
		return false
	}
	var se sqlite3.Error
	if errors.As(err, &se) && se.Code == sqlite3.ErrFull {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "database or disk is full")
}

// storageFullStatus is the HTTP status for a write refused for lack of space.
const storageFullStatus = http.StatusInsufficientStorage

// storageFullBody is the caller-facing refusal for a write that hit the
// storage limit. It keeps the pre-flight check's `error` value so clients
// that already handle "storage cap reached" handle this too.
func storageFullBody(app *App) map[string]any {
	body := map[string]any{"error": "storage cap reached", "code": "storage_limit"}
	limit := int64(0)
	if app != nil && app.Dir != "" {
		limit = effectiveDBStorageLimit(canonicalDBPath(filepath.Join(app.Dir, "data.db")))
	}
	if limit > 0 {
		body["limit_bytes"] = limit
		body["detail"] = fmt.Sprintf("This app's database is past its %s storage limit, so writes that need more space are refused. Reads and deletes keep working, and space freed by deleting rows is reused. %s",
			humanBytesShort(limit), storageLimitRemedy())
		return body
	}
	body["detail"] = "The database or the disk it lives on is full. Free space, then retry."
	return body
}

// respondStorageFull writes the storage refusal when err is SQLITE_FULL and
// reports whether it did.
func respondStorageFull(w http.ResponseWriter, app *App, err error) bool {
	if !isStorageFullError(err) {
		return false
	}
	httpJSON(w, storageFullStatus, storageFullBody(app))
	return true
}

// isDatabaseBusyError reports a write that could not get the database lock in
// time (SQLITE_BUSY/SQLITE_LOCKED). The request itself was fine, so it must
// not be reported as a 400 the client won't retry.
func isDatabaseBusyError(err error) bool {
	if err == nil {
		return false
	}
	var se sqlite3.Error
	if errors.As(err, &se) {
		return se.Code == sqlite3.ErrBusy || se.Code == sqlite3.ErrLocked
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked")
}

// respondDatabaseBusy answers 503 with Retry-After for a lock timeout and
// reports whether it did.
func respondDatabaseBusy(w http.ResponseWriter, err error) bool {
	if !isDatabaseBusyError(err) {
		return false
	}
	w.Header().Set("Retry-After", "1")
	httpJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "the database is busy, retry shortly"})
	return true
}

// storageFullMessage is the one-line form for non-HTTP callers (MCP tools,
// import state).
func storageFullMessage(app *App) string {
	body := storageFullBody(app)
	return fmt.Sprintf("storage cap reached: %s", body["detail"])
}

// humanBytesShort formats bytes as "50.0 MB" for limit messages.
func humanBytesShort(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
