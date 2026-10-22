//go:build !cli

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-sqlite3"
)

const (
	readOnlyQueryMaxRows = 1000
	readOnlyQueryTimeout = 8 * time.Second
	// SQLITE_RECURSIVE from sqlite3.h; go-sqlite3 does not export this action.
	sqliteRecursiveSelect = 33
)

// queryReadOnlyRows enforces read-only execution independently of the text
// validator. A pinned connection belongs exclusively to this call until all
// rows are closed and its previous query_only state is restored. SQLite's
// query_only flag blocks writes, including virtual-table writes; the authorizer
// prevents SQL from disabling it or changing connection state. Other pool
// connections retain their normal write behavior.
func queryReadOnlyRows(ctx context.Context, db *sql.DB, query string, limit int) ([]map[string]any, bool, error) {
	rows, _, truncated, err := queryReadOnlyRowsCols(ctx, db, query, limit)
	return rows, truncated, err
}

// queryReadOnlyRowsCols is queryReadOnlyRows that also returns the result's
// column names in order (for table UIs such as the dashboard SQL console).
func queryReadOnlyRowsCols(ctx context.Context, db *sql.DB, query string, limit int, args ...any) ([]map[string]any, []string, bool, error) {
	return queryReadOnlyRowsColsDecrypt(ctx, db, query, limit, nil, args...)
}

func queryReadOnlyRowsColsDecrypt(ctx context.Context, db *sql.DB, query string, limit int, decrypt rowDecryptFunc, args ...any) ([]map[string]any, []string, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyQueryTimeout)
	defer cancel()
	if limit <= 0 || limit > readOnlyQueryMaxRows {
		limit = readOnlyQueryMaxRows
	}
	// The callers' gates read the text with comments stripped, so a statement
	// followed by a comment or a second `;` passes them; the driver gets the
	// text it can run.
	query, ok := sqlRunnableText(query)
	if !ok {
		return nil, nil, false, errNoSQLStatement
	}
	conn, key, closeConn, err := openReadOnlyQueryConn(ctx, db)
	if err != nil {
		return nil, nil, false, err
	}
	defer closeConn()

	start := time.Now()
	rows, err := conn.QueryContext(ctx, query, args...)
	incDBQuery()
	metricDBLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		return nil, nil, false, err
	}
	cols, _ := rows.Columns()
	// Read one extra row to distinguish exactly-at-limit from truncated.
	result, err := scanRowsLimitHookDecrypt(rows, key, limit+1, nil, decrypt)
	if err != nil {
		return nil, nil, false, err
	}
	truncated := len(result) > limit
	if truncated {
		result = result[:limit]
	}
	return result, cols, truncated, nil
}

func openReadOnlyQueryConn(ctx context.Context, db *sql.DB) (conn *sql.Conn, key []byte, closeConn func(), err error) {
	conn, err = db.Conn(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = conn.Raw(func(raw any) error {
		sqlite, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("read-only query requires the SQLite authorizer")
		}
		// A pooled connection must not lend an earlier caller's uncommitted
		// data or transaction authority to this read. Discard dirty state.
		if !sqlite.AutoCommit() {
			return driver.ErrBadConn
		}
		if keys := cryptoKeysForDBPath(sqlite.GetFilename("main")); keys != nil {
			key = keys.aes
		} else if !isolateAppEnvironment.Load() {
			key = appEncryptionKey
		}
		return nil
	}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	var wasReadOnly bool
	if err = conn.QueryRowContext(ctx, "PRAGMA query_only").Scan(&wasReadOnly); err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	var closeOnce sync.Once
	closeConn = func() {
		closeOnce.Do(func() {
			_ = conn.Raw(func(raw any) error {
				sqlite, ok := raw.(*sqlite3.SQLiteConn)
				if !ok {
					return driver.ErrBadConn
				}
				// Canonical flow cleanup rolls back its own transaction first.
				// Unexpected transaction state must never reenter the pool.
				if !sqlite.AutoCommit() {
					return driver.ErrBadConn
				}
				// Back to the connection's default authorizer (the storage ceiling
				// guard), never none: this pooled connection runs app SQL next.
				restoreConnAuthorizer(sqlite)
				restore := "PRAGMA query_only=OFF"
				if wasReadOnly {
					restore = "PRAGMA query_only=ON"
				}
				// Raw cleanup outlives request cancellation. ErrBadConn discards
				// the connection rather than returning unsafe state to the pool.
				if _, err := sqlite.Exec(restore, nil); err != nil {
					return driver.ErrBadConn
				}
				return nil
			})
			_ = conn.Close()
		})
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		closeConn()
		return nil, nil, nil, err
	}
	if err = conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeReadOnlyQuery)
		return nil
	}); err != nil {
		closeConn()
		return nil, nil, nil, err
	}
	return conn, key, closeConn, nil
}

func authorizeReadOnlyQuery(action int, arg1, arg2, database string) int {
	switch action {
	case sqlite3.SQLITE_READ:
		if readOnlyQueryMaskedColumn(arg1, arg2) {
			// SQLITE_IGNORE makes the column read as NULL, so ordinary
			// queries over framework tables keep working.
			return sqlite3.SQLITE_IGNORE
		}
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_SELECT, sqliteRecursiveSelect:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_FUNCTION:
		if !strings.EqualFold(arg2, "load_extension") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_UPDATE:
		// Connecting an existing virtual table authorizes synthetic schema
		// updates. query_only still forbids an actual write to these tables.
		if arg1 == "sqlite_master" || arg1 == "sqlite_temp_master" {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_PRAGMA:
		// FTS checks the read-only data_version pragma when opening its index.
		if strings.EqualFold(arg1, "data_version") && arg2 == "" {
			return sqlite3.SQLITE_OK
		}
	}
	// Includes DML/DDL, PRAGMA, ATTACH/DETACH and transaction control.
	return sqlite3.SQLITE_DENY
}

// readOnlyMaskedColumnRe matches credential-bearing column names in the
// framework's own tables.
var readOnlyMaskedColumnRe = regexp.MustCompile(`(?i)(^|_)(password|passwd|secret|secrets|token|tokens|hash|otp|totp|backup|codes?|nonce|private|refresh|access|key|keys|salt|verifier|challenge)(_|$)`)

// readOnlyQueryMaskedColumn reports whether a read-only query (query_db,
// sql without write) must not see a column's value. query_db is a VIEWER
// tool: without this a viewer could read live session ids (a working login
// as any app user, including admins), password/reset/OTP hashes and TOTP
// secrets straight out of the framework tables. App tables are untouched.
func readOnlyQueryMaskedColumn(table, column string) bool {
	t := strings.ToLower(table)
	if !strings.HasPrefix(t, "_benmore_") {
		return false
	}
	c := strings.ToLower(column)
	if t == "_benmore_sessions" && (c == "id" || c == "" || c == "impersonator_session_id") {
		// Stored ids are hashes, but a row an older process wrote holds
		// the raw credential until it is rekeyed (auth_session_keys.go).
		// An impersonation row names the admin's own session the same way.
		return true
	}
	if t == "_benmore_broadcasts" && c == "publisher_session_id" {
		// The publisher's SFU session: what subscribers pull tracks from,
		// handed out only through the membership-checked subscribe route.
		return true
	}
	if t == "_benmore_idempotency" && c == "response" {
		// A stored create response is the row as its creator was shown it,
		// encrypted fields decrypted for that caller; a viewer reading the
		// app table itself sees ciphertext.
		return true
	}
	if t == "_benmore_jobs" && c == "payload" {
		// A job payload copies the written row (hidden columns, decrypted
		// encrypted fields) and env-derived enqueue values; json_extract
		// would reach any of them, so the whole column reads as NULL.
		// describe_jobs shows it redacted (redactJobPayloadForRead).
		return true
	}
	return readOnlyMaskedColumnRe.MatchString(c)
}

// isReadOnlyQuery does a conservative check for single-statement SELECT.
// It strips comments (string-literal-aware) and trailing whitespace/
// semicolons, requires the first keyword to be SELECT or WITH (for CTEs),
// and rejects anything containing multiple statements or a forbidden
// keyword ANYWHERE (incl. load_extension - that's RCE if the driver ever
// allows extensions). Word-level tokenization (M4, 2026-06-11 audit)
// replaces the old space-padded substring scan, which missed keywords
// followed by tabs/newlines/parens and didn't strip comments at all.
// String literals are scanned too - that's a deliberate false-positive
// trade-off (a literal containing "delete" is rejected); fail-closed is
// correct for this gate. SQLITE_LIMIT_ATTACHED=0 on the sqlite3_benmore
// driver backstops the ATTACH case at the engine level regardless.
func isReadOnlyQuery(sql string) bool {
	cleaned := strings.TrimSpace(stripSQLComments(sql))
	code := strings.TrimSuffix(strings.TrimSpace(stripSQLLiterals(cleaned)), ";")
	if strings.Contains(code, ";") {
		return false
	}
	upper := strings.ToUpper(strings.TrimSpace(cleaned))
	verbs := strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(code)), func(r rune) bool {
		return !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	if len(verbs) == 0 || (verbs[0] != "SELECT" && verbs[0] != "WITH") {
		return false
	}
	forbidden := map[string]bool{
		"DROP": true, "DELETE": true, "UPDATE": true, "INSERT": true,
		"ALTER": true, "CREATE": true, "TRUNCATE": true, "REPLACE": true,
		"ATTACH": true, "DETACH": true, "PRAGMA": true, "VACUUM": true,
		"REINDEX": true, "LOAD_EXTENSION": true,
	}
	for _, tok := range strings.FieldsFunc(upper, func(r rune) bool {
		return !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		if forbidden[tok] {
			return false
		}
	}
	return true
}
