//go:build !cli

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// The one implementation of "clear the app tables and run seeds.sql". Every
// path that runs seeds.sql goes through resetAppDataLocked: the dashboard and
// MCP reset_and_seed (data channel op reset_seed, app_data_ops_maintenance.go)
// and the testing-mode POST /api/_testing/reset (feedback_ui.go). Never run
// seed statements on the pool: that skips the transaction, the authorizer and
// the audit-table refusal below.

type appResetResult struct {
	Deletions map[string]int64 `json:"deletions"`
	SeedsRun  int              `json:"seeds_run"`
}

// appResetSeedsError is a reset refused or rolled back because of what
// seeds.sql holds (a statement that is not app-data DML or names an
// append-only audit table, one that fails, rows that break a foreign key),
// as opposed to a database or file error. Its text names the statement by
// number and never quotes it.
type appResetSeedsError struct{ err error }

func (e *appResetSeedsError) Error() string { return e.err.Error() }
func (e *appResetSeedsError) Unwrap() error { return e.err }

// resetAppDataLocked is the reset itself. The platform's callers hold the
// app's lifecycle lease (the router takes it, and the app's own process runs
// this: data channel op reset_seed); the testing reset runs in the app's own
// process with no router involved.
func resetAppDataLocked(ctx context.Context, db *sql.DB, dir string) (*appResetResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// seeds.sql is tenant-authored; bound the whole reset so a
	// non-terminating seed statement cannot pin a core.
	ctx, cancelReset := context.WithTimeout(ctx, appResetDeadline)
	defer cancelReset()
	data, err := readTenantSeeds(dir)
	if err != nil {
		return nil, fmt.Errorf("read seeds.sql before reset: %w", err)
	}
	var seeds []string
	if err := splitSQLStatements(strings.NewReader(string(data)), func(stmt string) error {
		words := strings.Fields(stripSQLComments(stmt))
		if len(words) == 0 {
			return nil
		}
		// Under `compliance: hipaa` no seed statement may name an audit
		// table, whatever it does with it (audit_append_only.go). The
		// authorizer below already denies the writes and the DDL; this
		// also covers a read and says why.
		if err := refuseAuditTableStatement(db, stmt); err != nil {
			return fmt.Errorf("seed statement %d: %w", len(seeds)+1, err)
		}
		if !allowedRestoreVerbs[strings.ToUpper(words[0])] {
			return fmt.Errorf("seed statement %d must be app-data INSERT, UPDATE, DELETE, REPLACE or WITH; reset owns the transaction", len(seeds)+1)
		}
		seeds = append(seeds, stmt)
		return nil
	}); err != nil {
		return nil, &appResetSeedsError{fmt.Errorf("parse seeds.sql before reset: %w", err)}
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Raw(func(raw any) error {
		if _, ok := sqliteConnOf(raw); !ok {
			return fmt.Errorf("app reset requires SQLite transaction protection")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// A pinned connection lets the SQLite authorizer prevent seed SQL from
	// committing/rolling back our transaction or changing connection settings.
	// Cleanup runs outside the canceled request and discards an unrepairable
	// connection instead of returning an open transaction to the shared pool.
	defer conn.Raw(func(raw any) error {
		sqlite := mustSQLiteConn(raw)
		// The pooled connection keeps its default authorizer (the storage
		// ceiling guard); clearing it would let later app SQL lift the ceiling.
		restoreConnAuthorizer(sqlite)
		if !sqlite.AutoCommit() {
			if _, err := sqlite.Exec("ROLLBACK", nil); err != nil {
				return driver.ErrBadConn
			}
		}
		return nil
	})
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("begin reset: %w", err)
	}
	// Keep foreign keys enforced, but permit parent/child seed order within
	// the batch. The final graph must be valid before any changes can commit.
	if _, err := conn.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON"); err != nil {
		return nil, err
	}
	rows, err := conn.QueryContext(ctx, `SELECT p.name FROM pragma_table_list p
		WHERE p.schema='main' AND p.type='table'
		AND lower(p.name) NOT GLOB 'sqlite_*' AND lower(p.name) NOT GLOB '_benmore_*'
		AND NOT (substr(p.name,-8)='_history' AND
			(SELECT COUNT(*) FROM pragma_table_info(p.name)
			WHERE name IN ('_version','_valid_from','_valid_to','_changed_by','_change_type'))=5)
		ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("list reset tables: %w", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	result := &appResetResult{Deletions: map[string]int64{}}
	// Count before any deletion so cascaded children are counted accurately.
	for _, name := range names {
		var count int64
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(name)).Scan(&count); err != nil {
			return nil, err
		}
		result.Deletions[name] = count
	}
	if err := conn.Raw(func(raw any) error { mustSQLiteConn(raw).RegisterAuthorizer(authorizeAppReset); return nil }); err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, err := conn.ExecContext(ctx, "DELETE FROM "+quoteIdent(name)); err != nil {
			return nil, fmt.Errorf("clear %s (reset rolled back): %w", name, err)
		}
	}
	for i, stmt := range seeds {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return nil, &appResetSeedsError{fmt.Errorf("seed statement %d (reset rolled back; seeds must contain app-data DML only): %w", i+1, err)}
		}
		result.SeedsRun++
	}
	if err := conn.Raw(func(raw any) error { restoreConnAuthorizer(mustSQLiteConn(raw)); return nil }); err != nil {
		return nil, err
	}
	violations, err := conn.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	invalid := violations.Next()
	checkErr := violations.Err()
	violations.Close()
	if checkErr != nil {
		return nil, checkErr
	}
	if invalid {
		return nil, &appResetSeedsError{fmt.Errorf("seed data violates foreign keys; reset rolled back")}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, fmt.Errorf("commit reset: %w", err)
	}
	return result, nil
}

func authorizeAppReset(action int, arg1, arg2, database string) int {
	switch action {
	case sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqliteRecursiveSelect:
		return sqlite3.SQLITE_OK
	case sqlite3.SQLITE_FUNCTION:
		if !strings.EqualFold(arg2, "load_extension") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE:
		name := strings.ToLower(arg1)
		if action == sqlite3.SQLITE_UPDATE && name == "sqlite_master" {
			return sqlite3.SQLITE_OK // SQLite's synthetic update when opening FTS.
		}
		if database == "main" && !strings.HasPrefix(name, "_benmore_") && !strings.HasPrefix(name, "sqlite_") {
			return sqlite3.SQLITE_OK
		}
	case sqlite3.SQLITE_PRAGMA:
		// FTS loads its connection-local index through this read-only pragma.
		if strings.EqualFold(arg1, "data_version") && arg2 == "" {
			return sqlite3.SQLITE_OK
		}
	}
	return sqlite3.SQLITE_DENY
}

// maxSeedsBytes bounds the seed file the router reads into memory.
const maxSeedsBytes = 256 << 20

// readTenantSeeds reads the app's seeds.sql for a reset, which runs the
// statements against that app's database. The file is the tenant's: it is
// read only as the regular file in that directory (treeDir), never through a
// link to a file somewhere else, and not past maxSeedsBytes. A missing file
// is an empty seed.
func readTenantSeeds(dir string) ([]byte, error) {
	top, err := openTreeDir(dir)
	if err != nil {
		return nil, err
	}
	defer top.Close()
	f, _, err := top.openRegular("seeds.sql")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSeedsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSeedsBytes {
		return nil, fmt.Errorf("seeds.sql is larger than %d MiB", maxSeedsBytes>>20)
	}
	return data, nil
}
