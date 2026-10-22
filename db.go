//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	RegisterEncryptedSQLiteDriver()
}

// OpenDB opens the app database. Uses DATABASE_URL env var if set (for remote SQLite/Turso),
// otherwise creates a local data.db in the app directory.
func OpenDB(dir string) (*sql.DB, error) {
	return openDBWithEnv(dir, nil)
}

func openDBWithEnv(dir string, appEnv map[string]string) (*sql.DB, error) {
	return openDBWithPolicyLock(dir, appEnv, nil, false)
}

// openDBWithPolicyLease is used by loadApp while it already owns the per-app
// policy/file lease. Corruption recovery reuses that held lease.
func openDBWithPolicyLease(dir string, appEnv map[string]string, lease *appMCPAuthorityLease) (*sql.DB, error) {
	return openDBWithPolicyLock(dir, appEnv, lease, true)
}

func openDBWithPolicyLock(dir string, appEnv map[string]string, lease *appMCPAuthorityLease, policyHeld bool) (*sql.DB, error) {
	if foreignAppDirs.Load() {
		return openForeignAppDB(dir, appEnv)
	}
	dbURL := resolveDatabaseURLWithEnv(dir, appEnv)
	cfg := buildDBOpenConfigWithEnv(dir, dbURL, appEnv)
	if cfg.Backend == DatabaseBackendPostgres {
		return nil, unsupportedPostgresRuntimeError(detectedPostgresScheme(dbURL))
	}

	db, err := sql.Open(cfg.DriverName, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		// If the file is irrecoverably corrupt (the classic "file is
		// not a database" / "database disk image is malformed" pair),
		// try to auto-restore from the most recent pre-migrate backup.
		// Pre-v2.7.8 the agent would loop forever - log.Fatalf →
		// systemd restart → same corrupt file → log.Fatalf → ... - and
		// the user had to delete + recreate the entire app to escape.
		// Now we look for backups/pre-migrate-*.db, sorted newest-
		// first, and try each one until something opens successfully.
		// The corrupt original is moved to data.db.corrupt-<timestamp>
		// so a human can post-mortem it; the backup becomes the new
		// data.db. Logged loudly so the operator knows recovery
		// happened.
		if cfg.LocalSQLite && isCorruptDBErr(err) {
			var recovered bool
			var rErr error
			if policyHeld {
				recovered, rErr = autoRestoreFromBackupInternal(dir, err, lease, true)
			} else {
				recovered, rErr = autoRestoreFromBackup(dir, err)
			}
			if rErr == nil && recovered {
				log.Printf("DB AUTO-RECOVERY: %s - restored from most recent pre-migrate backup, original moved to data.db.corrupt-*", dir)
				_ = db.Close()
				// Re-open with the same DSN; the file underneath is now the backup.
				db, err = sql.Open(cfg.DriverName, cfg.DSN)
				if err != nil {
					return nil, fmt.Errorf("re-open after recovery: %w", err)
				}
				if err := db.Ping(); err != nil {
					return nil, fmt.Errorf("ping after recovery (backup is also bad?): %w", err)
				}
				// Fall through to the connection-pool setup below.
			} else {
				return nil, fmt.Errorf("ping database (corrupt + no usable backup): %w", err)
			}
		} else {
			return nil, fmt.Errorf("ping database: %w", err)
		}
	}

	// Ping() only opens the file + reads the schema cookie; it does NOT walk the
	// b-tree, so page-level corruption ("2nd reference to page N", "database disk
	// image is malformed") slips past the check above and only detonates LATER -
	// when VACUUM INTO (the pre-migrate backup) or a query walks the pages. On
	// prod that backup failure is fatal, so systemd restart-loops the unit
	// (a real outage: the counter hit 86 before manual recovery). Probe with a
	// cheap quick_check up front and route any corruption to the SAME
	// auto-recovery + reopen the failed-Ping branch above uses.
	if cfg.LocalSQLite {
		if qcErr := sqliteQuickCheck(db); qcErr != nil {
			log.Printf("DB CORRUPTION (quick_check) in %s: %v", dir, qcErr)
			repaired := false
			// 1) Try an in-place REINDEX FIRST. INDEX corruption ("wrong # of
			//    entries in index", "row N missing from index") rebuilds from the
			//    intact table data with ZERO data loss - and restoring from a
			//    backup does NOT fix it because the backups carry the same stale
			//    index, so a restore-first policy crash-LOOPS (observed on
			//    _platform: restore → same bad index → restore → …).
			if _, rxErr := db.Exec("REINDEX"); rxErr == nil && sqliteQuickCheck(db) == nil {
				log.Printf("DB REPAIR: %s - rebuilt indexes via REINDEX (no data loss)", dir)
				repaired = true
			}
			// 2) Still bad → structural/table b-tree corruption REINDEX can't fix
			//    (malformed / 2nd-reference-to-page) → restore from the newest
			//    VALID backup (autoRestoreFromBackup validates each candidate).
			if !repaired {
				log.Printf("DB CORRUPTION in %s not fixable by REINDEX - attempting backup auto-recovery", dir)
				_ = db.Close()
				var recovered bool
				var rErr error
				if policyHeld {
					recovered, rErr = autoRestoreFromBackupInternal(dir, qcErr, lease, true)
				} else {
					recovered, rErr = autoRestoreFromBackup(dir, qcErr)
				}
				if rErr == nil && recovered {
					log.Printf("DB AUTO-RECOVERY: %s - restored from most recent valid backup; corrupt original moved to data.db.corrupt-*", dir)
				} else {
					// No usable backup. Reopen the original rather than returning
					// a nil db - the app boots degraded instead of crashing on a
					// nil handle, and a human can recover via `benmore restore`.
					log.Printf("DB AUTO-RECOVERY could not restore %s (%v) - reopening original; recover with `benmore restore`", dir, rErr)
				}
				db, err = sql.Open(cfg.DriverName, cfg.DSN)
				if err != nil {
					return nil, fmt.Errorf("re-open after corruption recovery: %w", err)
				}
				if err := db.Ping(); err != nil {
					return nil, fmt.Errorf("ping after corruption recovery: %w", err)
				}
			}
		}
	}

	// Connection pool settings: smaller for hosted tenants (db_pool.go).
	applyAppDBPoolLimits(db, currentAppDBPoolLimits())

	// Tighten file modes on the local DB + WAL/SHM siblings. Mode 0660
	// (owner+group RW, others none): the per-app user owns the file, and a
	// shared group can cover other trusted first-party readers (e.g. a
	// reverse proxy / admin process) for analytics/runtime views. Sibling tenants run
	// under distinct UIDs in distinct primary groups, so "others" (0)
	// blocks cross-tenant reads.
	//
	// SQLite creates these with the OS default umask (typically 0644 -
	// world-readable). Best-effort: ignore errors on remote DBs (Turso).
	if cfg.LocalSQLite {
		dbPath := filepath.Join(dir, "data.db")
		for _, suffix := range []string{"", "-wal", "-shm"} {
			os.Chmod(dbPath+suffix, 0660)
		}
	}

	return db, nil
}

// LoadSchema reads the app's schema definition and executes it against
// the database. Source-of-truth precedence:
//  1. schema.prisma - Prisma DSL, compiled to SQL by prisma_schema.go.
//     This is the recommended shape for new apps; the agent has seen
//     thousands of these in training.
//  2. schema.sql - raw SQLite DDL. Still supported for hand-tuned
//     schemas or when the Prisma subset doesn't express what's needed
//     (e.g. CHECK constraints, custom triggers).
//
// If both files exist, schema.prisma wins. The compiled SQL is stored
// in memory only - we don't write it back to disk to avoid confusing
// "where did this file come from" moments.
// LoadSchema parses + applies the schema and returns (tables, deferredDDL).
// deferredDDL holds CREATE [UNIQUE] INDEX / VIEW / TRIGGER statements that
// were NOT executed here because they can reference columns Migrate() (run
// by the caller right after) is about to ADD. The caller applies them via
// ApplyDeferredDDL AFTER Migrate. Pre-v2.7.140 these ran inline, so the first
// push of a schema that added a column AND an index on it failed the index
// ("no such column") and only converged on the second push.
func LoadSchema(db *sql.DB, dir string) ([]Table, []string, error) {
	return loadSchemaWithReader(db, dir, func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, name))
	}, false)
}

func loadSchemaWithReader(db *sql.DB, dir string, readSource func(string) ([]byte, error), runtimeJournal bool) ([]Table, []string, error) {
	schemaSQL := ""
	var prismaModels []PrismaModel
	if data, err := readSource("schema.prisma"); err == nil {
		models, perr := ParsePrismaSchema(string(data))
		if perr != nil {
			return nil, nil, fmt.Errorf("schema.prisma: %w", perr)
		}
		prismaModels = models
		schemaSQL = EmitSQL(models)
		// Generation, its safety backup, execution and the ledger must all
		// succeed before the candidate schema can be published.
		if name, err := applyPrismaMigration(db, dir, string(data), runtimeJournal); err != nil {
			return nil, nil, fmt.Errorf("Prisma migration: %w", err)
		} else if name != "" {
			if runtimeJournal {
				fmt.Fprintf(os.Stderr, "migration: recorded DB journal %s\n", name)
			} else {
				fmt.Fprintf(os.Stderr, "migration: wrote migrations/%s\n", name)
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read schema.prisma: %w", err)
	}

	if schemaSQL == "" {
		data, err := readSource("schema.sql")
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("read schema.sql: %w", err)
		}
		schemaSQL = string(data)
	}

	// Parse tables from CREATE TABLE statements before executing
	tables := ParseCreateTables(schemaSQL)
	// Carry the accepted source contract with the immutable schema generation;
	// request validation must not reread pending source edits or infer Prisma
	// declarations from SQLite's permissive physical column affinities.
	for ti := range tables {
		for _, model := range prismaModels {
			if model.Table != tables[ti].Name {
				continue
			}
			for ci := range tables[ti].Columns {
				for _, field := range model.Fields {
					if field.Column == tables[ti].Columns[ci].Name {
						tables[ti].Columns[ci].prismaScalar = true
						break
					}
				}
			}
		}
	}

	// Execute schema. Auto-inject IF NOT EXISTS into CREATE TABLE / INDEX /
	// VIEW / TRIGGER statements so hot-reloads are idempotent. Without this,
	// any reload after the first would fail with "table already exists" -
	// breaks the entire MCP-first workflow where every LLM file edit
	// triggers a hot reload. Per-column migrations (ADD COLUMN for new
	// columns on existing tables) are handled separately in Migrate().
	statements := splitStatements(schemaSQL)
	var deferred []string
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		stmt = ensureIfNotExists(stmt)
		// Defer index/view/trigger creation - they can reference columns
		// Migrate() (the caller, post-LoadSchema) is about to ADD. The
		// caller applies these after Migrate via ApplyDeferredDDL.
		if isDeferredDDL(stmt) {
			deferred = append(deferred, stmt)
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return tables, deferred, fmt.Errorf("execute schema statement: %s: %w", truncate(stmt, 80), err)
		}
	}

	return tables, deferred, nil
}

// isDeferredDDL reports whether a schema statement creates an index, view, or
// trigger - DDL that may depend on columns added by a later Migrate() pass,
// so LoadSchema defers it for the caller to apply after migration.
func isDeferredDDL(stmt string) bool {
	u := strings.ToUpper(strings.TrimLeft(stmt, " \t\n"))
	return strings.HasPrefix(u, "CREATE INDEX ") ||
		strings.HasPrefix(u, "CREATE UNIQUE INDEX ") ||
		strings.HasPrefix(u, "CREATE VIEW ") ||
		strings.HasPrefix(u, "CREATE TRIGGER ")
}

// ApplyDeferredDDL runs the index/view/trigger statements LoadSchema deferred,
// AFTER Migrate() has added any new columns. Statements are idempotent
// (ensureIfNotExists already applied). Return the first error after attempting
// all statements so reload can retain its current configuration on failure.
func ApplyDeferredDDL(db *sql.DB, deferred []string) error {
	if err := reconcilePrismaUpdatedAtTriggers(db, deferred); err != nil {
		return err
	}
	var firstErr error
	for _, stmt := range deferred {
		if _, err := db.Exec(stmt); err != nil {
			log.Printf("  schema DDL deferred-apply failed (retried next reload): %s: %s", truncate(stmt, 60), err)
			if firstErr == nil {
				firstErr = fmt.Errorf("deferred schema DDL: %w", err)
			}
		}
	}
	return firstErr
}

// ensureIfNotExists rewrites raw CREATE statements to use IF NOT EXISTS so
// schema reloads are idempotent. Handles CREATE TABLE, CREATE INDEX,
// CREATE UNIQUE INDEX, CREATE VIEW, and CREATE TRIGGER. Statements that
// already have IF NOT EXISTS are returned unchanged. This is the schema
// load equivalent of the framework's existing CREATE TABLE IF NOT EXISTS
// usage in db.go for system tables (_benmore_*).
func ensureIfNotExists(stmt string) string {
	trimmed := strings.TrimLeft(stmt, " \t\n")
	upper := strings.ToUpper(trimmed)
	// Patterns we'll inject IF NOT EXISTS into. Order matters - match the
	// most specific (CREATE UNIQUE INDEX) before the less specific (CREATE INDEX).
	patterns := []struct {
		prefix string
	}{
		{"CREATE TABLE "},
		{"CREATE UNIQUE INDEX "},
		{"CREATE INDEX "},
		{"CREATE VIEW "},
		{"CREATE TRIGGER "},
		{"CREATE TEMPORARY TABLE "},
		{"CREATE TEMP TABLE "},
		{"CREATE VIRTUAL TABLE "},
	}
	for _, p := range patterns {
		if strings.HasPrefix(upper, p.prefix) {
			rest := trimmed[len(p.prefix):]
			restUpper := strings.ToUpper(strings.TrimLeft(rest, " "))
			if strings.HasPrefix(restUpper, "IF NOT EXISTS") {
				// Already has it
				return stmt
			}
			// Rebuild while preserving the leading whitespace from the original
			leadingWS := stmt[:len(stmt)-len(trimmed)]
			return leadingWS + trimmed[:len(p.prefix)] + "IF NOT EXISTS " + rest
		}
	}
	return stmt
}

// DetectUUIDTables scans parsed tables and returns a set of table names that use TEXT primary keys (UUIDs).
// A table is considered UUID if its PK column has type TEXT.
func DetectUUIDTables(tables []Table) map[string]bool {
	result := make(map[string]bool)
	for _, t := range tables {
		for _, col := range t.Columns {
			if col.PK && strings.ToUpper(col.Type) == "TEXT" {
				result[t.Name] = true
				break
			}
		}
	}
	return result
}

// LoadSeeds reads seeds.sql and executes it.
func LoadSeeds(db *sql.DB, dir string) error {
	seedPath := filepath.Join(dir, "seeds.sql")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read seeds.sql: %w", err)
	}

	statements := splitStatements(string(data))
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("execute seed: %s: %w", truncate(stmt, 80), err)
		}
	}
	return nil
}

// QueryRows executes a SQL query and returns results as a slice of maps.
type mutationQuerier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}
type sqlExecutor interface {
	Exec(string, ...any) (sql.Result, error)
}
type mutationTx interface {
	mutationQuerier
	sqlExecutor
}

func QueryRows(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWith(db, query, args...)
}

func queryRowsWith(db mutationQuerier, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWithKey(db, cryptoKeyForQuerier(db), query, args...)
}

func queryRowsWithMainKey(db mutationQuerier, query string, args ...any) ([]map[string]any, error) {
	if bound, ok := db.(appMCPContextTx); !ok || !bound.private {
		return queryRowsWith(db, query, args...)
	}
	key, err := cryptoKeyForQuerierMainChecked(db)
	if err != nil {
		return nil, err
	}
	return queryRowsWithKey(db, key, query, args...)
}

func queryRowsWithKey(db mutationQuerier, key []byte, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWithKeyContext(context.Background(), db, key, query, args...)
}

// QueryRowsContext is QueryRows bound to ctx (typically r.Context()), so a
// client that disconnects cancels its query; the default statement deadline
// (queryDeadline) still applies on top.
func QueryRowsContext(ctx context.Context, db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWithKeyContext(ctx, db, cryptoKeyForQuerier(db), query, args...)
}

// queryRowsWithKeyContext runs the query and scans it. On a *sql.DB (the
// auto-CRUD, flow and admin read path, where request input shapes the SQL)
// the statement gets the default deadline: mattn/go-sqlite3 interrupts the
// running statement when the context ends, so a pathological ?sort= or
// filter over a large table returns "context deadline exceeded" instead of
// pinning a pool connection indefinitely. Transactions are left alone: an
// interrupted write inside an explicit transaction makes SQLite roll the
// whole transaction back, and their lock time is bounded by the
// transaction's own context.
//
// Every QueryRows variant ends here, and many of them carry SQL the framework
// did not write (flow, hook and template SQL, tool input, filters): the text
// is run in the form the driver can run (sqlRunnableText).
func queryRowsWithKeyContext(ctx context.Context, db mutationQuerier, key []byte, query string, args ...any) ([]map[string]any, error) {
	return queryRowsWithKeyContextDecrypt(ctx, db, key, nil, query, args...)
}

// A non-nil decoder is an explicit policy supplied by a framework-authored
// projection. nil retains the existing generic authored-SQL compatibility.
func queryRowsWithKeyContextDecrypt(ctx context.Context, db mutationQuerier, key []byte, decrypt rowDecryptFunc, query string, args ...any) ([]map[string]any, error) {
	query, ok := sqlRunnableText(query)
	if !ok {
		return nil, errNoSQLStatement
	}
	start := time.Now()
	if _, ok := db.(*sql.DB); ok {
		var cancel context.CancelFunc
		ctx, cancel = withQueryDeadline(ctx)
		defer cancel() // after scanning: the rows stay bound to ctx while read
	}
	var rows *sql.Rows
	var err error
	var step *firstStepContext
	cq, hasCtx := db.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	})
	if hasCtx && ctx.Done() != nil {
		step = newFirstStepContext(ctx)
		rows, err = cq.QueryContext(step, query, args...)
	} else {
		rows, err = db.Query(query, args...)
	}
	incDBQuery()
	metricDBLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		return nil, err
	}
	return scanRowsLimitHookDecrypt(rows, key, 0, step.disarm, decrypt)
}

// scanRows converts *sql.Rows into a slice of maps. Closes rows when done.
// Used by QueryRows and transactional flow steps.
//
// Type coercion happens here so every downstream consumer (CRUD JSON
// responses, flow `{{step.field}}` interpolation, hooks) sees the right
// Go type:
//
//   - []byte    → string (SQLite default for TEXT)
//   - BOOLEAN   → bool   (declared as Boolean in schema.prisma → stored
//     as 0/1 by SQLite → coerced back so JSON emits
//     true/false, avoiding the `0 && <X/>` React
//     gotcha where falsy SQLite booleans render "0")
//
// The column-type lookup happens once per result set (not per row).
func scanRows(rows *sql.Rows, key []byte) ([]map[string]any, error) {
	return scanRowsLimit(rows, key, 0)
}

// scanRowsLimit stops reading after limit rows; zero preserves unbounded callers.
func scanRowsLimit(rows *sql.Rows, key []byte, limit int) ([]map[string]any, error) {
	return scanRowsLimitHook(rows, key, limit, nil)
}

// scanRowsLimitHook is scanRowsLimit with afterFirst called once, right after
// the first row arrives (firstStepContext.disarm).
func scanRowsLimitHook(rows *sql.Rows, key []byte, limit int, afterFirst func()) ([]map[string]any, error) {
	return scanRowsLimitHookDecrypt(rows, key, limit, afterFirst, nil)
}

type rowDecryptFunc func(map[string]any, []byte)

func scanRowsLimitHookDecrypt(rows *sql.Rows, key []byte, limit int, afterFirst func(), decrypt rowDecryptFunc) ([]map[string]any, error) {
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Per-column type metadata derived once per result set. SQLite's
	// DatabaseTypeName() returns the schema-declared type (from CREATE
	// TABLE), which is what we want to drive both:
	//   - BOOLEAN coercion of 0/1 → false/true, including decrypted strings
	//   - INTEGER/REAL coercion of decrypted ciphertext strings back
	//     to numeric (v2.7.57+ for encrypted-integer support)
	//
	// For an INTEGER/REAL column that's encrypted, the on-disk value
	// is TEXT (the enc:v1:<hex> ciphertext). After DecryptRowFields
	// rewrites the row entry to plaintext (always a string), we then
	// coerce that string back to the declared numeric type - so the
	// API consumer sees a clean number, not "50000".
	colTypes, _ := rows.ColumnTypes()
	isBool := make([]bool, len(cols))
	numericKind := make([]byte, len(cols)) // 0=text, 'i'=int, 'f'=float
	for i, ct := range colTypes {
		if ct == nil {
			continue
		}
		tn := strings.ToUpper(ct.DatabaseTypeName())
		switch {
		case tn == "BOOLEAN":
			isBool[i] = true
		// SQLite type affinity rules (subset relevant for encrypted
		// numeric round-trip): anything containing "INT" → integer
		// affinity; anything containing "REAL", "FLOA", "DOUB" → real
		// affinity; NUMERIC + DECIMAL stay NUMERIC.
		case strings.Contains(tn, "INT"):
			numericKind[i] = 'i'
		case strings.Contains(tn, "REAL"), strings.Contains(tn, "FLOA"), strings.Contains(tn, "DOUB"):
			numericKind[i] = 'f'
		case strings.Contains(tn, "NUM"), strings.Contains(tn, "DEC"):
			// NUMERIC/DECIMAL - treat as float for safe coercion.
			numericKind[i] = 'f'
		}
	}

	results := make([]map[string]any, 0)
	// One scan buffer per result set: Scan into *any copies []byte values
	// (database/sql clones them for interface destinations) and every value
	// is moved into the row map below, so reusing the slots is safe.
	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	for rows.Next() {
		if afterFirst != nil {
			afterFirst()
			afterFirst = nil
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			v := values[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			// time.Time normalisation (v2.7.60+): some go-sqlite3
			// connection configurations auto-parse DATETIME columns
			// into time.Time on Scan even into `*any` destinations
			// (notably when the column's declared type matches the
			// DATE/TIME/TIMESTAMP affinity list and a _loc parameter
			// is set on the DSN). For a NULL value that path can
			// silently produce the Go zero time.Time, which
			// json.Marshal then serialises as the string
			// "0001-01-01T00:00:00Z" - a clear-as-day bug where a
			// nullable DateTime column appears non-null over the API.
			//
			// Normalise here so EVERY scan path returns:
			//   zero time.Time   → nil  (JSON null - matches the
			//                       NULL semantic of the source row)
			//   non-zero time.Time → RFC3339Nano string (matches the
			//                       coerceSQLValue convention used by
			//                       loadInsertedRow, so a fresh GET
			//                       and a post-insert read see the
			//                       same shape)
			if tv, ok := v.(time.Time); ok {
				if tv.IsZero() {
					v = nil
				} else {
					v = tv.UTC().Format(time.RFC3339Nano)
				}
			}
			row[col] = v
		}
		if decrypt == nil {
			DecryptRowFields(row, key)
		} else {
			decrypt(row, key)
		}
		// Declared-type coercion runs AFTER decryption - that's the whole
		// point: the ciphertext lived as TEXT in a column declared
		// INTEGER/REAL, and after decryption the plaintext is a
		// string we need to coerce back to its declared type.
		//
		// Skipped when the value is already numeric (no-op for
		// unencrypted INTEGER columns where SQLite already gave us
		// an int64) or nil. A parse failure leaves the string in
		// place - that's "we tried, it didn't look numeric, the
		// caller sees the text" and is safer than dropping the
		// value or panicking.
		for i, col := range cols {
			if isBool[i] {
				// Encryption stores even BOOLEAN values as ciphertext TEXT.
				// Decode after decryption so false cannot escape as truthy "0".
				switch v := row[col].(type) {
				case int64:
					row[col] = v != 0
				case float64:
					row[col] = v != 0
				case string:
					if b, err := strconv.ParseBool(v); err == nil {
						row[col] = b
					}
				}
				// bool and NULL are already canonical. Invalid plaintext and
				// decryption-failure masks remain unchanged, never false.
				continue
			}
			if numericKind[i] == 0 {
				continue
			}
			s, ok := row[col].(string)
			if !ok {
				continue
			}
			switch numericKind[i] {
			case 'i':
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					row[col] = n
				}
			case 'f':
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					row[col] = f
				}
			}
		}
		results = append(results, row)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	return results, rows.Err()
}

// QuerySingle executes a query expected to return a single scalar value.
func QuerySingle(db *sql.DB, query string, args ...any) (any, error) {
	query, ok := sqlRunnableText(query)
	if !ok {
		return nil, errNoSQLStatement
	}
	var result any
	err := db.QueryRow(query, args...).Scan(&result)
	if err != nil {
		return nil, err
	}
	if b, ok := result.([]byte); ok {
		return string(b), nil
	}
	return result, nil
}

// GetTableNames returns all user table names from the database.
type crudTableDefinition struct {
	name       string
	virtual    bool
	columns    map[string]bool
	allColumns map[string]bool
}

var crudInternalName = regexp.MustCompile(`(?s)^(?:sqlite.|.benmore.)`)
var versionMetadataColumns = []string{"_version", "_valid_from", "_valid_to", "_changed_by", "_change_type"}

// Retained framework history is not an ordinary user table, even after its
// source model or versioning configuration is removed. A suffix alone is not
// enough: apps may legitimately own tables named something_history.
func isVersionHistoryDefinition(definition crudTableDefinition) bool {
	if !strings.HasSuffix(definition.name, "_history") {
		return false
	}
	for _, column := range versionMetadataColumns {
		if !definition.columns[column] {
			return false
		}
	}
	return true
}

// Shared eligibility for source preflight and the actual SQLite CRUD inventory.
func eligibleCRUDTables(definitions []crudTableDefinition) map[string]bool {
	virtuals := map[string]bool{}
	for _, definition := range definitions {
		if definition.virtual {
			virtuals[definition.name] = true
		}
	}
	eligible := map[string]bool{}
	for _, definition := range definitions {
		// SQLite LIKE folds ASCII only; preserve its eligibility semantics.
		internalName := sqliteIdentifierFold(definition.name)
		if crudInternalName.MatchString(internalName) || definition.virtual {
			continue
		}
		// A migration can create a table with any name. Auto-CRUD serves
		// only plain names: the name becomes a route pattern, a URL segment
		// and part of every statement the handlers build. Any other table
		// stays reachable from the app's own SQL and from the tools that
		// list every table (GetAllTableNames).
		if !membershipIdentRe.MatchString(definition.name) {
			continue
		}
		shadow := false
		for virtual := range virtuals {
			if strings.HasPrefix(definition.name, virtual+"_") {
				shadow = true
				break
			}
		}
		if shadow {
			continue
		}
		if isVersionHistoryDefinition(definition) {
			continue
		}
		eligible[definition.name] = true
	}
	return eligible
}

func readCRUDTableDefinitions(db *sql.DB) ([]crudTableDefinition, error) {
	rows, err := db.Query("SELECT name,COALESCE(sql,'') FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		return nil, err
	}
	var definitions []crudTableDefinition
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			rows.Close()
			return nil, err
		}
		definitions = append(definitions, crudTableDefinition{name: name, virtual: strings.HasPrefix(strings.ToUpper(statement), "CREATE VIRTUAL TABLE")})
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	for i := range definitions {
		definition := &definitions[i]
		if !strings.HasSuffix(definition.name, "_history") {
			continue
		}
		columns, err := db.Query("SELECT name,hidden FROM pragma_table_xinfo(?)", definition.name)
		if err != nil {
			return nil, err
		}
		definition.columns = map[string]bool{}
		definition.allColumns = map[string]bool{}
		for columns.Next() {
			var name string
			var hidden int
			if err := columns.Scan(&name, &hidden); err != nil {
				columns.Close()
				return nil, err
			}
			definition.allColumns[name] = true
			if hidden == 0 {
				definition.columns[name] = true
			}
		}
		scanErr := columns.Err()
		columns.Close()
		if scanErr != nil {
			return nil, scanErr
		}
	}
	return definitions, nil
}
func sqliteIdentifierFold(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, name)
}
func GetTableNames(db *sql.DB) ([]string, error) {
	definitions, err := readCRUDTableDefinitions(db)
	if err != nil {
		return nil, err
	}
	eligible := eligibleCRUDTables(definitions)
	var names []string
	for _, definition := range definitions {
		if eligible[definition.name] {
			names = append(names, definition.name)
		}
	}
	return names, nil
}

// GetAllTableNames returns every table including _benmore_* system tables.
// Used by the context graph extractor and dashboard schema browser which
// need to show user-facing system tables like _benmore_users.
func GetAllTableNames(db *sql.DB) ([]string, error) {
	return allTableNamesWith(db)
}

func allTableNamesWith(db mutationQuerier) ([]string, error) {
	rows, err := db.Query("SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// GetTableColumns returns column info for a table from the live database.
func GetTableColumns(db *sql.DB, table string) ([]Column, error) {
	return tableColumnsWith(db, table)
}
func tableColumnsWith(db mutationQuerier, table string) ([]Column, error) {
	return tableColumnsQuery(db.Query, table)
}

func mainTableColumnsWith(db mutationQuerier, table string) ([]Column, error) {
	if !isValidColumnName(table) {
		return nil, fmt.Errorf("invalid table name %q", table)
	}
	rows, err := db.Query("PRAGMA main.table_info(" + quoteIdent(table) + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := make([]Column, 0)
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, Column{Name: name, Type: colType, NotNull: notNull == 1, Default: defaultValue.String, PK: pk > 0})
	}
	return cols, rows.Err()
}
func tableColumnsQuery(query func(string, ...any) (*sql.Rows, error), table string) ([]Column, error) {
	// Callers pass names from routes and tool arguments; only a plain
	// identifier may reach the PRAGMA text.
	if !isValidColumnName(table) {
		return nil, fmt.Errorf("invalid table name %q", table)
	}
	rows, err := query("PRAGMA table_info(" + quoteIdent(table) + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []Column
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, Column{
			Name:    name,
			Type:    colType,
			NotNull: notNull == 1,
			Default: dflt.String,
			PK:      pk > 0,
		})
	}
	return cols, rows.Err()
}

// GetForeignKeys returns foreign key info for a table.
func GetForeignKeys(db *sql.DB, table string) (map[string]ForeignKey, error) {
	if !isValidColumnName(table) {
		return nil, fmt.Errorf("invalid table name %q", table)
	}
	rows, err := db.Query("PRAGMA foreign_key_list(" + quoteIdent(table) + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fks := make(map[string]ForeignKey)
	for rows.Next() {
		var id, seq int
		var refTable, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &refTable, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			return nil, err
		}
		fks[from] = ForeignKey{Table: refTable, Column: to}
	}
	return fks, rows.Err()
}

// EnsureUsersTable creates the internal users table if auth is needed.
// Default schema includes identity, auth, and lifecycle columns.
// Developers can extend by defining _benmore_users in schema.sql - the
// runtime merges, ensuring required columns exist without overwriting extras.
func EnsureUsersTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE,
		phone TEXT UNIQUE,
		password_hash TEXT,
		password_change_required INTEGER NOT NULL DEFAULT 0,
		first_name TEXT DEFAULT '',
		last_name TEXT DEFAULT '',
		avatar_url TEXT DEFAULT '',
		role TEXT DEFAULT 'user',
		verified INTEGER DEFAULT 0,
		deactivated_at DATETIME,
		last_login_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return err
	}
	// Add columns if missing (safe for existing databases that predate new defaults)
	ensureColumns := []string{
		"username TEXT UNIQUE",
		"phone TEXT UNIQUE",
		"first_name TEXT DEFAULT ''",
		"last_name TEXT DEFAULT ''",
		"avatar_url TEXT DEFAULT ''",
		"role TEXT DEFAULT 'user'",
		"verified INTEGER DEFAULT 0",
		"deactivated_at DATETIME",
		"last_login_at DATETIME",
		"password_change_required INTEGER NOT NULL DEFAULT 0",
	}
	for _, col := range ensureColumns {
		name := strings.Fields(col)[0]
		var count int
		db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name=?", name).Scan(&count)
		if count == 0 {
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE _benmore_users ADD COLUMN %s", col)); err != nil && name == "password_change_required" {
				return fmt.Errorf("ensure password-change gate: %w", err)
			}
		}
	}
	if err := ensureMFASetupNonce(db); err != nil {
		return err
	}
	if err := ensureSignInChallenges(db); err != nil {
		return err
	}
	ensureEmailGrandfathering(db)
	// Backfill usernames for existing users that predate the username column
	BackfillUsernames(db)
	// Case-insensitive uniqueness on email (2026-06-11 audit): the plain
	// UNIQUE above is case-sensitive, so A@x and a@x could coexist as two
	// accounts. New writes are normalized to lowercase at the auth layer;
	// this index closes the raw-SQL/hook path too. Best-effort: creation
	// fails (and is skipped) on a legacy DB that already holds case-dupes -
	// those need a manual merge first.
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_benmore_users_email_nocase ON _benmore_users(email COLLATE NOCASE) WHERE email IS NOT NULL AND email != ''")
	return nil
}

// BackfillUsernames generates usernames for any users that don't have one.
// Derives from email (local part) or falls back to "user-{id}".
func BackfillUsernames(db *sql.DB) {
	rows, err := db.Query("SELECT id, email FROM _benmore_users WHERE username IS NULL OR username = ''")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var email sql.NullString
		rows.Scan(&id, &email)
		var base string
		if email.Valid && email.String != "" {
			base = strings.Split(email.String, "@")[0]
			base = strings.ToLower(base)
		} else {
			base = fmt.Sprintf("user-%d", id)
		}
		username := GenerateUniqueUsername(db, base, id)
		db.Exec("UPDATE _benmore_users SET username = ? WHERE id = ?", username, id)
	}
}

// GenerateUniqueUsername creates a unique username from a base string.
// Appends -2, -3, etc. if the base is taken (by another user).
func GenerateUniqueUsername(db *sql.DB, base string, excludeID int64) string {
	// Sanitize: lowercase, alphanumeric + hyphens only
	var clean strings.Builder
	for _, c := range strings.ToLower(base) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			clean.WriteRune(c)
		}
	}
	candidate := strings.Trim(clean.String(), "-_.")
	if candidate == "" {
		candidate = "user"
	}

	// Try the base, then base-2, base-3, etc.
	attempt := candidate
	for i := 2; i < 1000; i++ {
		var count int
		db.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE username = ? AND id != ?", attempt, excludeID).Scan(&count)
		if count == 0 {
			return attempt
		}
		attempt = fmt.Sprintf("%s-%d", candidate, i)
	}
	return fmt.Sprintf("%s-%d", candidate, time.Now().UnixNano())
}

// EnsureRequiredUserFields scans page require="" attributes and ensures
// the referenced columns exist on _benmore_users. This prevents runtime
// errors when a developer adds require="plan:pro" but forgets to add
// the plan column - the framework detects and creates it automatically.
// validColumnNameRe validates SQL column names to prevent injection in ALTER TABLE statements.
var validColumnNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func EnsureRequiredUserFields(db *sql.DB, pages map[string]*Page) {
	needed := make(map[string]bool)
	for _, page := range pages {
		if page.Require == "" {
			continue
		}
		for _, req := range strings.Fields(page.Require) {
			parts := strings.SplitN(req, ":", 2)
			if len(parts) == 2 {
				needed[parts[0]] = true
			}
		}
	}
	for field := range needed {
		ensureUserColumn(db, field, "page require attribute")
	}
}

// EnsureSignupFieldColumns ensures every column listed in auth.signup_fields
// exists on _benmore_users. Without this the signup handler INSERTs against
// columns that don't exist yet, returning a generic "Server error" - which
// is what happens to anyone who sets `signup_fields: "name"` in app.yaml
// without manually editing the schema.
func EnsureSignupFieldColumns(db *sql.DB, signupFields string) {
	if signupFields == "" {
		return
	}
	reserved := map[string]bool{
		"":                         true,
		"email":                    true,
		"password":                 true,
		"password_hash":            true,
		"password_change_required": true,
		"username":                 true,
	}
	for _, field := range strings.Split(signupFields, ",") {
		field = strings.TrimSpace(field)
		if reserved[field] {
			continue
		}
		ensureUserColumn(db, field, "auth.signup_fields")
	}
}

// ensureUserColumn adds a TEXT column to _benmore_users if it doesn't
// already exist. Logs the source so it's clear where the implicit
// schema change came from.
func ensureUserColumn(db *sql.DB, field, source string) {
	if !validColumnNameRe.MatchString(field) {
		log.Printf("  users: skipping invalid column name '%s' (must match [a-zA-Z_][a-zA-Z0-9_]*)", field)
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name=?", field).Scan(&count)
	if count == 0 {
		db.Exec(fmt.Sprintf("ALTER TABLE _benmore_users ADD COLUMN %s TEXT DEFAULT ''", field))
		log.Printf("  users: auto-added column '%s' (referenced by %s)", field, source)
	}
}

// LoadUserFields loads all columns from _benmore_users for a given user ID.
// Returns a map suitable for injection into template context as {{user.field}}.
// Excludes password_hash for security.
func LoadUserFields(db *sql.DB, userID int64) map[string]any {
	rows, err := db.Query("SELECT * FROM _benmore_users WHERE id = ? LIMIT 1", userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil
	}

	if !rows.Next() {
		return nil
	}

	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil
	}

	// Fields that must NEVER be exposed via API or templates. Heuristic
	// denylist - see isSensitiveUserColumn in auth_http.go.
	result := make(map[string]any, len(cols))
	for i, col := range cols {
		if isSensitiveUserColumn(col) {
			continue
		}
		val := values[i]
		// Convert []byte to string for template rendering
		if b, ok := val.([]byte); ok {
			result[col] = string(b)
		} else {
			result[col] = val
		}
	}
	return result
}

// EnsureAuditLogTable creates the framework audit log table.
func EnsureAuditLogTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT NOT NULL,
		table_name TEXT NOT NULL,
		row_id TEXT,
		user_id INTEGER,
		user_email TEXT,
		old_values TEXT,
		new_values TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	// The admin behind a support-impersonation session. user_id/user_email
	// stay the impersonated account (whose data changed); these name who
	// actually acted. Zero / empty for every other row.
	db.Exec("ALTER TABLE _benmore_audit_log ADD COLUMN impersonator_user_id INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE _benmore_audit_log ADD COLUMN impersonator_email TEXT DEFAULT ''")
	// The audit log only grows, and every reader filtered or counted it with
	// a full scan: per-record history (versioning, admin row view) by
	// (table_name, row_id), a user's trail by user_id newest first, and the
	// dashboards' "last 24h" counts by created_at.
	db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_log_row ON _benmore_audit_log(table_name, row_id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON _benmore_audit_log(user_id, id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_log_time ON _benmore_audit_log(created_at)")
}

// insertAuditRow writes one audit row, adding the impersonating admin when
// the session is a support-impersonation session.
func insertAuditRow(db *sql.DB, action, table, rowID string, session *Session, oldJSON, newJSON string) {
	if err := insertAuditRowChecked(db, action, table, rowID, session, oldJSON, newJSON); err != nil {
		log.Printf("audit: %s on %s could not be recorded: %v", action, table, err)
	}
}

func insertAuditRowChecked(exec sqlExecutor, action, table, rowID string, session *Session, oldJSON, newJSON string) error {
	var userID int64
	var email string
	if session != nil {
		userID = session.UserID
		email = session.Email
	}
	if session != nil && session.ImpersonatorUserID != 0 {
		if _, err := exec.Exec(
			"INSERT INTO main._benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values, impersonator_user_id, impersonator_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			action, table, rowID, userID, email, oldJSON, newJSON, session.ImpersonatorUserID, session.ImpersonatorEmail,
		); err != nil {
			return err
		}
		return nil
	}
	_, err := exec.Exec(
		"INSERT INTO main._benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES (?, ?, ?, ?, ?, ?, ?)",
		action, table, rowID, userID, email, oldJSON, newJSON,
	)
	return err
}

// LogAudit records a CRUD mutation in the audit log.
//
// Encryption parity: when `app.Encrypted` is configured for `table`,
// the configured fields in `oldRow` / `newRow` are re-encrypted before
// JSON-marshal so the audit log never carries a plaintext copy of a
// column that's encrypted at rest in the source table. Also covers
// the `old_<col>` change-delta keys the framework includes inside
// `newRow` (so `new_values` JSON doesn't leak prior values either).
//
// Hidden columns (apiHiddenColumn: `*_secret`, `*_token`, credential
// hashes, blind indexes) are recorded as changed but never by value
// (redactAuditHiddenFields): the audit log is served to admins
// (/api/_audit, get_audit_log) and shipped to audit sinks, and a copy
// of a secret there outlives its rotation.
//
// Backward-compatible variant LogAuditDB exists for the few callers
// that don't have an *App in scope (the retention worker logs only
// metadata - counts, TTLs - so no encryption is needed).
func LogAudit(app *App, action, table, rowID string, session *Session, oldRow, newRow map[string]any) {
	var config *EncryptedFieldConfig
	if app != nil {
		config = app.Encrypted
	}
	var auditKey []byte
	if app != nil && config != nil {
		auditKey = cryptoKeyForQuerier(app.DB)
	}
	oldForAudit := redactAuditHiddenFields(app, table, encryptAuditFieldsCopy(config, table, oldRow, auditKey))
	newForAudit := redactAuditHiddenFields(app, table, encryptAuditFieldsCopy(config, table, newRow, auditKey))

	var oldJSON, newJSON string
	if oldForAudit != nil {
		b, _ := json.Marshal(oldForAudit)
		oldJSON = string(b)
	}
	if newForAudit != nil {
		b, _ := json.Marshal(newForAudit)
		newJSON = string(b)
	}

	if app == nil || app.DB == nil {
		return
	}
	insertAuditRow(app.DB, action, table, rowID, session, oldJSON, newJSON)
}

// LogAuditTx writes the same encrypted audit representation through the
// mutation transaction, returning serialization and insert failures so the
// caller can roll back the mutation.
func LogAuditTx(tx mutationTx, app *App, action, table, rowID string, session *Session, oldRow, newRow map[string]any) error {
	var key []byte
	var config *EncryptedFieldConfig
	if app != nil {
		config = app.Encrypted
	}
	if config != nil {
		var err error
		key, err = cryptoKeyForQuerierMainChecked(tx)
		if err != nil {
			return fmt.Errorf("resolve audit encryption key: %w", err)
		}
	}
	oldForAudit := redactAuditHiddenFields(app, table, encryptAuditFieldsCopy(config, table, oldRow, key))
	newForAudit := redactAuditHiddenFields(app, table, encryptAuditFieldsCopy(config, table, newRow, key))
	var oldJSON, newJSON string
	if oldForAudit != nil {
		b, err := json.Marshal(oldForAudit)
		if err != nil {
			return fmt.Errorf("serialize old audit values: %w", err)
		}
		oldJSON = string(b)
	}
	if newForAudit != nil {
		b, err := json.Marshal(newForAudit)
		if err != nil {
			return fmt.Errorf("serialize new audit values: %w", err)
		}
		newJSON = string(b)
	}
	return insertAuditRowChecked(tx, action, table, rowID, session, oldJSON, newJSON)
}

// auditHiddenValue replaces a hidden column's value in audit old/new values.
const auditHiddenValue = "[hidden]"

// redactAuditHiddenFields returns row with the values of hidden columns, and
// of their `old_<col>` change-delta keys, replaced by auditHiddenValue. The
// caller's map is never modified (hooks and webhooks share it).
func redactAuditHiddenFields(app *App, table string, row map[string]any) map[string]any {
	if row == nil || app == nil {
		return row
	}
	var out map[string]any
	for k, v := range row {
		if v == nil {
			continue
		}
		if !hiddenEventKey(app, table, k) {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(row))
			for k2, v2 := range row {
				out[k2] = v2
			}
		}
		out[k] = auditHiddenValue
	}
	if out == nil {
		return row
	}
	return out
}

// LogAuditDB is the backwards-compat shim for callers that log
// metadata-only audit events without any row values to encrypt
// (e.g. the retention sweep, which logs counts + TTLs).
func LogAuditDB(db *sql.DB, action, table, rowID string, session *Session, oldRow, newRow map[string]any) {
	var oldJSON, newJSON string
	if oldRow != nil {
		b, _ := json.Marshal(oldRow)
		oldJSON = string(b)
	}
	if newRow != nil {
		b, _ := json.Marshal(newRow)
		newJSON = string(b)
	}
	if db == nil {
		return
	}
	insertAuditRow(db, action, table, rowID, session, oldJSON, newJSON)
}

// RegisterAuditAPI adds the audit trail query endpoint.
func RegisterAuditAPI(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_audit", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}

		query := "SELECT * FROM _benmore_audit_log WHERE 1=1"
		var args []any

		if table := r.URL.Query().Get("table"); table != "" {
			query += " AND table_name = ?"
			args = append(args, table)
		}
		if rowID := r.URL.Query().Get("row_id"); rowID != "" {
			query += " AND row_id = ?"
			args = append(args, rowID)
		}
		if userID := r.URL.Query().Get("user_id"); userID != "" {
			query += " AND user_id = ?"
			args = append(args, userID)
		}
		if action := r.URL.Query().Get("action"); action != "" {
			query += " AND action = ?"
			args = append(args, action)
		}

		query += " ORDER BY created_at DESC LIMIT 100"

		rows, err := queryMetadataRows(app.DB, query, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_audit", err, "query failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})
}

// EnsureDevicesTable creates the device registration table for push notifications.
func EnsureDevicesTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL,
		platform TEXT NOT NULL,
		app_version TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, token)
	)`)
}

// RegisterDeviceRoutes adds device registration endpoints for push notifications.
func RegisterDeviceRoutes(mux appRouteRegistrar, app *App) {
	EnsureDevicesTable(app.DB)
	registerDeviceRoutes(mux, app)
}

func registerDeviceRoutes(mux appRouteRegistrar, app *App) {
	// Register/update a device token
	mux.HandleFunc("POST /api/_devices", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		// A registered device receives the account's push notifications from
		// then on. A support or delegated session is someone else's browser
		// or phone: registering it would keep delivering the customer's
		// notifications there after the session ends.
		if delegatedIdentitySession(app, session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": delegatedIdentityRefusal})
			return
		}
		// Cookie sessions need CSRF: the JSON body is decoded whatever the
		// content type, so a plain cross-site POST could otherwise register
		// a device token on the visitor's account. Bearer (native) is exempt.
		if !requireCSRF(w, r) {
			return
		}

		var body struct {
			Token      string `json:"token"`
			Platform   string `json:"platform"`
			AppVersion string `json:"app_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" || body.Platform == "" {
			http.Error(w, `{"error":"token and platform required"}`, http.StatusBadRequest)
			return
		}

		app.DB.Exec(
			"INSERT INTO _benmore_devices (user_id, token, platform, app_version) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, token) DO UPDATE SET platform=?, app_version=?, updated_at=datetime('now')",
			session.UserID, body.Token, body.Platform, body.AppVersion,
			body.Platform, body.AppVersion,
		)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"registered"}`))
	})

	// Unregister a device (logout/uninstall)
	mux.HandleFunc("DELETE /api/_devices", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		// Nor may it unregister the owner's devices (an empty body removes
		// every one).
		if delegatedIdentitySession(app, session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": delegatedIdentityRefusal})
			return
		}
		if !requireCSRF(w, r) {
			return
		}

		var body struct {
			Token string `json:"token"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Token != "" {
			app.DB.Exec("DELETE FROM _benmore_devices WHERE user_id = ? AND token = ?", session.UserID, body.Token)
		} else {
			// Remove all devices for this user
			app.DB.Exec("DELETE FROM _benmore_devices WHERE user_id = ?", session.UserID)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"removed"}`))
	})
}

// GetUserDeviceTokens returns all device tokens for a user (for push notification flows).
func GetUserDeviceTokens(db *sql.DB, userID int64) []map[string]string {
	rows, _ := db.Query("SELECT token, platform FROM _benmore_devices WHERE user_id = ?", userID)
	if rows == nil {
		return nil
	}
	defer rows.Close()
	var devices []map[string]string
	for rows.Next() {
		var token, platform string
		rows.Scan(&token, &platform)
		devices = append(devices, map[string]string{"token": token, "platform": platform})
	}
	return devices
}

// EnsureIdempotencyTable creates the dedup table for idempotent mutations.
// Keys are scoped per-user so two clients submitting the same
// X-Idempotency-Key don't collide and get each other's cached response.
func EnsureIdempotencyTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_idempotency (
		key TEXT NOT NULL,
		user_id INTEGER NOT NULL DEFAULT 0,
		response TEXT NOT NULL,
		status_code INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (key, user_id)
	)`)
	// One-shot migration for older deployments where the table had key
	// as the sole PK. Add user_id if missing - ALTER on the PK is a no-op
	// on legacy rows; v2 keys include identity so either PK shape is safe.
	db.Exec("ALTER TABLE _benmore_idempotency ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0")
	// v2 keys include route and credential identity; legacy cache entries are
	// intentionally unreachable because they have no request fingerprint.
	db.Exec("ALTER TABLE _benmore_idempotency ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
	// Cleanup old entries (24h)
	db.Exec("DELETE FROM _benmore_idempotency WHERE created_at < datetime('now', '-1 day')")
}

// ParseCreateTables extracts table definitions from SQL.
func ParseCreateTables(schema string) []Table {
	var tables []Table
	_ = splitSQLStatements(strings.NewReader(schema), func(statement string) error {
		statement = stripSQLComments(statement)
		start, end, depth, offset := -1, -1, 0, 0
		_ = scanSQLBytes(statement, func(b byte, kind sqlByteKind) error {
			i := offset
			offset++
			if kind != sqlCode {
				return nil
			}
			if b == '(' {
				if depth == 0 && start < 0 {
					start = i
				}
				depth++
			}
			if b == ')' {
				depth--
				if depth == 0 && start >= 0 && end < 0 {
					end = i
				}
			}
			return nil
		})
		if start < 0 || end < start {
			return nil
		}
		name := extractTableName(statement[:start])
		if name == "" {
			return nil
		}
		table := Table{Name: name}
		definitions := splitSchemaParts(statement[start+1 : end])
		for _, definition := range definitions {
			if col := parseColumnDef(definition); col != nil {
				table.Columns = append(table.Columns, *col)
			}
		}
		for _, definition := range definitions {
			tokens := sqlTokenize(definition)
			if len(tokens) > 2 && tokens[0].kind == sqlTokWord && strings.EqualFold(tokens[0].text, "CONSTRAINT") {
				tokens = tokens[2:]
			}
			if len(tokens) < 4 || tokens[0].kind != sqlTokWord || !strings.EqualFold(tokens[0].text, "PRIMARY") || !strings.EqualFold(tokens[1].text, "KEY") || tokens[2].text != "(" {
				continue
			}
			for i := 3; i < len(tokens); i++ {
				if tokens[i].kind == sqlTokPunct && tokens[i].text == ")" {
					break
				}
				if i != 3 && !(tokens[i-1].kind == sqlTokPunct && tokens[i-1].text == ",") {
					continue
				}
				for j := range table.Columns {
					if sqliteIdentifierFold(table.Columns[j].Name) == sqliteIdentifierFold(tokens[i].text) {
						table.Columns[j].PK = true
					}
				}
			}
		}
		tables = append(tables, table)
		return nil
	})
	return tables
}

func extractTableName(line string) string {
	tokens := sqlTokenize(line)
	if len(tokens) < 3 || tokens[0].kind != sqlTokWord || !strings.EqualFold(tokens[0].text, "CREATE") || tokens[1].kind != sqlTokWord || !strings.EqualFold(tokens[1].text, "TABLE") {
		return ""
	}
	i := 2
	if len(tokens) > i+2 && strings.EqualFold(tokens[i].text, "IF") && strings.EqualFold(tokens[i+1].text, "NOT") && strings.EqualFold(tokens[i+2].text, "EXISTS") {
		i += 3
	}
	if i >= len(tokens) || tokens[i].kind == sqlTokPunct {
		return ""
	}
	if i+2 < len(tokens) && tokens[i+1].text == "." {
		i += 2
	}
	if tokens[i].kind == sqlTokPunct {
		return ""
	}
	if i+1 < len(tokens) && tokens[i+1].text != "(" {
		return ""
	}
	return tokens[i].text
}

// splitSchemaParts shares the SQL scanner so quoted text and nested expressions
// remain intact when splitting column declarations.
func splitSchemaParts(s string) []string {
	var parts []string
	start, offset, depth := 0, 0, 0
	_ = scanSQLBytes(s, func(b byte, kind sqlByteKind) error {
		i := offset
		offset++
		if kind != sqlCode {
			return nil
		}
		if b == '(' {
			depth++
		}
		if b == ')' {
			depth--
		}
		if depth == 0 && b == ',' {
			if part := strings.TrimSpace(s[start:i]); part != "" {
				parts = append(parts, part)
			}
			start = i + 1
		}
		return nil
	})
	if part := strings.TrimSpace(s[start:]); part != "" {
		parts = append(parts, part)
	}
	return parts
}

func parseColumnDef(line string) *Column {
	line = strings.TrimSpace(strings.TrimRight(stripSQLComments(line), ", \t\r\n"))
	tokens := sqlTokenize(line)
	if len(tokens) == 0 {
		return nil
	}
	wordAt := func(i int, word string) bool {
		return i < len(tokens) && tokens[i].kind == sqlTokWord && strings.EqualFold(tokens[i].text, word)
	}
	if tokens[0].kind == sqlTokWord {
		switch strings.ToUpper(tokens[0].text) {
		case "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT":
			return nil
		}
	}
	col := &Column{Name: tokens[0].text}
	typeEnd, depth := len(line), 0
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if token.kind == sqlTokPunct {
			if token.text == "(" {
				depth++
			}
			if token.text == ")" {
				depth--
			}
			continue
		}
		if depth != 0 || token.kind != sqlTokWord {
			continue
		}
		word := strings.ToUpper(token.text)
		switch word {
		case "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS", "CONSTRAINT":
			if typeEnd == len(line) {
				typeEnd = token.start
			}
		}
		if word == "PRIMARY" && wordAt(i+1, "KEY") {
			col.PK = true
		}
		if word == "NOT" && wordAt(i+1, "NULL") {
			col.NotNull = true
		}
		// SET DEFAULT belongs to a foreign-key action, not the column default.
		if word != "DEFAULT" || wordAt(i-1, "SET") || i+1 >= len(tokens) {
			continue
		}
		start := i + 1
		end := start
		if tokens[end].kind == sqlTokPunct && (tokens[end].text == "+" || tokens[end].text == "-") && end+1 < len(tokens) {
			end++
		}
		value := tokens[end]
		if wordAt(end, "X") && end+1 < len(tokens) && tokens[end+1].kind == sqlTokLiteral && value.end == tokens[end+1].start {
			end++ // SQLite blob literal X'...'
		} else if value.kind == sqlTokPunct && value.text == "(" {
			valueDepth := 1
			for end+1 < len(tokens) && valueDepth > 0 {
				end++
				if tokens[end].kind == sqlTokPunct {
					if tokens[end].text == "(" {
						valueDepth++
					}
					if tokens[end].text == ")" {
						valueDepth--
					}
				}
			}
		} else if value.kind == sqlTokWord && len(value.text) > 0 && value.text[0] >= '0' && value.text[0] <= '9' || value.kind == sqlTokPunct && value.text == "." {
			// The shared tokenizer separates decimal/exponent punctuation. Keep its
			// numeric tokens together; SQLite validates the resulting declaration.
			for end+1 < len(tokens) {
				next := tokens[end+1]
				numericWord := next.kind == sqlTokWord && len(next.text) > 0 && (next.text[0] >= '0' && next.text[0] <= '9' || next.text[0] == 'e' || next.text[0] == 'E')
				numericPunct := next.kind == sqlTokPunct && (next.text == "." || next.text == "+" || next.text == "-")
				if !numericWord && !numericPunct {
					break
				}
				end++
			}
		}
		col.Default = line[tokens[start].start:tokens[end].end]
		i = end
	}
	col.Type = strings.TrimSpace(line[tokens[0].end:typeEnd])
	return col
}

// splitStatements splits a SQL script into individual statements.
// BEGIN/END blocks (used by CREATE TRIGGER) are tracked so the `;`
// terminating each inner statement doesn't prematurely chop the
// trigger body. Without this, `CREATE TRIGGER ... BEGIN UPDATE x SET
// y=1; END;` gets split at the inner `;` and Exec rejects both halves.
func splitStatements(sql string) []string {
	var stmts []string
	var current strings.Builder
	beginDepth := 0
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")

		upper := strings.ToUpper(trimmed)
		// BEGIN opens a block we should not split inside. The token
		// appears at end-of-line in `... FOR EACH ROW BEGIN` (one
		// match) or as `BEGIN` on its own line - both increment.
		if strings.HasSuffix(upper, "BEGIN") || upper == "BEGIN" {
			beginDepth++
			continue
		}
		// END; closes the block. The trailing `;` is the terminator
		// for the trigger as a whole; only flush if we're now at
		// depth 0 (the closing END of the outermost trigger).
		if beginDepth > 0 && (upper == "END;" || upper == "END ;") {
			beginDepth--
			if beginDepth == 0 {
				stmts = append(stmts, current.String())
				current.Reset()
			}
			continue
		}
		// Inside a BEGIN block, never split on `;`.
		if beginDepth > 0 {
			continue
		}
		if strings.HasSuffix(trimmed, ";") {
			stmts = append(stmts, current.String())
			current.Reset()
		}
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// StartAppWALMaintenance runs PRAGMA wal_checkpoint(TRUNCATE) on the app's
// data.db every 5 minutes. SQLite's passive autocheckpoint can only run when
// no reader holds a snapshot - under continuous read traffic (analytics
// beacon, request log, page polls), the WAL grows to ~4MB and stays there,
// slowing every new reader (each one walks the WAL to acquire a snapshot).
// Forced TRUNCATE checkpoints work alongside readers (they keep their old
// snapshot until they complete) and reset the WAL once free.
//
// With PITR enabled this worker only backfills. The shipper owns generation
// rotation and its SQLite read pins prevent discarding required history.
// External SQLite connections use the same locking protocol; replacing live
// database/sidecar files outside that protocol remains unsafe.
//
// Issue #1.
func StartAppWALMaintenance(app *App) {
	stop := app.workerStopGeneration()
	safeGo("db.walMaintenance", func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				select {
				case <-stop:
					return
				default:
				}
				mode := walCheckpointMode(app, appWALSize(app))
				var busy, logPages, ckptPages int
				// Serialize with the WAL shipper's base snapshot so this
				// checkpoint can't write data.db mid-copy (torn base snapshot).
				app.walCheckpointMu.Lock()
				err := app.DB.QueryRow("PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &logPages, &ckptPages)
				app.walCheckpointMu.Unlock()
				if err != nil {
					log.Printf("[wal] checkpoint error on %s: %v", filepath.Base(app.Dir), err)
				}
			}
		}
	})
}

func appWALSize(app *App) int64 {
	if app == nil {
		return 0
	}
	fi, err := os.Stat(filepath.Join(app.Dir, "data.db-wal"))
	if err != nil {
		return 0
	}
	return fi.Size()
}

func walCheckpointMode(app *App, _ int64) string {
	if !walShippingEnabledForApp(app) {
		return "TRUNCATE"
	}
	// Physical length includes rollback/spill tails, and a new commit can land
	// between a coverage check and TRUNCATE. The shipper owns generation
	// rotation under SQLite coordination; ordinary maintenance only backfills.
	return "PASSIVE"
}

func walShippingEnabledForApp(app *App) bool {
	// Require a configured object store too: without it StartWALShipper bails,
	// but walCheckpointMode would otherwise keep returning PASSIVE forever
	// (shipping "enabled" by env) and the maintenance loop would stop
	// truncating the WAL - the exact bloat StartAppWALMaintenance exists to
	// prevent. Gate on BACKUP_S3_BUCKET (what backupS3Store keys off) so a
	// half-configured deployment still truncates. Inlined as an env check
	// rather than calling backupS3Store(), which is platform-only.
	return platformBuild && app != nil &&
		os.Getenv("BENMORE_WAL_SHIP") == "1" &&
		!IsDevSubdomain(filepath.Base(app.Dir)) &&
		os.Getenv("BACKUP_S3_BUCKET") != ""
}
