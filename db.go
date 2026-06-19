//go:build !cli

package main

import (
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
	dbURL := resolveDatabaseURL(dir)
	cfg := buildDBOpenConfig(dir, dbURL)
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
			if recovered, rErr := autoRestoreFromBackup(dir, err); rErr == nil && recovered {
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

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)

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
	prismaPath := filepath.Join(dir, "schema.prisma")
	schemaSQL := ""
	if data, err := os.ReadFile(prismaPath); err == nil {
		models, perr := ParsePrismaSchema(string(data))
		if perr != nil {
			return nil, nil, fmt.Errorf("schema.prisma: %w", perr)
		}
		schemaSQL = EmitSQL(models)
		// Generate + persist a migration file if the parsed schema
		// changed since the last apply. This is best-effort; if the
		// migrations directory or _benmore_migrations table can't
		// be written, we log + continue (the in-memory schema still
		// loads via the executor below).
		if name, err := ApplyPrismaMigration(db, dir, string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: migration generation failed: %s\n", err)
		} else if name != "" {
			fmt.Fprintf(os.Stderr, "migration: wrote migrations/%s\n", name)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read schema.prisma: %w", err)
	}

	if schemaSQL == "" {
		schemaPath := filepath.Join(dir, "schema.sql")
		data, err := os.ReadFile(schemaPath)
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
// (ensureIfNotExists already applied). A failure here is logged, not fatal:
// an index referencing a genuinely-bad column is a schema bug the app should
// boot through (surfaced in logs + the schema-drift check), not an outage.
func ApplyDeferredDDL(db *sql.DB, deferred []string) {
	for _, stmt := range deferred {
		if _, err := db.Exec(stmt); err != nil {
			log.Printf("  schema DDL deferred-apply failed (retried next reload): %s: %s", truncate(stmt, 60), err)
		}
	}
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
func QueryRows(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	start := time.Now()
	rows, err := db.Query(query, args...)
	incDBQuery()
	metricDBLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
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
func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Per-column type metadata derived once per result set. SQLite's
	// DatabaseTypeName() returns the schema-declared type (from CREATE
	// TABLE), which is what we want to drive both:
	//   - BOOLEAN coercion of 0/1 → true/false (pre-existing behavior)
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

	var results []map[string]any
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
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
			if isBool[i] {
				switch x := v.(type) {
				case int64:
					v = x != 0
				case float64:
					v = x != 0
				case bool:
					// already bool
				case nil:
					// leave nil - column is NULL, not false
				}
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
			//   non-zero time.Time → RFC3339 string (matches the
			//                       coerceSQLValue convention used by
			//                       loadInsertedRow, so a fresh GET
			//                       and a post-insert read see the
			//                       same shape)
			if tv, ok := v.(time.Time); ok {
				if tv.IsZero() {
					v = nil
				} else {
					v = tv.UTC().Format(time.RFC3339)
				}
			}
			row[col] = v
		}
		DecryptRowFields(row)
		// Numeric coercion runs AFTER decryption - that's the whole
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
	}
	return results, rows.Err()
}

// QuerySingle executes a query expected to return a single scalar value.
func QuerySingle(db *sql.DB, query string, args ...any) (any, error) {
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
func GetTableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_benmore_%' ORDER BY name")
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

// GetAllTableNames returns every table including _benmore_* system tables.
// Used by the context graph extractor and dashboard schema browser which
// need to show user-facing system tables like _benmore_users.
func GetAllTableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
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
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
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
			PK:      pk == 1,
		})
	}
	return cols, rows.Err()
}

// GetForeignKeys returns foreign key info for a table.
func GetForeignKeys(db *sql.DB, table string) (map[string]ForeignKey, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA foreign_key_list(%s)", table))
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
	}
	for _, col := range ensureColumns {
		name := strings.Fields(col)[0]
		var count int
		db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_users') WHERE name=?", name).Scan(&count)
		if count == 0 {
			db.Exec(fmt.Sprintf("ALTER TABLE _benmore_users ADD COLUMN %s", col))
		}
	}
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
		"":              true,
		"email":         true,
		"password":      true,
		"password_hash": true,
		"username":      true,
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
	// denylist - see isSensitiveUserColumn in auth.go.
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
// Backward-compatible variant LogAuditDB exists for the few callers
// that don't have an *App in scope (the retention worker logs only
// metadata - counts, TTLs - so no encryption is needed).
func LogAudit(app *App, action, table, rowID string, session *Session, oldRow, newRow map[string]any) {
	var userID int64
	var email string
	if session != nil {
		userID = session.UserID
		email = session.Email
	}

	var config *EncryptedFieldConfig
	if app != nil {
		config = app.Encrypted
	}
	oldForAudit := encryptAuditFieldsCopy(config, table, oldRow)
	newForAudit := encryptAuditFieldsCopy(config, table, newRow)

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
	app.DB.Exec(
		"INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES (?, ?, ?, ?, ?, ?, ?)",
		action, table, rowID, userID, email, oldJSON, newJSON,
	)
}

// LogAuditDB is the backwards-compat shim for callers that log
// metadata-only audit events without any row values to encrypt
// (e.g. the retention sweep, which logs counts + TTLs).
func LogAuditDB(db *sql.DB, action, table, rowID string, session *Session, oldRow, newRow map[string]any) {
	var userID int64
	var email string
	if session != nil {
		userID = session.UserID
		email = session.Email
	}
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
	db.Exec(
		"INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES (?, ?, ?, ?, ?, ?, ?)",
		action, table, rowID, userID, email, oldJSON, newJSON,
	)
}

// RegisterAuditAPI adds the audit trail query endpoint.
func RegisterAuditAPI(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /api/_audit", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
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

		rows, err := QueryRows(app.DB, query, args...)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
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
func RegisterDeviceRoutes(mux *http.ServeMux, app *App) {
	EnsureDevicesTable(app.DB)

	// Register/update a device token
	mux.HandleFunc("POST /api/_devices", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
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
	// on legacy rows; the new compound PK is enforced going forward.
	db.Exec("ALTER TABLE _benmore_idempotency ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0")
	// Cleanup old entries (24h)
	db.Exec("DELETE FROM _benmore_idempotency WHERE created_at < datetime('now', '-1 day')")
}

// CheckIdempotency checks if this request was already processed.
// Returns (cached_response, status_code, true) if duplicate, or ("", 0, false) if new.
// Scoped per user - userID=0 for anonymous requests.
func CheckIdempotency(db *sql.DB, key string, userID int64) (string, int, bool) {
	if key == "" {
		return "", 0, false
	}
	var response string
	var status int
	err := db.QueryRow("SELECT response, status_code FROM _benmore_idempotency WHERE key = ? AND user_id = ?", key, userID).Scan(&response, &status)
	if err != nil {
		return "", 0, false
	}
	return response, status, true
}

// SaveIdempotency stores the response for a processed request.
func SaveIdempotency(db *sql.DB, key string, userID int64, response string, status int) {
	if key == "" {
		return
	}
	db.Exec("INSERT OR IGNORE INTO _benmore_idempotency (key, user_id, response, status_code) VALUES (?, ?, ?, ?)",
		key, userID, response, status)
}

// ParseCreateTables extracts table definitions from SQL.
func ParseCreateTables(schema string) []Table {
	var tables []Table
	lines := strings.Split(schema, "\n")
	var currentTable *Table
	var inCreate bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "CREATE TABLE") {
			name := extractTableName(trimmed)
			if name != "" {
				currentTable = &Table{Name: name}
				inCreate = true
			}
			continue
		}

		if inCreate && currentTable != nil {
			if strings.Contains(trimmed, ");") || trimmed == ")" {
				tables = append(tables, *currentTable)
				currentTable = nil
				inCreate = false
				continue
			}

			col := parseColumnDef(trimmed)
			if col != nil {
				currentTable.Columns = append(currentTable.Columns, *col)
			}
		}
	}

	return tables
}

func extractTableName(line string) string {
	// Handle: CREATE TABLE [IF NOT EXISTS] name (
	upper := strings.ToUpper(line)
	idx := strings.Index(upper, "TABLE")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+5:])

	// Skip IF NOT EXISTS
	if strings.HasPrefix(strings.ToUpper(rest), "IF NOT EXISTS") {
		rest = strings.TrimSpace(rest[13:])
	}

	// Extract name (up to parenthesis or whitespace)
	name := strings.FieldsFunc(rest, func(r rune) bool {
		return r == '(' || r == ' ' || r == '\t'
	})
	if len(name) > 0 {
		return strings.Trim(name[0], "\"'`")
	}
	return ""
}

func parseColumnDef(line string) *Column {
	line = strings.TrimRight(line, ",")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "--") {
		return nil
	}

	upper := strings.ToUpper(line)
	// Skip constraints
	for _, prefix := range []string{"PRIMARY KEY", "FOREIGN KEY", "UNIQUE", "CHECK", "CONSTRAINT"} {
		if strings.HasPrefix(upper, prefix) {
			return nil
		}
	}

	parts := strings.Fields(line)
	if len(parts) < 1 {
		return nil
	}

	col := &Column{
		Name: strings.Trim(parts[0], "\"'`"),
	}
	if len(parts) > 1 {
		col.Type = parts[1]
	}

	if strings.Contains(upper, "PRIMARY KEY") {
		col.PK = true
	}
	if strings.Contains(upper, "NOT NULL") {
		col.NotNull = true
	}

	// Extract DEFAULT value
	if idx := strings.Index(upper, "DEFAULT "); idx >= 0 {
		rest := strings.TrimSpace(line[idx+8:])
		// Get the default value (up to next keyword or end)
		defaultVal := strings.Fields(rest)
		if len(defaultVal) > 0 {
			col.Default = defaultVal[0]
		}
	}

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
// IMPORTANT: this MUST run from inside the same process that holds the
// app.DB pool. Running checkpoint from an external sqlite3 invocation
// against an open DB corrupts the running process's connection state
// (data.db-shm mmap goes bad → 'disk I/O error: no such file or directory').
//
// Issue #1.
func StartAppWALMaintenance(app *App) {
	safeGo("db.walMaintenance", func() {
		stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
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
				var busy, logPages, ckptPages int
				if err := app.DB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logPages, &ckptPages); err != nil {
					log.Printf("[wal] checkpoint error on %s: %v", filepath.Base(app.Dir), err)
				}
			}
		}
	})
}
