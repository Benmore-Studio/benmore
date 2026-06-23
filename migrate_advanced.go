//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// uniqueIndexRe captures `CREATE UNIQUE INDEX [IF NOT EXISTS] <idx>
// ON <table> (<col1>, <col2>, …)`. Group 1: table. Group 2: column list.
var uniqueIndexRe = regexp.MustCompile(
	`(?is)\bCREATE\s+UNIQUE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?\w+\s+ON\s+(\w+)\s*\(([^)]+)\)`,
)

// precheckUniqueIndex queries the target table for rows that would
// violate the proposed unique constraint. If any are found, returns a
// structured error listing up to 10 example duplicate values so the
// caller can dedupe before re-running. nil on no duplicates / non-
// unique-index statements (passes through).
//
// The original failure mode: CREATE UNIQUE INDEX on a table with
// existing duplicates threw "UNIQUE constraint failed" with zero hint
// at which rows. The migration kept retrying on every app restart,
// blocking the entire app from booting. This precheck surfaces the
// data problem before the constraint applies.
func precheckUniqueIndex(db *sql.DB, stmt string) error {
	m := uniqueIndexRe.FindStringSubmatch(stmt)
	if len(m) < 3 {
		return nil // not a CREATE UNIQUE INDEX, nothing to precheck
	}
	table := strings.TrimSpace(m[1])
	colList := m[2]
	cols := []string{}
	for _, c := range strings.Split(colList, ",") {
		c = strings.TrimSpace(c)
		// Strip any DESC / ASC / COLLATE suffix.
		if i := strings.IndexAny(c, " \t"); i >= 0 {
			c = c[:i]
		}
		if c != "" {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return nil
	}
	colSQL := strings.Join(cols, ", ")
	query := fmt.Sprintf(
		"SELECT %s, COUNT(*) AS n FROM %s GROUP BY %s HAVING n > 1 LIMIT 10",
		colSQL, table, colSQL,
	)
	rows, err := db.Query(query)
	if err != nil {
		// If the table doesn't exist yet (CREATE INDEX before CREATE
		// TABLE in the same migration file), let the actual exec run
		// and surface its own error - precheck shouldn't block valid
		// migrations.
		return nil
	}
	defer rows.Close()
	type dup struct {
		Values []any
		Count  int64
	}
	var dups []dup
	colCount := len(cols)
	for rows.Next() {
		raw := make([]any, colCount+1)
		ptrs := make([]any, colCount+1)
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		count, _ := raw[colCount].(int64)
		dups = append(dups, dup{Values: raw[:colCount], Count: count})
	}
	if len(dups) == 0 {
		return nil
	}
	// Format the error. Each dup line shows column=value pairs + count.
	var b strings.Builder
	fmt.Fprintf(&b,
		"CREATE UNIQUE INDEX on %s(%s) would fail - existing data has %d duplicate row group(s):\n\n",
		table, colSQL, len(dups),
	)
	for _, d := range dups {
		b.WriteString("  ")
		for i, c := range cols {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%v", c, d.Values[i])
		}
		fmt.Fprintf(&b, "  (%d rows)\n", d.Count)
	}
	b.WriteString(
		"\nResolution: dedupe before re-running the migration. Options:\n" +
			fmt.Sprintf("  • Keep most recent: DELETE FROM %s WHERE rowid NOT IN (SELECT MAX(rowid) FROM %s GROUP BY %s)\n", table, table, colSQL) +
			"  • Or rename the constraint so duplicates are allowed.\n" +
			"  • Or rename the column to make the existing values distinct.\n\n" +
			"The migration is aborted - no partial state was applied. Once dedupe completes, the next app start picks up the migration cleanly.",
	)
	return fmt.Errorf("%s", b.String())
}

// AdvancedMigration handles column renames, type changes, and data migrations.
// SQLite doesn't support ALTER TABLE RENAME COLUMN in older versions,
// so we use the "create new table, copy data, drop old, rename" pattern.

// RenameColumn renames a column in a table.
func RenameColumn(db *sql.DB, table, oldName, newName string) error {
	// SQLite 3.25.0+ supports ALTER TABLE RENAME COLUMN
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", table, oldName, newName))
	if err == nil {
		log.Printf("MIGRATE: renamed %s.%s → %s", table, oldName, newName)
		return nil
	}

	// Fallback: rebuild table
	return rebuildTable(db, table, func(col Column) *Column {
		if col.Name == oldName {
			col.Name = newName
			return &col
		}
		return &col
	})
}

// AlterColumnType changes a column's type (SQLite is flexible about types, but this rebuilds for strictness).
func AlterColumnType(db *sql.DB, table, column, newType string) error {
	return rebuildTable(db, table, func(col Column) *Column {
		if col.Name == column {
			col.Type = newType
			return &col
		}
		return &col
	})
}

// DropColumn removes a column from a table.
func DropColumn(db *sql.DB, table, column string) error {
	// SQLite 3.35.0+ supports ALTER TABLE DROP COLUMN
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", table, column))
	if err == nil {
		log.Printf("MIGRATE: dropped %s.%s", table, column)
		return nil
	}

	// Fallback: rebuild without the column
	return rebuildTable(db, table, func(col Column) *Column {
		if col.Name == column {
			return nil // exclude this column
		}
		return &col
	})
}

// rebuildTable recreates a table with modified schema (SQLite table rebuild pattern).
func rebuildTable(db *sql.DB, table string, transform func(Column) *Column) error {
	cols, err := GetTableColumns(db, table)
	if err != nil {
		return err
	}

	// Build new schema
	var newCols []Column
	var oldNames []string
	var newNames []string
	for _, col := range cols {
		result := transform(col)
		if result == nil {
			continue // column dropped
		}
		newCols = append(newCols, *result)
		oldNames = append(oldNames, col.Name)
		newNames = append(newNames, result.Name)
	}

	if len(newCols) == 0 {
		return fmt.Errorf("rebuild: would result in empty table")
	}

	tmpTable := table + "_migrate_tmp"

	// Create new table
	var colDefs []string
	for _, c := range newCols {
		def := c.Name + " " + c.Type
		if c.PK {
			def += " PRIMARY KEY"
			if c.Type == "INTEGER" {
				def += " AUTOINCREMENT"
			}
		}
		if c.NotNull && !c.PK {
			def += " NOT NULL"
		}
		if c.Default != "" {
			def += " DEFAULT " + c.Default
		}
		colDefs = append(colDefs, def)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create temp table
	createSQL := fmt.Sprintf("CREATE TABLE %s (%s)", tmpTable, strings.Join(colDefs, ", "))
	if _, err := tx.Exec(createSQL); err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	// Copy data
	copySQL := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s",
		tmpTable, strings.Join(newNames, ", "), strings.Join(oldNames, ", "), table)
	if _, err := tx.Exec(copySQL); err != nil {
		return fmt.Errorf("copy data: %w", err)
	}

	// Drop old table
	if _, err := tx.Exec(fmt.Sprintf("DROP TABLE %s", table)); err != nil {
		return fmt.Errorf("drop old: %w", err)
	}

	// Rename new table
	if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", tmpTable, table)); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	log.Printf("MIGRATE: rebuilt table %s", table)
	return nil
}

// RunMigrationFile executes a .sql migration file.
func RunMigrationFile(db *sql.DB, path string) error {
	data, err := readFileBytes(path)
	if err != nil {
		return err
	}

	// Files generated by ApplyPrismaMigration carry both UP and DOWN
	// sections separated by `-- DOWN --`. We only run the UP block
	// here. Without this guard, on a fresh deploy where the data.db
	// is empty but migrations/ has prior files, this function used to
	// execute the entire file - creating tables in the UP section
	// then immediately dropping them via the DOWN section. The table
	// looked like it appeared (CREATE succeeded), then vanished, with
	// a misleading "applied 0001" log line.
	//
	// Legacy migration files without a `-- DOWN --` marker still run
	// in full via extractMigrationSection's fallback (returns the
	// whole body as UP).
	upSQL, _ := extractMigrationSection(string(data))

	statements := splitStatements(upSQL)
	// Apply every statement in the file inside ONE transaction so a mid-file
	// failure rolls the whole file back instead of committing a partial prefix.
	// Without this, a file that failed on statement N left 1..N-1 committed but
	// unrecorded, so the next boot re-ran from the top and the already-applied
	// prefix errored ("duplicate column") forever - a wedged, half-migrated
	// schema. Rolling back on failure means a retry always starts clean.
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		// Precheck: CREATE UNIQUE INDEX on a table with existing
		// duplicates fails at runtime with a useless "UNIQUE constraint
		// failed" error and leaves the app stuck in a restart loop
		// (router keeps retrying the migration, every retry fails the
		// same way). Surface the actual duplicate values instead so the
		// agent/user can decide whether to dedupe or rename the
		// constraint. (Reads committed state via db - a freshly-created
		// table in this same file is empty, so no false positive.)
		if dupErr := precheckUniqueIndex(db, stmt); dupErr != nil {
			return fmt.Errorf("migration %s: %w", truncate(stmt, 60), dupErr)
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	committed = true
	return nil
}

// RunMigrations checks for a migrations/ directory and runs any .sql files
// that haven't been run yet (tracked in _benmore_migrations table).
func RunMigrations(db *sql.DB, dir string) error {
	migrationsDir := filepath.Join(dir, "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil // no migrations directory, that's fine
	}

	// Ensure tracking table
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		// Check if already applied
		var count int
		db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?", entry.Name()).Scan(&count)
		if count > 0 {
			continue
		}

		// Run migration
		path := filepath.Join(migrationsDir, entry.Name())
		if err := RunMigrationFile(db, path); err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}

		// Record as applied
		db.Exec("INSERT INTO _benmore_migrations (name) VALUES (?)", entry.Name())
		log.Printf("  migration: applied %s", entry.Name())
	}

	return nil
}

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}
