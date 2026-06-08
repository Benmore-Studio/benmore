//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestIsDeferredDDL(t *testing.T) {
	deferred := []string{
		"CREATE INDEX idx ON t(a)",
		"CREATE UNIQUE INDEX u ON t(a)",
		"  create index lower ON t(a)",
		"CREATE VIEW v AS SELECT 1",
		"CREATE TRIGGER tr AFTER INSERT ON t BEGIN END",
	}
	notDeferred := []string{
		"CREATE TABLE t (id INTEGER)",
		"CREATE VIRTUAL TABLE ft USING fts5(x)",
		"INSERT INTO t VALUES (1)",
	}
	for _, s := range deferred {
		if !isDeferredDDL(s) {
			t.Errorf("isDeferredDDL(%q) = false, want true", s)
		}
	}
	for _, s := range notDeferred {
		if isDeferredDDL(s) {
			t.Errorf("isDeferredDDL(%q) = true, want false", s)
		}
	}
}

// #12: a schema that adds a column AND an index on that column must converge
// in ONE pass. Pre-fix, LoadSchema ran CREATE INDEX before Migrate added the
// column → "no such column" → only the second push succeeded. Now LoadSchema
// defers the index and the caller applies it after Migrate.
func TestLoadSchema_DefersIndexUntilAfterMigrate(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Pre-existing table WITHOUT the new column (simulates the live DB before
	// this push).
	if _, err := db.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("seed table: %v", err)
	}

	// New schema: adds column `tag` AND an index on it — in one file.
	// Multi-line (one column per line) is the shape EmitSQL produces and
	// ParseCreateTables consumes.
	schema := "CREATE TABLE t (\n" +
		"  id INTEGER PRIMARY KEY,\n" +
		"  tag TEXT\n" +
		");\n" +
		"CREATE INDEX idx_t_tag ON t(tag);\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(schema), 0644); err != nil {
		t.Fatalf("write schema: %v", err)
	}

	tables, deferred, err := LoadSchema(db, dir)
	if err != nil {
		t.Fatalf("LoadSchema errored (pre-fix bug: CREATE INDEX on missing column): %v", err)
	}
	// The index must have been DEFERRED, not run yet (column doesn't exist).
	if len(deferred) != 1 {
		t.Fatalf("expected 1 deferred DDL (the index), got %d: %v", len(deferred), deferred)
	}
	if indexExists(t, db, "idx_t_tag") {
		t.Error("index should NOT exist before Migrate — it was supposed to be deferred")
	}

	// Now the caller's sequence: Migrate adds the column, then deferred DDL.
	if _, err := Migrate(db, tables, false); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ApplyDeferredDDL(db, deferred)

	if !indexExists(t, db, "idx_t_tag") {
		t.Error("index missing after Migrate + ApplyDeferredDDL — single-pass convergence failed")
	}
}

func indexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", name).Scan(&n); err != nil {
		t.Fatalf("index check: %v", err)
	}
	return n > 0
}
