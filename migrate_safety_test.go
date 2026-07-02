//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func openMigrationTestDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func execMigrationTestSQL(t *testing.T, db *sql.DB, stmt string, args ...any) {
	t.Helper()
	if _, err := db.Exec(stmt, args...); err != nil {
		t.Fatalf("exec %q: %v", stmt, err)
	}
}

func migrationTestHasColumn(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	cols, err := GetTableColumns(db, table)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if strings.EqualFold(c.Name, column) {
			return true
		}
	}
	return false
}

func TestMigrateAddColumnsRollbackOnFailure(t *testing.T) {
	dir := t.TempDir()
	db := openMigrationTestDB(t, dir)
	defer db.Close()
	execMigrationTestSQL(t, db, `CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`)
	execMigrationTestSQL(t, db, `INSERT INTO widgets (name) VALUES ('existing')`)

	result, err := Migrate(db, []Table{{
		Name: "widgets",
		Columns: []Column{
			{Name: "id", Type: "INTEGER", PK: true},
			{Name: "name", Type: "TEXT"},
			{Name: "first_new", Type: "TEXT"},
			{Name: "bad-name", Type: "TEXT"},
			{Name: "later_new", Type: "TEXT"},
		},
	}}, false)
	if err == nil {
		t.Fatal("expected second ADD COLUMN to fail")
	}
	if len(result.Added) != 0 {
		t.Fatalf("failed migration should not report committed additions, got %v", result.Added)
	}
	for _, col := range []string{"first_new", "bad-name", "later_new"} {
		if migrationTestHasColumn(t, db, "widgets", col) {
			t.Fatalf("column %s survived failed additive migration; expected table-level rollback", col)
		}
	}
}

func TestPreparePreMigrationBackupProdFailureRefusesDevWarns(t *testing.T) {
	prodDir := filepath.Join(t.TempDir(), "customer-app")
	if err := os.MkdirAll(filepath.Join(prodDir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	prodDB := openMigrationTestDB(t, prodDir)
	execMigrationTestSQL(t, prodDB, `CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
	prodDB.Close()
	if err := os.WriteFile(filepath.Join(prodDir, ".benmore", "backups"), []byte("not a dir"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePreMigrationBackup(prodDir, true); err == nil {
		t.Fatal("prod backup failure should abort before migration")
	}

	devDir := filepath.Join(t.TempDir(), "customer-app-dev")
	if err := os.MkdirAll(filepath.Join(devDir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	devDB := openMigrationTestDB(t, devDir)
	execMigrationTestSQL(t, devDB, `CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
	devDB.Close()
	if err := os.WriteFile(filepath.Join(devDir, ".benmore", "backups"), []byte("not a dir"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := preparePreMigrationBackup(devDir, true); err != nil {
		t.Fatalf("dev backup failure should warn and continue, got %v", err)
	}
}

func TestPostMigrationMissingColumnServesWithoutRestore(t *testing.T) {
	dir := t.TempDir()
	db := openMigrationTestDB(t, dir)
	defer db.Close()
	execMigrationTestSQL(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	execMigrationTestSQL(t, db, `INSERT INTO notes (body) VALUES ('before')`)
	backupPath, err := backupDatabase(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(`CREATE TABLE notes (
	id INTEGER PRIMARY KEY,
	body TEXT,
	title TEXT
);
`), 0600); err != nil {
		t.Fatal(err)
	}

	// A column the drift parser expects but that isn't physically present is
	// NOT corruption. verifyPostMigrationAndRestore must keep serving (return
	// nil) and must NOT auto-restore the older backup - restoring would revert
	// every write since the backup and re-detect the same drift next boot
	// (permanent crash-loop + data loss).
	if err := verifyPostMigrationAndRestore(dir, db, backupPath); err != nil {
		t.Fatalf("missing-column drift should serve, not fail/restore; got %v", err)
	}

	// data.db must be untouched: no corrupt-aside file, original row intact.
	if matches, _ := filepath.Glob(filepath.Join(dir, "data.db.corrupt-*")); len(matches) != 0 {
		t.Fatalf("missing-column drift must NOT move data.db aside; found %v", matches)
	}
	verify := openMigrationTestDB(t, dir)
	defer verify.Close()
	var n int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM notes WHERE body = 'before'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("original row count = %d, want 1 (data must not be reverted)", n)
	}
}

func TestExpandContractGuidanceDetectsRenameShapedDiff(t *testing.T) {
	guidance := expandContractGuidance(&MigrateResult{
		Added:   []string{"ALTER TABLE users ADD COLUMN display_name TEXT"},
		Blocked: []string{"DROP COLUMN users.name - BLOCKED (destructive, requires --force)"},
	})
	if len(guidance) == 0 {
		t.Fatal("expected rename-shaped diff guidance")
	}
	got := strings.Join(guidance, "\n")
	for _, want := range []string{"rename-shaped", "expand/contract", "dual-write", "backfill", "force"} {
		if !strings.Contains(got, want) {
			t.Fatalf("guidance %q missing %q", got, want)
		}
	}
}
