package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// prismaShapedTracking mimics the 5-column table ApplyPrismaMigration creates.
func prismaShapedTracking(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE _benmore_migrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		source TEXT NOT NULL,
		source_hash TEXT NOT NULL)`)
	if err != nil {
		t.Fatalf("create tracking: %v", err)
	}
}

func writeMig(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "migrations", name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Regression for the NOT NULL bug: on a prisma-shaped table the record INSERT
// must succeed and the file must be marked applied exactly once.
func TestRunMigrations_RecordsOnPrismaShapedTable(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	if _, err := db.Exec(`CREATE TABLE box (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO box (n) VALUES (5)`); err != nil {
		t.Fatal(err)
	}
	writeMig(t, dir, "0001_x2.sql", `UPDATE box SET n = n * 2;`)

	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("run1: %v", err)
	}
	var n, cnt int
	db.QueryRow(`SELECT n FROM box`).Scan(&n)
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name='0001_x2.sql'`).Scan(&cnt)
	if n != 10 {
		t.Fatalf("want n=10 got %d", n)
	}
	if cnt != 1 {
		t.Fatalf("want migration recorded once, got %d", cnt)
	}

	// Idempotency: a second pass must NOT re-run the data statement.
	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("run2: %v", err)
	}
	db.QueryRow(`SELECT n FROM box`).Scan(&n)
	if n != 10 {
		t.Fatalf("double-apply! want n=10 got %d", n)
	}
}

// Task 2: a hard failure renames the file to .failed.sql so it doesn't
// re-attempt every reload/boot, and a second pass skips it.
func TestRunMigrations_RenamesFailedFile(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	writeMig(t, dir, "0001_bad.sql", `UPDATE table_that_does_not_exist SET x = 1;`)

	if err := RunMigrations(db, dir); err == nil {
		t.Fatal("expected error from bad migration")
	}
	if _, err := os.Stat(filepath.Join(dir, "migrations", "0001_bad.sql.failed.sql")); err != nil {
		t.Fatalf("expected .failed.sql rename, got %v", err)
	}
	// A second pass skips the renamed file and succeeds.
	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("second pass should skip .failed file: %v", err)
	}
}

// Task 3: the reload-path wrapper applies pending migrations and leaves a backup.
func TestRunUserMigrationsWithBackup_AppliesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	if _, err := db.Exec(`CREATE TABLE box (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO box (n) VALUES (3)`)
	writeMig(t, dir, "0001_add.sql", `UPDATE box SET n = n + 100;`)

	if err := runUserMigrationsWithBackup(db, dir); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var n int
	db.QueryRow(`SELECT n FROM box`).Scan(&n)
	if n != 103 {
		t.Fatalf("want 103 got %d", n)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".benmore", "backups"))
	if len(entries) == 0 {
		t.Fatal("expected a pre-migration backup")
	}
}

// Rename idempotency: a fresh DB already has the rename TARGET (schema sync
// created it directly), so `RENAME COLUMN old TO new` fails with `no such
// column: old`. The guard must skip those statements and record the file as
// applied instead of rolling back + warning on every boot.
func TestRunMigrations_SkipsAlreadyAppliedRename(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	// Fresh-DB shape: target columns exist, sources never did (a production
	// CRM role-column migration case).
	if _, err := db.Exec(`CREATE TABLE lead_companies (id INTEGER PRIMARY KEY, solar_role TEXT, notes TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lead_companies (solar_role, notes) VALUES ('installer', 'keep me')`); err != nil {
		t.Fatal(err)
	}
	writeMig(t, dir, "0014_crm.sql",
		`ALTER TABLE lead_companies RENAME COLUMN role TO solar_role;
UPDATE lead_companies SET notes = notes || '!';`)

	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name='0014_crm.sql'`).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("want migration recorded once, got %d", cnt)
	}
	// The rest of the file still applied (skip is per-statement, not per-file).
	var notes string
	db.QueryRow(`SELECT notes FROM lead_companies`).Scan(&notes)
	if notes != "keep me!" {
		t.Fatalf("later statement did not apply, notes=%q", notes)
	}
	// No .failed.sql rename.
	if _, err := os.Stat(filepath.Join(dir, "migrations", "0014_crm.sql")); err != nil {
		t.Fatalf("original file should remain: %v", err)
	}
}

// A genuine rename error - source missing AND target missing - must still
// fail and roll the file back. The guard only fires when the end state is
// verifiably in place.
func TestRunMigrations_GenuineRenameErrorStillFails(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	if _, err := db.Exec(`CREATE TABLE lead_companies (id INTEGER PRIMARY KEY, notes TEXT)`); err != nil {
		t.Fatal(err)
	}
	writeMig(t, dir, "0014_bad.sql", `ALTER TABLE lead_companies RENAME COLUMN role TO solar_role;`)

	if err := RunMigrations(db, dir); err == nil {
		t.Fatal("expected error: neither source nor target column exists")
	}
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name='0014_bad.sql'`).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("failed migration must not be recorded, got %d", cnt)
	}
}

// Non-rename statements keep their existing behavior: a real error fails the
// file even when some unrelated target column happens to exist.
func TestRunMigrations_NonRenameErrorStillFails(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	if _, err := db.Exec(`CREATE TABLE lead_companies (id INTEGER PRIMARY KEY, solar_role TEXT)`); err != nil {
		t.Fatal(err)
	}
	writeMig(t, dir, "0015_bad.sql", `UPDATE lead_companies SET role = 'x';`)

	if err := RunMigrations(db, dir); err == nil {
		t.Fatal("expected error from UPDATE on missing column")
	}
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name='0015_bad.sql'`).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("failed migration must not be recorded, got %d", cnt)
	}
}

// Table-rename variant: `ALTER TABLE old RENAME TO new` where old is gone and
// new already exists is skipped; the file records.
func TestRunMigrations_SkipsAlreadyAppliedTableRename(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	if _, err := db.Exec(`CREATE TABLE lead_companies (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	writeMig(t, dir, "0016_tbl.sql", `ALTER TABLE companies RENAME TO lead_companies;`)

	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name='0016_tbl.sql'`).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("want migration recorded once, got %d", cnt)
	}
}

// Task 5: pending + failed user migrations are reported for CLI surfacing.
func TestPendingUserMigrations(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	writeMig(t, dir, "0001_done.sql", `SELECT 1;`)
	writeMig(t, dir, "0002_todo.sql", `SELECT 1;`)
	os.WriteFile(filepath.Join(dir, "migrations", "0003_broke.sql.failed.sql"), []byte("x"), 0o644)
	db.Exec(`INSERT INTO _benmore_migrations (name, source, source_hash) VALUES ('0001_done.sql','','')`)

	pending, failed := pendingUserMigrations(db, dir)
	if len(pending) != 1 || pending[0] != "0002_todo.sql" {
		t.Fatalf("pending=%v", pending)
	}
	if len(failed) != 1 || failed[0] != "0003_broke.sql.failed.sql" {
		t.Fatalf("failed=%v", failed)
	}
}
