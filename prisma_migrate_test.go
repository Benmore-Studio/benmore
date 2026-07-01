//go:build !cli

package main

// Tests for the Prisma migration generator + applier. Three layers:
//
//   - Diff computation: prev models vs curr models → MigrationDiff.
//     Tables added/dropped, columns added, type changes flagged.
//   - SQL emission: diff → ALTER + CREATE statements in the right
//     order, with warnings inline as `-- WARNING:` comments.
//   - Full lifecycle: ApplyPrismaMigration runs against a real
//     SQLite db, writes the migration file, applies it, records
//     the row in _benmore_migrations.

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func parseOrFail(t *testing.T, src string) []PrismaModel {
	t.Helper()
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse %s: %s", src, err)
	}
	return models
}

func TestDiffSchemas_AddTable(t *testing.T) {
	prev := parseOrFail(t, `model Account { id Int @id @default(autoincrement()) }`)
	curr := parseOrFail(t, `
model Account { id Int @id @default(autoincrement()) }
model Note { id Int @id @default(autoincrement())  body String }
`)
	d := DiffSchemas(prev, curr)
	if len(d.TablesAdded) != 1 || d.TablesAdded[0].Name != "Note" {
		t.Errorf("expected Note added, got %+v", d.TablesAdded)
	}
}

func TestDiffSchemas_DropTable(t *testing.T) {
	prev := parseOrFail(t, `
model Account { id Int @id @default(autoincrement()) }
model Note { id Int @id @default(autoincrement()) }
`)
	curr := parseOrFail(t, `model Account { id Int @id @default(autoincrement()) }`)
	d := DiffSchemas(prev, curr)
	if len(d.TablesDropped) != 1 || d.TablesDropped[0] != "notes" {
		t.Errorf("expected notes dropped, got %+v", d.TablesDropped)
	}
}

func TestDiffSchemas_AddColumn(t *testing.T) {
	prev := parseOrFail(t, `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`)
	curr := parseOrFail(t, `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String @default("")
}`)
	d := DiffSchemas(prev, curr)
	if len(d.ColumnsAdded["notes"]) != 1 {
		t.Fatalf("expected 1 new column on notes, got: %+v", d.ColumnsAdded)
	}
	if d.ColumnsAdded["notes"][0].Column != "body" {
		t.Errorf("expected body column, got %q", d.ColumnsAdded["notes"][0].Column)
	}
}

func TestDiffSchemas_DropColumnWarns(t *testing.T) {
	prev := parseOrFail(t, `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String
}`)
	curr := parseOrFail(t, `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`)
	d := DiffSchemas(prev, curr)
	if len(d.Warnings) == 0 {
		t.Fatal("expected warning for dropped column")
	}
	if !strings.Contains(d.Warnings[0], "body") {
		t.Errorf("warning should name the dropped column: %s", d.Warnings[0])
	}
}

func TestDiffSchemas_TypeChangeWarns(t *testing.T) {
	prev := parseOrFail(t, `model Note {
  id  Int @id @default(autoincrement())
  age Int
}`)
	curr := parseOrFail(t, `model Note {
  id  Int    @id @default(autoincrement())
  age String
}`)
	d := DiffSchemas(prev, curr)
	if len(d.Warnings) == 0 {
		t.Fatal("expected warning for type change")
	}
	if !strings.Contains(d.Warnings[0], "INTEGER → TEXT") {
		t.Errorf("warning should describe the type change: %s", d.Warnings[0])
	}
}

func TestEmitMigrationSQL_ColumnAdd(t *testing.T) {
	prev := parseOrFail(t, `model Note { id Int @id @default(autoincrement()) }`)
	curr := parseOrFail(t, `model Note {
  id    Int    @id @default(autoincrement())
  body  String @default("")
}`)
	d := DiffSchemas(prev, curr)
	sql := EmitMigrationSQL(d, "add_body", "20260517T000000Z")
	want := `ALTER TABLE notes ADD COLUMN body TEXT NOT NULL DEFAULT ''`
	if !strings.Contains(sql, want) {
		t.Errorf("expected %q in:\n%s", want, sql)
	}
}

func TestRollbackPrismaMigration_ColumnAdd(t *testing.T) {
	// Forward: add column. Rollback: drop the column AND remove the
	// _benmore_migrations row + the migration file.
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	src1 := `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`
	if _, err := ApplyPrismaMigration(db, dir, src1); err != nil {
		t.Fatalf("seed: %s", err)
	}
	src2 := `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String @default("")
}`
	if _, err := ApplyPrismaMigration(db, dir, src2); err != nil {
		t.Fatalf("apply 2: %s", err)
	}
	// Sanity: body column exists.
	if !columnExists(t, db, "notes", "body") {
		t.Fatal("body column should exist after forward apply")
	}

	rolled, err := RollbackPrismaMigration(db, dir, 1, true)
	if err != nil {
		t.Fatalf("rollback: %s", err)
	}
	if len(rolled) != 1 {
		t.Fatalf("expected 1 rollback, got %d", len(rolled))
	}
	if !strings.Contains(rolled[0], "add_body_to_notes") {
		t.Errorf("rolled-back filename should match: %q", rolled[0])
	}

	// Column should be gone.
	if columnExists(t, db, "notes", "body") {
		t.Error("body column should be gone after rollback")
	}
	// Row in _benmore_migrations should be gone.
	var count int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 remaining migration row (the seed), got %d", count)
	}
	// File should be gone (deleteFiles=true).
	entries, _ := os.ReadDir(filepath.Join(dir, "migrations"))
	if len(entries) != 1 {
		t.Errorf("expected 1 migration file left (the seed), got %d", len(entries))
	}
}

func TestRollbackPrismaMigration_TableAdd(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	src1 := `model Account {
  id Int @id @default(autoincrement())
}`
	if _, err := ApplyPrismaMigration(db, dir, src1); err != nil {
		t.Fatalf("seed: %s", err)
	}
	src2 := `model Account {
  id Int @id @default(autoincrement())
}
model Note {
  id Int @id @default(autoincrement())
  body String
}`
	if _, err := ApplyPrismaMigration(db, dir, src2); err != nil {
		t.Fatalf("apply 2: %s", err)
	}
	if !tableExistsHelper(t, db, "notes") {
		t.Fatal("notes table should exist after add")
	}
	if _, err := RollbackPrismaMigration(db, dir, 1, true); err != nil {
		t.Fatalf("rollback: %s", err)
	}
	if tableExistsHelper(t, db, "notes") {
		t.Error("notes table should be gone after rollback")
	}
	// accounts table (created in the seed) should still be there.
	if !tableExistsHelper(t, db, "accounts") {
		t.Error("accounts (from seed) should still exist after rolling back add-notes")
	}
}

func TestRollbackPrismaMigration_TableDrop(t *testing.T) {
	// Forward: drop a table. Rollback: must RECREATE the table using
	// the previous schema source (stored in _benmore_migrations.source).
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	src1 := `model Account {
  id Int @id @default(autoincrement())
}
model Note {
  id Int @id @default(autoincrement())
  body String
}`
	if _, err := ApplyPrismaMigration(db, dir, src1); err != nil {
		t.Fatalf("seed: %s", err)
	}
	src2 := `model Account {
  id Int @id @default(autoincrement())
}`
	if _, err := ApplyPrismaMigration(db, dir, src2); err != nil {
		t.Fatalf("drop apply: %s", err)
	}
	if tableExistsHelper(t, db, "notes") {
		t.Fatal("notes should be dropped after forward apply")
	}

	if _, err := RollbackPrismaMigration(db, dir, 1, true); err != nil {
		t.Fatalf("rollback: %s", err)
	}
	if !tableExistsHelper(t, db, "notes") {
		t.Error("notes should be recreated after rollback of its drop")
	}
}

// Helpers for the rollback tests.
func columnExists(t *testing.T, db *sql.DB, table, col string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if name == col {
			return true
		}
	}
	return false
}

func tableExistsHelper(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return err == nil && n == name
}

func TestApplyPrismaMigration_IdempotentReconciliation(t *testing.T) {
	// v2.7.37 (B10): when the live DB already contains the column the
	// migration would add (manual ALTER, partial prior migration,
	// truncated _benmore_migrations table, etc.), the reconciler
	// drops the redundant ADD COLUMN before emitting SQL. The
	// migration succeeds as a no-op rather than crashing with
	// `duplicate column name` and accumulating .failed files.
	//
	// Pre-2.7.37 this shape (beacon's `duplicate column name:
	// thumbnail_url` debug session) failed every boot, accumulated a
	// new .failed file each time, and the agent had to scaffold a
	// fresh app to escape.
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Pre-seed: apply a valid initial schema so the diff path runs.
	src1 := `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`
	if _, err := ApplyPrismaMigration(db, dir, src1); err != nil {
		t.Fatalf("seed apply: %s", err)
	}

	// Sabotage: create the column manually so the next migration's
	// `ALTER TABLE notes ADD COLUMN body` would have crashed pre-B10.
	if _, err := db.Exec("ALTER TABLE notes ADD COLUMN body TEXT NOT NULL DEFAULT ''"); err != nil {
		t.Fatalf("sabotage prep: %s", err)
	}

	src2 := `model Note {
  id    Int    @id @default(autoincrement())
  title String
  body  String @default("")
}`
	name, err := ApplyPrismaMigration(db, dir, src2)
	if err != nil {
		t.Fatalf("apply should have succeeded after reconciler dropped the redundant ALTER; got err=%v name=%q", err, name)
	}

	// The new source-hash IS recorded so the fast-path "same hash, skip"
	// kicks in on subsequent boots. Two rows now: the seed + this one.
	var count int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations").Scan(&count)
	if count != 2 {
		t.Errorf("expected seed + reconciled-noop in _benmore_migrations, got %d rows", count)
	}

	// No .failed file should accumulate now that the path is idempotent.
	entries, _ := os.ReadDir(filepath.Join(dir, "migrations"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql.failed") {
			t.Errorf("unexpected .failed migration after idempotent reconciliation: %s", e.Name())
		}
	}
}

func TestApplyPrismaMigration_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Initial schema.
	src1 := `model Note {
  id        Int      @id @default(autoincrement())
  title     String
  userId    Int      @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
}`

	name1, err := ApplyPrismaMigration(db, dir, src1)
	if err != nil {
		t.Fatalf("apply 1: %s", err)
	}
	if name1 == "" {
		t.Fatal("first apply should produce a migration filename")
	}
	if !strings.HasPrefix(name1, "0001_") || !strings.HasSuffix(name1, "_create_notes.sql") {
		t.Errorf("first migration filename = %q", name1)
	}
	// File should exist on disk.
	if _, err := os.Stat(filepath.Join(dir, "migrations", name1)); err != nil {
		t.Errorf("migration file should be on disk: %s", err)
	}
	// Row in _benmore_migrations.
	var count int
	db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 migration row, got %d", count)
	}

	// No-op apply (same source).
	if name, err := ApplyPrismaMigration(db, dir, src1); err != nil || name != "" {
		t.Errorf("re-apply of same schema should be a no-op, got name=%q err=%v", name, err)
	}

	// Add a column.
	src2 := `model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  userId    Int      @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
}`
	name2, err := ApplyPrismaMigration(db, dir, src2)
	if err != nil {
		t.Fatalf("apply 2: %s", err)
	}
	if !strings.Contains(name2, "add_body_to_notes") {
		t.Errorf("expected add_body_to_notes slug, got %q", name2)
	}
	// Verify column lives in the live DB now.
	rows, _ := db.Query("PRAGMA table_info(notes)")
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if name == "body" {
			found = true
		}
	}
	if !found {
		t.Errorf("body column should be in live schema after migration")
	}

	// Two migrations recorded.
	db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 migration rows, got %d", count)
	}
}

// TestNotNullBackfillDefault: a new NOT NULL column on an existing table must
// back-fill with a type-appropriate zero, not a text ” jammed into a numeric
// or date column (which read-side coercion then mangles).
func TestNotNullBackfillDefault(t *testing.T) {
	cases := map[string]string{
		"INTEGER": "0", "BIGINT": "0", "REAL": "0", "BOOLEAN": "0",
		"DATETIME": "CURRENT_TIMESTAMP", "DATE": "CURRENT_TIMESTAMP",
		"TEXT": "''", "BLOB": "''", "": "''",
	}
	for typ, want := range cases {
		if got := notNullBackfillDefault(typ); got != want {
			t.Errorf("notNullBackfillDefault(%q) = %q, want %q", typ, got, want)
		}
	}
	// End-to-end: an INTEGER NOT NULL add emits DEFAULT 0, not DEFAULT ''.
	prev := parseOrFail(t, `model Note { id Int @id @default(autoincrement()) }`)
	curr := parseOrFail(t, `model Note {
  id    Int @id @default(autoincrement())
  count Int
}`)
	sql := emitUpSQL(DiffSchemas(prev, curr))
	if !strings.Contains(sql, "NOT NULL DEFAULT 0") {
		t.Errorf("expected INTEGER NOT NULL backfill with DEFAULT 0, got:\n%s", sql)
	}
	if strings.Contains(sql, "count INTEGER NOT NULL DEFAULT ''") {
		t.Errorf("INTEGER column wrongly back-filled with text '':\n%s", sql)
	}
}

// TestBackupTimestampSort: backups must order by timestamp suffix, not by the
// (prefix-dominated) whole filename - else a recent pre-migrate-* backup is
// shadowed by an older scheduled-* one and restore loses recent data.
func TestBackupTimestampSort(t *testing.T) {
	older := "/x/.benmore/backups/scheduled-20260101T000000Z.db"
	newer := "/x/.benmore/backups/pre-migrate-20260601T120000Z.db"
	got := []string{newer, older}
	sortBackupsByTimestamp(got) // oldest first
	if got[0] != older || got[1] != newer {
		t.Fatalf("sortBackupsByTimestamp ordered by prefix not timestamp: %v", got)
	}
	if backupTimestamp(newer) <= backupTimestamp(older) {
		t.Fatalf("newer pre-migrate ts (%s) should sort after older scheduled ts (%s)",
			backupTimestamp(newer), backupTimestamp(older))
	}
}
