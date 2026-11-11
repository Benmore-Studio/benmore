//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A removed field keeps its column until the builder ships the file the push
// names: a migrations/ file with `ALTER TABLE t DROP COLUMN c;`. The schema
// step builds a new database of that app from the current schema, where the
// column never existed, and the file then failed with `no such column`: the
// `benmore test` copy never loaded again, and a new instance set the file
// aside on its first start. SQLite has no DROP COLUMN IF EXISTS, so the file
// could not be written to suit both databases.

const (
	dropFreshSchemaBefore = "model Attachment {\n  id Int @id @default(autoincrement())\n  name String\n  contentType String? @map(\"content_type\")\n}\n"
	dropFreshSchemaAfter  = "model Attachment {\n  id Int @id @default(autoincrement())\n  name String\n}\n"
	dropFreshFile         = "0005_drop_attachment_content_type.sql"
)

func dropFreshLoad(t *testing.T, dir string) (string, error) {
	t.Helper()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	app, err := loadApp(dir)
	log.SetOutput(os.Stderr)
	if err == nil {
		app.DB.Close()
	}
	return logged.String(), err
}

func dropFreshLedgerCount(t *testing.T, db *sql.DB, name string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDocumentedDropColumnFileLoadsOnAFreshDatabase(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	root := t.TempDir()

	// The instance that had the column: the file drops it and keeps the rows.
	lived := filepath.Join(root, "lived")
	if err := os.MkdirAll(lived, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, lived, "app.yaml", "name: files\n")
	writeTestFile(t, lived, "schema.prisma", dropFreshSchemaBefore)
	if logged, err := dropFreshLoad(t, lived); err != nil {
		t.Fatalf("first load: %v\n%s", err, logged)
	}
	db, err := sql.Open("sqlite3", filepath.Join(lived, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO attachments (name, content_type) VALUES ('a.txt', 'text/plain')`)
	db.Close()
	writeTestFile(t, lived, "schema.prisma", dropFreshSchemaAfter)
	writeTestFile(t, lived, "migrations/"+dropFreshFile, "ALTER TABLE attachments DROP COLUMN content_type;\n")
	if logged, err := dropFreshLoad(t, lived); err != nil {
		t.Fatalf("load with the drop file on the database that has the column: %v\n%s", err, logged)
	}
	db, err = sql.Open("sqlite3", filepath.Join(lived, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	if dbColumnExists(db, "attachments", "content_type") {
		t.Fatal("the file did not drop the column on the database that had it")
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM attachments`).Scan(&name); err != nil || name != "a.txt" {
		t.Fatalf("the row did not survive the column drop: %q %v", name, err)
	}
	if n := dropFreshLedgerCount(t, db, dropFreshFile); n != 1 {
		t.Fatalf("ledger records the file %d times on the database that had the column, want 1", n)
	}
	db.Close()

	// A new database of the same source (the `benmore test` copy, a reset dev,
	// a first promote): built from the current schema, then handed the file.
	fresh := filepath.Join(root, "fresh")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fresh, "app.yaml", "name: files\n")
	writeTestFile(t, fresh, "schema.prisma", dropFreshSchemaAfter)
	entries, err := os.ReadDir(filepath.Join(lived, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(lived, "migrations", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, fresh, "migrations/"+e.Name(), string(data))
	}
	logged, err := dropFreshLoad(t, fresh)
	if err != nil {
		t.Fatalf("a fresh database does not load with the documented drop-column file: %v\n%s", err, logged)
	}
	if !strings.Contains(logged, "skipping") || !strings.Contains(logged, "content_type") {
		t.Fatalf("the load did not log the statement it skipped:\n%s", logged)
	}
	if _, err := os.Stat(filepath.Join(fresh, "migrations", dropFreshFile)); err != nil {
		t.Fatalf("the file was set aside on the fresh database: %v", err)
	}
	db, err = sql.Open("sqlite3", filepath.Join(fresh, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if n := dropFreshLedgerCount(t, db, dropFreshFile); n != 1 {
		t.Fatalf("ledger records the file %d times on the fresh database, want 1", n)
	}
	mustExec(t, db, `INSERT INTO attachments (name) VALUES ('b.txt')`)
	// The next load has nothing left to apply.
	if logged, err := dropFreshLoad(t, fresh); err != nil || strings.Contains(logged, "skipping") {
		t.Fatalf("second load of the fresh database: %v\n%s", err, logged)
	}
}

// Each drop below names something this database does not hold, so the
// statement has nothing to do: it is skipped, the rest of the file runs and
// the file is recorded once.
func TestRunMigrationsSkipsADropWhoseTargetIsAlreadyGone(t *testing.T) {
	for name, file := range map[string]string{
		"column":                 `ALTER TABLE attachments DROP COLUMN content_type;`,
		"column, no keyword":     `alter table attachments drop content_type;`,
		"column, quoted":         `ALTER TABLE "attachments" DROP COLUMN "content_type";`,
		"column, main schema":    `ALTER TABLE main.attachments DROP COLUMN [content_type];`,
		"column, after comment":  "-- the field left the model\nALTER TABLE attachments /* was text */ DROP COLUMN content_type;",
		"column of a gone table": `ALTER TABLE scans DROP COLUMN checksum;`,
		"table":                  `DROP TABLE scans;`,
		"table, quoted":          "DROP TABLE `scans`;",
		"index":                  `DROP INDEX idx_attachments_content_type;`,
		"index, main schema":     `DROP INDEX main."idx_attachments_content_type";`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
			defer db.Close()
			prismaShapedTracking(t, db)
			mustExec(t, db, `CREATE TABLE attachments (id INTEGER PRIMARY KEY, name TEXT)`)
			mustExec(t, db, `INSERT INTO attachments (name) VALUES ('a.txt')`)
			writeMig(t, dir, "0005_drop.sql", file+"\nUPDATE attachments SET name = name || '!';\n")

			var logged bytes.Buffer
			log.SetOutput(&logged)
			err := RunMigrations(db, dir)
			log.SetOutput(os.Stderr)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if n := dropFreshLedgerCount(t, db, "0005_drop.sql"); n != 1 {
				t.Fatalf("ledger records the file %d times, want 1", n)
			}
			var got string
			db.QueryRow(`SELECT name FROM attachments`).Scan(&got)
			if got != "a.txt!" {
				t.Fatalf("the statement after the skipped drop did not run: name=%q", got)
			}
			if !strings.Contains(logged.String(), "skipping") {
				t.Fatalf("no log line for the skipped drop:\n%s", logged.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "migrations", "0005_drop.sql")); err != nil {
				t.Fatalf("the file was set aside: %v", err)
			}
		})
	}
}

// A drop with work to do on this database does it.
func TestRunMigrationsDropStillDropsWhatTheDatabaseHolds(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	prismaShapedTracking(t, db)
	mustExec(t, db, `CREATE TABLE attachments (id INTEGER PRIMARY KEY, name TEXT, content_type TEXT)`)
	mustExec(t, db, `CREATE INDEX idx_attachments_name ON attachments(name)`)
	mustExec(t, db, `INSERT INTO attachments (name, content_type) VALUES ('a.txt', 'text/plain')`)
	mustExec(t, db, `CREATE TABLE scans (id INTEGER PRIMARY KEY)`)
	writeMig(t, dir, "0005_drop.sql", "ALTER TABLE attachments DROP COLUMN content_type;\nDROP INDEX idx_attachments_name;\nDROP TABLE scans;\n")

	if err := RunMigrations(db, dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	if dbColumnExists(db, "attachments", "content_type") {
		t.Fatal("the column was not dropped")
	}
	if dbTableExists(db, "scans") {
		t.Fatal("the table was not dropped")
	}
	var indexes int
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_attachments_name'`).Scan(&indexes)
	if indexes != 0 {
		t.Fatal("the index was not dropped")
	}
	var rows int
	db.QueryRow(`SELECT COUNT(*) FROM attachments WHERE name = 'a.txt'`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("the row did not survive the column drop: %d", rows)
	}
}

// A failure that is not "the target is already gone" still fails the file:
// nothing is recorded, nothing the file did before the failure stays, and the
// file is set aside as before.
func TestRunMigrationsDropThatReallyFailsStillFails(t *testing.T) {
	for name, tc := range map[string]struct {
		file string
		want string
	}{
		// The column exists; SQLite refuses because a trigger reads it. The
		// error text also says "no such column".
		"column a trigger reads": {`ALTER TABLE attachments DROP COLUMN content_type;`, "no such column"},
		// The column exists and cannot be dropped.
		"primary key column": {`ALTER TABLE attachments DROP COLUMN id;`, "PRIMARY KEY"},
		// Not exactly a drop: other statements that name what is missing.
		"update of a missing column":    {`UPDATE attachments SET checksum = 'x';`, "no such column"},
		"delete from a missing table":   {`DELETE FROM scans;`, "no such table"},
		"add column to a missing table": {`ALTER TABLE scans ADD COLUMN checksum TEXT;`, "no such table"},
		"view drop":                     {`DROP VIEW attachment_names;`, "no such view"},
		"trigger drop":                  {`DROP TRIGGER attachments_touch;`, "no such trigger"},
		// A table in another schema is not the app's data.
		"temp table drop":  {`DROP TABLE temp.scans;`, "no such table"},
		"temp column drop": {`ALTER TABLE temp.attachments DROP COLUMN content_type;`, "no such table"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
			defer db.Close()
			db.SetMaxOpenConns(1)
			prismaShapedTracking(t, db)
			mustExec(t, db, `CREATE TABLE attachments (id INTEGER PRIMARY KEY, name TEXT, content_type TEXT, seen INTEGER)`)
			mustExec(t, db, `CREATE TRIGGER attachments_seen AFTER UPDATE OF name ON attachments BEGIN UPDATE attachments SET seen = length(NEW.content_type) WHERE id = NEW.id; END`)
			mustExec(t, db, `INSERT INTO attachments (name, content_type) VALUES ('a.txt', 'text/plain')`)
			writeMig(t, dir, "0005_drop.sql", "UPDATE attachments SET name = 'changed';\n"+tc.file+"\n")

			err := RunMigrations(db, dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a failure naming %q, got %v", tc.want, err)
			}
			if n := dropFreshLedgerCount(t, db, "0005_drop.sql"); n != 0 {
				t.Fatalf("the failed file was recorded %d times", n)
			}
			var got, contentType string
			if err := db.QueryRow(`SELECT name, content_type FROM attachments`).Scan(&got, &contentType); err != nil {
				t.Fatal(err)
			}
			if got != "a.txt" || contentType != "text/plain" {
				t.Fatalf("the failed file left a change behind: name=%q content_type=%q", got, contentType)
			}
			if _, err := os.Stat(filepath.Join(dir, "migrations", "0005_drop.sql.failed.sql")); err != nil {
				t.Fatalf("the failed file was not set aside: %v", err)
			}
		})
	}
}

// A file reused for a schema.prisma change (prisma_migrate_adopt.go) asks the
// same question of a failed statement as the runner, so a drop of what is
// already gone does not make the generator abandon the file.
func TestMigrationStatementAlreadyAppliedCoversDrops(t *testing.T) {
	dir := t.TempDir()
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	mustExec(t, db, `CREATE TABLE attachments (id INTEGER PRIMARY KEY, name TEXT)`)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for stmt, wantSkip := range map[string]bool{
		`ALTER TABLE attachments DROP COLUMN content_type`: true,
		`DROP TABLE scans`:                       true,
		`DROP INDEX idx_scans_owner`:             true,
		`ALTER TABLE attachments DROP COLUMN id`: false,
		`UPDATE attachments SET checksum = 'x'`:  false,
		`DROP VIEW scans`:                        false,
	} {
		_, execErr := tx.Exec(stmt)
		if execErr == nil {
			t.Fatalf("%s: expected SQLite to refuse it", stmt)
		}
		if _, skip := migrationStatementAlreadyApplied(tx, stmt, execErr); skip != wantSkip {
			t.Fatalf("%s (%v): skip=%v, want %v", stmt, execErr, skip, wantSkip)
		}
	}
	// The error alone decides nothing: the same text for a statement that is
	// not a drop, and a drop with another error, are both real failures.
	missing := errors.New(`no such column: "content_type"`)
	if _, skip := migrationStatementAlreadyApplied(tx, `UPDATE attachments SET content_type = NULL`, missing); skip {
		t.Fatal("an UPDATE of a missing column was treated as applied")
	}
	if _, skip := migrationStatementAlreadyApplied(tx, `ALTER TABLE attachments DROP COLUMN content_type`, errors.New("database is locked")); skip {
		t.Fatal("a drop that failed for another reason was treated as applied")
	}
	if _, skip := migrationStatementAlreadyApplied(tx, `ALTER TABLE attachments DROP COLUMN name`, missing); skip {
		t.Fatal("a drop of a column the table holds was treated as applied")
	}
}
