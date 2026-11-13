//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func countPreMigrateBackups(dir string) int {
	entries, _ := os.ReadDir(filepath.Join(dir, ".benmore", "backups"))
	n := 0
	for _, e := range entries {
		if len(e.Name()) > 0 {
			n++
		}
	}
	return n
}

func checkLoadFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "probeapp")
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte("model Note {\n id Int @id @default(autoincrement())\n body String\n}\n"), 0644)
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("name: probe\n"), 0644)
	if msg := tryLoadApp(dir); msg != "" {
		t.Fatalf("first load: %s", msg)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 1000)
	for i := range blob {
		blob[i] = byte('a' + i%26)
	}
	tx, _ := db.Begin()
	for i := 0; i < 20000; i++ {
		if _, err := tx.Exec("INSERT INTO notes(body) VALUES (?)", string(blob)+fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	tx.Commit()
	db.Close()
	return dir
}

// Every write_file/edit_file runs RunCompleteCheck -> tryLoadApp in the router;
// each load used to VACUUM INTO a full copy of the tenant database.
func TestValidationLoadDoesNotCopyTheDatabaseOnEveryCall(t *testing.T) {
	dir := checkLoadFixture(t)
	for i := 0; i < 8; i++ {
		if msg := tryLoadApp(dir); msg != "" {
			t.Fatalf("load %d: %s", i, msg)
		}
	}
	if n := countPreMigrateBackups(dir); n > 1 {
		t.Fatalf("8 validation loads left %d full-database backups; want at most 1", n)
	}
}

// The app's own boot snapshots before a schema change, and only then: a boot
// that changes nothing has nothing to undo (schema_change_plan.go).
func TestBootLoadTakesPreMigrateBackupOnlyForASchemaChange(t *testing.T) {
	dir := checkLoadFixture(t)
	before := countPreMigrateBackups(dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.Close()
	if after := countPreMigrateBackups(dir); after != before {
		t.Fatalf("unchanged boot load took a backup: before=%d after=%d", before, after)
	}
	os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte("model Note {\n id Int @id @default(autoincrement())\n body String\n extra String?\n}\n"), 0644)
	app, err = loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.Close()
	if after := countPreMigrateBackups(dir); after != before+1 {
		t.Fatalf("schema-change boot load backups: before=%d after=%d", before, after)
	}
}

// A schema change still gets a verified load even when a recent snapshot exists.
func TestValidationLoadStillMigratesNewColumns(t *testing.T) {
	dir := checkLoadFixture(t)
	tryLoadApp(dir)
	os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte("model Note {\n id Int @id @default(autoincrement())\n body String\n extra String?\n}\n"), 0644)
	if msg := tryLoadApp(dir); msg != "" {
		t.Fatalf("load after schema change: %s", msg)
	}
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('notes') WHERE name='extra'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("new column not migrated: n=%d err=%v", n, err)
	}
}

// Migration SQL is tenant-authored and a validation load runs it in the router.
func TestValidationLoadInterruptsRunawayMigration(t *testing.T) {
	dir := checkLoadFixture(t)
	old := checkMigrationTimeout
	checkMigrationTimeout = 300 * time.Millisecond
	t.Cleanup(func() { checkMigrationTimeout = old })
	os.MkdirAll(filepath.Join(dir, "migrations"), 0755)
	mig := filepath.Join(dir, "migrations", "001_loop.sql")
	os.WriteFile(mig, []byte("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) DELETE FROM notes WHERE id IN (SELECT x FROM c);\n"), 0644)

	done := make(chan string, 1)
	go func() { done <- tryLoadApp(dir) }()
	select {
	case msg := <-done:
		if msg == "" {
			t.Fatal("runaway migration reported a clean load")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("validation load never returned: a router core is pinned by tenant migration SQL")
	}
	if _, err := os.Stat(mig); err != nil {
		t.Errorf("a timed-out migration must stay in place for the app's own boot: %v", err)
	}
}

// A pending file the Prisma step adopts (prisma_migrate_adopt.go) is
// tenant-authored SQL too, and it runs before the user-migration runner, so
// the validation deadline must reach it. Running out of time fails the load,
// leaves the file pending and generates no second file for the change.
func TestValidationLoadInterruptsRunawayAdoptedMigration(t *testing.T) {
	dir := checkLoadFixture(t)
	old := checkMigrationTimeout
	t.Cleanup(func() { checkMigrationTimeout = old })
	v1 := "model Note {\n id Int @id @default(autoincrement())\n body String\n}\n"
	v2 := "model Note {\n id Int @id @default(autoincrement())\n body String\n tag String @default(\"\")\n}\n"
	body := "-- Migration: add tag\n--\n" +
		"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) DELETE FROM notes WHERE id IN (SELECT x FROM c);\n" +
		"ALTER TABLE notes ADD COLUMN tag TEXT NOT NULL DEFAULT '';\n"
	migDir := filepath.Join(dir, "migrations")
	before, _ := os.ReadDir(migDir)
	mig := filepath.Join(migDir, "0002_20260101T000000Z_add_tag.sql")
	content := withSchemaChainHeader(body, prismaModelsDigest(mustParse(t, v1)), prismaModelsDigest(mustParse(t, v2)))
	if err := os.WriteFile(mig, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(v2), 0644); err != nil {
		t.Fatal(err)
	}

	// The limit is wall-clock time for the whole schema step, and what runs
	// before the adopted file (the pre-migration copy of this 20 MB database)
	// takes real time on a busy machine. When the limit runs out before the
	// file's first statement the load fails without naming the file, which
	// shows nothing about the file yet: the load is repeated with twice the
	// limit. The file's statement never ends, so the first limit that reaches
	// it must end in the file's own time-limit error.
	var msg string
	for limit := 300 * time.Millisecond; ; limit *= 2 {
		checkMigrationTimeout = limit
		done := make(chan string, 1)
		go func() { done <- tryLoadApp(dir) }()
		select {
		case msg = <-done:
		case <-time.After(limit + 15*time.Second):
			t.Fatal("validation load never returned: a router core is pinned by an adopted migration file")
		}
		if limit >= 20*time.Second || !strings.Contains(msg, context.DeadlineExceeded.Error()) || strings.Contains(msg, "0002_20260101T000000Z_add_tag.sql") {
			break
		}
		t.Logf("the %s limit ran out before the adopted file started (%s); trying twice the limit", limit, msg)
	}
	if !strings.Contains(msg, "0002_20260101T000000Z_add_tag.sql did not finish") {
		t.Fatalf("load error = %q, want the adopted file's time limit", msg)
	}
	if _, err := os.Stat(mig); err != nil {
		t.Errorf("a timed-out adopted file must stay pending for the app's own boot: %v", err)
	}
	after, _ := os.ReadDir(migDir)
	if len(after) != len(before)+1 {
		t.Errorf("migrations/ holds %d files, want %d: a timeout must not generate a second file for the change", len(after), len(before)+1)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n); err != nil || n != 20000 {
		t.Errorf("notes = %d (%v), want the 20000 rows untouched by the rolled-back file", n, err)
	}
}

// A generated migration is snapshotted before it runs. The loader's own
// pre-migrate snapshot (schema_backup) is taken after the Prisma step, so on
// its own it already held the migrated database.
func TestGeneratedMigrationIsBackedUpBeforeItRuns(t *testing.T) {
	dir := checkLoadFixture(t)
	backups := func() map[string]bool {
		out := map[string]bool{}
		entries, _ := os.ReadDir(filepath.Join(dir, ".benmore", "backups"))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".db") {
				out[e.Name()] = true
			}
		}
		return out
	}
	before := backups()
	schema := "model Note {\n id Int @id @default(autoincrement())\n body String\n tag String?\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0644); err != nil {
		t.Fatal(err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.Close()
	preMigration := false
	for name := range backups() {
		if before[name] {
			continue
		}
		db, err := sql.Open("sqlite3", filepath.Join(dir, ".benmore", "backups", name))
		if err != nil {
			t.Fatal(err)
		}
		if !dbColumnExists(db, "notes", "tag") {
			var n int
			db.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n)
			preMigration = n == 20000
		}
		db.Close()
	}
	if !preMigration {
		t.Fatal("no snapshot taken during the load holds the database before the generated migration added notes.tag")
	}
}
