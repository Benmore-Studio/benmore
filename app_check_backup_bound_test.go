//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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

// The app's own boot keeps its per-boot pre-migrate snapshot.
func TestBootLoadStillTakesPreMigrateBackup(t *testing.T) {
	dir := checkLoadFixture(t)
	before := countPreMigrateBackups(dir)
	time.Sleep(1100 * time.Millisecond)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	app.DB.Close()
	if after := countPreMigrateBackups(dir); after != before+1 {
		t.Fatalf("boot load backups: before=%d after=%d", before, after)
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
