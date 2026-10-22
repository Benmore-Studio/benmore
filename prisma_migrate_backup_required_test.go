//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrismaDestructiveMigrationRequiresBackupAndPropagatesFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	before := `model Note {
 id Int @id @default(autoincrement())
 body String
}
model Tag {
 id Int @id @default(autoincrement())
 label String
}`
	after := `model Tag {
 id Int @id @default(autoincrement())
 label String
}`
	loadSchemaForTest(t, db, dir, before)
	mustExec(t, db, `INSERT INTO notes(body) VALUES('only copy')`)
	if err := os.MkdirAll(filepath.Join(dir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, backupDirName), []byte("backup unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSchema(db, dir); err == nil || !strings.Contains(err.Error(), "pre-drop backup required") {
		t.Fatalf("schema load must fail on backup error: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("data changed after failure: n=%d err=%v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ledger changed after failure: n=%d err=%v", n, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed backup left runnable migration: entries=%v err=%v", entries, err)
	}
	if err := os.Remove(filepath.Join(dir, backupDirName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSchema(db, dir); err != nil {
		t.Fatalf("retry after backup repair: %v", err)
	}
	if dbTableExists(db, "notes") {
		t.Fatal("successful migration did not drop removed table")
	}
	backups := listBackups(dir)
	if len(backups) != 1 {
		t.Fatalf("backups=%v", backups)
	}
	backup, err := sql.Open("sqlite3", backups[0]+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var body string
	if err := backup.QueryRow(`SELECT body FROM notes`).Scan(&body); err != nil || body != "only copy" {
		t.Fatalf("pre-drop data not recoverable: %q %v", body, err)
	}
}

func TestPrismaMigrationExecutionFailureRejectsSchemaLoad(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	loadSchemaForTest(t, db, dir, `model Note {
 id Int @id @default(autoincrement())
 body String
}`)
	mustExec(t, db, `INSERT INTO notes(body) VALUES('same'),('same')`)
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(`model Note {
 id Int @id @default(autoincrement())
 body String @unique
}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSchema(db, dir); err == nil {
		t.Fatal("failed UNIQUE migration was silently accepted")
	}
	if n := migTestRows(t, db, "notes"); n != 2 {
		t.Fatalf("failed migration changed rows=%d", n)
	}
}
