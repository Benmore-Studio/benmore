//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrismaRuntimeJournalRollbackPreservesConventionalHistory(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initial := "model Note {\n id Int @id @default(autoincrement())\n title String\n}\n"
	first, err := ApplyPrismaMigration(db, dir, initial)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(initial, " title String", " title String\n body String @default(\"\")", 1)
	journal, err := applyPrismaMigration(db, dir, next, true)
	if err != nil || !strings.HasPrefix(journal, prismaRuntimeJournalPrefix) {
		t.Fatalf("runtime journal: %q, %v", journal, err)
	}
	if !dbColumnExists(db, "notes", "body") {
		t.Fatal("runtime migration was not applied")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if err != nil || len(entries) != 1 || entries[0].Name() != first {
		t.Fatalf("runtime migration changed conventional source: %v, %v", entries, err)
	}
	rolled, err := RollbackPrismaMigration(db, dir, 1, true)
	if err != nil || len(rolled) != 1 || rolled[0] != journal || dbColumnExists(db, "notes", "body") {
		t.Fatalf("runtime rollback: %v, %v", rolled, err)
	}
	var journals int
	if err := db.QueryRow("SELECT count(*) FROM _benmore_prisma_runtime_journals WHERE name=?", journal).Scan(&journals); err != nil || journals != 0 {
		t.Fatalf("runtime DB journal was not deleted: %d, %v", journals, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "migrations", first)); err != nil {
		t.Fatalf("conventional artifact was removed: %v", err)
	}
	var source string
	if err := db.QueryRow("SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1").Scan(&source); err != nil || source != initial {
		t.Fatalf("rollback ledger source: %q, %v", source, err)
	}
	if _, err := RollbackPrismaMigration(db, dir, 1, true); err != nil {
		t.Fatalf("conventional rollback after runtime rollback: %v", err)
	}
}

func TestPrismaMigrationArtifactPathRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../outside.sql", "/outside.sql", `..\outside.sql`, prismaRuntimeJournalPrefix + "../outside.sql", prismaRuntimeJournalPrefix + "nested/file.sql", "no_schema_change", ""} {
		if _, err := prismaMigrationArtifactPath(name); err == nil {
			t.Fatalf("accepted artifact path %q", name)
		}
	}
}

func TestPrismaRuntimeJournalNeverWritesFilesystem(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	for _, linkParent := range []bool{false, true} {
		dir, outside := t.TempDir(), t.TempDir()
		if err := os.Chmod(outside, 0700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, ".benmore")
		if !linkParent {
			if err := os.Mkdir(link, 0700); err != nil {
				t.Fatal(err)
			}
			link = filepath.Join(link, "prisma-migrations")
		}
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, applyErr := applyPrismaMigration(db, dir, "model Note {\n id Int @id\n}\n", true)
		if applyErr != nil || !dbColumnExists(db, "notes", "id") {
			t.Fatalf("DB journal migration: %v", applyErr)
		}
		db.Close()
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("external journal wrote files: %v, %v", entries, err)
		}
		info, err := os.Stat(outside)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("external journal changed mode: %v, %v", info, err)
		}
	}
}

func TestPrismaRuntimeJournalSurvivesDatabaseOnlyRestore(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	dir, restoredDir := t.TempDir(), t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initial := "model Note {\n id Int @id\n title String\n}\n"
	if _, err := applyPrismaMigration(db, dir, initial, true); err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(initial, " title String", " title String\n body String @default(\"\")", 1)
	name, err := applyPrismaMigration(db, dir, next, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("VACUUM INTO ?", filepath.Join(restoredDir, "data.db")); err != nil {
		t.Fatal(err)
	}
	restored, err := sql.Open("sqlite3", filepath.Join(restoredDir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	rolled, err := RollbackPrismaMigration(restored, restoredDir, 1, false)
	if err != nil || len(rolled) != 1 || rolled[0] != name || dbColumnExists(restored, "notes", "body") {
		t.Fatalf("database-only rollback: %v, %v", rolled, err)
	}
	if _, err := RollbackPrismaMigration(restored, restoredDir, 1, false); err != nil {
		t.Fatalf("database-only initial schema rollback: %v", err)
	}
	var journals, ledger int
	if err := restored.QueryRow("SELECT count(*) FROM _benmore_prisma_runtime_journals").Scan(&journals); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow("SELECT count(*) FROM _benmore_migrations").Scan(&ledger); err != nil || journals != 0 || ledger != 0 {
		t.Fatalf("rollback did not delete journal/ledger atomically: %d/%d, %v", journals, ledger, err)
	}
}

func TestPrismaRuntimeJournalFailureRollsBackSchemaAndLedger(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initial := "model Note {\n id Int @id\n title String\n}\n"
	if _, err := applyPrismaMigration(db, dir, initial, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER reject_runtime_journal BEFORE INSERT ON _benmore_prisma_runtime_journals BEGIN SELECT RAISE(ABORT,'journal unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(initial, " title String", " title String\n body String @default(\"\")", 1)
	if _, err := applyPrismaMigration(db, dir, next, true); err == nil || dbColumnExists(db, "notes", "body") {
		t.Fatalf("failed journal left schema applied: %v", err)
	}
	var journals, ledger int
	if err := db.QueryRow("SELECT count(*) FROM _benmore_prisma_runtime_journals").Scan(&journals); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM _benmore_migrations").Scan(&ledger); err != nil || journals != 1 || ledger != 1 {
		t.Fatalf("failed journal left partial metadata: %d/%d, %v", journals, ledger, err)
	}
}
