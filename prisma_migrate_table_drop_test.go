//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func loadSchemaForTest(t *testing.T, db *sql.DB, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	tables, deferred, err := LoadSchema(db, dir)
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	if _, err := Migrate(db, tables, false); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := ApplyDeferredDDL(db, deferred); err != nil {
		t.Fatalf("ApplyDeferredDDL: %v", err)
	}
}

func migTestRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Renaming a model while @@map keeps its table must not touch the data: the
// diff keyed models by name, so the rename emitted DROP TABLE for the mapped
// table and the reconcile pass then skipped the CREATE (the table was live).
func TestPrismaMigration_ModelRenameKeepsMappedTable(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	loadSchemaForTest(t, db, dir, `model Contact {
  id   Int    @id @default(autoincrement())
  name String
  @@map("contacts")
}`)
	if _, err := db.Exec(`INSERT INTO contacts (name) VALUES ('Ada'), ('Grace')`); err != nil {
		t.Fatal(err)
	}

	loadSchemaForTest(t, db, dir, `model Customer {
  id   Int    @id @default(autoincrement())
  name String
  @@map("contacts")
}`)
	if got := migTestRows(t, db, "contacts"); got != 2 {
		t.Fatalf("contacts rows after model rename = %d, want 2 (table was dropped)", got)
	}
}

// promote's preflight diff walks only the tables dev declares, so a model dev
// removed never showed as destructive while prod's boot migration dropped the
// table. PrismaTablesDroppedOnLoad previews those drops (tables holding rows).
func TestPrismaTablesDroppedOnLoad_ReportsRemovedModelWithRows(t *testing.T) {
	prodDir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(prodDir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	loadSchemaForTest(t, db, prodDir, `model Note {
  id   Int    @id @default(autoincrement())
  body String
}

model Tag {
  id   Int    @id @default(autoincrement())
  name String
}

model Draft {
  id   Int    @id @default(autoincrement())
  body String
}`)
	if _, err := db.Exec(`INSERT INTO tags (name) VALUES ('keep')`); err != nil {
		t.Fatal(err)
	}

	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "schema.prisma"), []byte(`model Note {
  id   Int    @id @default(autoincrement())
  body String
}`), 0644); err != nil {
		t.Fatal(err)
	}
	dropped, err := PrismaTablesDroppedOnLoad(db, devDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != "tags (1 rows)" {
		t.Fatalf("dropped = %v, want [tags (1 rows)] (empty drafts is not data loss)", dropped)
	}

	// Same source as the last applied one: nothing would run.
	if err := os.WriteFile(filepath.Join(devDir, "schema.prisma"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(filepath.Join(prodDir, "schema.prisma"))
	if err := os.WriteFile(filepath.Join(devDir, "schema.prisma"), src, 0644); err != nil {
		t.Fatal(err)
	}
	if dropped, err := PrismaTablesDroppedOnLoad(db, devDir); err != nil || len(dropped) != 0 {
		t.Fatalf("unchanged schema: dropped=%v err=%v, want none", dropped, err)
	}
}

// Adding @unique to a field of an existing table must reach the database.
// CREATE TABLE IF NOT EXISTS never re-runs for a live table and the diff
// ignored the attribute, so the schema said unique while duplicates saved.
func TestPrismaMigration_UniqueAddedToExistingColumn(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	loadSchemaForTest(t, db, dir, `model Invite {
  id   Int    @id @default(autoincrement())
  code String
}`)
	if _, err := db.Exec(`INSERT INTO invites (code) VALUES ('a')`); err != nil {
		t.Fatal(err)
	}

	loadSchemaForTest(t, db, dir, `model Invite {
  id   Int    @id @default(autoincrement())
  code String @unique
}`)
	if _, err := db.Exec(`INSERT INTO invites (code) VALUES ('a')`); err == nil {
		t.Fatal("duplicate code accepted after adding @unique to an existing column")
	}
}
