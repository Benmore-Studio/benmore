//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openNonConstTestDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// Adding @default(now()), @updatedAt or a required DateTime to a table that
// holds rows failed with "Cannot add a column with non-constant default": a
// dev push took the app down at its next restart and a promote left prod
// crash-looping (round-2 testing, 2026-10-23).
func TestPrismaMigrationAddsNonConstantDefaultColumnsToTableWithRows(t *testing.T) {
	dir := t.TempDir()
	db := openNonConstTestDB(t, dir)
	loadSchemaForTest(t, db, dir, `model Note {
  id   Int    @id @default(autoincrement())
  body String
}`)
	mustExec(t, db, `INSERT INTO notes (body) VALUES ('kept'), ('also kept')`)

	loadSchemaForTest(t, db, dir, `model Note {
  id        Int      @id @default(autoincrement())
  body      String
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")
  dueAt     DateTime @map("due_at")
}`)
	var n, missing int
	if err := db.QueryRow(`SELECT COUNT(*), SUM(created_at IS NULL OR updated_at IS NULL OR due_at IS NULL) FROM notes WHERE body LIKE '%kept'`).Scan(&n, &missing); err != nil {
		t.Fatal(err)
	}
	if n != 2 || missing != 0 {
		t.Fatalf("rows=%d with a missing new value=%d, want 2 and 0", n, missing)
	}
	// Later inserts get the database default, not the migration time.
	mustExec(t, db, `INSERT INTO notes (body, due_at) VALUES ('new', '2030-01-01 00:00:00')`)
	var created string
	if err := db.QueryRow(`SELECT created_at FROM notes WHERE body='new'`).Scan(&created); err != nil || created == "" {
		t.Fatalf("new row created_at=%q err=%v", created, err)
	}
	// The @updatedAt trigger came along.
	mustExec(t, db, `UPDATE notes SET updated_at='2000-01-01 00:00:00' WHERE body='kept'`)
	time.Sleep(1100 * time.Millisecond)
	mustExec(t, db, `UPDATE notes SET body='kept!' WHERE body='kept'`)
	var updated string
	if err := db.QueryRow(`SELECT updated_at FROM notes WHERE body='kept!'`).Scan(&updated); err != nil || strings.HasPrefix(updated, "2000-") {
		t.Fatalf("updated_at after an update = %q, err=%v", updated, err)
	}
	// The migration file journals what ran, so the other instance replays it.
	entries, _ := os.ReadDir(filepath.Join(dir, "migrations"))
	var journal string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			b, _ := os.ReadFile(filepath.Join(dir, "migrations", e.Name()))
			journal += string(b)
		}
	}
	if !strings.Contains(journal, "notes_migrate_tmp") || !strings.Contains(journal, "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP") {
		t.Fatalf("migration journal lacks the rebuild:\n%s", journal)
	}
}

func TestPrismaMigrationAddsNonConstantDefaultColumnToEmptyTable(t *testing.T) {
	dir := t.TempDir()
	db := openNonConstTestDB(t, dir)
	loadSchemaForTest(t, db, dir, `model Note {
  id   Int    @id @default(autoincrement())
  body String
}`)
	loadSchemaForTest(t, db, dir, `model Note {
  id        Int      @id @default(autoincrement())
  body      String
  createdAt DateTime @default(now()) @map("created_at")
}`)
	mustExec(t, db, `INSERT INTO notes (body) VALUES ('x')`)
	var created string
	if err := db.QueryRow(`SELECT created_at FROM notes`).Scan(&created); err != nil || created == "" {
		t.Fatalf("created_at=%q err=%v", created, err)
	}
}

// A table another table references is not rebuilt (checkTableRebuildReferences);
// the refusal says what to do instead of SQLite's error.
func TestPrismaMigrationRefusesNonConstantColumnOnReferencedTableWithRows(t *testing.T) {
	dir := t.TempDir()
	db := openNonConstTestDB(t, dir)
	loadSchemaForTest(t, db, dir, `model Author {
  id    Int    @id @default(autoincrement())
  name  String
  posts Post[]
}

model Post {
  id       Int    @id @default(autoincrement())
  authorId Int    @map("author_id")
  author   Author @relation(fields: [authorId], references: [id])
}`)
	mustExec(t, db, `INSERT INTO authors (name) VALUES ('a')`)
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(`model Author {
  id        Int      @id @default(autoincrement())
  name      String
  createdAt DateTime @default(now()) @map("created_at")
  posts     Post[]
}

model Post {
  id       Int    @id @default(autoincrement())
  authorId Int    @map("author_id")
  author   Author @relation(fields: [authorId], references: [id])
}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadSchema(db, dir)
	if err == nil || !strings.Contains(err.Error(), "Make the field optional, give it a constant default, or add it in an explicit migration") {
		t.Fatalf("referenced table: err=%v", err)
	}
	var names int
	if err := db.QueryRow(`SELECT COUNT(*) FROM authors WHERE name='a'`).Scan(&names); err != nil || names != 1 {
		t.Fatalf("authors after refused migration: %d %v", names, err)
	}
}

func TestInsertColumnDefinitionsKeepsTableConstraintsLast(t *testing.T) {
	ddl := `CREATE TABLE "t_tmp" (a INTEGER NOT NULL, b TEXT, PRIMARY KEY (a, b), CHECK (a > 0)) STRICT`
	got, err := insertColumnDefinitions(ddl, []string{"created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"})
	if err != nil {
		t.Fatal(err)
	}
	want := `CREATE TABLE "t_tmp" (a INTEGER NOT NULL, b TEXT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (a, b), CHECK (a > 0)) STRICT`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
