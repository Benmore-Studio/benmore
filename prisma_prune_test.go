//go:build !cli

package main

// Tests for PrunePrismaDrift — the operation that drops live-DB
// columns + tables that aren't in schema.prisma. Used when the agent
// iterates the schema smaller and the old shape lingers.

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestPrune_DropsExtraColumn(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Apply a schema with a richer Todo, then simplify schema.prisma
	// and run prune.
	rich := `model Todo {
  id          Int     @id @default(autoincrement())
  title       String
  description String  @default("")
  priority    String  @default("medium")
  userId      Int     @map("user_id")
}`
	if _, err := ApplyPrismaMigration(db, dir, rich); err != nil {
		t.Fatalf("seed: %s", err)
	}
	if !columnExists(t, db, "todos", "description") {
		t.Fatal("description should exist after seed")
	}

	// Simplify on-disk schema (rewrites schema.prisma).
	simple := `model Todo {
  id     Int    @id @default(autoincrement())
  title  String
  userId Int    @map("user_id")
}`
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(simple), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := PrunePrismaDrift(db, dir)
	if err != nil {
		t.Fatalf("prune: %s", err)
	}
	if result.MigrationFile == "" {
		t.Fatal("expected a prune migration file")
	}
	if !strings.Contains(result.MigrationFile, "_prune.sql") {
		t.Errorf("filename should have _prune.sql suffix, got %q", result.MigrationFile)
	}
	// The drifted columns should be in the result list.
	found := map[string]bool{}
	for _, c := range result.ColumnsDropped {
		found[c] = true
	}
	for _, want := range []string{"todos.description", "todos.priority"} {
		if !found[want] {
			t.Errorf("expected %s in dropped columns, got %v", want, result.ColumnsDropped)
		}
	}
	// Live DB should no longer have them.
	if columnExists(t, db, "todos", "description") {
		t.Errorf("description column should be dropped from live DB")
	}
	if columnExists(t, db, "todos", "priority") {
		t.Errorf("priority column should be dropped from live DB")
	}
	// title + id + user_id should still be there.
	for _, keep := range []string{"id", "title", "user_id"} {
		if !columnExists(t, db, "todos", keep) {
			t.Errorf("column %s shouldn't have been dropped", keep)
		}
	}
}

func TestPrune_NoOpOnCleanSchema(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := `model Todo {
  id    Int    @id @default(autoincrement())
  title String
}`
	if _, err := ApplyPrismaMigration(db, dir, src); err != nil {
		t.Fatalf("seed: %s", err)
	}
	result, err := PrunePrismaDrift(db, dir)
	if err != nil {
		t.Fatalf("prune (no drift): %s", err)
	}
	if result.MigrationFile != "" {
		t.Errorf("clean schema should produce no prune file, got %q", result.MigrationFile)
	}
	if len(result.ColumnsDropped) != 0 || len(result.TablesDropped) != 0 {
		t.Errorf("clean schema shouldn't drop anything, got %+v", result)
	}
}
