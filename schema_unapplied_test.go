//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	unappliedSchemaV1 = `model Note {
  id       Int       @id @default(autoincrement())
  body     String    @unique
  priority Int       @default(0)
  dueAt    DateTime?
  code     String    @default("")
  archived Boolean   @default(false)
}`
	// Every change the generator does not apply, at once.
	unappliedSchemaV2 = `model Note {
  id       Int      @id @default(autoincrement())
  body     String
  priority String   @default("0")
  dueAt    DateTime
  code     String   @default("X")
}`
)

func unappliedFixture(t *testing.T) (string, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	loadSchemaForTest(t, db, dir, unappliedSchemaV1)
	mustExec(t, db, `INSERT INTO notes (body, priority, archived) VALUES ('first', 3, 1)`)
	return dir, db
}

// Round-2 finding L5: changing Int to String (or nullability, a default, or
// removing a field) wrote no migration and said nothing, while the live
// column kept its old shape. Each change is now named with what the live
// database does instead.
func TestUnappliedSchemaChangesAreNamed(t *testing.T) {
	dir, db := unappliedFixture(t)
	changes, err := prismaUnappliedChanges(db, unappliedSchemaV2)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(changes, "\n")
	for _, want := range []string{
		"type changed: notes.priority INTEGER → TEXT",
		`"007" is stored as 7`,
		"now required: notes.due_at",
		"still accepts NULL",
		"default changed: notes.code '' → 'X'",
		"keeps the default it was created with",
		"field removed: notes.archived",
		"ALTER TABLE notes DROP COLUMN archived;",
		"@unique removed: notes.body",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("unapplied changes missing %q:\n%s", want, all)
		}
	}
	if again, _ := prismaUnappliedChanges(db, unappliedSchemaV1); len(again) != 0 {
		t.Fatalf("the applied schema reported changes: %v", again)
	}

	// `benmore check` reports the same list before the app reloads.
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(unappliedSchemaV2), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := schemaUnappliedFindings(dir)
	if len(findings) != len(changes) {
		t.Fatalf("check findings %+v, want %d", findings, len(changes))
	}
	for i, f := range findings {
		if f.Severity != "warning" || f.Source != "schema_not_applied" || f.Message != changes[i] {
			t.Fatalf("finding %d = %+v, want warning %q", i, f, changes[i])
		}
	}

	// The load still leaves the column alone, and now says so in its log
	// instead of recording the change in silence.
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	name, err := ApplyPrismaMigration(db, dir, unappliedSchemaV2)
	log.SetOutput(os.Stderr)
	if err != nil || name != "" {
		t.Fatalf("migration = %q, %v; want no file", name, err)
	}
	if !strings.Contains(logged.String(), "SCHEMA CHANGE NOT APPLIED to the live database: type changed: notes.priority") {
		t.Fatalf("load did not log the unapplied type change:\n%s", logged.String())
	}
	var liveType string
	if err := db.QueryRow(`SELECT type FROM pragma_table_info('notes') WHERE name = 'priority'`).Scan(&liveType); err != nil || liveType != "INTEGER" {
		t.Fatalf("live priority type = %q, %v", liveType, err)
	}
	if after, _ := prismaUnappliedChanges(db, unappliedSchemaV2); len(after) != 0 {
		t.Fatalf("after the load recorded the schema, still reported: %v", after)
	}
}

// A database without a recorded schema gets every table created from the new
// source, so nothing is left unapplied.
func TestUnappliedSchemaChangesNeedARecordedSchema(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if changes, err := prismaUnappliedChanges(db, unappliedSchemaV2); err != nil || len(changes) != 0 {
		t.Fatalf("fresh database: %v %v", changes, err)
	}
	if findings := schemaUnappliedFindings(t.TempDir()); len(findings) != 0 {
		t.Fatalf("app without data: %+v", findings)
	}
}
