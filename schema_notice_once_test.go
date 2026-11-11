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

// Round 2026-11-04 (lifecycle finding 5c): after a field was removed from a
// schema.prisma app, every start logged
// "DROP habits.legacy_tag - column exists in DB but not in schema.sql (use
// --force to drop)": the wrong file, a flag hosted apps do not have, on every
// start. The load now says what is true (the column keeps its data; a
// migrations/ file drops it) and says it once per change.
func TestRetainedColumnNoticeIsTrueAndLoggedOncePerChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "habits")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", "name: habits\n")
	writeTestFile(t, dir, "schema.prisma", "model Habit {\n  id Int @id @default(autoincrement())\n  name String\n  legacyTag String? @map(\"legacy_tag\")\n  note String?\n}\n")
	load := func() string {
		t.Helper()
		var logged bytes.Buffer
		log.SetOutput(&logged)
		app, err := loadApp(dir)
		log.SetOutput(os.Stderr)
		if err != nil {
			t.Fatalf("load: %v\n%s", err, logged.String())
		}
		app.DB.Close()
		return logged.String()
	}
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	load()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO habits (name, legacy_tag, note) VALUES ('run', 'old', 'n')`)
	db.Close()

	writeTestFile(t, dir, "schema.prisma", "model Habit {\n  id Int @id @default(autoincrement())\n  name String\n  note String?\n}\n")
	first := load()
	for _, want := range []string{
		"habits.legacy_tag: in the database but not in the schema - kept with its data",
		"add a migrations/ file with `ALTER TABLE habits DROP COLUMN legacy_tag;`",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("the load that removed the field did not log %q:\n%s", want, first)
		}
	}
	for _, stale := range []string{"schema.sql", "--force"} {
		if strings.Contains(first, stale) {
			t.Fatalf("load log still says %q:\n%s", stale, first)
		}
	}

	// (The schema-drift summary, "[extra_column] habits.legacy_tag", is a
	// separate one-line pointer to `benmore check`.)
	if again := load(); strings.Contains(again, "in the database but not in the schema") {
		t.Fatalf("an unchanged start logged the kept column again:\n%s", again)
	}

	// A new difference is a change: the list is logged again.
	writeTestFile(t, dir, "schema.prisma", "model Habit {\n  id Int @id @default(autoincrement())\n  name String\n}\n")
	changed := load()
	if !strings.Contains(changed, "habits.note: in the database but not in the schema") || !strings.Contains(changed, "habits.legacy_tag: in the database") {
		t.Fatalf("a changed set of kept columns was not logged:\n%s", changed)
	}
	if again := load(); strings.Contains(again, "in the database but not in the schema") {
		t.Fatalf("logged again without a change:\n%s", again)
	}

	// The column keeps its data throughout.
	db, err = sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tag string
	if err := db.QueryRow(`SELECT legacy_tag FROM habits WHERE name = 'run'`).Scan(&tag); err != nil || tag != "old" {
		t.Fatalf("legacy_tag = %q, %v", tag, err)
	}
}

// Migrate reports such a column, and a nullability change it does not
// rebuild, as kept (Retained), never as a blocked drop that needs --force.
func TestMigrateReportsUndeclaredColumnAsRetained(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE habits (id INTEGER PRIMARY KEY, name TEXT NOT NULL, legacy_tag TEXT)`)
	res, err := Migrate(db, []Table{{Name: "habits", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "name", Type: "TEXT"}}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Blocked) != 0 {
		t.Fatalf("blocked = %v", res.Blocked)
	}
	all := strings.Join(res.Retained, "\n")
	for _, want := range []string{
		"habits.legacy_tag" + retainedUndeclaredMarker,
		"habits.name: the database column is NOT NULL, the schema says NULL",
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("retained lacks %q:\n%s", want, all)
		}
	}
}
