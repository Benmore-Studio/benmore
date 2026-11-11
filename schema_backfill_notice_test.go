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

// Round 2026-11-04 (lifecycle finding 5f): adding a required `goal Int` with
// no @default to a table holding rows added `goal INTEGER NOT NULL DEFAULT 0`
// in silence: every old row read 0, and the database kept a default the API
// contradicts (a create without goal gets 422). The migration is unchanged;
// the write answer (schema_not_applied), `benmore check` and the load log now
// name the field, the backfilled value and how to choose one.
func TestRequiredFieldBackfillIsReported(t *testing.T) {
	const v1 = "model Habit {\n  id Int @id @default(autoincrement())\n  name String\n}\n"
	const v2 = "model Habit {\n  id Int @id @default(autoincrement())\n  name String\n  goal Int\n  label String\n  done Boolean\n  dueAt DateTime\n  streak Int @default(1)\n  memo String?\n  touchedAt DateTime @updatedAt\n}\n"
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	loadSchemaForTest(t, db, dir, v1)
	mustExec(t, db, `INSERT INTO habits (name) VALUES ('run')`)

	changes, err := prismaUnappliedChanges(db, v2)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(changes, "\n")
	for _, want := range []string{
		"required field added without a default: habits.goal (INTEGER) - every row that already exists gets goal = 0, and the live column keeps DEFAULT 0",
		"the API refuses a create without it",
		"`@default(<value>)`",
		"`UPDATE habits SET goal = <value>;`",
		"habits.label (TEXT) - every row that already exists gets label = '' (an empty string)",
		"habits.done (BOOLEAN) - every row that already exists gets done = 0 (false)",
		"habits.due_at (DATETIME) - every row that already exists gets due_at = the time the migration ran",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("reported changes lack %q:\n%s", want, all)
		}
	}
	for _, quiet := range []string{"habits.streak", "habits.memo", "habits.touched_at"} {
		if strings.Contains(all, quiet) {
			t.Errorf("%s has a default, is optional or is @updatedAt, but was reported:\n%s", quiet, all)
		}
	}

	// `benmore check` lists the same lines before the reload.
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(v2), 0o644); err != nil {
		t.Fatal(err)
	}
	if findings := schemaUnappliedFindings(dir); len(findings) != len(changes) || len(findings) == 0 {
		t.Fatalf("check findings = %+v, want %d", findings, len(changes))
	}

	// The load applies the migration as before and logs the backfill.
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if _, err := ApplyPrismaMigration(db, dir, v2); err != nil {
		log.SetOutput(os.Stderr)
		t.Fatal(err)
	}
	log.SetOutput(os.Stderr)
	if !strings.Contains(logged.String(), "SCHEMA BACKFILL: required field added without a default: habits.goal") {
		t.Fatalf("load did not log the backfill:\n%s", logged.String())
	}
	var goal int
	var dflt sql.NullString
	if err := db.QueryRow(`SELECT goal FROM habits WHERE name = 'run'`).Scan(&goal); err != nil || goal != 0 {
		t.Fatalf("existing row goal = %d, %v (migration behaviour must not change)", goal, err)
	}
	if err := db.QueryRow(`SELECT dflt_value FROM pragma_table_info('habits') WHERE name = 'goal'`).Scan(&dflt); err != nil || dflt.String != "0" {
		t.Fatalf("goal default = %v, %v", dflt, err)
	}
	if after, _ := prismaUnappliedChanges(db, v2); len(after) != 0 {
		t.Fatalf("after the load recorded the schema, still reported: %v", after)
	}
}
