//go:build !cli

package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const loadRefsSchema = "model Habit {\n  id Int @id @default(autoincrement())\n  name String @default(\"\")\n  note String @default(\"\")\n  userId Int? @map(\"user_id\")\n}\n\nmodel Tag {\n  id Int @id @default(autoincrement())\n  label String @default(\"\")\n  habitId Int? @map(\"habit_id\")\n}\n"

// loadRefsApp writes an app with loadRefsSchema, a durable encryption key
// and files.
func loadRefsApp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", loadRefsSchema)
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	for name, body := range files {
		writeTestFile(t, dir, name, body)
	}
	return dir
}

// loadRefsLoad starts the app from dir, as a restart does.
func loadRefsLoad(t *testing.T, dir string) error {
	t.Helper()
	app, err := loadApp(dir)
	if app != nil {
		app.Shutdown()
	}
	dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	return err
}

// sourceErrorFor is the `benmore check` source-layer error filed on file.
func sourceErrorFor(dir, file string) string {
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity == "error" && f.File == file {
			return f.Message
		}
	}
	return ""
}

// Each reference here makes the app's load fail. The write gate used to take
// the column cases with a warning (round 2026-11-04: an encrypted.yaml naming
// a missing column answered ok:true and the app crash-looped), computed.yaml
// with nothing at all. Each is now refused when written and an error in
// `benmore check`, and the load is shown to fail on it.
func TestWriteGateRefusesReferencesTheLoadRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, file, content string
		gate, load          string
		extra               map[string]string
	}{
		{"encrypted column", "encrypted.yaml", "tables:\n  habits:\n    fields: [note, ghost_col]\n", `habits.ghost_col is an encrypted field, but habits has no column "ghost_col"`, "encrypted field habits.ghost_col: source column does not exist", nil},
		{"app.yaml encrypted column", "app.yaml", "encrypted:\n  habits: [ghost_col]\n", `habits.ghost_col is an encrypted field`, "encrypted field habits.ghost_col: source column does not exist", nil},
		{"blind index column", "encrypted.yaml", "tables:\n  habits:\n    fields: [ghost_col]\n    blind_index: [ghost_col]\n", "encrypted field with a blind index", "blind index habits.ghost_col: source column does not exist", nil},
		{"encrypted table", "encrypted.yaml", "tables:\n  ghosts:\n    fields: [secret]\n", `encrypted fields name the table "ghosts"`, "ghosts", nil},
		{"versioned table", "app.yaml", "versioned: [ghosts]\n", `versioned lists "ghosts"`, "versioning ghosts: source table is missing", nil},
		{"computed table", "computed.yaml", "fields:\n  - table: ghosts\n    column: total\n    expr: \"1 + 1\"\n", `computed on the table "ghosts"`, "no such table", nil},
		{"computed column", "computed.yaml", "fields:\n  - table: habits\n    column: ghost\n    expr: \"name || 'x'\"\n", `habits has no column "ghost"`, "no such column: ghost", nil},
		{"computed expression column", "computed.yaml", "fields:\n  - table: habits\n    column: note\n    expr: \"ghost || 'x'\"\n", "habits.note reads a column the schema does not have", "no such column: ghost", nil},
		{"computed trigger table", "computed.yaml", "fields:\n  - table: habits\n    column: note\n    sql: \"SELECT COUNT(*) FROM tags WHERE habit_id = ?\"\n    triggers:\n      - table: ghosts\n        on: [insert]\n        fk: habit_id\n", `changes to the table "ghosts"`, "no such table", nil},
		{"computed trigger fk", "computed.yaml", "fields:\n  - table: habits\n    column: note\n    sql: \"SELECT COUNT(*) FROM tags WHERE habit_id = ?\"\n    triggers:\n      - table: tags\n        on: [insert]\n        fk: ghost_id\n", `names fk "ghost_id"`, "no such column: NEW.ghost_id", nil},
		{"fulltext field", "schema.prisma", strings.Replace(loadRefsSchema, "  userId Int? @map(\"user_id\")\n}", "  userId Int? @map(\"user_id\")\n  @@fulltext([ghost])\n}", 1), `@@fulltext names "ghost"`, "no such column", nil},
		// Computed triggers are installed before migrations run.
		{"computed over a column only a migration adds", "computed.yaml", "fields:\n  - table: habits\n    column: extra\n    expr: \"name || note\"\n", "only a migration adds the column \"extra\"", "no such column: extra", map[string]string{"migrations/0001_extra.sql": "ALTER TABLE habits ADD COLUMN extra TEXT;\n"}},
		{"computed reading a column only a migration adds", "computed.yaml", "fields:\n  - table: habits\n    column: note\n    expr: \"extra || name\"\n", "habits.note reads a column the schema does not have", "no such column: extra", map[string]string{"migrations/0001_extra.sql": "ALTER TABLE habits ADD COLUMN extra TEXT;\n"}},
		{"computed on a table only a migration creates", "computed.yaml", "fields:\n  - table: legacy\n    column: total\n    expr: \"1 + 1\"\n", "which only a migration creates", "no such table", map[string]string{"migrations/0001_legacy.sql": "CREATE TABLE IF NOT EXISTS legacy (id INTEGER PRIMARY KEY, total INTEGER);\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := loadRefsApp(t, tc.extra)
			msg := ValidateOnWriteIn(dir, tc.file, tc.content)
			if !strings.Contains(msg, tc.gate) || !strings.Contains(msg, "cannot") {
				t.Fatalf("write gate accepted or misnamed it:\n%s\nwant %q", msg, tc.gate)
			}
			if tc.file != "schema.prisma" && !strings.Contains(msg, "first encrypted field restarts the app") {
				t.Errorf("refusal does not say what the push would do to the app:\n%s", msg)
			}
			writeTestFile(t, dir, tc.file, tc.content)
			if got := sourceErrorFor(dir, tc.file); !strings.Contains(got, tc.gate) {
				t.Errorf("benmore check has no error on %s for it; got %q", tc.file, got)
			}
			if err := loadRefsLoad(t, dir); err == nil || !strings.Contains(err.Error(), tc.load) {
				t.Fatalf("load error = %v, want %q: the classification must match the load", err, tc.load)
			}
		})
	}
}

// What the load does resolve is not refused: a mapped column, an encrypted
// or versioned column or table a migration creates (installed after
// migrations run), and a computed field over the schema's own tables.
func TestWriteGateAcceptsReferencesTheLoadResolves(t *testing.T) {
	for _, tc := range []struct {
		name, file, content string
		extra               map[string]string
	}{
		{"mapped column", "encrypted.yaml", "tables:\n  habits:\n    fields: [note, user_id]\n    blind_index: [note]\n", nil},
		{"column a migration adds", "encrypted.yaml", "tables:\n  habits:\n    fields: [extra]\n", map[string]string{"migrations/0001_extra.sql": "ALTER TABLE habits ADD COLUMN extra TEXT;\n"}},
		{"table a migration creates", "encrypted.yaml", "tables:\n  legacy:\n    fields: [secret]\n", map[string]string{"migrations/0001_legacy.sql": "CREATE TABLE IF NOT EXISTS legacy (id INTEGER PRIMARY KEY, secret TEXT);\n"}},
		{"versioned", "app.yaml", "versioned: [habits, Tags]\n", nil},
		{"versioned table a migration creates", "app.yaml", "versioned: [legacy]\n", map[string]string{"migrations/0001_legacy.sql": "CREATE TABLE IF NOT EXISTS legacy (id INTEGER PRIMARY KEY, note TEXT);\n"}},
		{"computed aggregate", "computed.yaml", "fields:\n  - table: habits\n    column: note\n    sql: \"SELECT COUNT(*) FROM tags WHERE habit_id = ?\"\n    triggers:\n      - table: tags\n        on: [insert, delete]\n        fk: habit_id\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := loadRefsApp(t, tc.extra)
			if msg := ValidateOnWriteIn(dir, tc.file, tc.content); msg != "" {
				t.Fatalf("refused: %s", msg)
			}
			writeTestFile(t, dir, tc.file, tc.content)
			if got := sourceErrorFor(dir, tc.file); got != "" {
				t.Errorf("benmore check error: %s", got)
			}
			if err := loadRefsLoad(t, dir); err != nil {
				t.Fatalf("the app does not load, so it should have been refused: %v", err)
			}
		})
	}
	// Without a readable schema there is nothing to compare against.
	if msg := ValidateOnWriteIn(t.TempDir(), "app.yaml", "versioned: [anything]\n"); strings.Contains(msg, "versioned lists") {
		t.Errorf("schema-less app refused: %s", msg)
	}
}

// A schema.prisma write that leaves another file naming what it removes is
// refused (round 2026-11-04: removing an encrypted model ran the destructive
// migration, then the reload failed and /api/tags answered 500). A batch that
// writes the fixed file next names it in pending and lands; references that
// were already broken are not blamed on the schema write.
func TestSchemaWriteRefusedWhenItOrphansLoadReferences(t *testing.T) {
	encrypted := "tables:\n  tags:\n    fields: [label]\n"
	// A null test: the batch below encrypts note, and a computed field that
	// used note's value would be refused (validators_encrypted_compute.go).
	computed := "fields:\n  - table: habits\n    column: name\n    expr: \"CASE WHEN note IS NULL THEN 'none' ELSE 'some' END\"\n"
	app := map[string]string{"encrypted.yaml": encrypted, "computed.yaml": computed, "app.yaml": "versioned: [habits]\n"}
	withoutTag := strings.Replace(loadRefsSchema, "\nmodel Tag {\n  id Int @id @default(autoincrement())\n  label String @default(\"\")\n  habitId Int? @map(\"habit_id\")\n}\n", "", 1)
	withoutNote := strings.Replace(loadRefsSchema, "  note String @default(\"\")\n", "", 1)
	withoutHabit := strings.Replace(loadRefsSchema, "model Habit {\n  id Int @id @default(autoincrement())\n  name String @default(\"\")\n  note String @default(\"\")\n  userId Int? @map(\"user_id\")\n}\n\n", "", 1)

	t.Run("removed model", func(t *testing.T) {
		dir := loadRefsApp(t, app)
		if err := loadRefsLoad(t, dir); err != nil {
			t.Fatal(err)
		}
		msg := ValidateOnWriteIn(dir, "schema.prisma", withoutTag)
		for _, want := range []string{"schema.prisma not written", "encrypted.yaml", `encrypted fields name the table "tags"`, "push the fixed encrypted.yaml before schema.prisma", "benmore push schema.prisma encrypted.yaml"} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal lacks %q:\n%s", want, msg)
			}
		}
		// Grounding: the live database's reload of that schema drops the
		// table, then fails on the encrypted field.
		writeTestFile(t, dir, "schema.prisma", withoutTag)
		if err := loadRefsLoad(t, dir); err == nil || !strings.Contains(err.Error(), "tags.label: source column does not exist") {
			t.Fatalf("load error = %v", err)
		}
	})

	t.Run("removed field", func(t *testing.T) {
		dir := loadRefsApp(t, app)
		msg := ValidateOnWriteIn(dir, "schema.prisma", withoutNote)
		for _, want := range []string{"computed.yaml", "habits.name reads a column the schema does not have", "A removed field's column stays in this instance's database"} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal lacks %q:\n%s", want, msg)
			}
		}
		// A new database is created without the column; the load fails there.
		writeTestFile(t, dir, "schema.prisma", withoutNote)
		if err := loadRefsLoad(t, dir); err == nil || !strings.Contains(err.Error(), "no such column: note") {
			t.Fatalf("load error = %v", err)
		}
	})

	t.Run("removed versioned model", func(t *testing.T) {
		dir := loadRefsApp(t, app)
		msg := ValidateOnWriteIn(dir, "schema.prisma", withoutHabit)
		for _, want := range []string{`versioned lists "habits"`, `computed on the table "habits"`, "app.yaml and computed.yaml"} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal lacks %q:\n%s", want, msg)
			}
		}
	})

	t.Run("batch that drops the references", func(t *testing.T) {
		dir := loadRefsApp(t, app)
		if err := loadRefsLoad(t, dir); err != nil {
			t.Fatal(err)
		}
		// pending must name the file that holds the reference.
		if msg, _ := ValidateOnWriteInPending(dir, "schema.prisma", withoutTag, []string{"app.yaml"}); !strings.Contains(msg, "schema.prisma not written") {
			t.Fatalf("pending without encrypted.yaml excused it: %q", msg)
		}
		msg, excused := ValidateOnWriteInPending(dir, "schema.prisma", withoutTag, []string{"app.yaml", "encrypted.yaml"})
		if msg != "" || !slices.Equal(excused, []string{"encrypted.yaml"}) {
			t.Fatalf("batch schema write = %q, excused %v", msg, excused)
		}
		writeTestFile(t, dir, "schema.prisma", withoutTag)
		// The batch's encrypted.yaml is judged against the new schema.
		if msg := ValidateOnWriteIn(dir, "encrypted.yaml", encrypted); !strings.Contains(msg, `encrypted fields name the table "tags"`) {
			t.Fatalf("unchanged encrypted.yaml accepted after the schema removed its table: %q", msg)
		}
		fixed := "tables:\n  habits:\n    fields: [note]\n"
		if msg := ValidateOnWriteIn(dir, "encrypted.yaml", fixed); msg != "" {
			t.Fatalf("fixed encrypted.yaml refused: %s", msg)
		}
		writeTestFile(t, dir, "encrypted.yaml", fixed)
		if err := loadRefsLoad(t, dir); err != nil {
			t.Fatalf("the coordinated change does not load: %v", err)
		}
	})

	t.Run("references already broken", func(t *testing.T) {
		dir := loadRefsApp(t, map[string]string{"encrypted.yaml": "tables:\n  habits:\n    fields: [ghost_col]\n"})
		grown := loadRefsSchema + "\nmodel Goal {\n  id Int @id @default(autoincrement())\n  title String @default(\"\")\n}\n"
		if msg := ValidateOnWriteIn(dir, "schema.prisma", grown); strings.Contains(msg, "not written") || strings.Contains(msg, "ghost_col") {
			t.Fatalf("schema write blamed for a reference it did not break: %s", msg)
		}
		if got := sourceErrorFor(dir, "encrypted.yaml"); !strings.Contains(got, "ghost_col") {
			t.Fatalf("benmore check does not report the broken reference: %q", got)
		}
	})
}

// The post-write check of a batch write files errors about the batch's later
// files as warnings: each is judged when it is written.
func TestDeferPendingFindings(t *testing.T) {
	report := CheckReport{Findings: []CheckFinding{
		{Severity: "error", File: "encrypted.yaml", Message: "a"},
		{Severity: "error", File: "flows/x.yaml", Message: "b"},
		{Severity: "warning", Message: "c"},
	}, Errors: 2, Warnings: 1}
	got := deferPendingFindings(report, []string{"encrypted.yaml"})
	if got.Errors != 1 || got.Warnings != 2 || got.Findings[0].Severity != "warning" || !strings.Contains(got.Findings[0].Message, "checked then") || got.Findings[1].Severity != "error" {
		t.Fatalf("deferPendingFindings = %+v", got)
	}
}
