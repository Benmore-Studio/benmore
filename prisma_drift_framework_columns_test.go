//go:build !cli

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDetectSchemaDriftSkipsBlindIndexSibling: encrypted.yaml's blind_index
// makes the framework add `<col>_blind` (plus its index and triggers) to the
// app table. It is not in schema.prisma by design, so drift reported it as an
// extra column and told the developer to drop it - which would break
// equality search on the encrypted column (and prune's DROP COLUMN fails on
// its index).
func TestDetectSchemaDriftSkipsBlindIndexSibling(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Customer {
  id Int @id @default(autoincrement())
  email String
  @@map("customers")
}
`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  customers:\n    fields: [email]\n    blind_index: [email]\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if !hasColumn(app, "customers", "email_blind") {
		if cols, _ := getLiveColumns(app.DB, "customers"); cols["email_blind"].Name == "" {
			t.Fatal("blind index column was not created")
		}
	}
	// A column someone added by hand is still drift.
	crudScopeMustExec(t, app.DB, "ALTER TABLE customers ADD COLUMN legacy_note TEXT")

	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil {
		t.Fatal(err)
	}
	drifts, err := DetectSchemaDrift(app.DB, models)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range drifts {
		if d.Column == "email_blind" {
			t.Fatalf("framework blind-index column reported as drift: %+v", d)
		}
	}
	if len(drifts) != 1 || drifts[0].Kind != "extra_column" || drifts[0].Column != "legacy_note" {
		t.Fatalf("drifts = %+v, want only customers.legacy_note", drifts)
	}
}

// TestDetectSchemaDriftSkipsCustomFields: a custom field added through
// POST /api/_schema/{table}/fields is a live column recorded in
// _benmore_custom_fields, not in schema.prisma; dropping it would delete the
// field's data behind the custom-fields API.
func TestDetectSchemaDriftSkipsCustomFields(t *testing.T) {
	db := openTestDriftDB(t)
	defer db.Close()
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, priority INTEGER, stray TEXT)`)
	EnsureCustomFieldsTable(db)
	crudScopeMustExec(t, db, `INSERT INTO _benmore_custom_fields (table_name, column_name, column_type) VALUES ('notes', 'priority', 'INTEGER')`)
	models := []PrismaModel{{
		Name: "Note", Table: "notes",
		Fields: []PrismaField{
			{Name: "id", Column: "id", Type: "INTEGER", IsID: true, Autoincr: true},
			{Name: "title", Column: "title", Type: "TEXT"},
		},
	}}
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 1 || drifts[0].Column != "stray" {
		t.Fatalf("drifts = %+v, want only notes.stray (priority is a custom field)", drifts)
	}
}

// TestPostMigrationDriftLogListsTheIssues: the load log promised "see the
// drift report below" and printed no report.
func TestPostMigrationDriftLogListsTheIssues(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", `model Note {
  id Int @id @default(autoincrement())
  title String
  @@map("notes")
}
`)
	db := openTestDriftDB(t)
	defer db.Close()
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, stray TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE leftovers (id INTEGER PRIMARY KEY)`)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := reportPostMigrationDrift(dir, db); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	for _, want := range []string{"schema drift: 2 issue(s)", "[extra_column] notes.stray", "[extra_table] leftovers", "benmore check"} {
		if !strings.Contains(out, want) {
			t.Errorf("drift log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "see the drift report below") {
		t.Errorf("drift log still points at a report it does not print:\n%s", out)
	}
}
