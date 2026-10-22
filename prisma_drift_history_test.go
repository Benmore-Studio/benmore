//go:build !cli

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The hosted Casework check called all three generated history tables orphans
// and recommended DROP TABLE. Exercise that same loaded-app shape and the
// destructive drift consumer against an isolated database only.
func TestSchemaDriftPreservesGeneratedHistory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Record {
 id Int @id @default(autoincrement())
 title String
 @@map("records")
}`)
	writeTestFile(t, dir, "app.yaml", "versioned: [records]\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	crudScopeMustExec(t, app.DB, `INSERT INTO records(title) VALUES('retained before')`)
	crudScopeMustExec(t, app.DB, `UPDATE records SET title='current' WHERE id=1`)
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil {
		t.Fatal(err)
	}
	drifts, err := DetectSchemaDrift(app.DB, models)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range drifts {
		if d.Table == "records_history" {
			t.Errorf("generated history reported as drift: %+v", d)
		}
	}
	for _, d := range tryDriftCheck(dir) {
		if d.Table == "records_history" {
			t.Errorf("app check recommends dropping history: %+v", d)
		}
	}
	result, err := PrunePrismaDrift(app.DB, dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.MigrationFile != "" || len(result.TablesDropped) != 0 || len(result.ColumnsDropped) != 0 {
		t.Errorf("clean versioned app was pruned: %+v", result)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM records_history WHERE _version=1`).Scan(&title); err != nil || title != "retained before" {
		t.Fatalf("retained history lost: %q %v", title, err)
	}
	crudScopeMustExec(t, app.DB, `UPDATE records SET title='after maintenance' WHERE id=1`)
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM records_history`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("versioning stopped after maintenance: %d %v", count, err)
	}
}

func TestSchemaDriftHistorySuffixAndRetainedHistory(t *testing.T) {
	db := openTestDriftDB(t)
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE manual_history(id INTEGER PRIMARY KEY, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE partial_history(id INTEGER, _version INTEGER)`)
	// Retained snapshots must not become disposable when their source model or
	// versioning configuration is removed.
	crudScopeMustExec(t, db, `CREATE TABLE retained_history(id INTEGER, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by INTEGER, _change_type TEXT)`)
	drifts, err := DetectSchemaDrift(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range drifts {
		got[d.Table] = true
	}
	if !got["manual_history"] || !got["partial_history"] || got["retained_history"] {
		t.Fatalf("history classification wrong: %v", drifts)
	}
	if strings.Contains(FormatDriftReport(drifts), "retained_history") {
		t.Fatal("retained history has destructive advice")
	}
}

func TestSchemaDriftDeclaredHistoryPreservesMetadata(t *testing.T) {
	db := openTestDriftDB(t)
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE records_history(id INTEGER, title TEXT, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by INTEGER, _change_type TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE manual_history(id INTEGER, title TEXT, legacy TEXT)`)
	models := []PrismaModel{
		{Name: "RecordHistory", Table: "records_history", Fields: []PrismaField{{Column: "id", Type: "INTEGER"}, {Column: "title", Type: "TEXT"}}},
		{Name: "ManualHistory", Table: "manual_history", Fields: []PrismaField{{Column: "id", Type: "INTEGER"}, {Column: "title", Type: "TEXT"}}},
	}
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 1 || drifts[0].Table != "manual_history" || drifts[0].Column != "legacy" || drifts[0].Kind != "extra_column" {
		t.Fatalf("declared history metadata must not become prune candidates, ordinary column drift must remain: %v", drifts)
	}
}
