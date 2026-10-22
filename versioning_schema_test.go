//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionHistoryReconcilesAddedColumns(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	crudScopeMustExec(t, db, `CREATE TABLE records(id INTEGER PRIMARY KEY,title TEXT,created_at DATETIME,updated_at DATETIME)`)
	cfg := &VersionedConfig{Tables: []string{"records"}}
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `INSERT INTO records(id,title) VALUES(1,'original')`)
	crudScopeMustExec(t, db, `UPDATE records SET title='before' WHERE id=1`)
	crudScopeMustExec(t, db, `ALTER TABLE records ADD COLUMN summary TEXT NOT NULL DEFAULT ''`)
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, db, `UPDATE records SET title='after',summary='new field' WHERE id=1`)
	crudScopeMustExec(t, db, `DELETE FROM records WHERE id=1`)
	var oldSummary sql.NullString
	if err := db.QueryRow(`SELECT summary FROM records_history WHERE _version=1`).Scan(&oldSummary); err != nil || oldSummary.Valid {
		t.Fatalf("old version default invented: %v %v", oldSummary, err)
	}
	var lastSummary string
	if err := db.QueryRow(`SELECT summary FROM records_history WHERE _version=3`).Scan(&lastSummary); err != nil || lastSummary != "new field" {
		t.Fatalf("delete snapshot=%q %v", lastSummary, err)
	}
	if err := InstallVersioningTriggers(db, cfg); err != nil {
		t.Fatalf("reconciliation not idempotent: %v", err)
	}
}

func TestVersionHistoryStartupAndReloadReconcileMigrations(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	schema := "CREATE TABLE records (\n id INTEGER PRIMARY KEY,\n title TEXT\n);\n"
	writeTestFile(t, dir, "schema.sql", schema)
	writeTestFile(t, dir, "app.yaml", "versioned:\n  - records\n")
	writeTestFile(t, dir, "migrations/0001_summary.sql", "ALTER TABLE records ADD COLUMN summary TEXT;\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	crudScopeMustExec(t, app.DB, `INSERT INTO records(id,title,summary) VALUES(1,'before','first')`)
	crudScopeMustExec(t, app.DB, `UPDATE records SET title='after' WHERE id=1`)
	writeTestFile(t, dir, "migrations/0002_extra.sql", "ALTER TABLE records ADD COLUMN extra TEXT;\n")
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, `UPDATE records SET extra='added' WHERE id=1`)
	crudScopeMustExec(t, app.DB, `DELETE FROM records WHERE id=1`)
	var extra string
	if err := app.DB.QueryRow(`SELECT extra FROM records_history WHERE _change_type='delete'`).Scan(&extra); err != nil || extra != "added" {
		t.Fatalf("reload missed migration column: %q %v", extra, err)
	}
}

func TestVersionHistoryStartupAndReloadRejectInvalidHistory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE records (\n id INTEGER PRIMARY KEY,\n title TEXT\n);\n")
	writeTestFile(t, dir, "app.yaml", "versioned:\n  - records\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldDesign := app.Design
	crudScopeMustExec(t, app.DB, `DROP TABLE records_history`)
	crudScopeMustExec(t, app.DB, `CREATE VIEW records_history AS SELECT * FROM records`)
	if err := reloadAppConfig(app); err == nil || !strings.Contains(err.Error(), "versioning") {
		t.Fatalf("invalid history reload: %v", err)
	}
	if app.Design != oldDesign {
		t.Fatal("failed history reload published new config")
	}
	app.Shutdown()
	restarted, err := loadApp(dir)
	if restarted != nil {
		restarted.Shutdown()
	}
	if err == nil || !strings.Contains(err.Error(), "versioning") {
		t.Fatalf("invalid history startup: %v", err)
	}
}

func TestVersionHistoryAcceptsTableCreatedByUserMigration(t *testing.T) {
	for _, create := range []bool{true, false} {
		t.Run(fmt.Sprint(create), func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE seed (\n id INTEGER PRIMARY KEY\n);\n")
			writeTestFile(t, dir, "app.yaml", "versioned:\n  - records\n")
			if create {
				writeTestFile(t, dir, "migrations/0001_records.sql", "CREATE TABLE records(id INTEGER PRIMARY KEY,title TEXT); INSERT INTO records VALUES(1,'before');\n")
			}
			app, err := loadApp(dir)
			if !create {
				if app != nil {
					app.Shutdown()
				}
				if err == nil {
					t.Fatal("missing source accepted after migrations")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			crudScopeMustExec(t, app.DB, `UPDATE records SET title='after' WHERE id=1`)
			var title string
			if err := app.DB.QueryRow(`SELECT title FROM records_history WHERE _version=1`).Scan(&title); err != nil || title != "before" {
				t.Fatalf("migration-created source history: %q %v", title, err)
			}
		})
	}
}
