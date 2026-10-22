//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fresh database has no live routes: pending ALTER migrations apply first and
// the manifest is then checked against the migrated schema.
func TestAppMCPFreshDatabaseAppliesMigrationsBeforeManifestCheck(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, dir, "migrations/001.sql", "ALTER TABLE notes ADD COLUMN extra TEXT;")
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("fresh database with reviewed manifest refused: %v", err)
	}
	defer app.Shutdown()
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM pragma_table_info('notes') WHERE name='extra'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration not applied: count=%d err=%v", count, err)
	}
}

// An existing database whose pending migration changes routes under a live
// reviewed manifest is still refused, and nothing is applied.
func TestAppMCPExistingDatabaseStillRefusesPendingRouteDDL(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	first, err := loadApp(dir)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	first.Shutdown()
	writeTestFile(t, dir, "migrations/001.sql", "ALTER TABLE notes ADD COLUMN extra TEXT;")
	reviewAppMCPFixture(t, dir)
	if app, err := loadApp(dir); err == nil {
		app.Shutdown()
		t.Fatal("pending route-changing DDL accepted on an existing database")
	} else if !strings.Contains(err.Error(), "pending route-changing migration DDL") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// A first boot that fails after creating its schema (bad migration, then
// fixed) must retry on the fresh path, and the marker goes once a load completes.
func TestAppMCPFailedFirstBootRetriesAsFresh(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, dir, "migrations/001.sql", "ALTER TABLE nope ADD COLUMN extra TEXT;")
	reviewAppMCPFixture(t, dir)
	if app, err := loadApp(dir); err == nil {
		app.Shutdown()
		t.Fatal("broken migration accepted")
	}
	marker := appMCPFirstBootMarker(dir)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker missing after failed first boot: %v", err)
	}
	os.Remove(filepath.Join(dir, "migrations", "001.sql.failed.sql"))
	os.Remove(filepath.Join(dir, "migrations", "001.sql"))
	writeTestFile(t, dir, "migrations/001.sql", "ALTER TABLE notes ADD COLUMN extra TEXT;")
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("retried first boot refused: %v", err)
	}
	defer app.Shutdown()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker not removed after completed load: %v", err)
	}
}

func TestAppMCPDatabaseIsFresh(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if !appMCPDatabaseIsFresh(app.DB) {
		t.Fatal("empty database not fresh")
	}
	mustExec(t, app.DB, "CREATE TABLE _benmore_migrations (name TEXT PRIMARY KEY)")
	if !appMCPDatabaseIsFresh(app.DB) {
		t.Fatal("empty ledger not fresh")
	}
	mustExec(t, app.DB, "INSERT INTO _benmore_migrations VALUES ('a.sql')")
	if appMCPDatabaseIsFresh(app.DB) {
		t.Fatal("applied migration still fresh")
	}
	mustExec(t, app.DB, "DELETE FROM _benmore_migrations")
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	if appMCPDatabaseIsFresh(app.DB) {
		t.Fatal("database with a table is fresh")
	}
}
