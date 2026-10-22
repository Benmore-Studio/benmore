//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const appMCPMigrationCaptureSchema = `CREATE TABLE captured_docs (
	id INTEGER PRIMARY KEY,
	org_id TEXT,
	title TEXT
);`

func stageAppMCPMigrationCapture(t *testing.T, app *App, schema, migration string) *runtimeConfig {
	t.Helper()
	writeTestFile(t, app.Dir, "schema.sql", schema)
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "captured_docs"))
	writeTestFile(t, app.Dir, "migrations/001.sql", migration)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.mcp == nil {
		t.Fatal("staged config has no MCP manifest")
	}
	if got := string(config.migrations["001.sql"]); got != migration {
		t.Fatalf("captured migration = %q, want reviewed bytes %q", got, migration)
	}
	return config
}

func TestAppMCPReloadAppliesCapturedMigrationBytesOnce(t *testing.T) {
	app, _ := auditApp(t)
	approved := "INSERT INTO captured_docs(id,org_id,title) VALUES(1,'17','reviewed');"
	config := stageAppMCPMigrationCapture(t, app, appMCPMigrationCaptureSchema, approved)
	writeTestFile(t, app.Dir, "migrations/001.sql", "INSERT INTO captured_docs(id,org_id,title) VALUES(1,'17','unreviewed');")
	writeTestFile(t, app.Dir, "migrations/002.sql", "CREATE TABLE evil_table (id INTEGER); INSERT INTO evil_table VALUES (1);")

	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("reload staged migration: %v", err)
	}
	var title string
	if err := app.DB.QueryRow("SELECT title FROM captured_docs WHERE id=1").Scan(&title); err != nil || title != "reviewed" {
		t.Fatalf("captured_docs title = %q, err=%v; want reviewed", title, err)
	}
	assertAppMCPTableMissing(t, app, "evil_table")
	assertAppMCPMigrationLedgerCount(t, app, "001.sql", 1)
	assertAppMCPMigrationLedgerCount(t, app, "002.sql", 0)

	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("repeat reload with same staged config: %v", err)
	}
	var rows int
	if err := app.DB.QueryRow("SELECT count(*) FROM captured_docs").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("captured_docs rows after repeated reload = %d, err=%v; want 1", rows, err)
	}
	assertAppMCPMigrationLedgerCount(t, app, "001.sql", 1)
}

func TestAppMCPReloadAppliesCapturedMigrationAfterFileRemoval(t *testing.T) {
	app, _ := auditApp(t)
	approved := "INSERT INTO captured_docs(id,org_id,title) VALUES(1,'17','reviewed');"
	config := stageAppMCPMigrationCapture(t, app, appMCPMigrationCaptureSchema, approved)
	if err := os.Remove(filepath.Join(app.Dir, "migrations", "001.sql")); err != nil {
		t.Fatal(err)
	}

	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("reload after removing staged migration file: %v", err)
	}
	var title string
	if err := app.DB.QueryRow("SELECT title FROM captured_docs WHERE id=1").Scan(&title); err != nil || title != "reviewed" {
		t.Fatalf("captured_docs title = %q, err=%v; want reviewed", title, err)
	}
	assertAppMCPMigrationLedgerCount(t, app, "001.sql", 1)
}

func TestAppMCPRouteValidationUsesCapturedMigrationBytes(t *testing.T) {
	app, _ := auditApp(t)
	schema := "CREATE TABLE notes (id INTEGER PRIMARY KEY);"
	migration := "CREATE TABLE pending_docs (id INTEGER PRIMARY KEY);"
	writeTestFile(t, app.Dir, "schema.sql", schema)
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, app.Dir, "migrations/001.sql", migration)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(config.migrations["001.sql"]); got != migration {
		t.Fatalf("captured migration = %q, want %q", got, migration)
	}
	writeTestFile(t, app.Dir, "migrations/001.sql", "DROP TABLE notes; CREATE TABLE evil_table (id INTEGER);")

	if err := validateAppMCPCandidateRoutes(app.Dir, config, app.DB, nil); err != nil {
		t.Fatalf("validate routes with captured migration: %v", err)
	}
	tables, err := appMCPCandidateTablesWithSchema(app.Dir, app.DB, func(name string) ([]byte, error) {
		return config.schemaSource(app.Dir, name)
	}, config.migrations)
	if err != nil {
		t.Fatalf("project captured migration tables: %v", err)
	}
	if !tables["pending_docs"] || tables["evil_table"] {
		t.Fatalf("projected migration tables contain pending_docs=%v evil_table=%v", tables["pending_docs"], tables["evil_table"])
	}
}

func TestAppMCPFailedCapturedMigrationRollsBackWithoutTouchingReplacement(t *testing.T) {
	app, _ := auditApp(t)
	approved := "INSERT INTO captured_docs(id,org_id,title) VALUES(1,'17','reviewed');\nINSERT INTO missing_table(id) VALUES(2);"
	config := stageAppMCPMigrationCapture(t, app, appMCPMigrationCaptureSchema, approved)
	replacement := []byte("INSERT INTO captured_docs(id,org_id,title) VALUES(2,'17','replacement');")
	path := filepath.Join(app.Dir, "migrations", "001.sql")
	if err := os.WriteFile(path, replacement, 0o644); err != nil {
		t.Fatal(err)
	}

	previous := &AppMCPManifest{Version: 1}
	app.MCP = previous
	app.Flows = []Flow{{Name: "previous_config"}}
	stop := app.Stop
	if err := reloadAppConfigStaged(app, config, nil); err == nil {
		t.Fatal("reload accepted captured migration with missing-table SQL")
	}
	if app.MCP != previous || len(app.Flows) != 1 || app.Flows[0].Name != "previous_config" {
		t.Fatal("failed reload replaced the previous app config")
	}
	if app.Stop != stop {
		t.Fatal("failed reload replaced the worker stop channel")
	}
	select {
	case <-app.Stop:
		t.Fatal("failed reload stopped the existing workers")
	default:
	}
	var rows int
	if err := app.DB.QueryRow("SELECT count(*) FROM captured_docs").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("captured_docs rows after rollback = %d, err=%v; want 0", rows, err)
	}
	assertAppMCPMigrationLedgerCount(t, app, "001.sql", 0)
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(replacement) {
		t.Fatalf("replacement migration bytes = %q, err=%v; want unchanged replacement", got, err)
	}
	if _, err := os.Stat(path + ".failed.sql"); !os.IsNotExist(err) {
		t.Fatalf("replacement migration was renamed to failed file: %v", err)
	}
}

func assertAppMCPMigrationLedgerCount(t *testing.T, app *App, name string, want int) {
	t.Helper()
	var got int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_migrations WHERE name=?", name).Scan(&got); err != nil || got != want {
		t.Fatalf("migration ledger entries for %q = %d, err=%v; want %d", name, got, err, want)
	}
}

func TestAppMCPEmptyCapturedMigrationSetIgnoresLateFiles(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", appMCPMigrationCaptureSchema)
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "captured_docs"))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.migrations == nil || len(config.migrations) != 0 {
		t.Fatalf("migration absence not captured: %#v", config.migrations)
	}
	writeTestFile(t, app.Dir, "migrations/late.sql", "CREATE TABLE evil_table(id INTEGER); INSERT INTO captured_docs(id,title) VALUES(1,'unreviewed');")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	assertAppMCPTableMissing(t, app, "evil_table")
	var rows int
	if err := app.DB.QueryRow("SELECT count(*) FROM captured_docs").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("late migration executed: rows=%d err=%v", rows, err)
	}
	exists, err := tableExists(app.DB, "_benmore_migrations")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		assertAppMCPMigrationLedgerCount(t, app, "late.sql", 0)
	}
}
func TestAppMCPRejectsNonDirectoryMigrationSource(t *testing.T) {
	dir := t.TempDir()
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "migrations", "not a directory")
	if _, _, err := appMCPDigests(dir, manifest); err == nil {
		t.Fatal("invalid migration directory accepted")
	}
}
