//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppMCPReloadUsesCapturedShorthandSchemaAndSources(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.yaml", "reviewed_notes: title, +user\n")
	writeTestFile(t, app.Dir, "static/reviewed.tsx", "export const Reviewed = () => null")
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "reviewed_notes"))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.mcp == nil {
		t.Fatal("staged config has no MCP manifest")
	}

	if err := os.Remove(filepath.Join(app.Dir, "schema.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(app.Dir, "static/reviewed.tsx")); err != nil {
		t.Fatal(err)
	}
	lateSQL := "CREATE TABLE evil_sql (id INTEGER PRIMARY KEY);"
	writeTestFile(t, app.Dir, "schema.sql", lateSQL)
	writeTestFile(t, app.Dir, "schema.prisma", "model Evil { id Int @id @@map(\"evil_prisma\") }\n")
	writeTestFile(t, app.Dir, "static/late.tsx", "export const Late = () => null")

	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("reload with captured shorthand schema: %v", err)
	}
	assertAppMCPTableColumns(t, app, "reviewed_notes", []string{"id", "title", "user_id", "created_at"})
	assertAppMCPTableMissing(t, app, "evil_sql")
	assertAppMCPTableMissing(t, app, "evil_prisma")

	report, err := inspectAppMCPSourceStaged(app.Dir, config)
	if err != nil {
		t.Fatalf("inspect staged MCP sources: %v", err)
	}
	if entry := appMCPInventoryEntryForTest(t, report, "crud", "GET /api/reviewed_notes"); entry.State != "exposed" || !appMCPTestContains(entry.Tools, "list_reviewed_notes") {
		t.Errorf("reviewed CRUD inventory: %+v", entry)
	}
	if _, ok := appMCPInventoryEntryForTestOptional(report, "ui_source", "static/reviewed.tsx"); !ok {
		t.Error("inventory omitted captured static source")
	}
	if _, ok := appMCPInventoryEntryForTestOptional(report, "ui_source", "static/late.tsx"); ok {
		t.Error("inventory included static source added after review")
	}
	if got, err := os.ReadFile(filepath.Join(app.Dir, "schema.sql")); err != nil || string(got) != lateSQL {
		t.Errorf("reload changed late schema.sql: %q, %v", got, err)
	}
}

func TestAppMCPStartupLoadsReviewedShorthandWithoutWritingSQL(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.yaml", "reviewed_notes: title, +user\n")
	writeTestFile(t, dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "reviewed_notes"))
	reviewAppMCPFixture(t, dir)

	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	assertAppMCPTableColumns(t, app, "reviewed_notes", []string{"id", "title", "user_id", "created_at"})
	if _, err := os.Stat(filepath.Join(dir, "schema.sql")); !os.IsNotExist(err) {
		t.Fatalf("startup created schema.sql: %v", err)
	}
	if err := validateAppMCPDigests(dir, app.MCP); err != nil {
		t.Fatalf("generated runtime state invalidated reviewed digests: %v", err)
	}
}

func TestAppMCPCapturedSQLPrecedesShorthand(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	dir := t.TempDir()
	sqlSource := "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);"
	writeTestFile(t, dir, "schema.sql", sqlSource)
	writeTestFile(t, dir, "schema.yaml", "evil_yaml: title\n")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)

	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	assertAppMCPTableColumns(t, app, "notes", []string{"id", "title"})
	assertAppMCPTableMissing(t, app, "evil_yaml")
}

func TestAppMCPInvalidShorthandFailsBeforeDatabaseEffects(t *testing.T) {
	t.Run("malformed yaml", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
		writeTestFile(t, dir, "schema.yaml", "notes: [unterminated\n")
		writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
		reviewAppMCPFixture(t, dir)
		if _, err := loadApp(dir); err == nil {
			t.Fatal("startup accepted malformed schema.yaml")
		}
		if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
			t.Fatalf("malformed shorthand reached database initialization: %v", err)
		}
	})

	t.Run("schema yaml directory", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
		writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
		reviewAppMCPFixture(t, dir)
		if err := os.Mkdir(filepath.Join(dir, "schema.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := loadApp(dir); err == nil {
			t.Fatal("startup accepted schema.yaml directory")
		}
		if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
			t.Fatalf("schema.yaml directory reached database initialization: %v", err)
		}
	})
}

func TestAppMCPEmptyCapturedShorthandIgnoresLateDiskFile(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.yaml", "")
	fixture := appMCPManifestFixture()
	emptyTools := fixture[:strings.Index(fixture, "tools:\n")] + "tools: []\n" + fixture[strings.Index(fixture, "resources: []\n"):]
	writeTestFile(t, app.Dir, "mcp.yaml", emptyTools)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "schema.yaml", "late_evil: title\n")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatalf("reload using empty captured shorthand: %v", err)
	}
	assertAppMCPTableMissing(t, app, "late_evil")
}

func TestSchemaShorthandFlatStructuredAndDiskWrappers(t *testing.T) {
	for _, source := range []string{
		"notes: title, +user\n",
		"models:\n  notes: title, +user\n",
	} {
		if got := parseSchemaShorthand([]byte(source)); !strings.Contains(got, "CREATE TABLE IF NOT EXISTS notes") || !strings.Contains(got, "user_id INTEGER") {
			t.Errorf("parseSchemaShorthand(%q) = %q", source, got)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.yaml", "notes: title\n")
	if got := LoadSchemaShorthand(dir); !strings.Contains(got, "CREATE TABLE IF NOT EXISTS notes") {
		t.Fatalf("LoadSchemaShorthand() = %q", got)
	}
	if err := WriteSchemaSQL(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "schema.sql")); err != nil || !strings.Contains(string(got), "CREATE TABLE IF NOT EXISTS notes") {
		t.Fatalf("WriteSchemaSQL() = %q, %v", got, err)
	}
}

func assertAppMCPTableColumns(t *testing.T, app *App, name string, want []string) {
	t.Helper()
	columns, err := GetTableColumns(app.DB, name)
	if err != nil {
		t.Fatalf("GetTableColumns(%s): %v", name, err)
	}
	got := make([]string, 0, len(columns))
	for _, column := range columns {
		got = append(got, column.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("live %s columns = %v, want %v", name, got, want)
	}
	if _, ok := appMCPTable(t, app, name); !ok {
		t.Fatalf("app.Tables omits %s", name)
	}
}

func appMCPInventoryEntryForTest(t *testing.T, report *appMCPInspection, kind, name string) appMCPInventoryEntry {
	t.Helper()
	if entry, ok := appMCPInventoryEntryForTestOptional(report, kind, name); ok {
		return entry
	}
	t.Fatalf("missing MCP inventory entry %s %q", kind, name)
	return appMCPInventoryEntry{}
}

func appMCPInventoryEntryForTestOptional(report *appMCPInspection, kind, name string) (appMCPInventoryEntry, bool) {
	for _, entry := range report.Inventory {
		if entry.Kind == kind && entry.Name == name {
			return entry, true
		}
	}
	return appMCPInventoryEntry{}, false
}

func appMCPTestContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestAppMCPEmptyStructuredShorthand(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "schema.yaml", "models: {}\n")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("deliberate empty structured shorthand rejected: %v", err)
	}
}

func TestAppMCPShorthandRejectsAdditionalDocumentsBeforeEffects(t *testing.T) {
	for _, tail := range []string{"other: body\n", "other: [unterminated\n"} {
		t.Run(tail, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.yaml", "notes: title\n---\n"+tail)
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, dir)
			if _, err := loadApp(dir); err == nil {
				t.Fatal("startup accepted additional shorthand document")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("additional document reached database initialization: %v", err)
			}
		})
	}
}
