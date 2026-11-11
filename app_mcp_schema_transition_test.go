//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const transitionSchemaBoth = `model Note {
  id   Int    @id @default(autoincrement())
  body String
}

model Item {
  id   Int    @id @default(autoincrement())
  name String
}
`

const transitionSchemaItemsOnly = `model Item {
  id   Int    @id @default(autoincrement())
  name String
}
`

// Replacing the scaffold's Note model and deploying the new reviewed mcp.yaml
// in the same batch made every reload fail with a bare "destructive Prisma
// schema transition is unsupported". The refusal now names the table and the
// recovery order, check reports it before a reload does, and that order
// (manifest off, migrate, review again) restores the connector without
// touching command flows.
func TestAppMCPDestructiveSchemaTransitionIsExplainedAndRecoverable(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", transitionSchemaBoth)
	writeTestFile(t, dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "items"))
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP == nil {
		t.Fatal("reviewed connector not loaded")
	}

	// The builder removes Note and reviews the manifest against the new source.
	writeTestFile(t, dir, "schema.prisma", transitionSchemaItemsOnly)
	reviewed := reviewAppMCPFixture(t, dir)

	refusals := func(findings []CheckFinding) (n int) {
		for _, f := range findings {
			if strings.Contains(f.Message, "destructive Prisma schema transition") {
				if f.Severity != "error" || !strings.Contains(f.Message, "table notes") || !strings.Contains(f.Message, "benmore mcp review") {
					t.Fatalf("check reported the transition without its table or recovery: %+v", f)
				}
				n++
			}
		}
		return n
	}
	if findings := checkLiveLayersWithDB(dir, app.DB, func(string) string { return "" }); refusals(findings) != 1 {
		t.Fatalf("check did not report the refused transition: %+v", findings)
	}
	err = reloadAppConfig(app)
	if err == nil || !strings.Contains(err.Error(), "destructive Prisma schema transition is unsupported") {
		t.Fatalf("reload accepted a destructive transition under a reviewed manifest: %v", err)
	}
	if !strings.Contains(err.Error(), "table notes") || !strings.Contains(err.Error(), "1) keep the reviewed mcp.yaml off the server") {
		t.Fatalf("refusal names neither the table nor the recovery order: %v", err)
	}
	// check reports it once even when the load fails with the same text.
	if again := checkLiveLayersWithDB(dir, app.DB, func(string) string { return err.Error() }); refusals(again) != 1 {
		t.Fatalf("check reported the refusal twice: %+v", again)
	}
	// Without the serving pool (benmore check in an app dir), the failed load
	// reports it, once.
	if local := checkLiveLayersWith(dir, func(string) string { return err.Error() }); refusals(local) != 1 {
		t.Fatalf("check without the serving pool: %+v", local)
	}

	// 1) manifest off, 2) the reload migrates.
	if err := os.Remove(filepath.Join(dir, "mcp.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload without mcp.yaml did not migrate: %v", err)
	}
	var notes int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='notes'").Scan(&notes); err != nil || notes != 0 {
		t.Fatalf("the migration did not drop notes: %d %v", notes, err)
	}
	// 3) the server wrote a migration the earlier review did not cover, so
	// restoring that manifest leaves the connector off ...
	writeTestFile(t, dir, "mcp.yaml", reviewed)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.MCP != nil {
		t.Fatal("a review that predates the server's migration file served the connector")
	}
	// 4-5) ... until it is reviewed again.
	reviewAppMCPFixture(t, dir)
	if findings := appMCPSchemaTransitionFindings(dir, app.DB); len(findings) != 0 {
		t.Fatalf("check still reports a migrated transition: %+v", findings)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.MCP == nil {
		t.Fatal("review after the migration did not restore the connector")
	}
}
