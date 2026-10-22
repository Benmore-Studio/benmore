//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTMLScaffoldMCPStarterReadOnlyAndOwnerScoped(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	authority, err := filepath.EvalSymlinks(epochFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLScaffoldFiles(dir, "Notes fixture"); err != nil {
		t.Fatal(err)
	}
	config, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest := config.mcp
	if manifest == nil || len(manifest.Tools) != 1 || len(manifest.Resources) != 0 || len(manifest.Connections) != 0 || appMCPSupportedScopes(manifest) != "notes:read" {
		t.Fatalf("starter connector: %+v", manifest)
	}
	tool := manifest.Tools[0]
	if tool.Name != "list_notes" || tool.Handler.Operation != "table.list" || tool.Effect != "read" || strings.Join(tool.Output.Include, ",") != "id,title,body" {
		t.Fatalf("starter tool: %+v", tool)
	}
	// Hosting adds only excluded metadata/generated types after scaffolding.
	writeTestFile(t, dir, ".benmore/creator.json", "{}")
	writeTestFile(t, dir, ".benmore/env", "PORT=9000")
	if err := gitEnsureRepo(dir, "Notes fixture"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "src/bm.d.ts", "// regenerated types")
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("hosting metadata invalidated starter: %v", err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	buildAppMux(app, true, "https://fixture.example")
	if err := validateAppMCPDigests(dir, app.MCP); err != nil {
		t.Fatalf("startup changed reviewed source: %v", err)
	}
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "owner@example.com", "member", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if _, err := createAppMCPGrant(app, uid, "", "starter-client", grantFixtureResource, "notes:read", time.Now()); err == nil {
		t.Fatal("scaffold enabled owner exposure")
	}
	// Exercise the owner's existing opt-in gate in this isolated fixture.
	if _, err := updateAppMCPEpoch(dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPGrant(app, uid, "", "starter-client", grantFixtureResource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "INSERT INTO notes(user_id,title,body) VALUES (?, 'mine', 'private body'),(999,'foreign','secret')", uid)
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(data), "private body") || strings.Contains(string(data), "foreign") || strings.Contains(string(data), "user_id") {
		t.Fatalf("scoped projected read: %s, %v", data, err)
	}
	if _, err := createAppMCPGrant(app, uid, "", "starter-client", grantFixtureResource, "notes:write", time.Now()); err == nil {
		t.Fatal("starter admitted write scope")
	}
	writeTestFile(t, dir, "static/changed.ts", "export const changed = true")
	if _, err := loadRuntimeConfig(dir); err == nil {
		t.Fatal("source edit bypassed explicit review")
	}
}

func TestBareScaffoldDoesNotAddMCPDemo(t *testing.T) {
	dir := t.TempDir()
	if err := WriteBareScaffoldFiles(dir, "Existing app"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mcp.yaml")); !os.IsNotExist(err) {
		t.Fatalf("bare scaffold added starter MCP: %v", err)
	}
}
