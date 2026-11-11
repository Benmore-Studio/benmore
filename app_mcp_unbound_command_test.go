//go:build !cli && !windows

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A first connector on a hosted app: the app was created without mcp.yaml (or
// its mcp.yaml was removed), its Notes model is replaced and command flows are
// added. Until a reviewed mcp.yaml binds them, every load failed with
// `flows: command "complete_item" requires an mcp.yaml binding`, so the reload
// that had to migrate the schema before the manifest could be written was
// refused, and the instance could not start at its next restart. The served
// load now keeps the command flows unexposed, as it does for a stale review:
// no connector route, no HTTP route, and the strict loaders behind review and
// check still refuse the unbound command.
func TestCommandFlowWithoutManifestLoadsUnexposed(t *testing.T) {
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
	if err := os.Remove(filepath.Join(dir, "mcp.yaml")); err != nil {
		t.Fatal(err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Shutdown() })
	if !appTableExistsForTest(t, app, "notes") {
		t.Fatal("scaffold did not migrate notes")
	}

	// Replace the demo model and add the connector's command.
	scaffold, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", strings.Replace(string(scaffold), "model Note {", "model WorkItem {\n  status    String   @default(\"open\")", 1))
	writeTestFile(t, dir, "flows/complete_item.yaml", commandFixture)

	if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), "requires an mcp.yaml binding") {
		t.Fatalf("strict load (review, check) must still refuse the unbound command: %v", err)
	}
	config, err := loadServedRuntimeConfig(dir)
	if err != nil {
		t.Fatalf("served load refused the unbound command: %v", err)
	}
	if config.mcp != nil || config.mcpWithheld != "" || !strings.Contains(config.mcpUnbound, "complete_item") || !strings.Contains(config.mcpUnbound, "mcp.yaml") {
		t.Fatalf("unbound command state: mcp=%v withheld=%q unbound=%q", config.mcp != nil, config.mcpWithheld, config.mcpUnbound)
	}

	// The reload migrates the schema with the command loaded but unexposed.
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload with an unbound command flow refused: %v", err)
	}
	if appTableExistsForTest(t, app, "notes") || !appTableExistsForTest(t, app, "work_items") {
		t.Fatal("the reload did not apply the schema change")
	}
	if app.MCP != nil || app.mcpWithheld != "" {
		t.Fatalf("connector state after reload: mcp=%v withheld=%q", app.MCP != nil, app.mcpWithheld)
	}
	var command *Flow
	for i := range app.Flows {
		if app.Flows[i].Name == "complete_item" {
			command = &app.Flows[i]
		}
	}
	if command == nil || command.Command == nil {
		t.Fatal("the command flow was not kept (it guards the fields it owns)")
	}
	mux := buildAppMux(app, true, "https://fixture.example")
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/_mcp", strings.NewReader(`{}`)),
		httptest.NewRequest(http.MethodPost, appMCPOperationRoute+"op-1/approve", nil),
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s answered %d without a reviewed mcp.yaml", req.Method, req.URL.Path, rec.Code)
		}
	}
	if st := appMCPConnectorStatusFor(context.Background(), app); st.ManifestPresent || st.CommandTools != 0 {
		t.Fatalf("status reports a connector: %+v", st)
	}
	if err := appMCPConnectorApply(context.Background(), app, appMCPConnectorRequest{Action: "enable"}); err == nil || !strings.Contains(err.Error(), "no reviewed mcp.yaml") {
		t.Fatalf("enable without a reviewed mcp.yaml: %v", err)
	}

	// The next restart starts the instance too.
	restarted, err := loadApp(dir)
	if err != nil {
		t.Fatalf("restart with an unbound command flow refused: %v", err)
	}
	restarted.Shutdown()
}

func appTableExistsForTest(t *testing.T, app *App, table string) bool {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}
