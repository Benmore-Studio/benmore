//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every new HTML app ships a reviewed mcp.yaml. Adding one image used to make
// every reload fail, so the app kept serving its previous version and the new
// image 404'd. A stale review now turns off only the connector.
func TestStaleMCPReviewWithholdsOnlyTheConnector(t *testing.T) {
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
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP == nil || app.mcpWithheld != "" {
		t.Fatalf("reviewed starter not loaded: withheld=%q", app.mcpWithheld)
	}
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("fresh scaffold reported a withheld connector: %s", notice)
	}

	writeTestFile(t, dir, "static/hero.png", "\x89PNG-hero")
	var stale *appMCPReviewStaleError
	if _, err := loadRuntimeConfig(dir); !errors.As(err, &stale) || !strings.Contains(err.Error(), "benmore mcp review") {
		t.Fatalf("strict load must still report the stale review: %v", err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload refused after a source change: %v", err)
	}
	if app.MCP != nil || app.sourceFiles != nil || !strings.Contains(app.mcpWithheld, "digest mismatch") {
		t.Fatalf("connector not withheld: mcp=%v sources=%v withheld=%q", app.MCP != nil, app.sourceFiles != nil, app.mcpWithheld)
	}
	mux := buildAppMux(app, true, "https://fixture.example")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/hero.png", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "\x89PNG-hero" {
		t.Fatalf("new static file not served after reload: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/_mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("withheld connector still answered: %d", rec.Code)
	}
	if st := appMCPConnectorStatusFor(context.Background(), app); !st.ManifestPresent || !strings.Contains(st.Problem, "benmore mcp review") {
		t.Fatalf("status hides the withheld connector: %+v", st)
	}
	notice := appMCPConnectorWithheldNotice(dir)
	if !strings.Contains(notice, "connector is off") || !strings.Contains(notice, "benmore mcp review <appdir> --reviewed") {
		t.Fatalf("notice: %q", notice)
	}
	resp := map[string]any{"ok": true}
	noteAppMCPConnectorWithheld(resp, dir)
	if resp["ok"] != true || resp["mcp_connector_withheld"] != notice {
		t.Fatalf("write response: %#v", resp)
	}

	// Review brings the connector back on the next reload.
	if _, err := reviewAppMCPSource(dir); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.MCP == nil || app.mcpWithheld != "" {
		t.Fatalf("reviewed connector not restored: withheld=%q", app.mcpWithheld)
	}

	// Other mcp.yaml errors still refuse the load.
	writeTestFile(t, dir, "mcp.yaml", "version: 1\nunknown_key: true\n")
	if _, err := loadServedRuntimeConfig(dir); err == nil || errors.As(err, &stale) {
		t.Fatalf("malformed mcp.yaml must still refuse the load: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "mcp.yaml")); err != nil {
		t.Fatal(err)
	}
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("app without mcp.yaml reported a withheld connector: %s", notice)
	}
}

// An exposed connector keeps its owner state, revision ledger and command
// flows while withheld, so a review restores it. (Any reload turns approved
// writes off until the owner enables them again; that is unchanged.)
func TestStaleMCPReviewKeepsAnExposedConnectorRecoverable(t *testing.T) {
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	ctx := context.Background()
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "static/hero.png", "\x89PNG")
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload refused after a source change: %v", err)
	}
	if app.MCP != nil || app.mcpWithheld == "" {
		t.Fatal("connector not withheld")
	}
	commands := 0
	for _, flow := range app.Flows {
		if flow.Command != nil {
			commands++
		}
	}
	if commands == 0 {
		t.Fatal("command flows dropped while withheld")
	}
	retireUnusedAppMCPRevisionLedger(app)
	if installed, err := appMCPRevisionLedgerInstalled(ctx, app.DB); err != nil || !installed {
		t.Fatalf("start-up retired the ledger of a withheld connector: %v", err)
	}
	if st := connectorStatus(t, app); !st.Exposed || st.Enrollment != "active" || !strings.Contains(st.Problem, "review") {
		t.Fatalf("status while withheld: %+v", st)
	}
	if err := connectorApply(t, app, "enable", false); err == nil || !strings.Contains(err.Error(), "benmore mcp review") {
		t.Fatalf("enable while withheld: %v", err)
	}
	if _, err := reviewAppMCPSource(app.Dir); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.MCP == nil || app.mcpWithheld != "" {
		t.Fatal("reviewed connector did not come back")
	}
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatalf("enable writes after review: %v", err)
	}
	if _, live := appMCPWritesLive(app); !live {
		t.Fatal("approved writes not live after review and enable")
	}
}
