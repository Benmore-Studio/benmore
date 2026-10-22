//go:build !cli

package main

import (
	"context"
	"strings"
	"testing"
)

func connectionCredentialCount(t *testing.T, app *App, connection string) int {
	t.Helper()
	query, args := `SELECT COUNT(*) FROM _benmore_mcp_connection_credentials`, []any{}
	if connection != "" {
		query, args = query+` WHERE connection = ?`, []any{connection}
	}
	var n int
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// externalManifestWithoutKeyed is the fixture manifest with the "keyed"
// connection and the one tool bound to it removed.
func externalManifestWithoutKeyed(t *testing.T) string {
	t.Helper()
	m := externalRuntimeManifest
	connection := "  - name: keyed\n    base_url: https://example.com\n    auth: {kind: header, env: KEYED_API_KEY, header: X-Api-Key}\n    openapi: openapi/items.yaml\n"
	tool := m[strings.Index(m, "  - name: search_items\n"):strings.Index(m, "resources: []")]
	if !strings.Contains(m, connection) || tool == "" {
		t.Fatal("fixture manifest changed shape")
	}
	return strings.Replace(strings.Replace(m, connection, "", 1), tool, "", 1)
}

// `benmore mcp disable --revoke` invalidates every connected client for good;
// the per-user upstream credentials stored for its connections go with them,
// so a later enable does not bring them back. A plain disable is a pause and
// keeps them.
func TestAppMCPRevokePurgesConnectionCredentials(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	f.setCredential(t, "keyed", externalSecret)
	ctx := context.Background()
	if err := appMCPConnectorApply(ctx, f.app, appMCPConnectorRequest{Action: "disable"}); err != nil {
		t.Fatal(err)
	}
	if n := connectionCredentialCount(t, f.app, ""); n != 2 {
		t.Fatalf("a plain disable (pause) removed connection credentials: %d left", n)
	}
	if err := appMCPConnectorApply(ctx, f.app, appMCPConnectorRequest{Action: "disable", Revoke: true}); err != nil {
		t.Fatal(err)
	}
	if n := connectionCredentialCount(t, f.app, ""); n != 0 {
		t.Fatalf("disable --revoke kept %d connection credential(s)", n)
	}
}

// Removing a connection from mcp.yaml deletes the credentials users stored
// for it when the manifest loads, so re-adding the same name and host later
// does not bring them back. Credentials of connections still declared stay.
func TestAppMCPRemovedConnectionCredentialsArePurgedOnLoad(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	f.setCredential(t, "keyed", externalSecret)

	// Hot reload.
	writeTestFile(t, f.app.Dir, "mcp.yaml", externalManifestWithoutKeyed(t))
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("reload without the connection: %v", err)
	}
	if n := connectionCredentialCount(t, f.app, "keyed"); n != 0 {
		t.Fatalf("reload kept %d credential(s) of a removed connection", n)
	}
	if n := connectionCredentialCount(t, f.app, "items"); n != 1 {
		t.Fatalf("reload removed a declared connection's credential: %d left", n)
	}
	writeTestFile(t, f.app.Dir, "mcp.yaml", externalRuntimeManifest)
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("reload with the connection re-added: %v", err)
	}
	if ok, err := hasAppMCPConnectionCredential(context.Background(), f.app, f.uid, f.connection("keyed")); err != nil || ok {
		t.Fatalf("re-adding the connection brought its old credential back: %v %v", ok, err)
	}

	// Process start (loadApp) with the connection removed.
	f.setCredential(t, "keyed", externalSecret)
	writeTestFile(t, f.app.Dir, "mcp.yaml", externalManifestWithoutKeyed(t))
	reviewAppMCPFixture(t, f.app.Dir)
	loaded, err := loadApp(f.app.Dir)
	if err != nil {
		t.Fatalf("load without the connection: %v", err)
	}
	t.Cleanup(loaded.Shutdown)
	if n := connectionCredentialCount(t, loaded, "keyed"); n != 0 {
		t.Fatalf("load kept %d credential(s) of a removed connection", n)
	}
	if n := connectionCredentialCount(t, loaded, "items"); n != 1 {
		t.Fatalf("load removed a declared connection's credential: %d left", n)
	}
}
