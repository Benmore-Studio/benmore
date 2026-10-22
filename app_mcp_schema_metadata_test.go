//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAppMCPSingleLineSchemaPreservesTenantReadBoundary(t *testing.T) {
	for _, groupColumn := range []string{"org_id", "ORG_ID"} {
		t.Run(groupColumn, func(t *testing.T) {
			app, uid, _ := appMCPGrantFixture(t)
			writeTestFile(t, app.Dir, "schema.sql", fmt.Sprintf("CREATE TABLE orgdocs (id INTEGER PRIMARY KEY, %s TEXT, title TEXT);", groupColumn))
			writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\naccess: {orgdocs: {read: group}}\nroles: {editor: {scopes: [orgdocs:read]}}\n")
			writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "orgdocs"))
			reviewAppMCPFixture(t, app.Dir)
			if err := reloadAppConfig(app); err != nil {
				t.Fatal(err)
			}
			auditExec(t, app.DB, "INSERT INTO orgdocs(id,org_id,title) VALUES (11,'17','owned'),(12,'29','foreign')")
			pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, "orgdocs:read", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_orgdocs", map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			rows, ok := result.Data.([]map[string]any)
			if !ok || len(rows) != 1 || rows[0]["id"] != json.Number("11") || result.Pagination == nil || result.Pagination.Total != 1 {
				t.Fatalf("schema metadata widened tenant read: rows=%#v pagination=%+v", result.Data, result.Pagination)
			}
		})
	}
}
