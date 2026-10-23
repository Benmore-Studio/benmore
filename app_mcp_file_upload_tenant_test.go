//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func appMCPUploadTenantFixture(t *testing.T) (*App, *appMCPTokenPair, *appMCPRuntimeGeneration) {
	t.Helper()
	app, pair := appMCPFileRuntimeFixture(t)
	_, originalActor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	if _, err := app.DB.Exec(`ALTER TABLE notes ADD COLUMN org_id TEXT; UPDATE notes SET org_id='17' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, file_path TEXT, org_id TEXT); CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\n")
	source, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(source)
	if err != nil {
		t.Fatal(err)
	}
	current := "current"
	for i := range manifest.Tools {
		if manifest.Tools[i].Handler.Kind == "file" {
			manifest.Tools[i].Handler.FileColumn = "file_path"
			manifest.Tools[i].Handler.UploadTenant = &current
		}
	}
	status := *appMCPFileTool(manifest, "ingest_file")
	status.Name = "status_file"
	status.Handler.Operation = "status"
	status.InputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"processing_id", "record_id", "file_ref"}, Properties: map[string]*AppMCPSchema{
		"processing_id": {Type: "string", MinLength: intPointer(32), MaxLength: intPointer(32)}, "record_id": {Type: "string"}, "file_ref": {Type: "string"},
	}}
	status.Output.Include = []string{"processing_id", "record_id", "file_ref", "complete"}
	status.OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: status.Output.Include, Properties: map[string]*AppMCPSchema{
		"processing_id": {Type: "string"}, "record_id": {Type: "string"}, "file_ref": {Type: "string"}, "complete": {Type: "boolean"},
	}}
	manifest.Tools = append(manifest.Tools, status)
	encoded, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", string(encoded))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	app.Group = LoadGroupConfig(app.Dir)
	for i := range app.MCP.Tools {
		if app.MCP.Tools[i].Handler.Kind == "file" {
			app.MCP.Tools[i].Handler.FileColumn = "file_path"
			app.MCP.Tools[i].Handler.UploadTenant = &current
		}
	}
	pair, err = createAppMCPGrant(app, originalActor.UserID, "17", "client-fixture", grantFixtureResource, "files:read notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return app, pair, snapshotAppMCPGeneration(app)
}

func setAppMCPUploadOwner(t *testing.T, app *App, logical string, uid int64, group string, admin int) {
	t.Helper()
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT OR REPLACE INTO _benmore_upload_owners(path,user_id,group_id,uploader_admin) VALUES(?,?,?,?)`, privateUploadKey(app, logical), uid, group, admin); err != nil {
		t.Fatal(err)
	}
}

func appMCPUploadTenantHandler(t *testing.T, app *App, name string, strict bool) AppMCPHandler {
	t.Helper()
	tool := appMCPFileTool(app.MCP, name)
	if tool == nil {
		t.Fatalf("missing file tool %q", name)
	}
	handler := tool.Handler
	if !strict {
		handler.UploadTenant = nil
	}
	return handler
}

func TestAppMCPUploadTenantCurrentRequiresSameRecordedAndSourceGroup(t *testing.T) {
	app, pair, generation := appMCPUploadTenantFixture(t)
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	logical := "uploads/private/source.csv"
	strict := appMCPUploadTenantHandler(t, app, "ingest_file", true)
	legacy := appMCPUploadTenantHandler(t, app, "ingest_file", false)
	setAppMCPUploadOwner(t, app, logical, actor.UserID, "29", 1)
	if !appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, legacy, grant.Tenant) {
		t.Fatal("legacy policy lost its established admin-upload vouch")
	}
	if appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, strict, grant.Tenant) {
		t.Fatal("strict policy accepted foreign admin provenance even when actor and row owner match")
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": logical, "record_id": "1"}); err == nil {
		t.Fatal("strict ingest read a foreign-group upload")
	}

	setAppMCPUploadOwner(t, app, logical, 999, "17", 0)
	if !appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, strict, grant.Tenant) {
		t.Fatal("strict policy rejected a valid same-group owner record")
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": logical, "record_id": "1"}); err != nil {
		t.Fatalf("valid same-group strict ingest failed: %v", err)
	}

	setAppMCPUploadOwner(t, app, logical, actor.UserID, "", 0)
	if appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, strict, grant.Tenant) {
		t.Fatal("strict policy accepted empty owner-group provenance")
	}
	if _, err := app.DB.Exec(`DELETE FROM _benmore_upload_owners WHERE path=?`, privateUploadKey(app, logical)); err != nil {
		t.Fatal(err)
	}
	if appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, strict, grant.Tenant) {
		t.Fatal("strict policy accepted a missing owner record")
	}
	if !appMCPAuthorizeFileRecordForTool(app, actor, "notes", "1", logical, legacy, grant.Tenant) {
		t.Fatal("legacy policy changed for an upload without recorded owner provenance")
	}
	setAppMCPUploadOwner(t, app, logical, actor.UserID, "17", 0)
	if _, err := app.DB.Exec(`UPDATE notes SET org_id='29' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if appMCPAuthorizeFileRecordForTool(app, actor, strict.Table, "1", logical, strict, grant.Tenant) {
		t.Fatal("strict policy accepted a source row from another group")
	}
}

func TestAppMCPUploadTenantSeparatesLegacySnapshotsAndRechecksPublication(t *testing.T) {
	app, pair, generation := appMCPUploadTenantFixture(t)
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	app.DB.SetMaxOpenConns(1)
	logical := "uploads/private/source.csv"
	setAppMCPUploadOwner(t, app, logical, actor.UserID, "29", 1)
	if !appMCPAuthorizeFileRecordForTool(app, actor, "notes", "1", logical, appMCPUploadTenantHandler(t, app, "ingest_file", false), grant.Tenant) {
		t.Fatal("legacy policy lost its established admin-upload vouch")
	}
	original, err := os.ReadFile(filepath.Join(app.Dir, filepath.FromSlash(logical)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := IngestCSV(bytes.NewReader(original), DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	legacyScope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: "notes", RecordID: "1", FileRef: logical, FileColumn: "file_path"}
	legacyID, err := appMCPRecordFileProcessing(app, actor.UserID, logical, parsed.SHA256, "private_upload", parsed.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: legacyScope, Original: original, Result: parsed, Actor: actor})
	if err != nil {
		t.Fatalf("legacy admin snapshot could not be recorded: %v", err)
	}
	for _, name := range []string{"verify_file", "status_file", "ingest_file"} {
		input := map[string]any{"file_ref": logical, "record_id": "1"}
		if name != "ingest_file" {
			input["processing_id"] = legacyID
		}
		if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, name, input); err == nil {
			t.Fatalf("strict %s reused a legacy snapshot with mismatched current owner provenance", name)
		}
	}
	if _, err := appMCPReadFileSnapshot(context.Background(), app, legacyID, actor.UserID, grant.UserCreated, grant.Tenant, "notes", "1", logical, "current"); err == nil {
		t.Fatal("strict snapshot read accepted a legacy snapshot")
	}
	if _, err := appMCPReadFileProcessingStatus(context.Background(), app, legacyID, actor.UserID, grant.UserCreated, grant.Tenant, "notes", "1", logical, "current"); err == nil {
		t.Fatal("strict status accepted a legacy snapshot")
	}

	scope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: "notes", RecordID: "1", FileRef: logical, FileColumn: "file_path", UploadTenant: "current"}
	if _, err := appMCPRecordFileProcessing(app, actor.UserID, logical, parsed.SHA256, "private_upload", parsed.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: parsed, Actor: actor}); err == nil {
		t.Fatal("publication transaction accepted foreign upload provenance")
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE upload_tenant='current'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign strict processing was published: count=%d err=%v", count, err)
	}
}

func TestAppMCPUploadTenantManifestContractAndInspection(t *testing.T) {
	app, _, _ := appMCPUploadTenantFixture(t)
	data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	strictDigest, err := appMCPContractDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	legacyManifest := *manifest
	legacyManifest.Tools = append([]AppMCPTool(nil), manifest.Tools...)
	for i := range legacyManifest.Tools {
		if legacyManifest.Tools[i].Handler.Kind == "file" {
			legacyManifest.Tools[i].Handler.UploadTenant = nil
		}
	}
	legacyDigest, err := appMCPContractDigest(&legacyManifest)
	if err != nil || strictDigest == legacyDigest {
		t.Fatalf("upload tenant policy did not change contract digest: strict=%q legacy=%q err=%v", strictDigest, legacyDigest, err)
	}
	publicHandler, err := json.Marshal(manifest.Tools[0].Handler)
	if err != nil || !strings.Contains(string(publicHandler), `"UploadTenant":"current"`) {
		t.Fatalf("public handler JSON omitted reviewed UploadTenant field: %s err=%v", publicHandler, err)
	}
	for _, mode := range []string{"other", ""} {
		for i := range manifest.Tools {
			if manifest.Tools[i].Handler.Kind == "file" {
				value := mode
				manifest.Tools[i].Handler.UploadTenant = &value
			}
		}
		encoded, _ := yaml.Marshal(manifest)
		if _, err := parseAppMCPManifest(encoded); err == nil {
			t.Fatalf("accepted upload_tenant mode %q", mode)
		}
	}
	copyManifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	copyManifest.Tools[0].Handler.FileColumn = ""
	encoded, _ := yaml.Marshal(copyManifest)
	if _, err := parseAppMCPManifest(encoded); err == nil {
		t.Fatal("accepted upload_tenant without exact file_column")
	}
	report, err := inspectAppMCPSource(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range report.ReviewedTools {
		handler := tool["handler"].(map[string]any)
		if handler["file_column"] != "file_path" || handler["upload_tenant"] != "current" {
			t.Fatalf("inspection omitted reviewed strict file binding: %#v", handler)
		}
	}
	if !strings.Contains(string(data), "upload_tenant: current") {
		t.Fatal("test manifest lost explicit strict policy")
	}
	validManifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	strictTool := appMCPFileTool(validManifest, "ingest_file")
	strictManifest := &AppMCPManifest{Tools: []AppMCPTool{*strictTool}}
	group := &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	definitions := []crudTableDefinition{
		{name: "notes", columns: map[string]bool{"file_path": true, "org_id": true}},
		{name: "members", columns: map[string]bool{"org_id": true, "email": true}},
	}
	if err := validateAppMCPFileUploadTenantBindings(strictManifest, nil, definitions); err == nil {
		t.Fatal("upload tenant accepted missing configured groups")
	}
	if err := validateAppMCPFileUploadTenantBindings(strictManifest, group, []crudTableDefinition{
		{name: "notes", columns: map[string]bool{"file_path": true}},
		{name: "members", columns: map[string]bool{"org_id": true, "email": true}},
	}); err == nil {
		t.Fatal("upload tenant accepted a source table without the configured tenant key")
	}
	if err := validateAppMCPFileUploadTenantBindings(strictManifest, group, definitions); err != nil {
		t.Fatalf("valid canonical tenant bindings rejected: %v", err)
	}
}

func TestAppMCPFileMembershipBindingsWithoutEncryptedConfig(t *testing.T) {
	app, _, _ := appMCPUploadTenantFixture(t)
	encryptedPath := filepath.Join(app.Dir, "encrypted.yaml")
	if _, err := os.Stat(encryptedPath); !os.IsNotExist(err) {
		t.Fatalf("fixture must omit encrypted.yaml, stat err=%v", err)
	}

	data, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Tools {
		if manifest.Tools[i].Handler.Kind == "file" {
			manifest.Tools[i].Handler.MembershipConstraints = map[string]any{"kind": "human", "status": "active"}
		}
	}
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, file_path TEXT, org_id TEXT); CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, kind TEXT, status TEXT);\n")
	if err := validateAppMCPBindings(app.Dir, manifest, nil); err != nil {
		t.Fatalf("valid file membership bindings without encrypted.yaml were rejected: %v", err)
	}

	writeTestFile(t, app.Dir, "encrypted.yaml", "tables:\n  members:\n    fields: [kind]\n")
	if err := validateAppMCPBindings(app.Dir, manifest, nil); err == nil || !strings.Contains(err.Error(), "cannot use an encrypted column") {
		t.Fatalf("encrypted membership column was not refused: %v", err)
	}
}
