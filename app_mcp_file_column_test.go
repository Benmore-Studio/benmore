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

	"gopkg.in/yaml.v3"
)

func appMCPFileColumnManifest(t *testing.T, source []byte) []byte {
	t.Helper()
	manifest, err := parseAppMCPManifest(source)
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Tools {
		manifest.Tools[i].Handler.FileColumn = "file_path"
	}
	strict, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return strict
}

func appMCPFileColumnFixture(t *testing.T) (*App, *appMCPTokenPair) {
	t.Helper()
	app, pair := appMCPFileRuntimeFixture(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, file_path TEXT);\n")
	source, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	strictSource := appMCPFileColumnManifest(t, source)
	writeTestFile(t, app.Dir, "mcp.yaml", string(strictSource))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	report, err := inspectAppMCPSource(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ReviewedTools) != 2 {
		t.Fatalf("reviewed file bindings missing: %#v", report.ReviewedTools)
	}
	for _, tool := range report.ReviewedTools {
		if tool["handler"].(map[string]string)["file_column"] != "file_path" {
			t.Fatal("source inspection hid the exact reviewed file column")
		}
	}
	return app, pair
}

func TestAppMCPFileColumnManifestValidationAndDigest(t *testing.T) {
	app, _ := appMCPFileRuntimeFixture(t)
	source, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := parseAppMCPManifest(source)
	if err != nil {
		t.Fatal(err)
	}
	strictSource := string(appMCPFileColumnManifest(t, source))
	strict, err := parseAppMCPManifest([]byte(strictSource))
	if err != nil {
		t.Fatal(err)
	}
	legacyDigest, err := appMCPContractDigest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	strictDigest, err := appMCPContractDigest(strict)
	if err != nil {
		t.Fatal(err)
	}
	if legacyDigest == strictDigest {
		t.Fatal("file_column did not affect reviewed contract")
	}
	for _, column := range []string{"file_path.x", "../file_path", "file_path;SELECT 1", "private_key", "file_path_blind"} {
		_, err := parseAppMCPManifest([]byte(strings.ReplaceAll(strictSource, "file_column: file_path", "file_column: "+column)))
		if err == nil {
			t.Fatalf("accepted unsafe file column %q", column)
		}
	}
	native := strings.Replace(appMCPManifestFixture(), "operation: table.list", "operation: table.list, file_column: title", 1)
	if _, err := parseAppMCPManifest([]byte(native)); err == nil {
		t.Fatal("file_column allowed on non-file handler")
	}
	if err := validateAppMCPBindings(app.Dir, strict, nil); err == nil || !strings.Contains(err.Error(), "file_column") {
		t.Fatal("source check accepted a column absent from declared schema")
	}
}

func TestAppMCPFileColumnRejectsSameRowMetadataAndStaleSnapshot(t *testing.T) {
	app, pair := appMCPFileColumnFixture(t)
	generation := snapshotAppMCPGeneration(app)
	args := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "per_page": json.Number("100")}
	first, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", args)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "uploads/private/current.csv", "name,value\nAda,99\n")
	if _, err := app.DB.Exec(`UPDATE notes SET title='uploads/private/source.csv',file_path='uploads/private/current.csv' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", args); err == nil {
		t.Fatal("alternate metadata path authorized ingest/cache reuse")
	}
	verify := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "processing_id": first.ProcessingID, "sheet": "csv", "ref": "B2", "expected": "42"}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify); err == nil {
		t.Fatal("stale cached extraction remained authorized by metadata")
	}
	args["file_ref"] = "uploads/private/current.csv"
	current, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", args)
	if err != nil {
		t.Fatal(err)
	}
	if current.Data.(map[string]any)["blocks"].([]any)[3].(map[string]any)["value"] != "99" {
		t.Fatal("current version did not yield current bytes")
	}
	// The exact current ref remains authorized; immutable processing IDs still distinguish overwritten bytes.
	writeTestFile(t, app.Dir, "uploads/private/current.csv", "name,value\nAda,100\n")
	verify["file_ref"], verify["processing_id"], verify["expected"] = "uploads/private/current.csv", current.ProcessingID, "99"
	result, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify)
	if err != nil || result.Data.(map[string]any)["valid"] != true {
		t.Fatalf("immutable same-ref snapshot verification changed: %#v %v", result, err)
	}
}

func TestAppMCPFileColumnPublicationTransactionRechecksChangedFile(t *testing.T) {
	app, pair := appMCPFileColumnFixture(t)
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("name,value\nAda,42\n")
	parsed, err := appMCPParsePrivateUpload("uploads/private/source.csv", "text/csv", original, DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the column changing after authorized bytes were read and parsed.
	if _, err := app.DB.Exec(`UPDATE notes SET title=file_path,file_path='uploads/private/current.csv' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: "notes", RecordID: "1", FileRef: "uploads/private/source.csv", FileColumn: "file_path"}
	_, err = appMCPRecordFileProcessing(app, actor.UserID, scope.FileRef, parsed.SHA256, "private_upload", parsed.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: parsed, Actor: actor})
	if err == nil {
		t.Fatal("published after bound file column changed")
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE snapshot_version=1`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed publication persisted snapshot count=%d: %v", count, err)
	}
}

func TestAppMCPFileColumnKeepsOwnershipAndCanonicalCDNChecks(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	if !appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv", "file_path") {
		t.Fatal("strict current file refused")
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "2", "uploads/private/other.csv", "file_path") {
		t.Fatal("strict binding bypassed row authority")
	}
	for _, id := range []string{" 1", "1 ", "1/", "1?x", "1\x00"} {
		if appMCPAuthorizeFileRecord(app, actor, "tasks", id, "uploads/private/source.csv", "file_path") {
			t.Fatalf("invalid record ID accepted: %q", id)
		}
	}
	for _, column := range []string{"id", "missing", "private_key", "file_path_blind"} {
		if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv", column) {
			t.Fatalf("unreadable/non-text column accepted: %s", column)
		}
	}
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	canonical, private, ok := cdnURLForServe(app, "uploads/private/source.csv", cfg)
	if !ok || !private {
		t.Fatal("fixture CDN conversion failed")
	}
	if _, err := app.DB.Exec(`UPDATE tasks SET file_path=?,title='uploads/private/other.csv' WHERE id=1`, canonical); err != nil {
		t.Fatal(err)
	}
	if !appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv", "file_path") {
		t.Fatal("canonical CDN reference no longer matches logical upload")
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/other.csv", "file_path") {
		t.Fatal("CDN fallback accepted unrelated text column")
	}
	if _, err := app.DB.Exec(`UPDATE tasks SET file_path='https://elsewhere.invalid/source.csv' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv", "file_path") {
		t.Fatal("unconfigured URL vouched for logical upload")
	}
}

func TestAppMCPFileColumnRejectsLegacyProcessingReplayUnderStrictTool(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	args := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"}
	legacy, err := runAppMCPFileTool(context.Background(), app, snapshotAppMCPGeneration(app), pair.AccessToken, grantFixtureResource, "ingest_file", args)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE notes SET title=file_path,file_path='uploads/private/current.csv' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY,file_path TEXT);\n")
	writeTestFile(t, app.Dir, "mcp.yaml", string(appMCPFileColumnManifest(t, source)))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	verify := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "processing_id": legacy.ProcessingID, "sheet": "csv", "ref": "B2", "expected": "42"}
	if _, err := runAppMCPFileTool(context.Background(), app, snapshotAppMCPGeneration(app), pair.AccessToken, grantFixtureResource, "verify_file", verify); err == nil {
		t.Fatal("legacy cached extraction bypassed stricter current-column authorization")
	}
}

func TestAppMCPFileColumnRefusesEncryptedAndMismatchedUploadOwnership(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	logical := "uploads/private/source.csv"
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"tasks": {{Column: "file_path", Roles: []string{"admin"}}}}}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", logical, "file_path") {
		t.Fatal("configured encrypted file column was accepted")
	}
	app.Encrypted = nil
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_upload_owners(path,user_id,group_id) VALUES (?,999999,'29')`, privateUploadKey(app, logical)); err != nil {
		t.Fatal(err)
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", logical, "file_path") {
		t.Fatal("strict binding bypassed recorded foreign upload ownership")
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_upload_owners SET user_id=?`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if !appMCPAuthorizeFileRecord(app, actor, "tasks", "1", logical, "file_path") {
		t.Fatal("recorded upload owner could not read current file")
	}
}

func TestAppMCPFileColumnExistingSnapshotConflictStillRefusesOuterRead(t *testing.T) {
	app, pair := appMCPFileColumnFixture(t)
	generation := snapshotAppMCPGeneration(app)
	args := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"}
	first, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", args)
	if err != nil {
		t.Fatal(err)
	}
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("name,value\nAda,42\n")
	parsed, err := appMCPParsePrivateUpload("uploads/private/source.csv", "text/csv", original, DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE notes SET title=file_path,file_path='uploads/private/current.csv' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: "notes", RecordID: "1", FileRef: "uploads/private/source.csv", FileColumn: "file_path"}
	reusedID, err := appMCPRecordFileProcessing(app, actor.UserID, scope.FileRef, parsed.SHA256, "private_upload", parsed.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: parsed, Actor: actor})
	if err != nil || reusedID != first.ProcessingID {
		t.Fatalf("identical immutable snapshot conflict: %q %v", reusedID, err)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE snapshot_version=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("conflict published another snapshot: %d %v", count, err)
	}
	verify := map[string]any{"file_ref": scope.FileRef, "record_id": "1", "processing_id": reusedID, "sheet": "csv", "ref": "B2", "expected": "42"}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify); err == nil {
		t.Fatal("reused snapshot ID conferred stale column authority")
	}
	if appMCPAuthorizeFileRecord(app, actor, "notes", "1", scope.FileRef, "file_path") {
		t.Fatal("current authorization would release stale reused snapshot")
	}
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, scope.FileRef); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_mcp_grants SET revoked=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verify); err == nil {
		t.Fatal("revoked grant retained immutable snapshot access")
	}
}
