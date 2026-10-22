//go:build !cli && !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		if tool["handler"].(map[string]any)["file_column"] != "file_path" {
			t.Fatal("source inspection hid the exact reviewed file column")
		}
	}
	return app, pair
}

func TestAppMCPFileMembershipConstraintsAndMetadataStatus(t *testing.T) {
	app, oldPair := appMCPFileColumnFixture(t)
	originalGrant, originalActor, err := resolveAppMCPAccess(app, oldPair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`ALTER TABLE members ADD COLUMN kind TEXT; ALTER TABLE members ADD COLUMN status TEXT; ALTER TABLE members ADD COLUMN numeric_status INTEGER`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE members SET kind='human',status='active',numeric_status=1`); err != nil {
		t.Fatal(err)
	}
	app.Group.ActiveField = "status"
	constraints := map[string]any{"kind": "human", "status": "active"}
	for i := range app.MCP.Tools {
		if app.MCP.Tools[i].Handler.Kind == "file" {
			app.MCP.Tools[i].Handler.MembershipConstraints = constraints
		}
	}
	statusTool := app.MCP.Tools[0]
	statusTool.Name = "status_file"
	statusTool.Handler.Operation = "status"
	statusTool.InputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"processing_id", "record_id", "file_ref"}, Properties: map[string]*AppMCPSchema{
		"processing_id": {Type: "string"}, "record_id": {Type: "string"}, "file_ref": {Type: "string"},
	}}
	statusFields := []string{"processing_id", "record_id", "file_ref", "sha256", "content_type", "parser_version", "limits", "complete", "quality_flags", "created_at", "source_connection", "source_file_id", "source_revision"}
	statusProperties := map[string]*AppMCPSchema{}
	for _, field := range statusFields {
		statusProperties[field] = &AppMCPSchema{Type: "string"}
	}
	statusProperties["complete"] = &AppMCPSchema{Type: "boolean"}
	limitProperties := map[string]*AppMCPSchema{}
	for _, field := range []string{"MaxFileBytes", "MaxCells", "MaxDecompressedBytes", "MaxEntryBytes", "MaxZipEntries", "MaxCompressionRatio", "MaxSharedStrings", "MaxSheets", "MaxXMLDepth", "MaxXMLTokens", "MaxCSVRows", "MaxFieldBytes", "MaxExtractedBytes"} {
		limitProperties[field] = &AppMCPSchema{Type: "integer"}
	}
	statusProperties["limits"] = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Properties: limitProperties}
	statusProperties["quality_flags"] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "string"}}
	statusTool.OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Properties: statusProperties}
	statusTool.Output.Include = statusFields
	app.MCP.Tools = append(app.MCP.Tools, statusTool)
	manifestData, err := yaml.Marshal(app.MCP)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", string(manifestData))
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, file_path TEXT); CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, kind TEXT, status TEXT);\n")
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	pair, err := createAppMCPGrant(app, originalActor.UserID, "17", "client-fixture", grantFixtureResource, "files:read notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, actor, accessErr := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if accessErr != nil || !appMCPFileMembershipConstraintsValid(app.DB, app, constraints) || !appMCPFileMembershipAllowed(app.DB, app, actor, "17", constraints) {
		t.Fatal("canonical active human membership did not satisfy its reviewed constraints")
	}
	if err := validateAppMCPFileMembershipConstraints(map[string]any{"kind": []string{"human"}}); err == nil {
		t.Fatal("array membership constraint accepted")
	}
	if err := validateAppMCPFileMembershipConstraints(map[string]any{"kind": nil}); err == nil {
		t.Fatal("null membership constraint accepted")
	}
	if err := validateAppMCPFileMembershipConstraints(map[string]any{"kind;DROP": "human"}); err == nil {
		t.Fatal("unsafe membership column accepted")
	}
	if appMCPFileMembershipConstraintsValid(app.DB, app, map[string]any{"missing": "human"}) {
		t.Fatal("unknown membership column accepted")
	}
	if !appMCPFileMembershipAllowed(app.DB, app, actor, "17", map[string]any{"numeric_status": true}) {
		t.Fatal("native boolean did not match its SQLite integer representation")
	}
	if appMCPFileMembershipAllowed(app.DB, app, actor, "17", map[string]any{"numeric_status": "1"}) {
		t.Fatal("text scalar was coerced to an integer membership value")
	}

	generation := snapshotAppMCPGeneration(app)
	app.DB.SetMaxOpenConns(1)
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"})
	if err != nil || ingested.ProcessingID == "" {
		t.Fatalf("constrained ingest = %#v, %v", ingested, err)
	}
	input := map[string]any{"processing_id": ingested.ProcessingID, "record_id": "1", "file_ref": "uploads/private/source.csv"}
	status, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "status_file", input)
	if err != nil {
		t.Fatalf("metadata status = %#v, %v", status, err)
	}
	row := status.Data.(map[string]any)
	if row["processing_id"] != ingested.ProcessingID || row["file_ref"] != input["file_ref"] || row["record_id"] != "1" || row["complete"] != true || row["sha256"] == "" {
		t.Fatalf("metadata status incomplete: %#v", row)
	}
	var sourceDigest string
	if err := app.DB.QueryRow(`SELECT file_sha256 FROM _benmore_mcp_file_processings WHERE id=?`, ingested.ProcessingID).Scan(&sourceDigest); err != nil || row["sha256"] != sourceDigest {
		t.Fatalf("status source digest = %v, stored digest %q, err %v", row["sha256"], sourceDigest, err)
	}
	if _, ok := row["limits"].(map[string]any); !ok {
		t.Fatalf("status limits are not a native object: %T", row["limits"])
	}
	if _, ok := row["blocks"]; ok {
		t.Fatal("metadata status exposed parsed blocks")
	}
	if _, ok := row["snapshot_data"]; ok {
		t.Fatal("metadata status exposed private snapshot payload")
	}
	if _, err := appMCPReadFileProcessingStatus(context.Background(), app, ingested.ProcessingID, originalActor.UserID+1, originalGrant.UserCreated, "17", "notes", "1", "uploads/private/source.csv"); err == nil {
		t.Fatal("processing status accepted another owner")
	}
	if _, err := appMCPReadFileProcessingStatus(context.Background(), app, ingested.ProcessingID, originalActor.UserID, originalGrant.UserCreated, "other-tenant", "notes", "1", "uploads/private/source.csv"); err == nil {
		t.Fatal("processing status accepted another tenant")
	}
	verifyInput := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "processing_id": ingested.ProcessingID, "sheet": "csv", "ref": "B2", "expected": "42"}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput); err != nil {
		t.Fatalf("constrained verify = %v", err)
	}
	pdfOriginal := []byte("%PDF-1.4\nstatus fixture\n")
	pdfHash := sha256.Sum256(pdfOriginal)
	pdfDigest := hex.EncodeToString(pdfHash[:])
	if _, err := app.DB.Exec(`INSERT INTO notes(id,user_id,title,file_path) VALUES(3,?,'PDF source','uploads/private/source.pdf')`, originalActor.UserID); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "uploads/private/source.pdf", string(pdfOriginal))
	pdfParsed := IngestResult{Format: "pdf", Complete: true, ParserVersion: appMCPPDFParserVersion, SHA256: pdfDigest}
	pdfExtracted := &appMCPPDFResult{Complete: true, ParserVersion: appMCPPDFParserVersion, SHA256: pdfDigest}
	pdfScope := appMCPFileSnapshotScope{OwnerCreatedAt: originalGrant.UserCreated, Tenant: "17", Table: "notes", RecordID: "3", FileRef: "uploads/private/source.pdf", FileColumn: "file_path", MembershipConstraints: constraints}
	pdfID, err := appMCPRecordFileProcessing(app, originalActor.UserID, pdfScope.FileRef, pdfDigest, "private_upload", pdfDigest, "application/pdf", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: pdfScope, Original: pdfOriginal, Result: pdfParsed, PDF: pdfExtracted, Actor: actor})
	if err != nil {
		t.Fatalf("persist synthetic successful PDF snapshot: %v", err)
	}
	pdfStatus, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "status_file", map[string]any{"processing_id": pdfID, "record_id": "3", "file_ref": pdfScope.FileRef})
	if err != nil || pdfStatus.Data.(map[string]any)["parser_version"] != appMCPPDFParserVersion {
		t.Fatalf("metadata status for snapshot-backed PDF = %#v, %v", pdfStatus, err)
	}
	for _, bad := range []map[string]any{
		{"processing_id": strings.Repeat("0", 32), "record_id": "1", "file_ref": "uploads/private/source.csv"},
		{"processing_id": ingested.ProcessingID, "record_id": "2", "file_ref": "uploads/private/source.csv"},
		{"processing_id": ingested.ProcessingID, "record_id": "1", "file_ref": "uploads/private/other.csv"},
	} {
		if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "status_file", bad); err == nil {
			t.Fatalf("status accepted mismatched processing binding: %#v", bad)
		}
	}
	if _, err := app.DB.Exec(`INSERT INTO members(org_id,email,kind,status) VALUES('17','delegate@example.com','service','active')`); err != nil {
		t.Fatal(err)
	}
	if appMCPFileMembershipAllowed(app.DB, app, actor, "17", constraints) {
		t.Fatal("one qualifying row borrowed authority from duplicate live membership rows")
	}
	if _, err := app.DB.Exec(`DELETE FROM members WHERE id=(SELECT MAX(id) FROM members WHERE org_id='17' AND email='delegate@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE members SET kind='service' WHERE org_id='17'`); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput); err == nil {
		t.Fatal("verify remained available after membership-kind revocation")
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"}); err == nil {
		t.Fatal("cached ingest remained available after membership-kind revocation")
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "status_file", input); err == nil {
		t.Fatal("status remained available after membership-kind revocation")
	}
	if _, err := app.DB.Exec(`UPDATE members SET kind='human',status='inactive' WHERE org_id='17'`); err != nil {
		t.Fatal(err)
	}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "status_file", input); err == nil {
		t.Fatal("status remained available after live-membership revocation")
	}
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
	constrained := strict
	for i := range constrained.Tools {
		if constrained.Tools[i].Handler.Kind == "file" {
			constrained.Tools[i].Handler.MembershipConstraints = map[string]any{"kind": "human", "status": "active"}
		}
	}
	constrainedSource, err := yaml.Marshal(constrained)
	if err != nil {
		t.Fatal(err)
	}
	constrained, err = parseAppMCPManifest(constrainedSource)
	if err != nil {
		t.Fatalf("valid reviewed membership constraints rejected: %v", err)
	}
	constrainedDigest, err := appMCPContractDigest(constrained)
	if err != nil || constrainedDigest == strictDigest {
		t.Fatalf("membership constraints did not affect reviewed contract: %v", err)
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

func TestAppMCPFileMembershipPublicationTransactionRechecksCanonicalRow(t *testing.T) {
	app, pair := appMCPFileColumnFixture(t)
	grant, actor, err := resolveAppMCPAccess(app, pair.AccessToken, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`ALTER TABLE members ADD COLUMN kind TEXT; ALTER TABLE members ADD COLUMN status TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE members SET kind='human',status='active'`); err != nil {
		t.Fatal(err)
	}
	app.Group.ActiveField = "status"
	constraints := map[string]any{"kind": "human", "status": "active"}
	original := []byte("name,value\nAda,42\n")
	parsed, err := appMCPParsePrivateUpload("uploads/private/source.csv", "text/csv", original, DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	// Parsing completed under the active-human row; revoke that same canonical
	// row before snapshot publication to exercise the transaction recheck.
	if _, err := app.DB.Exec(`UPDATE members SET kind='integration'`); err != nil {
		t.Fatal(err)
	}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: "notes", RecordID: "1", FileRef: "uploads/private/source.csv", FileColumn: "file_path", MembershipConstraints: constraints}
	_, err = appMCPRecordFileProcessing(app, actor.UserID, scope.FileRef, parsed.SHA256, "private_upload", parsed.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: parsed, Actor: actor})
	if err == nil {
		t.Fatal("published a snapshot after the canonical membership row stopped satisfying its constraints")
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE source_table='notes' AND record_id='1' AND snapshot_version=1`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed membership publication persisted snapshot count=%d: %v", count, err)
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
