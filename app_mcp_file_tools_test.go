//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAppMCPFileManifestRequiresBothReadScopesAndFileOperation(t *testing.T) {
	valid := `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: ingest_private_file
    description: Read a referenced private file.
    handler: {kind: file, operation: ingest, table: documents}
    input_schema:
      type: object
      additionalProperties: false
      required: [file_ref, record_id]
      properties:
        file_ref: {type: string}
        record_id: {type: string}
    output_schema:
      type: object
      additionalProperties: false
      required: [complete]
      properties:
        complete: {type: boolean}
    permissions: [files:read, documents:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [complete]}
    component: none
resources: []
connections: []
`
	if _, err := parseAppMCPManifest([]byte(valid)); err != nil {
		t.Fatalf("valid file tool manifest rejected: %v", err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, "permissions: [files:read, documents:read]", "permissions: [files:read]", 1),
		strings.Replace(valid, "operation: ingest", "operation: table.read", 1),
		strings.Replace(valid, "operation: ingest", "operation: verify", 1),
		strings.Replace(valid, "    input_schema:\n      type: object\n      additionalProperties: false\n      required: [file_ref, record_id]\n      properties:\n        file_ref: {type: string}\n        record_id: {type: string}\n", "", 1),
	} {
		if _, err := parseAppMCPManifest([]byte(invalid)); err == nil {
			t.Fatalf("invalid file tool manifest accepted: %s", invalid)
		}
	}
}

func appMCPFileAccessFixture(t *testing.T) (*App, *Session, string) {
	t.Helper()
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	if _, err := app.DB.Exec(`ALTER TABLE tasks ADD COLUMN file_path TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE tasks SET file_path=? WHERE id=1`, "uploads/private/source.csv"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO tasks(id,project_id,org_id,title,status,file_path) VALUES(2,8,'29','Other task','open',?)`, "uploads/private/other.csv"); err != nil {
		t.Fatal(err)
	}
	actor := getSessionByStoredID(app.DB, sessionID)
	if actor == nil {
		t.Fatal("fixture actor missing")
	}
	writeTestFile(t, app.Dir, "uploads/private/source.csv", "name,value\nAda,42\n")
	writeTestFile(t, app.Dir, "uploads/private/other.csv", "private,content\n")
	return app, actor, sessionID
}

func TestAppMCPFileToolAuthorizationBeforeReadAndURLRefusal(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	if !appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv") {
		t.Fatal("readable row did not authorize its exact private file")
	}
	data, contentType, err := appMCPReadAuthorizedPrivateUpload(context.Background(), app, actor, "tasks", "1", "uploads/private/source.csv", DefaultIngestLimits().MaxFileBytes)
	if err != nil || contentType != "text/csv; charset=utf-8" || string(data) != "name,value\nAda,42\n" {
		t.Fatalf("authorized file read = %q %q, %v", data, contentType, err)
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "2", "uploads/private/other.csv") {
		t.Fatal("foreign row authorized a private file")
	}
	if _, err := privateLogicalUploadPath("https://example.invalid/file.csv"); err == nil {
		t.Fatal("URL input was accepted as a private upload reference")
	}
	if _, err := privateLogicalUploadPath("uploads/private/../secret.csv"); err == nil {
		t.Fatal("traversal path was accepted as a private upload reference")
	}
	missing := "uploads/private/not-present.csv"
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "2", missing) {
		t.Fatal("unauthorized row was accepted before the missing file could be read")
	}

	// A readable row naming connector artifact storage must not expose the
	// artifact bytes, which only the artifact route may serve.
	artifact := "uploads/private/mcp-artifacts/receipt.html"
	writeTestFile(t, app.Dir, artifact, "<p>receipt</p>")
	if _, err := app.DB.Exec(`UPDATE tasks SET file_path=? WHERE id=1`, artifact); err != nil {
		t.Fatal(err)
	}
	if data, _, err := appMCPReadAuthorizedPrivateUpload(context.Background(), app, actor, "tasks", "1", artifact, DefaultIngestLimits().MaxFileBytes); err == nil {
		t.Fatalf("file tool read connector artifact bytes through a row: %q", data)
	}
}

func TestAppMCPFileToolCSVAndXLSXCoordinatesVerifyAndLimits(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	csvBytes, err := os.ReadFile(filepath.Join(app.Dir, "uploads/private/source.csv"))
	if err != nil {
		t.Fatal(err)
	}
	csvResult, err := appMCPParsePrivateUpload("uploads/private/source.csv", "text/csv; charset=utf-8", csvBytes, DefaultIngestLimits())
	if err != nil || !csvResult.Complete || csvResult.Blocks[3].Ref != "B2" || csvResult.Blocks[3].Value != "42" {
		t.Fatalf("CSV ingest = %+v, %v", csvResult, err)
	}
	if !VerifySpan(csvResult, "csv", "B2", "42") || VerifySpan(csvResult, "csv", "B2", "43") {
		t.Fatal("VerifySpan did not distinguish matching and mismatching values")
	}
	if id, err := appMCPRecordFileProcessing(app, actor.UserID, "private/source.csv", csvResult.SHA256, "private_upload", csvResult.SHA256, "text/csv", DefaultIngestLimits(), true, csvResult.Quality); err != nil || id == "" {
		t.Fatalf("processing record = %q, %v", id, err)
	}
	var recordedHash, parser string
	var complete int
	if err := app.DB.QueryRow(`SELECT file_sha256,parser_version,complete FROM _benmore_mcp_file_processings WHERE file_id=?`, "private/source.csv").Scan(&recordedHash, &parser, &complete); err != nil || recordedHash != csvResult.SHA256 || parser != IngestParserVersion || complete != 1 {
		t.Fatalf("processing record = %q %q %d, %v", recordedHash, parser, complete, err)
	}

	xlsx := (ingWB{sheets: []ingSheet{{name: "Data", rows: `<row r="1"><c r="A1" t="inlineStr"><is><t>value</t></is></c></row><row r="2"><c r="A2"><v>7</v></c></row>`}}}).build(t)
	writeTestFile(t, app.Dir, "uploads/private/source.xlsx", string(xlsx))
	if _, err := app.DB.Exec(`UPDATE tasks SET file_path=? WHERE id=1`, "uploads/private/source.xlsx"); err != nil {
		t.Fatal(err)
	}
	xlsxResult, err := appMCPParsePrivateUpload("uploads/private/source.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", xlsx, DefaultIngestLimits())
	if err != nil || !xlsxResult.Complete || len(xlsxResult.Blocks) != 2 || xlsxResult.Blocks[1].Sheet != "Data" || xlsxResult.Blocks[1].Ref != "A2" || xlsxResult.Blocks[1].Value != "7" {
		t.Fatalf("XLSX ingest = %+v, %v", xlsxResult, err)
	}

	limits := DefaultIngestLimits()
	limits.MaxFileBytes = 3
	partial, err := appMCPParsePrivateUpload("uploads/private/source.csv", "text/csv; charset=utf-8", []byte("a,b\n"), limits)
	if !errors.Is(err, ErrIngestTooLarge) || partial.Complete || len(partial.Blocks) != 0 {
		t.Fatalf("over-limit ingest returned partial output: %+v, %v", partial, err)
	}
	if _, _, err := appMCPReadPrivateUpload(context.Background(), app, "uploads/private/source.csv", 3); !errors.Is(err, ErrIngestTooLarge) {
		t.Fatalf("over-limit private file read = %v", err)
	}
	if start, end, ok := appMCPFilePageRange(4, 1, appMCPFileDefaultPageSize); !ok || start != 0 || end != 4 {
		t.Fatalf("first bounded page = %d:%d, %v", start, end, ok)
	}
	if start, end, ok := appMCPFilePageRange(4, 2, 2); !ok || start != 2 || end != 4 {
		t.Fatalf("second page = %d:%d, %v", start, end, ok)
	}
	if _, _, ok := appMCPFilePageRange(4, int(^uint(0)>>1), appMCPFileMaxPageSize); ok {
		t.Fatal("overflowing page offset was accepted")
	}
}

func TestAppMCPFileToolRejectsUnauthorizedReadBeforeStorageAccess(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	_, _, err := appMCPReadAuthorizedPrivateUpload(context.Background(), app, actor, "tasks", "2", "uploads/private/not-present.csv", DefaultIngestLimits().MaxFileBytes)
	var failure *appMCPResultError
	if !errors.As(err, &failure) || failure.Code != "denied" {
		t.Fatalf("unauthorized file did not fail before storage access: %v", err)
	}
}

func TestAppMCPFileProcessingPurge(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=1`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	original := []byte("name,value\nAda,42\n")
	sum := sha256.Sum256(original)
	digest := hex.EncodeToString(sum[:])
	result := IngestResult{Format: IngestFormatCSV, Complete: true, ParserVersion: IngestParserVersion, SHA256: digest, Blocks: []SourceBlock{{Kind: "cell", Sheet: "csv", Ref: "A1", Value: "name"}}}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: createdAt, Tenant: "17", Table: "tasks", RecordID: "1", FileRef: "uploads/private/source.csv"}
	id, err := appMCPRecordFileProcessing(app, 1, scope.FileRef, digest, "private_upload", digest, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := appMCPReadFileSnapshot(context.Background(), app, id, 1, createdAt, "17", "tasks", "1", scope.FileRef)
	if err != nil || !bytes.Equal(stored.Snapshot.Original, original) {
		t.Fatalf("committed private BLOB snapshot unreadable: %v", err)
	}
	rollback, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rollback.Exec(`DELETE FROM _benmore_mcp_file_processings WHERE created_by=1`); err != nil {
		_ = rollback.Rollback()
		t.Fatal(err)
	}
	if err := rollback.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPReadFileSnapshot(context.Background(), app, id, 1, createdAt, "17", "tasks", "1", scope.FileRef); err != nil {
		t.Fatalf("rolled-back purge removed immutable BLOB: %v", err)
	}
	rawSession := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/account-delete", nil)
	ctx := &FlowContext{App: app, Session: &Session{ID: sessionStorageKey(rawSession), UserID: 1, Email: "owner@example.com"}, Request: request, Tx: tx, Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepPurgeCurrentUser(ctx, &FlowStep{Type: "purge_current_user", PurgeCurrentUserConfirm: "DELETE"}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_mcp_file_processings WHERE created_by=1`, 0)
	if _, err := appMCPReadFileSnapshot(context.Background(), app, id, 1, createdAt, "17", "tasks", "1", scope.FileRef); err == nil {
		t.Fatal("purged snapshot remained readable")
	}
}

func TestAppMCPFileProcessingRestoreCarryForward(t *testing.T) {
	live, liveCleanup := newTestApp(t)
	defer liveCleanup()
	candidate, candidateCleanup := newTestApp(t)
	defer candidateCleanup()
	if err := EnsureUsersTable(live.DB); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUsersTable(candidate.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := live.DB.Exec(`INSERT INTO _benmore_users(id,username,email,password_hash,created_at) VALUES(1,'live','live@example.com','hash','2026-10-05T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.DB.Exec(`INSERT INTO _benmore_users(id,username,email,password_hash,created_at) VALUES(2,'candidate','candidate@example.com','hash','2026-10-05T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := ensureAppMCPFileProcessingTable(live.DB); err != nil {
		t.Fatal(err)
	}
	if err := ensureAppMCPFileProcessingTable(candidate.DB); err != nil {
		t.Fatal(err)
	}
	original := []byte("a,b\n1,2\n")
	sum := sha256.Sum256(original)
	digest := hex.EncodeToString(sum[:])
	result := IngestResult{Format: IngestFormatCSV, Complete: true, ParserVersion: IngestParserVersion, SHA256: digest, Blocks: []SourceBlock{{Kind: "cell", Sheet: "csv", Ref: "A1", Value: "a"}}}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: "2026-10-05T00:00:00Z", Tenant: "17", Table: "tasks", RecordID: "1", FileRef: "uploads/private/a.csv"}
	processingID, err := appMCPRecordFileProcessing(live, 1, scope.FileRef, digest, "private_upload", digest, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: result})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := readCredTable(context.Background(), live.DB, mcpFileProcessingsTable, false, mcpFileProcessingRestoreColumns)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := candidate.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	summary := &restoreCredentialSummary{Kept: map[string]int{}, Removed: map[string]int{}}
	if err := carryForwardMCPFileProcessings(context.Background(), tx, map[string]*credTable{mcpFileProcessingsTable: rows}, filepath.Join(live.Dir, "data.db"), map[int64]int64{2: 1}, summary); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var owner int64
	var restoredOwnerCreatedAt string
	if err := candidate.DB.QueryRow(`SELECT created_by,owner_created_at FROM _benmore_mcp_file_processings WHERE id=?`, processingID).Scan(&owner, &restoredOwnerCreatedAt); err != nil || owner != 2 || restoredOwnerCreatedAt != scope.OwnerCreatedAt {
		t.Fatalf("restored processing owner = %d, %v", owner, err)
	}
	if _, err := appMCPReadFileSnapshot(context.Background(), candidate, processingID, 2, scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef); err != nil {
		t.Fatalf("restored BLOB snapshot unavailable: %v", err)
	}
	noLiveTx, err := candidate.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := carryForwardMCPFileProcessings(context.Background(), noLiveTx, map[string]*credTable{}, "", map[int64]int64{2: 2}, summary); err != nil {
		_ = noLiveTx.Rollback()
		t.Fatal(err)
	}
	if err := noLiveTx.Commit(); err != nil {
		t.Fatal(err)
	}
	assertCount(t, candidate, `SELECT COUNT(*) FROM _benmore_mcp_file_processings`, 0)
}

func TestAppMCPFileProcessingLegacyMigrationDoesNotInventSnapshots(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_users(id,username,email,password_hash,created_at) VALUES(1,'legacy','legacy@example.com','hash','2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`CREATE TABLE _benmore_mcp_file_processings (id TEXT PRIMARY KEY,file_id TEXT NOT NULL,file_sha256 TEXT NOT NULL DEFAULT '',origin TEXT NOT NULL,origin_version TEXT NOT NULL DEFAULT '',content_type TEXT NOT NULL DEFAULT '',parser_version TEXT NOT NULL,limits_json TEXT NOT NULL,complete INTEGER NOT NULL,quality_flags TEXT NOT NULL,created_by INTEGER NOT NULL,created_at TEXT NOT NULL,source_connection TEXT NOT NULL DEFAULT '',source_file_id TEXT NOT NULL DEFAULT '',source_revision TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_mcp_file_processings(id,file_id,origin,parser_version,limits_json,complete,quality_flags,created_by,created_at) VALUES('legacy','uploads/private/old.csv','private_upload','old','{}',1,'[]',1,'2026-10-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := ensureAppMCPFileProcessingTable(app.DB); err != nil {
		t.Fatal(err)
	}
	var owner, tenant, tableName, recordID, fileRef, digest string
	var version, size int
	if err := app.DB.QueryRow(`SELECT owner_created_at,tenant,source_table,record_id,file_ref,snapshot_version,snapshot_sha256,snapshot_size FROM _benmore_mcp_file_processings WHERE id='legacy'`).Scan(&owner, &tenant, &tableName, &recordID, &fileRef, &version, &digest, &size); err != nil {
		t.Fatal(err)
	}
	if owner != "" || tenant != "" || tableName != "" || recordID != "" || fileRef != "" || version != 0 || digest != "" || size != 0 {
		t.Fatalf("legacy processing was falsely upgraded into an immutable snapshot: %q %q %q %q %q %d %q %d", owner, tenant, tableName, recordID, fileRef, version, digest, size)
	}
}

func appMCPFileRuntimeFixture(t *testing.T) (*App, *appMCPTokenPair) {
	t.Helper()
	app, uid, _ := appMCPGrantFixture(t)
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{
		"editor": {Scopes: "files:read notes:read"},
		"admin":  {Scopes: "files:read notes:read"},
	}}
	if _, err := app.DB.Exec(`ALTER TABLE notes ADD COLUMN file_path TEXT`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO notes(id,user_id,title,file_path) VALUES(1,?,'Source','uploads/private/source.csv'),(2,999,'Foreign','uploads/private/missing.csv')`, uid); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "uploads/private/source.csv", "name,value\nAda,42\n")
	manifest := `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: ingest_file
    description: Ingest a referenced private file.
    handler: {kind: file, operation: ingest, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      required: [file_ref, record_id]
      properties:
        file_ref: {type: string}
        record_id: {type: string}
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 100}
    output_schema:
      type: object
      additionalProperties: false
      required: [complete, quality_flags, blocks]
      properties:
        complete: {type: boolean}
        quality_flags: {type: array, items: {type: string}}
        blocks:
          type: array
          items:
            type: object
            additionalProperties: false
            properties:
              kind: {type: string}
              sheet: {type: string}
              ref: {type: string}
              row: {type: integer}
              col: {type: integer}
              value: {type: string}
              type: {type: string}
              num_fmt: {type: string}
              formula: {type: boolean}
              cached_formula: {type: boolean}
              page: {type: integer, minimum: 1}
              bbox:
                type: object
                additionalProperties: false
                required: [x_min, y_min, x_max, y_max]
                properties:
                  x_min: {type: number}
                  y_min: {type: number}
                  x_max: {type: number}
                  y_max: {type: number}
              bbox_unit: {type: string}
              confidence: {type: number, minimum: 0, maximum: 100}
              quality: {type: array, items: {type: string}}
    permissions: [files:read, notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [complete, quality_flags, blocks]}
    component: none
  - name: verify_file
    description: Verify a source cell.
    handler: {kind: file, operation: verify, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      required: [file_ref, record_id, processing_id, sheet, ref, expected]
      properties:
        file_ref: {type: string}
        record_id: {type: string}
        processing_id: {type: string, minLength: 32, maxLength: 32}
        sheet: {type: string}
        ref: {type: string}
        expected: {type: string}
    output_schema:
      type: object
      additionalProperties: false
      required: [valid, quality_flags]
      properties:
        valid: {type: boolean}
        quality_flags: {type: array, items: {type: string}}
    permissions: [files:read, notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [valid, quality_flags]}
    component: none
resources: []
connections: []
`
	writeTestFile(t, app.Dir, "mcp.yaml", manifest)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, "files:read notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return app, pair
}

func TestAppMCPFileToolRuntimeProjectsAndVerifiesBoundedBlocks(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	generation := snapshotAppMCPGeneration(app)
	hash, err := appMCPCredentialHash(pair.AccessToken, "access")
	if err != nil {
		t.Fatal(err)
	}
	var credentialRows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_credentials WHERE token_hash=? AND kind='access'`, hash).Scan(&credentialRows); err != nil || credentialRows != 1 {
		t.Fatalf("fixture access token row count=%d err=%v scopes=%q", credentialRows, err, pair.Scopes)
	}
	grant, err := readAppMCPAccessGrant(context.Background(), app, hash, grantFixtureResource, time.Now())
	if err != nil {
		t.Fatalf("fixture access credential: %v", err)
	}
	actor, err := appMCPGrantActorForGeneration(context.Background(), app, generation, grant, time.Now())
	if err != nil || !appMCPToolAllowed(generation.view, appMCPFileTool(generation.manifest, "ingest_file"), actor) {
		t.Fatalf("fixture connector authority: grant=%+v actor=%+v err=%v", grant, actor, err)
	}
	input := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "per_page": json.Number("100")}
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	if err != nil {
		t.Fatalf("file tool ingest: %#v", err)
	}
	data, ok := ingested.Data.(map[string]any)
	if !ok || data["complete"] != true {
		t.Fatalf("ingest output = %#v", ingested.Data)
	}
	flags, ok := data["quality_flags"].([]any)
	if !ok || len(flags) != 0 {
		t.Fatalf("quality flags are not a JSON array: %#v", data["quality_flags"])
	}
	blocks, ok := data["blocks"].([]any)
	if !ok || len(blocks) != 4 {
		t.Fatalf("bounded source blocks = %#v", data["blocks"])
	}
	processingID := ingested.ProcessingID
	if len(processingID) != 32 {
		t.Fatalf("ingest processing id = %q", processingID)
	}
	cell, ok := blocks[3].(map[string]any)
	if !ok || cell["sheet"] != "csv" || cell["ref"] != "B2" || cell["value"] != "42" {
		t.Fatalf("source coordinate block = %#v", blocks[3])
	}
	verifyInput := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "processing_id": processingID, "sheet": "csv", "ref": "B2", "expected": "42"}
	verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("matching verify = %#v, %v", verified, err)
	}
	verifyInput["expected"] = "43"
	verified, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	if err != nil || verified.Data.(map[string]any)["valid"] != false {
		t.Fatalf("mismatching verify = %#v, %v", verified, err)
	}
	writeTestFile(t, app.Dir, "uploads/private/source.csv", "name,value\nAda,99\n")
	newIngest, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	if err != nil {
		t.Fatalf("re-ingest overwritten source: %#v %v", newIngest, err)
	}
	newProcessingID := newIngest.ProcessingID
	verifyInput["expected"] = "42"
	verified, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("old processing did not verify its immutable A snapshot: %#v %v", verified, err)
	}
	verifyInput["processing_id"], verifyInput["expected"] = newProcessingID, "99"
	verified, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("new processing did not verify overwritten B source: %#v %v", verified, err)
	}
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=2`, "uploads/private/other.csv"); err != nil {
		t.Fatal(err)
	}
	foreignVerify := map[string]any{"file_ref": "uploads/private/other.csv", "record_id": "2", "processing_id": processingID, "sheet": "csv", "ref": "B2", "expected": "42"}
	if _, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", foreignVerify); err == nil {
		t.Fatal("foreign row read an existing processing snapshot")
	}
	if _, err := app.DB.Exec(`DROP TRIGGER _benmore_mcp_file_processings_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_mcp_file_processings SET snapshot_data=? WHERE id=?`, []byte("tampered snapshot"), newProcessingID); err != nil {
		t.Fatal(err)
	}
	_, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", verifyInput)
	var tamperedFailure *appMCPResultError
	if !errors.As(err, &tamperedFailure) || tamperedFailure.Code != "denied" {
		t.Fatalf("tampered immutable snapshot was accepted: %v", err)
	}
	_, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/missing.csv", "record_id": "2"})
	var failure *appMCPResultError
	if !errors.As(err, &failure) || failure.Code != "denied" {
		t.Fatalf("foreign row authorization failure = %v", err)
	}
	large := strings.Repeat(strings.Repeat("<", 32767)+"\n", 100)
	writeTestFile(t, app.Dir, "uploads/private/large.csv", large)
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, "uploads/private/large.csv"); err != nil {
		t.Fatal(err)
	}
	_, err = runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/large.csv", "record_id": "1", "per_page": json.Number("100")})
	if !errors.As(err, &failure) || failure.Code != "incomplete_result" {
		t.Fatalf("oversized encoded result = %v", err)
	}
}

func TestAppMCPPDFFileToolSnapshotVerifiesOriginalExtraction(t *testing.T) {
	if !pdfExtractionAvailable(appMCPPDFTestAppDir(t)) {
		t.Skip("fixed Poppler/Tesseract binaries, English data, or sandbox probe are unavailable")
	}
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	writeTestFile(t, app.Dir, "uploads/private/document.pdf", string(appMCPTestPDF(t, "Hello PDF")))
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, "uploads/private/document.pdf"); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/document.pdf", "record_id": "1", "per_page": json.Number("100")})
	if err != nil {
		t.Fatalf("PDF tool ingest: %v", err)
	}
	data, ok := ingested.Data.(map[string]any)
	blocks, blocksOK := data["blocks"].([]any)
	if !ok || data["complete"] != true || !blocksOK || len(blocks) == 0 || len(ingested.ProcessingID) != 32 {
		t.Fatalf("PDF ingest response incomplete: %#v", ingested)
	}
	first, ok := blocks[0].(map[string]any)
	ref, refOK := first["ref"].(string)
	expected, expectedOK := first["value"].(string)
	if !ok || !refOK || !expectedOK || expected == "" {
		t.Fatalf("PDF source block malformed: %#v", blocks[0])
	}
	writeTestFile(t, app.Dir, "uploads/private/document.pdf", "overwritten after PDF ingestion")
	verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", map[string]any{"file_ref": "uploads/private/document.pdf", "record_id": "1", "processing_id": ingested.ProcessingID, "sheet": "pdf", "ref": ref, "expected": expected})
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("PDF immutable snapshot verification: %#v %v", verified, err)
	}
}

func TestAppMCPPDFOCRFileToolSnapshotVerifiesOriginalExtraction(t *testing.T) {
	requireAppMCPPDFIntegrationCapability(t)
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	fileRef := "uploads/private/scanned.pdf"
	writeTestFile(t, app.Dir, fileRef, string(appMCPTestPDFFixture(t, "scanned_hello_world.pdf")))
	if _, err := app.DB.Exec(`UPDATE notes SET file_path=? WHERE id=1`, fileRef); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": fileRef, "record_id": "1", "per_page": json.Number("100")})
	if err != nil {
		t.Fatalf("OCR PDF tool ingest: %v", err)
	}
	data, ok := ingested.Data.(map[string]any)
	blocks, blocksOK := data["blocks"].([]any)
	if !ok || data["complete"] != true || !blocksOK || len(blocks) == 0 || len(ingested.ProcessingID) != 32 {
		t.Fatalf("OCR PDF ingest response incomplete: %#v", ingested)
	}
	var selected map[string]any
	for _, candidate := range blocks {
		block, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		qualities, _ := block["quality"].([]any)
		for _, quality := range qualities {
			if quality == "ocr" {
				selected = block
				break
			}
		}
		if selected != nil {
			break
		}
	}
	if selected == nil {
		t.Fatalf("OCR file-tool ingest returned no OCR quality block: %#v", blocks)
	}
	ref, refOK := selected["ref"].(string)
	expected, expectedOK := selected["value"].(string)
	if !refOK || !expectedOK || expected == "" {
		t.Fatalf("OCR source block malformed: %#v", selected)
	}
	var ownerID int64
	var createdAt string
	if err := app.DB.QueryRow(`SELECT user_id FROM _benmore_mcp_grants WHERE id=?`, pair.GrantID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, ownerID).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	stored, err := appMCPReadFileSnapshot(context.Background(), app, ingested.ProcessingID, ownerID, createdAt, "17", "notes", "1", fileRef)
	if err != nil {
		t.Fatalf("read retained OCR snapshot: %v", err)
	}
	foundOCR := false
	for _, block := range stored.Snapshot.PDF.Blocks {
		if block.Value == expected && block.Confidence != nil && *block.Confidence > 0 && *block.Confidence <= 100 && appMCPPDFValidBox(block.BBox.XMin, block.BBox.YMin, block.BBox.XMax, block.BBox.YMax) {
			for _, quality := range block.Quality {
				if quality == "ocr" {
					foundOCR = true
				}
			}
		}
	}
	if !foundOCR {
		t.Fatalf("immutable OCR snapshot lost exact recognized value, confidence, or coordinates: %#v", stored.Snapshot.PDF.Blocks)
	}
	writeTestFile(t, app.Dir, fileRef, "overwritten after OCR ingestion")
	verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", map[string]any{"file_ref": fileRef, "record_id": "1", "processing_id": ingested.ProcessingID, "sheet": "pdf", "ref": ref, "expected": expected})
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("OCR immutable snapshot verification: %#v %v", verified, err)
	}
}

func TestAppMCPFileSnapshotRetainsPDFCoordinatesAndConfidence(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	var createdAt string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, uid).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	original := []byte("%PDF-1.7\nimmutable fixture source\n")
	sum := sha256.Sum256(original)
	digest := hex.EncodeToString(sum[:])
	confidence := 87.5
	pdf := &appMCPPDFResult{Complete: true, ParserVersion: appMCPPDFParserVersion, SHA256: digest, Blocks: []appMCPPDFBlock{{Page: 2, Ref: "p2w3", BBox: appMCPPDFBox{XMin: 12.25, YMin: 34.5, XMax: 56.75, YMax: 78.125}, BBoxUnit: "pixels", Value: "verified", Confidence: &confidence, Quality: []string{"ocr"}}}}
	result := IngestResult{Format: "pdf", Complete: true, ParserVersion: appMCPPDFParserVersion, SHA256: digest, Blocks: []SourceBlock{{Kind: "pdf", Sheet: "pdf", Ref: "p2w3", Row: 2, Col: 1, Value: "verified", Type: "text", Quality: []string{"ocr"}}}}
	scope := appMCPFileSnapshotScope{OwnerCreatedAt: createdAt, Tenant: "17", Table: "tasks", RecordID: "1", FileRef: "uploads/private/document.pdf"}
	id, err := appMCPRecordFileProcessing(app, uid, scope.FileRef, digest, "private_upload", digest, "application/pdf", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: result, PDF: pdf})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := appMCPRecordFileProcessing(app, uid, scope.FileRef, digest, "private_upload", digest, "application/pdf", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: original, Result: result, PDF: pdf})
	if err != nil || reused != id {
		t.Fatalf("repeated page processing did not reuse the immutable snapshot: id=%q err=%v", reused, err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_mcp_file_processings(id,file_id,origin,parser_version,limits_json,complete,quality_flags,created_by,created_at,snapshot_version,snapshot_size) VALUES('ffffffffffffffffffffffffffffffff','budget-reservation','private_upload','test','{}',0,'[]',?,datetime('now'),1,?)`, uid, appMCPFileSnapshotBudgetBytes); err != nil {
		t.Fatal(err)
	}
	if err := appMCPCheckFileSnapshotBudget(app.DB, "", 1); err == nil {
		t.Fatal("snapshot budget admitted bytes beyond the fixed app-wide cap")
	}
	stored, err := appMCPReadFileSnapshot(context.Background(), app, id, uid, createdAt, "17", "tasks", "1", scope.FileRef)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Snapshot.PDF, pdf) || !reflect.DeepEqual(stored.Snapshot.Result, result) || !reflect.DeepEqual(stored.Snapshot.Original, original) {
		t.Fatalf("PDF snapshot changed exact source, coordinate, confidence, or block values: got=%+v wantPDF=%+v wantResult=%+v", stored.Snapshot, pdf, result)
	}
}

// The account's creation time reaches the snapshot reader in either SQLite's
// datetime text or the driver's RFC 3339 form; both name the same account.
// The OCR integration test reads it the second way and failed on Linux CI.
func TestAppMCPReadFileSnapshotAcceptsEitherCreatedAtSpelling(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	generation := snapshotAppMCPGeneration(app)
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "per_page": json.Number("100")})
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := app.DB.QueryRow(`SELECT owner_created_at FROM _benmore_mcp_file_processings WHERE id=?`, ingested.ProcessingID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var viaDriver string
	if err := app.DB.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=1`).Scan(&viaDriver); err != nil {
		t.Fatal(err)
	}
	for _, createdAt := range []string{stored, viaDriver} {
		if _, err := appMCPReadFileSnapshot(context.Background(), app, ingested.ProcessingID, 1, createdAt, "17", "notes", "1", "uploads/private/source.csv"); err != nil {
			t.Fatalf("read with owner created_at %q: %v", createdAt, err)
		}
	}
	if _, err := appMCPReadFileSnapshot(context.Background(), app, ingested.ProcessingID, 1, "2001-01-01 00:00:00", "17", "notes", "1", "uploads/private/source.csv"); err == nil {
		t.Fatal("a different account incarnation read the snapshot")
	}
}

// File calls are admitted one at a time per process: a worst-case parse plus
// snapshot or a PDF child can use most of a hosted unit's 768 MiB, and two
// overlapping ones could OOM-kill (and so stop) the whole app unit.
func TestAppMCPFileToolCallsWaitForTheProcessWorkSlot(t *testing.T) {
	app, pair := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	generation := snapshotAppMCPGeneration(app)
	input := map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"}
	release, ok := appMCPAcquireFileWork(context.Background())
	if !ok {
		t.Fatal("work slot unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, err := runAppMCPFileTool(ctx, app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	cancel()
	var failure *appMCPResultError
	if !errors.As(err, &failure) || failure.Code != "denied" {
		release()
		t.Fatalf("call overlapped a running file call: %v", err)
	}
	var processings int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='_benmore_mcp_file_processings'`).Scan(&processings); err == nil && processings > 0 {
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_file_processings`).Scan(&processings); err != nil || processings != 0 {
			release()
			t.Fatalf("a call that never got the work slot recorded %d processings: %v", processings, err)
		}
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		release()
	}()
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", input)
	if err != nil || ingested.Data.(map[string]any)["complete"] != true {
		t.Fatalf("queued call did not run once the slot was free: %#v %v", ingested, err)
	}
}

// The publication-transaction recheck must hide soft-deleted rows exactly as
// the request-time check (canAccessRowScoped) does, or a row deleted while a
// long parse ran could still vouch for publishing its file's snapshot.
func TestAppMCPFilePublicationRecheckRefusesSoftDeletedRow(t *testing.T) {
	app, actor, _ := appMCPFileAccessFixture(t)
	if _, err := app.DB.Exec(`ALTER TABLE tasks ADD COLUMN deleted_at TEXT`); err != nil {
		t.Fatal(err)
	}
	for i := range app.Tables {
		if app.Tables[i].Name == "tasks" {
			app.Tables[i].Columns = append(app.Tables[i].Columns, Column{Name: "deleted_at", Type: "TEXT"})
		}
	}
	if !appMCPFileRecordAuthorizedFrom(app.DB, app, actor, "tasks", "1", "uploads/private/source.csv") {
		t.Fatal("live readable row did not authorize its file in the publication recheck")
	}
	if _, err := app.DB.Exec(`UPDATE tasks SET deleted_at=datetime('now') WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if appMCPAuthorizeFileRecord(app, actor, "tasks", "1", "uploads/private/source.csv") {
		t.Fatal("request-time check accepted a soft-deleted row")
	}
	if appMCPFileRecordAuthorizedFrom(app.DB, app, actor, "tasks", "1", "uploads/private/source.csv") {
		t.Fatal("publication recheck accepted a soft-deleted row")
	}
}

// An app without groups has no workspace, so its grants carry an empty
// tenant. Ingest must still retain a snapshot that verify can read, bound to
// that empty tenant by equality; an app with groups still refuses "".
func TestAppMCPFileToolSnapshotsOnAppWithoutGroups(t *testing.T) {
	app, _ := appMCPFileRuntimeFixture(t)
	app.DB.SetMaxOpenConns(1)
	groups := app.Group
	app.Group = nil
	var uid int64
	var createdAt string
	if err := app.DB.QueryRow(`SELECT n.user_id,u.created_at FROM notes n JOIN _benmore_users u ON u.id=n.user_id WHERE n.id=1`).Scan(&uid, &createdAt); err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPGrant(app, uid, "", "client-fixture", grantFixtureResource, "files:read notes:read", time.Now())
	if err != nil {
		t.Fatalf("group-less grant: %v", err)
	}
	generation := snapshotAppMCPGeneration(app)
	ingested, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"})
	if err != nil || len(ingested.ProcessingID) != 32 {
		t.Fatalf("ingest on an app without groups: %#v %v", ingested, err)
	}
	verified, err := runAppMCPFileTool(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "verify_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1", "processing_id": ingested.ProcessingID, "sheet": "csv", "ref": "B2", "expected": "42"})
	if err != nil || verified.Data.(map[string]any)["valid"] != true {
		t.Fatalf("verify on an app without groups: %#v %v", verified, err)
	}
	if _, err := appMCPReadFileSnapshot(context.Background(), app, ingested.ProcessingID, uid, createdAt, "17", "notes", "1", "uploads/private/source.csv"); err == nil {
		t.Fatal("an empty-tenant snapshot was readable under another tenant")
	}
	app.Group = groups
	if app.Group == nil || app.Group.Table == "" {
		t.Fatal("fixture app has no groups to restore")
	}
	data := []byte("name,value\nAda,42\n")
	result, err := IngestCSV(bytes.NewReader(data), DefaultIngestLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "0"} {
		scope := appMCPFileSnapshotScope{OwnerCreatedAt: createdAt, Tenant: tenant, Table: "notes", RecordID: "1", FileRef: "uploads/private/source.csv"}
		if _, err := appMCPRecordFileProcessing(app, uid, scope.FileRef, result.SHA256, "private_upload", result.SHA256, "text/csv", DefaultIngestLimits(), true, nil, appMCPFileSnapshotInput{Scope: scope, Original: data, Result: result}); err == nil {
			t.Fatalf("a group app stored a snapshot for tenant %q", tenant)
		}
	}
}
