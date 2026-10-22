//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const appMCPFileProcessingsTable = "_benmore_mcp_file_processings"
const appMCPFileDefaultPageSize = 50
const appMCPFileMaxPageSize = 100
const appMCPFileSnapshotVersion = 1
const appMCPFileSnapshotMaxBytes = 128 << 20
const appMCPFileSnapshotBudgetBytes = 1 << 30

// appMCPFileWorkSlot admits one private file ingest or verify at a time per
// process. A single call can hold the source bytes, its blocks, a snapshot
// encoding of up to 128 MiB plus SQLite's copy of it, or a PDF child at its
// 512 MiB address-space cap; a hosted app unit has 768 MiB in total and an
// OOM kill there stops the whole unit, so concurrent calls wait their turn
// (until their request ends) instead of multiplying that peak.
var appMCPFileWorkSlot = make(chan struct{}, 1)

func appMCPAcquireFileWork(ctx context.Context) (func(), bool) {
	select {
	case appMCPFileWorkSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, false
	}
	release := func() { <-appMCPFileWorkSlot }
	if ctx.Err() != nil {
		release()
		return nil, false
	}
	return release, true
}

const appMCPFileProcessingDDL = `CREATE TABLE IF NOT EXISTS _benmore_mcp_file_processings (
	id TEXT PRIMARY KEY,
	file_id TEXT NOT NULL,
	file_sha256 TEXT NOT NULL DEFAULT '',
	origin TEXT NOT NULL,
	origin_version TEXT NOT NULL DEFAULT '',
	content_type TEXT NOT NULL DEFAULT '',
	parser_version TEXT NOT NULL,
	limits_json TEXT NOT NULL,
	complete INTEGER NOT NULL CHECK (complete IN (0,1)),
	quality_flags TEXT NOT NULL,
	created_by INTEGER NOT NULL REFERENCES _benmore_users(id),
	created_at TEXT NOT NULL,
	source_connection TEXT NOT NULL DEFAULT '',
	source_file_id TEXT NOT NULL DEFAULT '',
	source_revision TEXT NOT NULL DEFAULT '',
	owner_created_at TEXT NOT NULL DEFAULT '',
	tenant TEXT NOT NULL DEFAULT '',
	source_table TEXT NOT NULL DEFAULT '',
	record_id TEXT NOT NULL DEFAULT '',
	file_ref TEXT NOT NULL DEFAULT '',
	upload_tenant TEXT NOT NULL DEFAULT '',
	snapshot_version INTEGER NOT NULL DEFAULT 0,
	snapshot_sha256 TEXT NOT NULL DEFAULT '',
	snapshot_size INTEGER NOT NULL DEFAULT 0,
	snapshot_data BLOB NOT NULL DEFAULT X''
)`

func ensureAppMCPFileProcessingTable(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("file processing database unavailable")
	}
	return ensureAppMCPFileProcessingSchema(db)
}

type appMCPFileProcessingSchemaDB interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func ensureAppMCPFileProcessingSchema(db appMCPFileProcessingSchemaDB) error {
	if db == nil {
		return fmt.Errorf("file processing database unavailable")
	}
	if _, err := db.Exec(appMCPFileProcessingDDL); err != nil {
		return err
	}
	columns := map[string]bool{}
	rows, err := db.Query("PRAGMA main.table_info(" + appMCPFileProcessingsTable + ")")
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, primary int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for name, declaration := range map[string]string{
		"source_connection": "TEXT NOT NULL DEFAULT ''", "source_file_id": "TEXT NOT NULL DEFAULT ''", "source_revision": "TEXT NOT NULL DEFAULT ''",
		"owner_created_at": "TEXT NOT NULL DEFAULT ''", "tenant": "TEXT NOT NULL DEFAULT ''", "source_table": "TEXT NOT NULL DEFAULT ''",
		"record_id": "TEXT NOT NULL DEFAULT ''", "file_ref": "TEXT NOT NULL DEFAULT ''", "upload_tenant": "TEXT NOT NULL DEFAULT ''",
		"snapshot_version": "INTEGER NOT NULL DEFAULT 0", "snapshot_sha256": "TEXT NOT NULL DEFAULT ''", "snapshot_size": "INTEGER NOT NULL DEFAULT 0",
		"snapshot_data": "BLOB NOT NULL DEFAULT X''",
	} {
		if !columns[name] {
			if _, err := db.Exec("ALTER TABLE " + appMCPFileProcessingsTable + " ADD COLUMN " + name + " " + declaration); err != nil {
				return err
			}
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER IF NOT EXISTS _benmore_mcp_file_processings_immutable BEFORE UPDATE ON _benmore_mcp_file_processings BEGIN SELECT RAISE(ABORT, 'MCP file processing records are immutable'); END`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS _benmore_mcp_file_processings_owner ON _benmore_mcp_file_processings(created_by,owner_created_at,tenant,source_table,record_id,file_ref,file_sha256,parser_version)`); err != nil {
		return err
	}
	var hasLegacyIdentityIndex int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_master WHERE type='index' AND name='_benmore_mcp_file_processings_snapshot_identity'`).Scan(&hasLegacyIdentityIndex); err != nil {
		return err
	}
	if hasLegacyIdentityIndex != 0 {
		if _, err := db.Exec(`DROP INDEX _benmore_mcp_file_processings_snapshot_identity`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS _benmore_mcp_file_processings_snapshot_identity_v2 ON _benmore_mcp_file_processings(created_by,owner_created_at,tenant,source_table,record_id,file_ref,upload_tenant,file_sha256,parser_version,limits_json) WHERE snapshot_version=1`); err != nil {
		return err
	}
	return nil
}

func appMCPRegisterFileTools(server *sdk.Server, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, raw, resource string) {
	if server == nil || app == nil || generation == nil || generation.manifest == nil || grant == nil || actor == nil {
		return
	}
	for _, declared := range generation.manifest.Tools {
		tool := declared
		if tool.Handler.Kind != "file" || (tool.Handler.Operation != "ingest" && tool.Handler.Operation != "verify" && tool.Handler.Operation != "status") || !appMCPToolAllowed(generation.view, &tool, actor) {
			continue
		}
		description := tool.Description
		if tool.Handler.Operation == "status" {
			description += " Returns bounded metadata for a known successful snapshot-backed processing result after current row, file, membership, and owner checks. It does not return parsed blocks or snapshot content; complete describes historical parser completion, not current file integrity."
		} else {
			description += " Supports private CSV, XLSX and XLSM uploads, plus PDF text/OCR when fixed Poppler, Tesseract, English trained data and enforced seccomp network isolation are available. OCR runs on pages with no native text blocks; mixed pages may omit raster-only text. PDFs are capped at 200 pages, 40 MP per rendered page, 60 seconds and 512 MiB per page, 512 MiB total temporary storage, and 10 minutes total. Results return bounded page blocks with page, bounding box, OCR confidence when applicable, and quality flags."
		}
		server.AddTool(&sdk.Tool{Name: tool.Name, Description: description, InputSchema: tool.InputSchema, OutputSchema: appMCPEnvelopeSchema(&tool), Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}}, func(ctx context.Context, request *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			input, ok := appMCPDecodeToolArguments(request.Params.Arguments)
			if !ok {
				return appMCPSDKFailure(appMCPResultFailure("invalid_input")), nil
			}
			result, err := runAppMCPFileTool(ctx, app, generation, raw, resource, tool.Name, input)
			if err != nil {
				return appMCPSDKFailure(err), nil
			}
			text, err := json.Marshal(result)
			if err != nil {
				return appMCPSDKFailure(appMCPResultFailure("incomplete_result")), nil
			}
			meta := sdk.Meta{"observed_at": result.ObservedAt}
			if result.ProcessingID != "" {
				meta["processing_id"] = result.ProcessingID
			}
			return &sdk.CallToolResult{Meta: meta, StructuredContent: result, Content: []sdk.Content{&sdk.TextContent{Text: string(text)}}}, nil
		})
	}
}

type appMCPFileSnapshotScope struct {
	OwnerCreatedAt        string
	Tenant                string
	Table                 string
	RecordID              string
	FileRef               string
	FileColumn            string
	UploadTenant          string
	MembershipConstraints map[string]any
}

// validateAppMCPFileMembershipConstraints accepts only a small, deterministic
// set of scalar equality predicates. The keys are resolved against the live
// configured membership table before use; values are always SQL parameters.
func validateAppMCPFileMembershipConstraints(constraints map[string]any) error {
	if len(constraints) > 8 {
		return errors.New("at most eight membership columns may be constrained")
	}
	for column, value := range constraints {
		if !membershipIdentRe.MatchString(column) || strings.HasSuffix(column, blindColSuffix) {
			return fmt.Errorf("%q is not a supported canonical membership column", column)
		}
		switch v := value.(type) {
		case string:
			if len(v) > 128 || strings.ContainsRune(v, 0) {
				return fmt.Errorf("%q must be a string of at most 128 bytes without NUL", column)
			}
		case bool:
		case int:
			if v < -1e15 || v > 1e15 {
				return fmt.Errorf("%q must be a bounded number", column)
			}
		case int64:
			if v < -1e15 || v > 1e15 {
				return fmt.Errorf("%q must be a bounded number", column)
			}
		case uint64:
			if v > 1e15 {
				return fmt.Errorf("%q must be a bounded number", column)
			}
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e15 {
				return fmt.Errorf("%q must be a finite bounded number", column)
			}
		default:
			return fmt.Errorf("%q must use a string, boolean, or number scalar", column)
		}
	}
	return nil
}

func appMCPFileStatusInputSchemaValid(schema *AppMCPSchema) bool {
	if schema == nil || schema.Type != "object" {
		return false
	}
	for _, name := range []string{"processing_id", "record_id", "file_ref"} {
		property := schema.Properties[name]
		if property == nil || property.Type != "string" || !slices.Contains(schema.Required, name) {
			return false
		}
	}
	return true
}

func appMCPFileMembershipConstraintsValid(q appMCPFileSnapshotQueryer, app *App, constraints map[string]any) bool {
	if len(constraints) == 0 {
		return true
	}
	if validateAppMCPFileMembershipConstraints(constraints) != nil || q == nil || app == nil || app.DB == nil || app.Group == nil || app.Group.Table == "" || app.Group.Key == "" || app.Group.UserField == "" || !membershipIdentRe.MatchString(app.Group.Table) || !membershipIdentRe.MatchString(app.Group.Key) || !membershipIdentRe.MatchString(app.Group.UserField) {
		return false
	}
	for column := range constraints {
		if apiHiddenColumn(app, app.Group.Table, column) || (app.Encrypted != nil && func() bool {
			for _, field := range app.Encrypted.Fields[app.Group.Table] {
				if field.Column == column {
					return true
				}
			}
			return false
		}()) || !appMCPHasDeclaredColumn(q, app.Group.Table, column) {
			return false
		}
	}
	return true
}

// appMCPFileMembershipAllowed requires exactly one live row for this actor and
// tenant before applying the reviewed equality constraints. This prevents a
// second, qualifying membership row from borrowing authority from the row that
// established the actor's tenant.
func appMCPFileMembershipAllowed(q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, app *App, actor *Session, tenant string, constraints map[string]any) bool {
	if len(constraints) == 0 {
		return true
	}
	if !appMCPFileMembershipConstraintsValid(q, app, constraints) || q == nil || actor == nil || tenant == "" || tenant == "0" {
		return false
	}
	group := app.Group
	member, ok := groupMemberValue(group, actor)
	if !ok {
		return false
	}
	keys := make([]string, 0, len(constraints))
	for key := range constraints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	from := "main." + quoteIdent(group.Table)
	identity := quoteColumn(group.Table, group.Key) + "=? AND " + quoteColumn(group.Table, group.UserField) + "=?"
	live := membershipLiveConds(group, group.Table, "", func(col string) bool { return appMCPHasDeclaredColumn(q, group.Table, col) })
	match := "1"
	matchArgs := make([]any, 0, len(keys))
	for _, key := range keys {
		sqlType := "text"
		switch constraints[key].(type) {
		case bool, int, int64, uint64:
			sqlType = "integer"
		case float64:
			sqlType = "real"
		}
		column := quoteColumn(group.Table, key)
		match += " AND typeof(" + column + ")=? AND " + column + "=?"
		matchArgs = append(matchArgs, sqlType)
		matchArgs = append(matchArgs, constraints[key])
	}
	query := "SELECT COUNT(*), COALESCE(SUM(CASE WHEN " + match + " THEN 1 ELSE 0 END),0) FROM " + from + " WHERE " + identity + live
	args := append(append([]any{}, matchArgs...), tenant, member)
	var liveCount, matchingCount int
	if q.QueryRowContext(context.Background(), query, args...).Scan(&liveCount, &matchingCount) != nil {
		return false
	}
	return liveCount == 1 && matchingCount == 1
}

type appMCPFileSnapshot struct {
	Version  int              `json:"version"`
	Original []byte           `json:"original"`
	Result   IngestResult     `json:"result"`
	PDF      *appMCPPDFResult `json:"pdf,omitempty"`
}

type appMCPFileSnapshotInput struct {
	Scope    appMCPFileSnapshotScope
	Original []byte
	Result   IngestResult
	PDF      *appMCPPDFResult
	Actor    *Session
}

type appMCPStoredFileSnapshot struct {
	ID             string
	OwnerID        int64
	OwnerCreatedAt string
	Tenant         string
	Table          string
	RecordID       string
	FileRef        string
	UploadTenant   string
	Digest         string
	SourceDigest   string
	Size           int64
	Snapshot       appMCPFileSnapshot
}

type appMCPFileSnapshotQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// appMCPFileRecordAuthorizedFrom repeats the established file-read gates using
// the publication transaction, so a long parse cannot publish after its row,
// scope, uploader ownership, or file reference has changed.
func appMCPFileRecordAuthorizedFrom(q appMCPFileSnapshotQueryer, app *App, actor *Session, table, id, logical string, fileColumns ...string) bool {
	return appMCPFileRecordAuthorizedWithUploadTenantFrom(q, app, actor, table, id, logical, "", "", fileColumns...)
}

func appMCPFileRecordAuthorizedWithUploadTenantFrom(q appMCPFileSnapshotQueryer, app *App, actor *Session, table, id, logical, uploadTenant, tenant string, fileColumns ...string) bool {
	column := ""
	if len(fileColumns) > 1 {
		return false
	}
	if len(fileColumns) == 1 {
		column = fileColumns[0]
	}
	if q == nil || app == nil || actor == nil || actor.UserID <= 0 || !safeIdent(table) || !appHasTable(app, table) || id == "" || id != strings.TrimSpace(id) || strings.ContainsAny(id, "/?#\\\x00") || !SessionCanAccessTable(app, table, OpRead, actor) || checkScope(actor, table, "read") != nil {
		return false
	}
	if column != "" && !appMCPFileColumnReadable(q, app, table, column) {
		return false
	}
	predicate, args, bypass := rowScopeClause(app, table, actor, "view")
	query := "SELECT * FROM main." + quoteIdent(table) + " WHERE id=?"
	queryArgs := []any{id}
	if hasColumn(app, table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}
	if !bypass && predicate != "" {
		query += " AND (" + predicate + ")"
		queryArgs = append(queryArgs, args...)
	}
	rows, err := q.QueryContext(context.Background(), query, queryArgs...)
	if err != nil {
		return false
	}
	if !rows.Next() {
		_ = rows.Close()
		return false
	}
	columnNames, err := rows.Columns()
	if err != nil {
		_ = rows.Close()
		return false
	}
	values := make([]any, len(columnNames))
	if len(values) == 0 {
		_ = rows.Close()
		return false
	}
	ptrs := make([]any, len(values))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if rows.Scan(ptrs...) != nil {
		_ = rows.Close()
		return false
	}
	if rows.Next() {
		_ = rows.Close()
		return false
	}
	if rows.Close() != nil {
		return false
	}
	want := uploadRelPath(logical)
	referenced := false
	for i, value := range values {
		if column != "" && columnNames[i] != column {
			continue
		}
		if text, ok := value.(string); ok && text != "" {
			if uploadRelPath(text) == want {
				referenced = true
				break
			}
			if cfg := getPlatformMedia(); cfg != nil {
				wantURL, _, wantOK := cdnURLForServe(app, logical, cfg)
				gotURL, _, gotOK := cdnURLForServe(app, text, cfg)
				if wantOK && gotOK && wantURL == gotURL {
					referenced = true
					break
				}
			}
		}
	}
	if !referenced {
		return false
	}
	if uploadTenant != "" && !appMCPFileUploadTenantMatches(q, app, table, id, logical, uploadTenant, tenant) {
		return false
	}
	var uploader int64
	var group string
	var admin int
	err = q.QueryRowContext(context.Background(), `SELECT user_id,group_id,uploader_admin FROM _benmore_upload_owners WHERE path=?`, privateUploadKey(app, logical)).Scan(&uploader, &group, &admin)
	if errors.Is(err, sql.ErrNoRows) || (err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")) {
		return true
	}
	if err != nil {
		return false
	}
	if admin == 1 || (uploader != 0 && actor.UserID == uploader) {
		return true
	}
	if uploader != 0 && appMCPHasDeclaredColumn(q, table, "user_id") {
		var owner int64
		if q.QueryRowContext(context.Background(), "SELECT user_id FROM "+quoteIdent(table)+" WHERE id=?", id).Scan(&owner) == nil && owner == uploader {
			return true
		}
	}
	if group != "" && app.Group != nil && app.Group.Key != "" && appMCPHasDeclaredColumn(q, table, app.Group.Key) {
		var rowGroup string
		if q.QueryRowContext(context.Background(), "SELECT "+quoteColumn(table, app.Group.Key)+" FROM "+quoteIdent(table)+" WHERE id=?", id).Scan(&rowGroup) == nil && rowGroup == group {
			return true
		}
	}
	return false
}

// appMCPFileUploadTenantMatches is an opt-in strengthening for apps whose
// authorization policy allows admins to attach files across workspace rows.
// It deliberately runs before legacy admin/uploader/row-owner vouching.
func appMCPFileUploadTenantMatches(q appMCPFileSnapshotQueryer, app *App, table, id, logical, policy, tenant string) bool {
	if policy != "current" || tenant == "" || tenant == "0" || q == nil || app == nil || app.Group == nil {
		return false
	}
	group := app.Group
	if !safeIdent(group.Table) || !safeIdent(group.Key) || !safeIdent(group.UserField) || !appMCPHasDeclaredColumn(q, group.Table, group.Key) || !appMCPHasDeclaredColumn(q, group.Table, group.UserField) || !appMCPHasDeclaredColumn(q, table, group.Key) {
		return false
	}
	var rowTenant sql.NullString
	if err := q.QueryRowContext(context.Background(), "SELECT CAST("+quoteColumn(table, group.Key)+" AS TEXT) FROM main."+quoteIdent(table)+" WHERE id=?", id).Scan(&rowTenant); err != nil || !rowTenant.Valid || rowTenant.String == "" || rowTenant.String != tenant {
		return false
	}
	var ownerTenant sql.NullString
	if err := q.QueryRowContext(context.Background(), `SELECT group_id FROM main._benmore_upload_owners WHERE path=?`, privateUploadKey(app, logical)).Scan(&ownerTenant); err != nil || !ownerTenant.Valid || ownerTenant.String == "" || ownerTenant.String != tenant {
		return false
	}
	return true
}

func validateAppMCPFileColumnBindings(manifest *AppMCPManifest, definitions []crudTableDefinition) error {
	if manifest == nil {
		return nil
	}
	for _, tool := range manifest.Tools {
		if tool.Handler.FileColumn == "" {
			continue
		}
		found := false
		for _, table := range definitions {
			if table.name == tool.Handler.Table && table.columns[tool.Handler.FileColumn] {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("mcp.yaml: tool %q has unresolved file_column %q", tool.Name, tool.Handler.FileColumn)
		}
	}
	return nil
}

func validateAppMCPFileUploadTenantBindings(manifest *AppMCPManifest, group *GroupConfig, definitions []crudTableDefinition) error {
	if manifest == nil {
		return nil
	}
	for _, tool := range manifest.Tools {
		if tool.Handler.UploadTenant == nil {
			continue
		}
		if *tool.Handler.UploadTenant != "current" || tool.Handler.Kind != "file" || tool.Handler.FileColumn == "" || group == nil || !safeIdent(group.Table) || !safeIdent(group.Key) || !safeIdent(group.UserField) {
			return fmt.Errorf("mcp.yaml: tool %q upload_tenant requires current, a file_column, and configured groups.table/key/user_field", tool.Name)
		}
		var sourceTable, membershipTable *crudTableDefinition
		for i := range definitions {
			if definitions[i].name == tool.Handler.Table {
				sourceTable = &definitions[i]
			}
			if definitions[i].name == group.Table {
				membershipTable = &definitions[i]
			}
		}
		if sourceTable == nil || !sourceTable.columns[group.Key] || membershipTable == nil || !membershipTable.columns[group.Key] || !membershipTable.columns[group.UserField] {
			return fmt.Errorf("mcp.yaml: tool %q upload_tenant requires the configured tenant key on its source row and canonical groups table", tool.Name)
		}
	}
	return nil
}

func validateAppMCPFileMembershipConstraintBindings(dir string, manifest *AppMCPManifest, group *GroupConfig, definitions []crudTableDefinition) error {
	if manifest == nil {
		return nil
	}
	for _, tool := range manifest.Tools {
		constraints := tool.Handler.MembershipConstraints
		if len(constraints) == 0 {
			continue
		}
		if err := validateAppMCPFileMembershipConstraints(constraints); err != nil {
			return fmt.Errorf("mcp.yaml: tool %q membership_constraints: %w", tool.Name, err)
		}
		if tool.Handler.Kind != "file" || group == nil || !membershipIdentRe.MatchString(group.Table) || !membershipIdentRe.MatchString(group.Key) || !membershipIdentRe.MatchString(group.UserField) {
			return fmt.Errorf("mcp.yaml: tool %q membership_constraints require configured groups.table, groups.key, and groups.user_field", tool.Name)
		}
		var membershipTable *crudTableDefinition
		for i := range definitions {
			if definitions[i].name == group.Table {
				membershipTable = &definitions[i]
				break
			}
		}
		if membershipTable == nil || !membershipTable.columns[group.Key] || !membershipTable.columns[group.UserField] {
			return fmt.Errorf("mcp.yaml: tool %q membership_constraints must use the configured canonical groups table and key columns", tool.Name)
		}
		encrypted := LoadEncryptedFieldsConfig(dir).Fields[group.Table]
		for column := range constraints {
			if !membershipTable.columns[column] || apiHiddenColumn(nil, group.Table, column) {
				return fmt.Errorf("mcp.yaml: tool %q membership constraint %q is not a canonical readable groups column", tool.Name, column)
			}
			if strings.HasSuffix(column, blindColSuffix) {
				return fmt.Errorf("mcp.yaml: tool %q membership constraint %q cannot use a blind index", tool.Name, column)
			}
			for _, field := range encrypted {
				if field.Column == column {
					return fmt.Errorf("mcp.yaml: tool %q membership constraint %q cannot use an encrypted column", tool.Name, column)
				}
			}
		}
	}
	return nil
}

func appMCPFileColumnReadable(q appMCPFileSnapshotQueryer, app *App, table, column string) bool {
	if q == nil || app == nil || !safeIdent(table) || !safeIdent(column) || apiHiddenColumn(app, table, column) {
		return false
	}
	if app.Encrypted != nil {
		for _, field := range app.Encrypted.Fields[table] {
			if field.Column == column {
				return false
			}
		}
	}
	rows, err := q.QueryContext(context.Background(), "PRAGMA main.table_info("+quoteIdent(table)+")")
	if err != nil {
		return false
	}
	defer rows.Close()
	columns := []Column{}
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var def any
		if rows.Scan(&cid, &name, &kind, &notNull, &def, &primary) != nil {
			return false
		}
		columns = append(columns, Column{Name: name, Type: kind})
	}
	if rows.Err() != nil || !listColumnAllowlist(app, table, columns)[column] {
		return false
	}
	for _, field := range columns {
		if field.Name == column {
			kind := strings.ToUpper(field.Type)
			return strings.Contains(kind, "TEXT") || strings.Contains(kind, "CHAR") || strings.Contains(kind, "CLOB")
		}
	}
	return false
}

func appMCPHasDeclaredColumn(q appMCPFileSnapshotQueryer, table, column string) bool {
	rows, err := q.QueryContext(context.Background(), "PRAGMA main.table_info("+quoteIdent(table)+")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var def any
		if rows.Scan(&cid, &name, &kind, &notNull, &def, &primary) == nil && name == column {
			return true
		}
	}
	return false
}

// JSON can expand every source byte to six bytes (for example a control
// character), so reject a conservative estimate before allocating the encoding.
func appMCPFileSnapshotEstimate(snapshot appMCPFileSnapshot) int64 {
	total := int64(len(snapshot.Original))
	add := func(s string) bool {
		if int64(len(s)) > appMCPFileSnapshotMaxBytes/6 {
			return false
		}
		total += int64(len(s))*6 + 16
		return total <= appMCPFileSnapshotMaxBytes
	}
	if !add(snapshot.Result.Format) || !add(snapshot.Result.ParserVersion) || !add(snapshot.Result.SHA256) {
		return appMCPFileSnapshotMaxBytes + 1
	}
	for _, sheet := range snapshot.Result.Sheets {
		if !add(sheet.Name) || !add(sheet.State) {
			return appMCPFileSnapshotMaxBytes + 1
		}
	}
	for _, b := range snapshot.Result.Blocks {
		if !add(b.Kind) || !add(b.Sheet) || !add(b.Ref) || !add(b.Value) || !add(b.Type) || !add(b.NumFmt) {
			return appMCPFileSnapshotMaxBytes + 1
		}
		for _, q := range b.Quality {
			if !add(q) {
				return appMCPFileSnapshotMaxBytes + 1
			}
		}
	}
	for _, s := range append(append([]string{}, snapshot.Result.Quality...), snapshot.Result.Warnings...) {
		if !add(s) {
			return appMCPFileSnapshotMaxBytes + 1
		}
	}
	if snapshot.PDF != nil {
		if !add(snapshot.PDF.ParserVersion) || !add(snapshot.PDF.SHA256) {
			return appMCPFileSnapshotMaxBytes + 1
		}
		for _, q := range snapshot.PDF.Quality {
			if !add(q) {
				return appMCPFileSnapshotMaxBytes + 1
			}
		}
		for _, b := range snapshot.PDF.Blocks {
			if !add(b.Ref) || !add(b.BBoxUnit) || !add(b.Value) {
				return appMCPFileSnapshotMaxBytes + 1
			}
			for _, q := range b.Quality {
				if !add(q) {
					return appMCPFileSnapshotMaxBytes + 1
				}
			}
		}
	}
	return total
}

func runAppMCPFileTool(ctx context.Context, origin *App, generation *appMCPRuntimeGeneration, raw, resource, name string, input map[string]any) (*appMCPReadResult, error) {
	if ctx == nil || ctx.Err() != nil || generation == nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	grant, actor, err := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	if err != nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	app := generation.view
	tool := appMCPFileTool(generation.manifest, name)
	uploadTenant := appMCPHandlerUploadTenant(tool.Handler)
	if !appMCPToolAllowed(app, tool, actor) {
		return nil, appMCPResultFailure("denied")
	}
	if !appMCPFileMembershipConstraintsValid(app.DB, app, tool.Handler.MembershipConstraints) || !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
		return nil, appMCPResultFailure("denied")
	}
	if validateAppMCPSchemaValue(tool.InputSchema, input) != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	fileRef, _ := input["file_ref"].(string)
	encodedInput, marshalErr := json.Marshal(input)
	if marshalErr != nil || len(encodedInput) > appMCPInputLimit || len(fileRef) > 4096 {
		return nil, appMCPResultFailure("invalid_input")
	}
	logical, err := privateLogicalUploadPath(fileRef)
	if err != nil {
		return nil, appMCPResultFailure("invalid_input")
	}
	recordID, _ := input["record_id"].(string)
	if len(recordID) > 256 {
		return nil, appMCPResultFailure("invalid_input")
	}
	if tool.Handler.Operation == "status" {
		processingID, _ := input["processing_id"].(string)
		if !appMCPFileProcessingID(processingID) || recordID == "" || len(fileRef) == 0 {
			return nil, appMCPResultFailure("invalid_input")
		}
		if !appMCPAuthorizeFileRecordForTool(app, actor, tool.Handler.Table, recordID, logical, tool.Handler, grant.Tenant) || !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
			return nil, appMCPResultFailure("denied")
		}
		row, statusErr := appMCPReadFileProcessingStatus(ctx, app, processingID, actor.UserID, grant.UserCreated, grant.Tenant, tool.Handler.Table, recordID, logical, uploadTenant)
		if statusErr != nil {
			return nil, appMCPResultFailure("denied")
		}
		projected, projectErr := appMCPProjectRow(tool, row)
		currentGrant, currentActor, authErr := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
		if projectErr != nil || len(projected) == 0 || authErr != nil || currentGrant.ID != grant.ID || !appMCPAuthorityUnchanged(actor, currentActor) || !appMCPToolAllowed(app, tool, currentActor) || !appMCPAuthorizeFileRecordForTool(app, currentActor, tool.Handler.Table, recordID, logical, tool.Handler, currentGrant.Tenant) || !appMCPFileMembershipAllowed(app.DB, app, currentActor, currentGrant.Tenant, tool.Handler.MembershipConstraints) {
			return nil, appMCPResultFailure("denied")
		}
		response := &appMCPReadResult{Data: projected, ProcessingID: processingID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRevisions: map[string]string{"contract": generation.manifest.ContractDigest, "execution": generation.manifest.ExecutionDigest}, Completeness: appMCPCompleteness{State: "complete", Basis: "authorized_row"}, Freshness: "observed", Warnings: []string{}}
		encoded, encodeErr := json.Marshal(response)
		if encodeErr != nil || len(encoded) > appMCPResultLimit {
			return nil, appMCPResultFailure("incomplete_result")
		}
		return response, nil
	}
	page, perPage := 1, appMCPFileDefaultPageSize
	if tool.Handler.Operation == "ingest" {
		if rawPage, ok := input["page"]; ok {
			var valid bool
			page, valid = appMCPNativePositiveInt(rawPage, int(^uint(0)>>1))
			if !valid {
				return nil, appMCPResultFailure("invalid_input")
			}
		}
		if rawSize, ok := input["per_page"]; ok {
			var valid bool
			perPage, valid = appMCPNativePositiveInt(rawSize, appMCPFileMaxPageSize)
			if !valid {
				return nil, appMCPResultFailure("invalid_input")
			}
		}
		if _, _, ok := appMCPFilePageRange(0, page, perPage); !ok {
			return nil, appMCPResultFailure("invalid_input")
		}
	}
	if ctx.Err() != nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	releaseWork, admitted := appMCPAcquireFileWork(ctx)
	if !admitted {
		return nil, appMCPResultFailure("denied")
	}
	defer releaseWork()
	if !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	limits := DefaultIngestLimits()
	var processingID string
	var pdfResult *appMCPPDFResult
	var result IngestResult
	if tool.Handler.Operation == "verify" {
		processingID, _ = input["processing_id"].(string)
		if !appMCPAuthorizeFileRecordForTool(app, actor, tool.Handler.Table, recordID, logical, tool.Handler, grant.Tenant) || !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
			return nil, appMCPResultFailure("denied")
		}
		stored, readErr := appMCPReadFileSnapshot(ctx, app, processingID, actor.UserID, grant.UserCreated, grant.Tenant, tool.Handler.Table, recordID, logical, uploadTenant)
		if readErr != nil {
			return nil, appMCPResultFailure("denied")
		}
		result = stored.Snapshot.Result
		pdfResult = stored.Snapshot.PDF
	} else {
		if !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
			return nil, appMCPResultFailure("denied")
		}
		data, contentType, err := appMCPReadAuthorizedPrivateUploadForTool(ctx, app, actor, tool.Handler.Table, recordID, logical, limits.MaxFileBytes, tool.Handler, grant.Tenant)
		if err != nil {
			var failure *appMCPResultError
			if errors.As(err, &failure) && failure.Code == "denied" {
				return nil, failure
			}
			if errors.Is(err, ErrIngestTooLarge) {
				_, _ = appMCPRecordFileProcessing(app, actor.UserID, logical, "", "private_upload", "", mime.TypeByExtension(filepath.Ext(logical)), limits, false, []string{"limit_exceeded"})
				return nil, appMCPResultFailure("incomplete_result")
			}
			return nil, appMCPResultFailure("incomplete_result")
		}
		scope := appMCPFileSnapshotScope{OwnerCreatedAt: grant.UserCreated, Tenant: grant.Tenant, Table: tool.Handler.Table, RecordID: recordID, FileRef: logical, FileColumn: tool.Handler.FileColumn, UploadTenant: uploadTenant, MembershipConstraints: tool.Handler.MembershipConstraints}
		if !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
			return nil, appMCPResultFailure("denied")
		}
		if reusedID, reused, ok := appMCPFindReusableFileProcessing(ctx, app, actor.UserID, scope, data, limits); ok {
			processingID = reusedID
			result, pdfResult = reused.Snapshot.Result, reused.Snapshot.PDF
		} else {
			var parseErr error
			if errorsIsPDF(logical, data) {
				detectedType := strings.ToLower(http.DetectContentType(data[:min(len(data), 512)]))
				parsedType, _, _ := mime.ParseMediaType(contentType)
				if detectedType != "application/pdf" || strings.ToLower(parsedType) != "application/pdf" {
					return nil, appMCPResultFailure("incomplete_result")
				}
				if !pdfExtractionAvailable(app.Dir) {
					sum := sha256.Sum256(data)
					quality := []string{"provider_unavailable"}
					if _, err := appMCPRecordFileProcessing(app, actor.UserID, logical, hex.EncodeToString(sum[:]), "private_upload", hex.EncodeToString(sum[:]), contentType, limits, false, quality); err != nil {
						return nil, appMCPResultFailure("incomplete_result")
					}
					return nil, &appMCPResultError{Code: "unavailable_provider", Message: "pdf extraction tools or English language data are unavailable"}
				}
				parsed, err := appMCPPDFExtract(ctx, app.Dir, data)
				parseErr = err
				pdfResult = &parsed
				result = IngestResult{Format: "pdf", Complete: parsed.Complete, ParserVersion: parsed.ParserVersion, SHA256: parsed.SHA256, Quality: parsed.Quality}
				for i, block := range parsed.Blocks {
					result.Blocks = append(result.Blocks, SourceBlock{Kind: "pdf", Sheet: "pdf", Ref: block.Ref, Row: block.Page, Col: i + 1, Value: block.Value, Type: "text", Quality: append([]string(nil), block.Quality...)})
				}
				result.Sheets = []SheetInfo{{Name: "pdf", Cells: len(result.Blocks), MaxRow: len(parsed.Blocks)}}
			} else {
				result, parseErr = appMCPParsePrivateUpload(logical, contentType, data, limits)
			}
			quality := append([]string(nil), result.Quality...)
			if parseErr != nil {
				if errors.Is(parseErr, ErrIngestEncrypted) {
					quality = append(quality, "encrypted_pdf")
				}
				if processingID, err = appMCPRecordFileProcessing(app, actor.UserID, logical, result.SHA256, "private_upload", result.SHA256, contentType, limits, false, quality); err != nil {
					return nil, appMCPResultFailure("incomplete_result")
				}
				if errors.Is(parseErr, errAppMCPPDFUnavailable) {
					return nil, &appMCPResultError{Code: "unavailable_provider", Message: "pdf extraction tools or English language data are unavailable"}
				}
				return nil, appMCPResultFailure("incomplete_result")
			}
			if !appMCPAuthorizeFileRecordForTool(app, actor, tool.Handler.Table, recordID, logical, tool.Handler, grant.Tenant) || !appMCPFileMembershipAllowed(app.DB, app, actor, grant.Tenant, tool.Handler.MembershipConstraints) {
				return nil, appMCPResultFailure("denied")
			}
			if processingID, err = appMCPRecordFileProcessing(app, actor.UserID, logical, result.SHA256, "private_upload", result.SHA256, contentType, limits, true, quality, appMCPFileSnapshotInput{Scope: scope, Original: data, Result: result, PDF: pdfResult, Actor: actor}); err != nil {
				return nil, appMCPResultFailure("incomplete_result")
			}
		}
	}
	if ctx.Err() != nil || !appMCPGenerationCurrent(origin, generation) {
		return nil, appMCPResultFailure("denied")
	}
	start, end, ok := appMCPFilePageRange(len(result.Blocks), page, perPage)
	if !ok {
		return nil, appMCPResultFailure("invalid_input")
	}
	blocks := make([]any, 0)
	if tool.Handler.Operation == "ingest" {
		for _, block := range result.Blocks[start:end] {
			b, _ := json.Marshal(block)
			var value any
			if json.Unmarshal(b, &value) != nil {
				return nil, appMCPResultFailure("incomplete_result")
			}
			blocks = append(blocks, value)
		}
	}
	row := map[string]any{"format": result.Format, "sha256": result.SHA256, "parser_version": result.ParserVersion, "complete": result.Complete, "quality_flags": appMCPFileQualityFlags(result.Quality), "page": page, "per_page": perPage, "total_blocks": len(result.Blocks), "blocks": blocks}
	if pdfResult != nil && tool.Handler.Operation == "ingest" {
		blocks = make([]any, 0, end-start)
		for _, block := range pdfResult.Blocks[start:end] {
			encoded, _ := json.Marshal(block)
			var value any
			if json.Unmarshal(encoded, &value) != nil {
				return nil, appMCPResultFailure("incomplete_result")
			}
			blocks = append(blocks, value)
		}
		row["blocks"] = blocks
	}
	if tool.Handler.Operation == "verify" {
		sheet, _ := input["sheet"].(string)
		ref, _ := input["ref"].(string)
		expected, _ := input["expected"].(string)
		row["sheet"], row["ref"] = sheet, ref
		row["valid"] = VerifySpan(result, sheet, ref, expected)
	}
	projected, err := appMCPProjectRow(tool, row)
	if err != nil || len(projected) == 0 {
		return nil, appMCPResultFailure("incomplete_result")
	}
	currentGrant, currentActor, authErr := resolveAppMCPAccessForGeneration(ctx, origin, generation, raw, resource, time.Now())
	if authErr != nil || currentGrant.ID != grant.ID || !appMCPAuthorityUnchanged(actor, currentActor) || !appMCPToolAllowed(app, tool, currentActor) || !appMCPAuthorizeFileRecordForTool(app, currentActor, tool.Handler.Table, recordID, logical, tool.Handler, currentGrant.Tenant) || !appMCPFileMembershipAllowed(app.DB, app, currentActor, currentGrant.Tenant, tool.Handler.MembershipConstraints) {
		return nil, appMCPResultFailure("denied")
	}
	pageCount := (len(result.Blocks) + perPage - 1) / perPage
	response := &appMCPReadResult{Data: projected, ProcessingID: processingID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRevisions: map[string]string{"contract": generation.manifest.ContractDigest, "execution": generation.manifest.ExecutionDigest}, Completeness: appMCPCompleteness{State: "complete", Basis: "authorized_row"}, Pagination: &appMCPPagination{Page: page, PerPage: perPage, Total: len(result.Blocks), HasNext: page < pageCount}, Freshness: "observed", Warnings: []string{}}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr != nil || len(encoded) > appMCPResultLimit {
		return nil, appMCPResultFailure("incomplete_result")
	}
	return response, nil
}

func appMCPFileQualityFlags(flags []string) []any {
	values := make([]any, len(flags))
	for i, flag := range flags {
		values[i] = flag
	}
	return values
}

func appMCPFilePageRange(total, page, perPage int) (int, int, bool) {
	if total < 0 || page < 1 || perPage < 1 || perPage > appMCPFileMaxPageSize || page-1 > int(^uint(0)>>1)/perPage {
		return 0, 0, false
	}
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end < start || end > total {
		end = total
	}
	return start, end, true
}

func appMCPFileTool(manifest *AppMCPManifest, name string) *AppMCPTool {
	if manifest == nil {
		return nil
	}
	for i := range manifest.Tools {
		tool := &manifest.Tools[i]
		if tool.Name == name && tool.Handler.Kind == "file" && tool.Effect == "read" {
			return tool
		}
	}
	return nil
}

func appMCPHandlerUploadTenant(handler AppMCPHandler) string {
	if handler.UploadTenant == nil {
		return ""
	}
	return *handler.UploadTenant
}

func appMCPAuthorizeFileRecord(app *App, actor *Session, table, id, logical string, fileColumns ...string) bool {
	if len(fileColumns) > 1 {
		return false
	}
	if len(fileColumns) == 1 && fileColumns[0] != "" {
		return app != nil && app.DB != nil && appMCPFileRecordAuthorizedFrom(app.DB, app, actor, table, id, logical, fileColumns[0])
	}
	if app == nil || actor == nil || actor.UserID <= 0 || !safeIdent(table) || !appHasTable(app, table) || id == "" || id != strings.TrimSpace(id) || strings.ContainsAny(id, "/?#\\\x00") {
		return false
	}
	if !SessionCanAccessTable(app, table, OpRead, actor) || checkScope(actor, table, "read") != nil || !canAccessRow(app, table, id, actor) {
		return false
	}
	if !recordReferencesLocalFile(app, table, id, logical) {
		if cfg := getPlatformMedia(); cfg == nil || !recordReferencesFile(app, table, id, logical, cfg) {
			return false
		}
	}
	return privateUploadVouched(app, actor, table, id, privateUploadKey(app, logical))
}

func appMCPAuthorizeFileRecordForTool(app *App, actor *Session, table, id, logical string, handler AppMCPHandler, tenant string) bool {
	policy := ""
	if handler.UploadTenant != nil {
		policy = *handler.UploadTenant
	}
	if handler.FileColumn != "" {
		return app != nil && app.DB != nil && appMCPFileRecordAuthorizedWithUploadTenantFrom(app.DB, app, actor, table, id, logical, policy, tenant, handler.FileColumn)
	}
	if policy != "" {
		return false
	}
	return appMCPAuthorizeFileRecord(app, actor, table, id, logical)
}

func appMCPReadAuthorizedPrivateUpload(ctx context.Context, app *App, actor *Session, table, id, logical string, maxBytes int64, fileColumns ...string) ([]byte, string, error) {
	if !appMCPAuthorizeFileRecord(app, actor, table, id, logical, fileColumns...) {
		return nil, "", appMCPResultFailure("denied")
	}
	return appMCPReadPrivateUpload(ctx, app, logical, maxBytes)
}

func appMCPReadAuthorizedPrivateUploadForTool(ctx context.Context, app *App, actor *Session, table, id, logical string, maxBytes int64, handler AppMCPHandler, tenant string) ([]byte, string, error) {
	if !appMCPAuthorizeFileRecordForTool(app, actor, table, id, logical, handler, tenant) {
		return nil, "", appMCPResultFailure("denied")
	}
	return appMCPReadPrivateUpload(ctx, app, logical, maxBytes)
}

func appMCPReadPrivateUpload(ctx context.Context, app *App, logical string, maxBytes int64) ([]byte, string, error) {
	if ctx == nil || app == nil || maxBytes <= 0 {
		return nil, "", ErrIngestCorrupt
	}
	// Artifact bytes are reachable only through the artifact route's owner,
	// incarnation, tenant, role and scope checks, never through a row that
	// happens to name their storage path.
	if appMCPArtifactStorageReference(logical) {
		return nil, "", appMCPResultFailure("denied")
	}
	root := filepath.Join(app.Dir, "uploads")
	target := filepath.Join(app.Dir, filepath.FromSlash(logical))
	if f, ok := openServableFile(root, target); ok {
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
		if err != nil {
			return nil, "", err
		}
		if int64(len(data)) > maxBytes {
			return nil, "", ErrIngestTooLarge
		}
		return data, mime.TypeByExtension(filepath.Ext(logical)), nil
	}
	cfg := getPlatformMedia()
	if cfg == nil {
		return nil, "", os.ErrNotExist
	}
	unsigned, private, ok := cdnURLForServe(app, logical, cfg)
	if !ok || !private || isPrivateURL(unsigned) {
		return nil, "", os.ErrNotExist
	}
	signed, err := signPrivateMediaURL(app, cfg, unsigned, 2*time.Minute)
	if err != nil || isPrivateURL(signed) {
		return nil, "", fmt.Errorf("private file storage unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signed, nil)
	if err != nil {
		return nil, "", err
	}
	client := safeHTTPClientStrict(15 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("private file storage returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > maxBytes {
		return nil, "", ErrIngestTooLarge
	}
	return data, mime.TypeByExtension(filepath.Ext(logical)), nil
}

func appMCPParsePrivateUpload(logical, contentType string, data []byte, limits IngestLimits) (IngestResult, error) {
	ext := strings.ToLower(filepath.Ext(logical))
	contentType = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if ext == ".pdf" {
		result := failedIngest("pdf")
		if !errorsIsPDF(logical, data) || http.DetectContentType(data[:min(len(data), 512)]) != "application/pdf" {
			return result, ErrIngestUnsupported
		}
		sum := sha256.Sum256(data)
		result.SHA256 = hex.EncodeToString(sum[:])
		return result, ErrIngestUnsupported
	}
	switch ext {
	case ".csv":
		sniffed := http.DetectContentType(data[:min(len(data), 512)])
		if (contentType != "text/csv" && contentType != "application/vnd.ms-excel") || (!strings.HasPrefix(sniffed, "text/plain") && !strings.HasPrefix(sniffed, "text/csv")) || bytes.IndexByte(data, 0) >= 0 {
			return failedIngest(IngestFormatCSV), ErrIngestUnsupported
		}
		return IngestCSV(bytes.NewReader(data), limits)
	case ".xlsx", ".xlsm":
		if len(data) < 4 || !bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) || http.DetectContentType(data[:min(len(data), 512)]) != "application/zip" || (contentType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" && contentType != "application/vnd.ms-excel.sheet.macroenabled.12" && contentType != "application/zip") {
			return failedIngest(IngestFormatXLSX), ErrIngestUnsupported
		}
		result, err := IngestXLSX(bytes.NewReader(data), int64(len(data)), limits)
		if err == nil && ((ext == ".xlsm") != (result.Format == IngestFormatXLSM)) {
			return failedIngest(result.Format), ErrIngestUnsupported
		}
		return result, err
	default:
		result := failedIngest("")
		sum := sha256.Sum256(data)
		result.SHA256 = hex.EncodeToString(sum[:])
		return result, ErrIngestUnsupported
	}
}

func errorsIsPDF(logical string, data []byte) bool {
	return strings.EqualFold(filepath.Ext(logical), ".pdf") && bytes.HasPrefix(data, []byte("%PDF-"))
}

func appMCPRecordFileProcessing(app *App, userID int64, fileID, sha, origin, version, contentType string, limits IngestLimits, complete bool, quality []string, snapshots ...appMCPFileSnapshotInput) (string, error) {
	if len(snapshots) > 1 {
		return "", errors.New("multiple source snapshots supplied")
	}
	if app == nil || app.DB == nil {
		return "", errors.New("file processing database unavailable")
	}
	if err := ensureAppMCPFileProcessingTable(app.DB); err != nil {
		return "", err
	}
	parser, limitJSON, err := appMCPFileParserAndLimits(fileID, limits)
	if err != nil {
		return "", err
	}
	qualityJSON, err := json.Marshal(quality)
	if err != nil {
		return "", err
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(idBytes[:])
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	if len(snapshots) == 0 {
		_, err = app.DB.Exec(`INSERT INTO _benmore_mcp_file_processings (id,file_id,file_sha256,origin,origin_version,content_type,parser_version,limits_json,complete,quality_flags,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, id, fileID, sha, origin, version, contentType, parser, string(limitJSON), complete, string(qualityJSON), userID, createdAt)
		return id, err
	}
	if !complete || !snapshots[0].Result.Complete {
		return "", errors.New("incomplete file processing cannot have a source snapshot")
	}
	snapshotInput := snapshots[0]
	scope := snapshotInput.Scope
	// An app without groups has no workspace, so its grants carry an empty
	// tenant; the snapshot is still bound to it by equality on every read. An
	// app with groups never has an empty or "0" tenant (the grant authority
	// refuses one), so neither is stored for it.
	grouped := app.Group != nil && app.Group.Table != ""
	if (scope.FileColumn != "" && (!safeIdent(scope.FileColumn) || snapshotInput.Actor == nil)) || (scope.UploadTenant != "" && (scope.UploadTenant != "current" || scope.FileColumn == "" || !grouped || snapshotInput.Actor == nil)) || scope.OwnerCreatedAt == "" || (grouped && (scope.Tenant == "" || scope.Tenant == "0")) || len(scope.Tenant) > appMCPInputLimit || !safeIdent(scope.Table) || scope.RecordID == "" || scope.FileRef != fileID || len(snapshotInput.Original) == 0 || int64(len(snapshotInput.Original)) > limits.MaxFileBytes {
		return "", errors.New("source snapshot scope or size is invalid")
	}
	sourceHash := sha256.Sum256(snapshotInput.Original)
	sourceDigest := hex.EncodeToString(sourceHash[:])
	if !SecureCompare(sourceDigest, snapshotInput.Result.SHA256) || !SecureCompare(sourceDigest, sha) {
		return "", errors.New("source snapshot digest does not match processing result")
	}
	snapshot := appMCPFileSnapshot{Version: appMCPFileSnapshotVersion, Original: snapshotInput.Original, Result: snapshotInput.Result, PDF: snapshotInput.PDF}
	if appMCPFileSnapshotEstimate(snapshot) > appMCPFileSnapshotMaxBytes {
		return "", errors.New("source snapshot exceeds its bounded combined size")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) == 0 || len(encoded) > appMCPFileSnapshotMaxBytes {
		return "", errors.New("source snapshot exceeds its bounded combined size")
	}
	if err := appMCPCheckFileSnapshotDBCap(app, int64(len(encoded))+2048); err != nil {
		return "", err
	}
	snapshotHash := sha256.Sum256(encoded)
	snapshotDigest := hex.EncodeToString(snapshotHash[:])
	tx, err := app.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO _benmore_mcp_file_processings
(id,file_id,file_sha256,origin,origin_version,content_type,parser_version,limits_json,complete,quality_flags,created_by,created_at,owner_created_at,tenant,source_table,record_id,file_ref,upload_tenant,snapshot_version,snapshot_sha256,snapshot_size,snapshot_data)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, fileID, sha, origin, version, contentType, parser, string(limitJSON), complete, string(qualityJSON), userID, createdAt,
		scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant, appMCPFileSnapshotVersion, snapshotDigest, len(encoded), encoded)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			_ = tx.Rollback()
			var existingID string
			lookupErr := app.DB.QueryRow(`SELECT id FROM _benmore_mcp_file_processings WHERE created_by=? AND owner_created_at=? AND tenant=? AND source_table=? AND record_id=? AND file_ref=? AND upload_tenant=? AND file_sha256=? AND parser_version=? AND limits_json=? AND snapshot_version=?`, userID, scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant, sha, parser, string(limitJSON), appMCPFileSnapshotVersion).Scan(&existingID)
			if lookupErr != nil {
				return "", lookupErr
			}
			stored, readErr := appMCPReadFileSnapshot(context.Background(), app, existingID, userID, scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant)
			if readErr != nil || !bytes.Equal(stored.Snapshot.Original, snapshotInput.Original) {
				return "", errors.New("existing source snapshot failed immutable reuse validation")
			}
			return existingID, nil
		}
		return "", fmt.Errorf("record source snapshot: %w", err)
	}
	var currentOwnerCreatedAt string
	if err := tx.QueryRow(`SELECT created_at FROM _benmore_users WHERE id=?`, userID).Scan(&currentOwnerCreatedAt); err != nil || !sameAccountIncarnation(currentOwnerCreatedAt, scope.OwnerCreatedAt) {
		return "", errors.New("source snapshot owner account changed during processing")
	}
	if snapshotInput.Actor != nil && !appMCPFileRecordAuthorizedWithUploadTenantFrom(tx, app, snapshotInput.Actor, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant, scope.Tenant, scope.FileColumn) {
		return "", errors.New("source record authorization changed during processing")
	}
	if snapshotInput.Actor != nil && !appMCPFileMembershipAllowed(tx, app, snapshotInput.Actor, scope.Tenant, scope.MembershipConstraints) {
		return "", errors.New("source membership authorization changed during processing")
	}
	if err := appMCPCheckFileSnapshotBudget(tx, id, 0); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit source snapshot record: %w", err)
	}
	return id, nil
}

func appMCPCheckFileSnapshotBudget(q appMCPFileProcessingSchemaDB, _ string, additional int64) error {
	if q == nil || additional < 0 || additional > appMCPFileSnapshotMaxBytes {
		return errors.New("invalid source snapshot storage reservation")
	}
	var total int64
	if err := q.QueryRow(`SELECT COALESCE(SUM(snapshot_size),0) FROM _benmore_mcp_file_processings WHERE snapshot_version=?`, appMCPFileSnapshotVersion).Scan(&total); err != nil {
		return err
	}
	if total > appMCPFileSnapshotBudgetBytes || additional > appMCPFileSnapshotBudgetBytes-total {
		return errors.New("private source snapshot storage budget exceeded")
	}
	return nil
}

func appMCPFileParserAndLimits(fileID string, limits IngestLimits) (string, []byte, error) {
	var persistedLimits any = limits
	parser := IngestParserVersion
	if strings.EqualFold(filepath.Ext(fileID), ".pdf") {
		parser = appMCPPDFParserVersion
		persistedLimits = map[string]any{
			"ingest": limits,
			"pdf": map[string]any{
				"max_pages":                   appMCPPDFMaxPages,
				"max_decoded_pixels_per_page": appMCPPDFMaxPixelsPerPage,
				"page_timeout_seconds":        int(appMCPPDFPageTimeout.Seconds()),
				"page_memory_bytes":           appMCPPDFPageMemoryBytes,
				"max_temp_bytes":              appMCPPDFMaxTempBytes,
				"total_timeout_seconds":       int(appMCPPDFTotalTimeout.Seconds()),
				"max_extracted_bytes":         appMCPPDFMaxExtractedBytes,
			},
		}
	}
	encoded, err := json.Marshal(persistedLimits)
	return parser, encoded, err
}

func appMCPFindReusableFileProcessing(ctx context.Context, app *App, ownerID int64, scope appMCPFileSnapshotScope, original []byte, limits IngestLimits) (string, *appMCPStoredFileSnapshot, bool) {
	if app == nil || app.DB == nil || len(original) == 0 {
		return "", nil, false
	}
	if ensureAppMCPFileProcessingTable(app.DB) != nil {
		return "", nil, false
	}
	sum := sha256.Sum256(original)
	sourceDigest := hex.EncodeToString(sum[:])
	parser, limitJSON, err := appMCPFileParserAndLimits(scope.FileRef, limits)
	if err != nil {
		return "", nil, false
	}
	var id string
	err = app.DB.QueryRowContext(ctx, `SELECT id FROM _benmore_mcp_file_processings
WHERE created_by=? AND owner_created_at=? AND tenant=? AND source_table=? AND record_id=? AND file_ref=? AND upload_tenant=?
AND file_sha256=? AND parser_version=? AND limits_json=? AND complete=1 AND snapshot_version=?
ORDER BY created_at DESC,id DESC LIMIT 1`, ownerID, scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant, sourceDigest, parser, string(limitJSON), appMCPFileSnapshotVersion).Scan(&id)
	if err != nil {
		return "", nil, false
	}
	stored, err := appMCPReadFileSnapshot(ctx, app, id, ownerID, scope.OwnerCreatedAt, scope.Tenant, scope.Table, scope.RecordID, scope.FileRef, scope.UploadTenant)
	if err != nil || !bytes.Equal(stored.Snapshot.Original, original) || stored.Snapshot.Result.ParserVersion != parser {
		return "", nil, false
	}
	return id, stored, true
}

func appMCPReadFileSnapshot(ctx context.Context, app *App, id string, ownerID int64, ownerCreatedAt, tenant, table, recordID, fileRef string, uploadTenants ...string) (*appMCPStoredFileSnapshot, error) {
	if len(uploadTenants) > 1 {
		return nil, errors.New("source snapshot policy is invalid")
	}
	wantUploadTenant := ""
	if len(uploadTenants) == 1 {
		wantUploadTenant = uploadTenants[0]
	}
	if ctx == nil || ctx.Err() != nil || app == nil || app.DB == nil || len(id) != 32 {
		return nil, errors.New("source snapshot reference is invalid")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, errors.New("source snapshot reference is invalid")
	}
	stored := &appMCPStoredFileSnapshot{}
	var complete int
	var blobSize int64
	err := app.DB.QueryRowContext(ctx, `SELECT id,created_by,owner_created_at,tenant,source_table,record_id,file_ref,upload_tenant,snapshot_version,snapshot_sha256,snapshot_size,file_sha256,complete,length(snapshot_data)
	FROM _benmore_mcp_file_processings WHERE id=?`, id).Scan(&stored.ID, &stored.OwnerID, &stored.OwnerCreatedAt, &stored.Tenant, &stored.Table, &stored.RecordID, &stored.FileRef, &stored.UploadTenant, &stored.Snapshot.Version, &stored.Digest, &stored.Size, &stored.SourceDigest, &complete, &blobSize)
	if err != nil || complete != 1 || stored.OwnerID != ownerID || !sameAccountIncarnation(stored.OwnerCreatedAt, ownerCreatedAt) || stored.Tenant != tenant || stored.Table != table || stored.RecordID != recordID || stored.FileRef != fileRef || stored.UploadTenant != wantUploadTenant || stored.Snapshot.Version != appMCPFileSnapshotVersion || stored.Size <= 0 || stored.Size > appMCPFileSnapshotMaxBytes || !appMCPFileDigest(stored.Digest) {
		return nil, errors.New("source snapshot authority or metadata mismatch")
	}
	if blobSize != stored.Size {
		return nil, errors.New("source snapshot is missing or has an invalid size")
	}
	var data []byte
	// Bind the row's own owner_created_at: the caller's value was already
	// matched as a time by sameAccountIncarnation, but may be spelled in the
	// other format (RFC 3339 from the driver vs SQLite's datetime text).
	if err := app.DB.QueryRowContext(ctx, `SELECT snapshot_data FROM _benmore_mcp_file_processings WHERE id=? AND created_by=? AND owner_created_at=? AND tenant=? AND source_table=? AND record_id=? AND file_ref=? AND upload_tenant=? AND snapshot_version=? AND snapshot_sha256=? AND snapshot_size=? AND length(snapshot_data)=?`, id, ownerID, stored.OwnerCreatedAt, tenant, table, recordID, fileRef, wantUploadTenant, appMCPFileSnapshotVersion, stored.Digest, stored.Size, stored.Size).Scan(&data); err != nil {
		return nil, errors.New("source snapshot authority or metadata mismatch")
	}
	digest := sha256.Sum256(data)
	if !SecureCompare(hex.EncodeToString(digest[:]), stored.Digest) {
		return nil, errors.New("source snapshot digest mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored.Snapshot); err != nil || stored.Snapshot.Version != appMCPFileSnapshotVersion || len(stored.Snapshot.Original) == 0 || int64(len(stored.Snapshot.Original)) > DefaultIngestLimits().MaxFileBytes || !stored.Snapshot.Result.Complete {
		return nil, errors.New("source snapshot contents are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("source snapshot contents have trailing data")
	}
	originalHash := sha256.Sum256(stored.Snapshot.Original)
	if !SecureCompare(hex.EncodeToString(originalHash[:]), stored.Snapshot.Result.SHA256) || !SecureCompare(stored.SourceDigest, stored.Snapshot.Result.SHA256) || !appMCPFileDigest(stored.Snapshot.Result.SHA256) {
		return nil, errors.New("source snapshot original bytes do not match extracted result")
	}
	if stored.Snapshot.PDF != nil && (!stored.Snapshot.PDF.Complete || stored.Snapshot.PDF.SHA256 != stored.Snapshot.Result.SHA256 || len(stored.Snapshot.PDF.Blocks) > appMCPPDFMaxBlocks) {
		return nil, errors.New("source PDF snapshot is invalid")
	}
	return stored, nil
}

// appMCPReadFileProcessingStatus returns only bounded metadata from a
// successful, snapshot-backed processing row. The private snapshot payload is
// neither selected nor decoded, and historical completion is not a claim that
// the current file bytes still match.
func appMCPReadFileProcessingStatus(ctx context.Context, app *App, id string, ownerID int64, ownerCreatedAt, tenant, table, recordID, fileRef string, uploadTenants ...string) (map[string]any, error) {
	if len(uploadTenants) > 1 {
		return nil, errors.New("file processing status policy is invalid")
	}
	wantUploadTenant := ""
	if len(uploadTenants) == 1 {
		wantUploadTenant = uploadTenants[0]
	}
	if ctx == nil || ctx.Err() != nil || app == nil || app.DB == nil || !appMCPFileProcessingID(id) {
		return nil, errors.New("file processing status reference is invalid")
	}
	var storedID, storedOwnerCreatedAt, storedTenant, storedTable, storedRecordID, storedFileRef, storedUploadTenant string
	var digest, contentType, parser, limitsJSON, qualityJSON, createdAt, sourceConnection, sourceFileID, sourceRevision string
	var complete int
	err := app.DB.QueryRowContext(ctx, `SELECT id,owner_created_at,tenant,source_table,record_id,file_ref,upload_tenant,file_sha256,content_type,parser_version,limits_json,complete,quality_flags,created_at,source_connection,source_file_id,source_revision
FROM _benmore_mcp_file_processings
WHERE id=? AND created_by=? AND tenant=? AND source_table=? AND record_id=? AND file_ref=? AND upload_tenant=? AND complete=1 AND snapshot_version=? AND snapshot_size>0 AND snapshot_size<=? AND snapshot_data IS NOT NULL AND length(snapshot_data)=snapshot_size`,
		id, ownerID, tenant, table, recordID, fileRef, wantUploadTenant, appMCPFileSnapshotVersion, appMCPFileSnapshotMaxBytes).Scan(&storedID, &storedOwnerCreatedAt, &storedTenant, &storedTable, &storedRecordID, &storedFileRef, &storedUploadTenant, &digest, &contentType, &parser, &limitsJSON, &complete, &qualityJSON, &createdAt, &sourceConnection, &sourceFileID, &sourceRevision)
	if err != nil || storedID != id || complete != 1 || !sameAccountIncarnation(storedOwnerCreatedAt, ownerCreatedAt) || storedTenant != tenant || storedTable != table || storedRecordID != recordID || storedFileRef != fileRef || storedUploadTenant != wantUploadTenant || !appMCPFileDigest(digest) || len(contentType) > 256 || len(parser) > 128 || len(createdAt) > 64 || len(sourceConnection) > 128 || len(sourceFileID) > 512 || len(sourceRevision) > 512 || len(limitsJSON) > 2048 || len(qualityJSON) > 2048 {
		return nil, errors.New("file processing status authority or metadata mismatch")
	}
	limitsValue, err := appMCPDecodeFileProcessingLimits(parser, limitsJSON)
	if err != nil {
		return nil, err
	}
	var quality []string
	if err := json.Unmarshal([]byte(qualityJSON), &quality); err != nil || len(quality) > 32 {
		return nil, errors.New("file processing quality metadata is invalid")
	}
	for _, flag := range quality {
		if len(flag) > 128 || strings.ContainsRune(flag, 0) {
			return nil, errors.New("file processing quality metadata is invalid")
		}
	}
	return map[string]any{
		"processing_id": storedID, "record_id": storedRecordID, "file_ref": storedFileRef,
		"sha256": digest, "content_type": contentType, "parser_version": parser, "limits": limitsValue,
		"complete": true, "quality_flags": appMCPFileQualityFlags(quality), "created_at": createdAt,
		"source_connection": sourceConnection, "source_file_id": sourceFileID, "source_revision": sourceRevision,
	}, nil
}

func appMCPDecodeFileProcessingLimits(parser, encoded string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var limits IngestLimits
	if parser == IngestParserVersion {
		if err := decoder.Decode(&limits); err != nil {
			return nil, errors.New("file processing limits metadata is invalid")
		}
	} else if parser == appMCPPDFParserVersion {
		var persisted struct {
			Ingest IngestLimits `json:"ingest"`
			PDF    struct {
				MaxPages                int   `json:"max_pages"`
				MaxDecodedPixelsPerPage int   `json:"max_decoded_pixels_per_page"`
				PageTimeoutSeconds      int   `json:"page_timeout_seconds"`
				PageMemoryBytes         int64 `json:"page_memory_bytes"`
				MaxTempBytes            int64 `json:"max_temp_bytes"`
				TotalTimeoutSeconds     int   `json:"total_timeout_seconds"`
				MaxExtractedBytes       int64 `json:"max_extracted_bytes"`
			} `json:"pdf"`
		}
		if err := decoder.Decode(&persisted); err != nil || persisted.PDF.MaxPages != appMCPPDFMaxPages || persisted.PDF.MaxDecodedPixelsPerPage != appMCPPDFMaxPixelsPerPage || persisted.PDF.PageTimeoutSeconds != int(appMCPPDFPageTimeout.Seconds()) || persisted.PDF.PageMemoryBytes != appMCPPDFPageMemoryBytes || persisted.PDF.MaxTempBytes != appMCPPDFMaxTempBytes || persisted.PDF.TotalTimeoutSeconds != int(appMCPPDFTotalTimeout.Seconds()) || persisted.PDF.MaxExtractedBytes != appMCPPDFMaxExtractedBytes {
			return nil, errors.New("file processing PDF limits metadata is invalid")
		}
		limits = persisted.Ingest
	} else {
		return nil, errors.New("file processing parser version is unsupported")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("file processing limits metadata has trailing data")
	}
	defaults := DefaultIngestLimits()
	if limits.MaxFileBytes <= 0 || limits.MaxFileBytes > defaults.MaxFileBytes || limits.MaxCells <= 0 || limits.MaxCells > defaults.MaxCells || limits.MaxDecompressedBytes <= 0 || limits.MaxDecompressedBytes > defaults.MaxDecompressedBytes || limits.MaxEntryBytes <= 0 || limits.MaxEntryBytes > defaults.MaxEntryBytes || limits.MaxZipEntries <= 0 || limits.MaxZipEntries > defaults.MaxZipEntries || limits.MaxCompressionRatio <= 0 || limits.MaxCompressionRatio > defaults.MaxCompressionRatio || limits.MaxSharedStrings <= 0 || limits.MaxSharedStrings > defaults.MaxSharedStrings || limits.MaxSheets <= 0 || limits.MaxSheets > defaults.MaxSheets || limits.MaxXMLDepth <= 0 || limits.MaxXMLDepth > defaults.MaxXMLDepth || limits.MaxXMLTokens <= 0 || limits.MaxXMLTokens > defaults.MaxXMLTokens || limits.MaxCSVRows <= 0 || limits.MaxCSVRows > defaults.MaxCSVRows || limits.MaxFieldBytes <= 0 || limits.MaxFieldBytes > defaults.MaxFieldBytes || limits.MaxExtractedBytes <= 0 || limits.MaxExtractedBytes > defaults.MaxExtractedBytes {
		return nil, errors.New("file processing limits metadata is outside supported bounds")
	}
	limitsBytes, err := json.Marshal(limits)
	if err != nil {
		return nil, errors.New("file processing limits metadata is invalid")
	}
	limitsDecoder := json.NewDecoder(bytes.NewReader(limitsBytes))
	limitsDecoder.UseNumber()
	var limitsValue any
	if err := limitsDecoder.Decode(&limitsValue); err != nil {
		return nil, errors.New("file processing limits metadata is invalid")
	}
	return limitsValue, nil
}

func appMCPFileDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func appMCPFileProcessingID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
