//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	appMCPTelemetryRowLimit = 256
	appMCPTelemetryVersion  = 1
)

var appMCPTelemetryOutcomes = []string{"applied", "denied", "conflict", "unknown", "failed", "incomplete"}
var appMCPTelemetryEffects = []string{"pending", "delivered", "failed", "unknown", "blocked"}

func appMCPTelemetryColumns() []string {
	columns := []string{"calls", "workflow_completions"}
	columns = append(columns, appMCPTelemetryOutcomes...)
	columns = append(columns, "attempts", "retries")
	for _, effect := range appMCPTelemetryEffects {
		columns = append(columns, "effects_"+effect)
	}
	for _, bucket := range latencyBucketsSec {
		columns = append(columns, "latency_le_"+strings.ReplaceAll(formatFloat(bucket), ".", "_"))
	}
	columns = append(columns, "latency_inf")
	return columns
}

func ensureAppMCPTelemetryTable(db *sql.DB) error {
	if db == nil {
		return errors.New("telemetry database is unavailable")
	}
	columns := appMCPTelemetryColumns()
	definitions := make([]string, len(columns))
	for i, column := range columns {
		definitions[i] = column + " INTEGER NOT NULL DEFAULT 0"
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_mcp_telemetry (
		tool_name TEXT NOT NULL,
		contract_digest TEXT NOT NULL,
		execution_digest TEXT NOT NULL,
		schema_revision TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL DEFAULT 0,
		` + strings.Join(definitions, ",\n\t\t") + `,
		PRIMARY KEY (tool_name, contract_digest, execution_digest)
	)`)
	if err != nil {
		return err
	}
	for _, column := range []struct{ name, declaration string }{
		{"schema_revision", "TEXT NOT NULL DEFAULT ''"},
		{"workflow_completions", "INTEGER NOT NULL DEFAULT 0"},
	} {
		rows, err := db.Query("PRAGMA table_info(_benmore_mcp_telemetry)")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notNull, primary int
			var name, dataType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primary); err != nil {
				rows.Close()
				return err
			}
			found = found || name == column.name
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if !found {
			if _, err := db.Exec("ALTER TABLE _benmore_mcp_telemetry ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	return nil
}

// appMCPRecordTelemetry accepts only reviewed metadata and aggregate deltas.
// Request arguments, output values, grant/user identity and credentials are
// deliberately absent from this API.
func appMCPRecordTelemetry(app *App, tool, contract, execution, schemaRevision, outcome string, elapsed time.Duration) error {
	if app == nil || app.DB == nil || tool == "" {
		return nil
	}
	if !appMCPStringIn(appMCPTelemetryOutcomes, outcome) {
		outcome = "failed"
	}
	contract, execution = appMCPTelemetryDigestPrefix(contract), appMCPTelemetryDigestPrefix(execution)
	columns := appMCPTelemetryColumns()
	deltas := make(map[string]int64, len(columns))
	deltas["calls"], deltas[outcome] = 1, 1
	seconds := elapsed.Seconds()
	for _, bucket := range latencyBucketsSec {
		if seconds <= bucket {
			deltas["latency_le_"+strings.ReplaceAll(formatFloat(bucket), ".", "_")] = 1
		}
	}
	deltas["latency_inf"] = 1
	insertColumns := append([]string{"tool_name", "contract_digest", "execution_digest", "schema_revision", "updated_at"}, columns...)
	marks := make([]string, len(insertColumns))
	args := make([]any, 0, len(insertColumns))
	for i := range marks {
		marks[i] = "?"
	}
	args = append(args, tool, contract, execution, schemaRevision, time.Now().UTC().UnixNano())
	for _, column := range columns {
		args = append(args, deltas[column])
	}
	updates := make([]string, len(columns))
	for i, column := range columns {
		updates[i] = column + "=" + column + "+excluded." + column
	}
	updates = append(updates, "schema_revision=CASE WHEN excluded.schema_revision<>'' THEN excluded.schema_revision ELSE schema_revision END", "updated_at=excluded.updated_at")
	tx, err := app.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO _benmore_mcp_telemetry (`+strings.Join(insertColumns, ",")+
		`) VALUES (`+strings.Join(marks, ",")+
		`) ON CONFLICT(tool_name,contract_digest,execution_digest) DO UPDATE SET `+strings.Join(updates, ","), args...); err != nil {
		return err
	}
	if err := appMCPTrimTelemetry(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func appMCPTrimTelemetry(tx *sql.Tx) error {
	var rows int
	if err := tx.QueryRow("SELECT count(*) FROM _benmore_mcp_telemetry").Scan(&rows); err != nil {
		return err
	}
	if rows > appMCPTelemetryRowLimit {
		_, err := tx.Exec(`DELETE FROM _benmore_mcp_telemetry WHERE rowid IN (
			SELECT rowid FROM _benmore_mcp_telemetry ORDER BY updated_at DESC, rowid DESC LIMIT -1 OFFSET ?
		)`, appMCPTelemetryRowLimit)
		return err
	}
	return nil
}

func appMCPRecordAttemptTelemetry(app *App, tool, contract, execution, schemaRevision string, retry bool) {
	if app == nil || app.DB == nil || tool == "" {
		return
	}
	retries := 0
	if retry {
		retries = 1
	}
	tx, err := app.DB.Begin()
	if err != nil {
		log.Printf("MCP telemetry attempt update failed")
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO _benmore_mcp_telemetry (tool_name,contract_digest,execution_digest,schema_revision,updated_at,attempts,retries)
		VALUES (?,?,?,?,?,1,?) ON CONFLICT(tool_name,contract_digest,execution_digest) DO UPDATE SET
		attempts=attempts+1, retries=retries+excluded.retries,
		schema_revision=CASE WHEN excluded.schema_revision<>'' THEN excluded.schema_revision ELSE schema_revision END,updated_at=excluded.updated_at`,
		tool, appMCPTelemetryDigestPrefix(contract), appMCPTelemetryDigestPrefix(execution), schemaRevision, time.Now().UTC().UnixNano(), retries); err != nil {
		log.Printf("MCP telemetry attempt update failed")
		return
	}
	if err := appMCPTrimTelemetry(tx); err != nil || tx.Commit() != nil {
		log.Printf("MCP telemetry attempt update failed")
	}
}

func appMCPRecordEffectTelemetry(app *App, data map[string]any, status string, count int64) {
	if app == nil || app.DB == nil || count <= 0 || !appMCPStringIn(appMCPTelemetryEffects, status) {
		return
	}
	tool, contract, execution, ok := appMCPResolveEffectTelemetryTarget(app, data)
	if ok {
		generation := snapshotAppMCPGeneration(app)
		var revision string
		if generation != nil {
			revision = appMCPTelemetrySchemaRevision(generation.manifest, execution)
		}
		appMCPRecordEffectDelta(app, tool, contract, execution, revision, status, count)
	}
}

func appMCPRecordEffectAttempt(app *App, data map[string]any, retry bool) {
	tool, contract, execution, ok := appMCPResolveEffectTelemetryTarget(app, data)
	if ok {
		generation := snapshotAppMCPGeneration(app)
		var revision string
		if generation != nil {
			revision = appMCPTelemetrySchemaRevision(generation.manifest, execution)
		}
		appMCPRecordAttemptTelemetry(app, tool, contract, execution, revision, retry)
	}
}

func appMCPResolveEffectTelemetryTarget(app *App, data map[string]any) (string, string, string, bool) {
	if app == nil || app.DB == nil {
		return "", "", "", false
	}
	raw, ok := data[appMCPEffectKey]
	if !ok {
		return "", "", "", false
	}
	encoded, err := json.Marshal(raw)
	var stamp appMCPEffectGrant
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&stamp) != nil || !appMCPOperationHex(stamp.OperationID, 32) {
		return "", "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOnlyQueryTimeout)
	defer cancel()
	tx, err := app.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", false
	}
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	var prepared *appMCPStoredOperation
	if err == nil {
		prepared, err = appMCPReadOperationWithKey(ctx, tx, appID, key, stamp.OperationID)
	}
	_ = tx.Rollback()
	if err != nil || prepared == nil {
		return "", "", "", false
	}
	return prepared.Prepared.Command, prepared.Prepared.ContractDigest, prepared.Prepared.ExecutionDigest, true
}

func appMCPJobEffectOutcome(err error) string {
	if err == nil {
		return "delivered"
	}
	var blocked jobNotRetryable
	if errors.As(err, &blocked) && strings.HasPrefix(err.Error(), appMCPEffectBlockedPrefix) {
		return "blocked"
	}
	if strings.HasPrefix(err.Error(), "unknown:") {
		return "unknown"
	}
	return "failed"
}

func appMCPRecordEffectDelta(app *App, tool, contract, execution, schemaRevision, status string, count int64) {
	if app == nil || app.DB == nil || tool == "" || count <= 0 || !appMCPStringIn(appMCPTelemetryEffects, status) {
		return
	}
	tx, err := app.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	query := `INSERT INTO _benmore_mcp_telemetry (tool_name,contract_digest,execution_digest,schema_revision,updated_at,effects_` + status + `)
		VALUES (?,?,?,?,?,?) ON CONFLICT(tool_name,contract_digest,execution_digest) DO UPDATE SET
		effects_` + status + `=effects_` + status + `+excluded.effects_` + status + `,
		schema_revision=CASE WHEN excluded.schema_revision<>'' THEN excluded.schema_revision ELSE schema_revision END,updated_at=excluded.updated_at`
	if _, err := tx.Exec(query, tool, appMCPTelemetryDigestPrefix(contract), appMCPTelemetryDigestPrefix(execution), schemaRevision, time.Now().UTC().UnixNano(), count); err != nil {
		return
	}
	if err := appMCPTrimTelemetry(tx); err != nil {
		return
	}
	_ = tx.Commit()
}

func appMCPRecordWorkflowCompletions(app *App, tool, contract, execution, schemaRevision string, count int64) {
	if app == nil || app.DB == nil || tool == "" || count <= 0 {
		return
	}
	tx, err := app.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO _benmore_mcp_telemetry
		(tool_name,contract_digest,execution_digest,schema_revision,updated_at,workflow_completions)
		VALUES(?,?,?,?,?,?) ON CONFLICT(tool_name,contract_digest,execution_digest) DO UPDATE SET
		workflow_completions=workflow_completions+excluded.workflow_completions,
		schema_revision=CASE WHEN excluded.schema_revision<>'' THEN excluded.schema_revision ELSE schema_revision END,updated_at=excluded.updated_at`,
		tool, appMCPTelemetryDigestPrefix(contract), appMCPTelemetryDigestPrefix(execution), schemaRevision, time.Now().UTC().UnixNano(), count)
	if err != nil || appMCPTrimTelemetry(tx) != nil {
		return
	}
	_ = tx.Commit()
}

// appMCPWorkflowCompletionCount checks the final workflow state inside the
// command transaction so later apply steps and hook SQL cannot skew the count.
func appMCPWorkflowCompletionCount(cap *appMCPCommandCapability) int64 {
	if cap == nil || cap.generation == nil || cap.generation.workflows == nil || len(cap.workflowTransitions) == 0 {
		return 0
	}
	var count int64
	err := cap.withNativeMetadata(appMCPCommandMetadataHookRead, func() error {
		for _, transition := range cap.workflowTransitions {
			workflow := cap.generation.workflows.Workflows[transition.Workflow]
			if workflow == nil || sqliteIdentifierFold(workflow.Table) != sqliteIdentifierFold(transition.Table) {
				continue
			}
			var final any
			err := cap.tx.QueryRowContext(cap.ctx, "SELECT "+quoteColumn(workflow.Table, workflow.Field)+" FROM main."+quoteIdent(workflow.Table)+" WHERE id=?", transition.RowID).Scan(&final)
			if err != nil || !appMCPWorkflowHasState(workflow, transition.From) || appMCPWorkflowTerminal(workflow, transition.From) || fmt.Sprint(final) == transition.From || !appMCPWorkflowTerminal(workflow, fmt.Sprint(final)) {
				continue
			}
			count++
		}
		return nil
	})
	if err != nil {
		return 0
	}
	return count
}

func appMCPWorkflowTerminal(workflow *Workflow, state string) bool {
	if workflow == nil || !appMCPWorkflowHasState(workflow, state) || len(workflow.Transitions[state]) != 0 {
		return false
	}
	_, hasTimeout := workflow.Timeouts[state]
	return !hasTimeout
}

func appMCPWorkflowHasState(workflow *Workflow, state string) bool {
	if workflow == nil || state == "" {
		return false
	}
	for _, declared := range workflow.States {
		if declared == state {
			return true
		}
	}
	return false
}

// appMCPTelemetrySchemaRevision identifies schema.prisma/schema.sql/schema.yaml
// and captured migration bytes without storing their contents. An old operation
// whose generation is no longer live has no recoverable schema revision here.
func appMCPTelemetrySchemaRevision(manifest *AppMCPManifest, execution string) string {
	if manifest == nil || execution == "" || manifest.ExecutionDigest != execution {
		return ""
	}
	files := make(map[string]string)
	for path, digest := range manifest.sourceHashes {
		if path == "schema.prisma" || path == "schema.sql" || path == "schema.yaml" || strings.HasPrefix(path, "migrations/") {
			files[path] = digest
		}
	}
	if len(files) == 0 {
		return ""
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	ordered := make([]SourceManifestFile, 0, len(paths))
	for _, path := range paths {
		ordered = append(ordered, SourceManifestFile{Path: path, SHA256: files[path]})
	}
	encoded, err := json.Marshal(ordered)
	if err != nil {
		return ""
	}
	return hashBytesSHA256(encoded)
}

func appMCPRecordQueuedEffects(app *App, tool, contract, execution, schemaRevision string, receipt map[string]any) {
	effects, ok := receipt["effects"].(map[string]any)
	if !ok {
		return
	}
	items, ok := effects["items"].([]any)
	if ok && len(items) > 0 {
		appMCPRecordEffectDelta(app, tool, contract, execution, schemaRevision, "pending", int64(len(items)))
	}
}

func appMCPRecordToolCall(app *App, call *sdk.CallToolParamsRaw, manifest *AppMCPManifest, started time.Time, result sdk.Result, err error, forced string) {
	if call == nil || call.Name == "" || manifest == nil {
		return
	}
	outcome := forced
	if outcome == "" {
		outcome = appMCPTelemetryOutcome(call.Name, result, err)
	}
	if err := appMCPRecordTelemetry(app, call.Name, manifest.ContractDigest, manifest.ExecutionDigest, appMCPTelemetrySchemaRevision(manifest, manifest.ExecutionDigest), outcome, time.Since(started)); err != nil {
		log.Printf("MCP telemetry write failed")
	}
}

func appMCPTelemetryKnownTool(manifest *AppMCPManifest, name string) bool {
	if name == appMCPCommitTool || name == appMCPStatusTool || name == mcpArtifactExportTool || name == mcpArtifactCreateTool {
		return true
	}
	if manifest == nil {
		return false
	}
	for i := range manifest.Tools {
		if manifest.Tools[i].Name == name {
			return true
		}
	}
	return false
}

func appMCPTelemetryDigestPrefix(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func appMCPTelemetryOutcome(tool string, result any, err error) string {
	if err != nil {
		return "failed"
	}
	call, ok := result.(*sdk.CallToolResult)
	if !ok || call == nil {
		return "applied"
	}
	if data, ok := call.StructuredContent.(map[string]any); ok {
		if tool == appMCPCommitTool {
			outcome, _ := data["outcome"].(string)
			switch outcome {
			case "applied", "already_applied":
				return "applied"
			case "conflict":
				return "conflict"
			case "unknown":
				return "unknown"
			case "incomplete":
				return "incomplete"
			}
		}
		if tool == appMCPStatusTool {
			state, _ := data["state"].(string)
			switch state {
			case "denied":
				return "denied"
			case "conflict":
				return "conflict"
			case "unknown":
				return "unknown"
			case "failed":
				return "failed"
			case "succeeded":
				return "applied"
			case "prepared", "approved", "running":
				return "incomplete"
			case "expired":
				return "failed"
			}
		}
		if completeness, ok := data["completeness"].(map[string]any); ok && completeness["state"] != "complete" {
			return "incomplete"
		}
	}
	if !call.IsError {
		return "applied"
	}
	code, _ := call.Meta["error_code"].(string)
	switch code {
	case "denied":
		return "denied"
	case "conflict":
		return "conflict"
	case "unknown_execution":
		return "unknown"
	case "incomplete_result":
		return "incomplete"
	default:
		return "failed"
	}
}

func appMCPStringIn(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func registerAppMCPTelemetryRoute(mux appRouteRegistrar, app *App) {
	if err := ensureAppMCPTelemetryTable(app.DB); err != nil {
		return
	}
	mux.HandleFunc("GET /api/_mcp/telemetry", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		columns := strings.Join(append([]string{"tool_name", "contract_digest", "execution_digest", "schema_revision"}, appMCPTelemetryColumns()...), ",")
		rows, err := queryMetadataRows(app.DB, "SELECT "+columns+" FROM _benmore_mcp_telemetry ORDER BY updated_at DESC, tool_name, contract_digest, execution_digest LIMIT ?", appMCPTelemetryRowLimit)
		if err != nil {
			serverErrorJSON(w, r, app, "_mcp telemetry", err, "telemetry unavailable")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"telemetry_version": appMCPTelemetryVersion, "rows": rows})
	})
}
