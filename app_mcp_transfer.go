//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	appMCPTransferContentLimit int64 = 25 << 20
	appMCPTransferWireLimit    int64 = 35 << 20
	appMCPTransferJobType            = "mcp_external_transfer"
	appMCPTransferPayloadKey         = "_mcp_transfer"
)

const appMCPTransferStateDDL = `CREATE TABLE IF NOT EXISTS main._benmore_mcp_transfer_state (
	job_id INTEGER PRIMARY KEY NOT NULL,
	operation_id TEXT NOT NULL,
	phase TEXT NOT NULL CHECK(phase IN ('queued','requesting','downloaded','attached','pushed','unknown')),
	recovery_ref TEXT NOT NULL DEFAULT '',
	upstream_id TEXT NOT NULL DEFAULT '',
	content_sha256 TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
)`

func appMCPEnsureTransferState(app *App) error {
	if app == nil || app.DB == nil {
		return errors.New("transfer state database is unavailable")
	}
	_, err := app.DB.Exec(appMCPTransferStateDDL)
	return err
}

func appMCPSetTransferState(app *App, job appMCPTransferJob, jobID int64, phase, recoveryRef, upstreamID, checksum string) error {
	if err := appMCPEnsureTransferState(app); err != nil {
		return err
	}
	_, err := app.DB.Exec(`INSERT INTO main._benmore_mcp_transfer_state(job_id,operation_id,phase,recovery_ref,upstream_id,content_sha256,updated_at)
	VALUES(?,?,?,?,?,?,datetime('now')) ON CONFLICT(job_id) DO UPDATE SET operation_id=excluded.operation_id,phase=excluded.phase,
	recovery_ref=excluded.recovery_ref,upstream_id=excluded.upstream_id,content_sha256=excluded.content_sha256,updated_at=datetime('now')
	WHERE main._benmore_mcp_transfer_state.phase<>'pushed'`,
		jobID, job.OperationID, phase, recoveryRef, upstreamID, checksum)
	return err
}

type appMCPTransferJob struct {
	Tool                string         `json:"tool"`
	Kind                string         `json:"kind"`
	Connection          string         `json:"connection"`
	OperationID         string         `json:"operation_id"`
	UpstreamOperationID string         `json:"upstream_operation_id"`
	ContractDigest      string         `json:"contract_digest"`
	ExecutionDigest     string         `json:"execution_digest"`
	Intent              map[string]any `json:"intent"`
	Preview             map[string]any `json:"preview"`
	ArtifactID          string         `json:"artifact_id,omitempty"`
	ArtifactSHA256      string         `json:"artifact_sha256,omitempty"`
	ArtifactSize        int64          `json:"artifact_size,omitempty"`
	UpstreamFileID      string         `json:"upstream_file_id,omitempty"`
	RecordID            string         `json:"record_id,omitempty"`
	UploadPath          string         `json:"upload_path,omitempty"`
	RowDigest           string         `json:"row_digest,omitempty"`
}

func appMCPRequiredStringField(schema *AppMCPSchema, name string) bool {
	if schema == nil || schema.Type != "object" || !slices.Contains(schema.Required, name) {
		return false
	}
	field := schema.Properties[name]
	return field != nil && field.Type == "string" && !field.Nullable
}

func appMCPTransferExtension(mediaType string) string {
	switch mediaType {
	case "text/csv":
		return ".csv"
	case "application/pdf":
		return ".pdf"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return ".xlsx"
	case "application/vnd.ms-excel.sheet.macroEnabled.12":
		return ".xlsm"
	default:
		return ""
	}
}

func appMCPStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func appMCPTransferParameter(schema *AppMCPSchema, path string) bool {
	location, name, ok := strings.Cut(path, ".")
	if !ok || name == "" || strings.Contains(name, ".") || (location != "path" && location != "query") {
		return false
	}
	return appMCPRequiredStringField(schema.Properties[location], name)
}

func validateAppMCPTransferOperation(transfer *AppMCPTransfer, op *appMCPExternalOperation, reconcile bool) error {
	if transfer == nil || op == nil || op.Input == nil || op.Output == nil {
		return errors.New("pinned transfer schema is unavailable")
	}
	if transfer.Kind == "pull" {
		if reconcile || !appMCPTransferParameter(op.Input, transfer.SelectorParameter) || !appMCPRequiredStringField(op.Output, transfer.ContentField) || !appMCPRequiredStringField(op.Output, transfer.MIMEField) || !appMCPRequiredStringField(op.Output, transfer.ChecksumField) || transfer.RevisionField != "" && !appMCPRequiredStringField(op.Output, transfer.RevisionField) {
			return errors.New("pull mapping fields must be required strings in pinned schemas")
		}
		return nil
	}
	if transfer.Kind != "push" {
		return errors.New("unsupported transfer kind")
	}
	if reconcile {
		if !appMCPTransferParameter(op.Input, transfer.ReconcileParameter) || !appMCPRequiredStringField(op.Output, transfer.ResultIDField) || !appMCPRequiredStringField(op.Output, transfer.ResultChecksumField) {
			return errors.New("reconciliation mapping fields must be required strings in pinned schemas")
		}
		return nil
	}
	body := op.Input.Properties["body"]
	if !appMCPRequiredStringField(body, transfer.RequestContentField) || !appMCPRequiredStringField(body, transfer.RequestIdempotencyField) || !appMCPRequiredStringField(op.Output, transfer.ResultIDField) || !appMCPRequiredStringField(op.Output, transfer.ResultChecksumField) {
		return errors.New("push mapping fields must be required strings in pinned schemas")
	}
	return nil
}

func appMCPTransferValue(object map[string]any, path string) (string, bool) {
	var current any = object
	for _, name := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = m[name]
		if !ok {
			return "", false
		}
	}
	v, ok := current.(string)
	return v, ok && v != ""
}

func appMCPTransferRowDigest(ctx context.Context, tx *sql.Tx, app *App, table, id string) (string, error) {
	query := "SELECT * FROM main." + quoteIdent(table) + " WHERE id=?"
	key, err := cryptoKeyForQuerierMainChecked(tx)
	if err != nil {
		return "", err
	}
	rows, err := queryRowsWithKeyContextDecrypt(ctx, tx, key, nativeRowDecryptor(app, table), query, id)
	if err != nil || len(rows) != 1 {
		return "", errors.New("target record is unavailable")
	}
	var incarnation, rowType string
	if err := tx.QueryRowContext(ctx, `SELECT incarnation FROM main._benmore_mcp_revision_tables WHERE table_name=?`, table).Scan(&incarnation); err != nil || !appMCPOperationHex(incarnation, 16) {
		return "", errors.New("target table revision is unavailable")
	}
	if err := tx.QueryRowContext(ctx, "SELECT typeof(id) FROM main."+quoteIdent(table)+" WHERE id=?", id).Scan(&rowType); err != nil || rowType != "integer" && rowType != "text" {
		return "", errors.New("target row key is invalid")
	}
	var revision int64
	var deleted int
	if err := tx.QueryRowContext(ctx, `SELECT revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation=? AND key_type=? AND row_key=?`, table, incarnation, rowType, id).Scan(&revision, &deleted); err != nil || deleted != 0 || revision <= 0 {
		return "", errors.New("target row revision is unavailable")
	}
	encoded, err := json.Marshal(struct {
		Incarnation string         `json:"incarnation"`
		KeyType     string         `json:"key_type"`
		RowKey      string         `json:"row_key"`
		Revision    int64          `json:"revision"`
		Deleted     int            `json:"deleted"`
		Row         map[string]any `json:"row"`
	}{incarnation, rowType, id, revision, deleted, rows[0]})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func appMCPAddTransferPreview(cap *appMCPCommandCapability, intent, preview map[string]any) error {
	transfer := cap.tool.Transfer
	view := map[string]any{"kind": transfer.Kind, "connection": transfer.Connection, "operation_id": transfer.OperationID}
	if transfer.Kind == "pull" {
		id, ok := appMCPTransferValue(intent, transfer.SelectorIntentPath)
		recordID, recordOK := appMCPTransferValue(intent, transfer.RecordIDIntentPath)
		if !ok || !recordOK || len(id) > 512 || len(recordID) > 256 {
			return appMCPResultFailure("invalid_input")
		}
		attach := appMCPUpdateTool(cap.generation.manifest, transfer.AttachTool)
		if attach == nil || !SessionCanAccessTable(cap.generation.view, attach.Handler.Table, OpUpdate, &cap.actor) {
			return appMCPResultFailure("denied")
		}
		if err := cap.withInternalRead(func() error {
			_, err := txAuthorizedRow(cap.tx, cap.generation.view, attach.Handler.Table, recordID, &cap.actor, "edit")
			return err
		}); err != nil {
			return appMCPResultFailure("denied")
		}
		var digest string
		err := cap.withInternalRead(func() error {
			var err error
			digest, err = appMCPTransferRowDigest(cap.ctx, cap.tx, cap.generation.view, attach.Handler.Table, recordID)
			return err
		})
		if err != nil {
			return appMCPResultFailure("denied")
		}
		dest, err := appMCPRandomHex(32)
		if err != nil {
			return err
		}
		view["selected_source_id"], view["target_table"], view["target_record_id"] = id, attach.Handler.Table, recordID
		extension := appMCPTransferExtension(transfer.ExpectedMIME)
		if extension == "" {
			return appMCPResultFailure("invalid_input")
		}
		view["target_file_column"], view["private_destination"], view["target_row_digest"] = transfer.FileColumn, "uploads/private/mcp/"+dest+extension, digest
	} else {
		artifactID, ok := appMCPTransferValue(intent, transfer.ArtifactIntentPath)
		if !ok {
			return appMCPResultFailure("invalid_input")
		}
		var artifact appMCPArtifact
		err := cap.withInternalRead(func() error {
			var err error
			artifact, err = appMCPReadArtifactManifestFrom(cap.ctx, cap.tx, cap.app, cap.actor, artifactID)
			return err
		})
		if err != nil {
			return appMCPResultFailure("denied")
		}
		view["artifact_id"], view["artifact_sha256"], view["artifact_size"] = artifact.ID, artifact.SHA256, artifact.Size
	}
	preview["external_transfer"] = view
	return nil
}

func appMCPValidateTransferTargetSnapshot(cap *appMCPCommandCapability, prepared *appMCPCommandPrepared) error {
	if cap == nil || prepared == nil || cap.tool == nil || cap.tool.Transfer == nil || cap.tool.Transfer.Kind != "pull" {
		return errors.New("pull target snapshot is unavailable")
	}
	view, ok := prepared.Preview["external_transfer"].(map[string]any)
	if !ok {
		return appMCPResultFailure("invalid_input")
	}
	attach := appMCPUpdateTool(cap.generation.manifest, cap.tool.Transfer.AttachTool)
	recordID, _ := view["target_record_id"].(string)
	digest, _ := view["target_row_digest"].(string)
	if attach == nil || recordID == "" || !appMCPOperationHex(digest, 32) ||
		!SessionCanAccessTable(cap.generation.view, attach.Handler.Table, OpUpdate, &cap.actor) {
		return appMCPResultFailure("denied")
	}
	var current string
	err := cap.withInternalRead(func() error {
		if _, err := txAuthorizedRow(cap.tx, cap.generation.view, attach.Handler.Table, recordID, &cap.actor, "edit"); err != nil {
			return err
		}
		var err error
		current, err = appMCPTransferRowDigest(cap.ctx, cap.tx, cap.generation.view, attach.Handler.Table, recordID)
		return err
	})
	if err != nil || !SecureCompare(current, digest) {
		return appMCPResultFailure("denied")
	}
	return nil
}

func appMCPReadArtifactManifest(ctx context.Context, app *App, actor Session, id string) (appMCPArtifact, error) {
	return appMCPReadArtifactManifestFrom(ctx, app.DB, app, actor, id)
}

type appMCPArtifactQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func appMCPReadArtifactManifestFrom(ctx context.Context, queryer appMCPArtifactQueryer, app *App, actor Session, id string) (appMCPArtifact, error) {
	var a appMCPArtifact
	var revisions, scopes string
	err := queryer.QueryRowContext(ctx, `SELECT id,owner_user_id,owner_created_at,tenant,kind,content_sha256,size,storage_ref,source_bundle_digest,source_revisions,template_version,engine_version,created_at,operation_id,required_role,required_scopes FROM main._benmore_mcp_artifacts WHERE id=?`, id).Scan(
		&a.ID, &a.OwnerUserID, &a.OwnerCreatedAt, &a.Tenant, &a.Kind, &a.SHA256, &a.Size, &a.StorageRef, &a.SourceBundleDigest, &revisions, &a.TemplateVersion, &a.EngineVersion, &a.CreatedAt, &a.OperationID, &a.RequiredRole, &scopes)
	if err != nil || json.Unmarshal([]byte(revisions), &a.SourceRevisions) != nil || json.Unmarshal([]byte(scopes), &a.RequiredScopes) != nil || !appMCPArtifactAuthorizedFrom(ctx, queryer, app, &actor, a) || !appMCPOperationHex(a.SHA256, 32) || a.Size <= 0 || a.Size > mcpArtifactMaxBytes {
		return appMCPArtifact{}, errors.New("artifact unavailable")
	}
	return a, nil
}

func appMCPQueueTransfer(cap *appMCPCommandCapability, prepared *appMCPCommandPrepared) error {
	transfer := cap.tool.Transfer
	view, ok := prepared.Preview["external_transfer"].(map[string]any)
	if !ok || transfer == nil || cap.operationID == "" {
		return errors.New("approved transfer preview is unavailable")
	}
	job := appMCPTransferJob{Tool: cap.tool.Name, Kind: transfer.Kind, Connection: transfer.Connection, OperationID: cap.operationID, UpstreamOperationID: transfer.OperationID,
		ContractDigest: prepared.ContractDigest, ExecutionDigest: prepared.ExecutionDigest, Intent: prepared.Intent, Preview: view}
	if transfer.Kind == "push" {
		job.ArtifactID, _ = view["artifact_id"].(string)
		job.ArtifactSHA256, _ = view["artifact_sha256"].(string)
		job.ArtifactSize = appMCPNumberInt64(view["artifact_size"])
	} else {
		job.UpstreamFileID, _ = view["selected_source_id"].(string)
		job.RecordID, _ = view["target_record_id"].(string)
		job.UploadPath, _ = view["private_destination"].(string)
		attach := appMCPUpdateTool(cap.generation.manifest, transfer.AttachTool)
		if attach == nil {
			return errors.New("pull target declaration is unavailable")
		}
		// Seal the post-command state. The prepared digest guards the source
		// dependency before approval; it can legitimately change in apply.
		_ = cap.withInternalRead(func() error {
			var err error
			job.RowDigest, err = appMCPTransferRowDigest(cap.ctx, cap.tx, cap.generation.view, attach.Handler.Table, job.RecordID)
			return err
		})
		if !appMCPOperationHex(job.RowDigest, 32) {
			return errors.New("pull target snapshot is unavailable")
		}
	}
	return cap.enqueueEffect(appMCPContextTx{tx: cap.tx, ctx: cap.ctx, private: true, cap: cap}, "transfer", transfer.Connection, transfer.Kind, appMCPTransferJobType, "", map[string]any{"user_id": cap.actor.UserID, appMCPTransferPayloadKey: job})
}

func appMCPNumberInt64(value any) int64 {
	switch n := value.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		result, _ := n.Int64()
		return result
	case float64:
		return int64(n)
	default:
		return 0
	}
}

func appMCPVerifyTransferReceiptJobTx(ctx context.Context, tx *sql.Tx, app *App, generation *appMCPRuntimeGeneration, authority appMCPWriteEffectAuthority) error {
	job := authority.Transfer
	stored, err := readAppMCPStoredOperation(ctx, tx, app, authority.OperationID)
	if err != nil || stored == nil || stored.Receipt == nil || stored.Prepared.Command != job.Tool || stored.Prepared.ContractDigest != job.ContractDigest || stored.Prepared.ExecutionDigest != job.ExecutionDigest {
		return errors.New("sealed transfer operation is unavailable")
	}
	approval, err := readAppMCPCommandApproval(ctx, tx, app, authority.OperationID)
	if err != nil {
		return err
	}
	receipt, err := decodeAppMCPCommandReceipt(stored, approval)
	if err != nil || receipt.State != "committed" {
		return errors.New("transfer approval was not consumed by a committed command")
	}
	effects, err := appMCPDecodeEffects(receipt.Effects)
	if err != nil {
		return err
	}
	jobID := strconv.FormatInt(authority.JobID, 10)
	wantTarget := job.Connection + "." + job.Kind
	found := false
	for _, effect := range effects {
		if effect.ID == jobID && effect.Kind == "transfer" && effect.Target == wantTarget && effect.PayloadDigest == authority.PayloadDigest {
			found = true
			break
		}
	}
	if !found {
		return errors.New("transfer job is not sealed in the consumed receipt")
	}
	manifestTool := appMCPManifestTool(generation.manifest, job.Tool)
	if manifestTool == nil || manifestTool.Transfer == nil || manifestTool.Transfer.Kind != job.Kind || manifestTool.Transfer.Connection != job.Connection || manifestTool.Transfer.OperationID != job.UpstreamOperationID {
		return errors.New("transfer manifest binding changed")
	}
	prepared := stored.Prepared
	if prepared.Origin.Kind != "connector" || authority.Grant.OperationID != job.OperationID ||
		authority.Grant.GrantID != prepared.Origin.GrantID || authority.Grant.ActorID != prepared.Origin.ActorID ||
		authority.Grant.ActorCreated != prepared.Origin.ActorCreated || authority.Grant.Tenant != prepared.Origin.Tenant ||
		authority.Grant.Client != prepared.Origin.Client || authority.Grant.Resource != prepared.Origin.Resource ||
		!SecureCompare(authority.Grant.OwnerEpoch, prepared.RuntimeAuthority.OwnerEpoch) ||
		!SecureCompare(authority.Grant.WriteEpoch, prepared.RuntimeAuthority.WriteEpoch) ||
		!SecureCompare(authority.Grant.ExternalExportEpoch, prepared.RuntimeAuthority.ExternalExportEpoch) ||
		!appMCPStringSlicesEqual(authority.Grant.Permissions, prepared.Origin.Permissions) {
		return errors.New("transfer authority differs from sealed operation")
	}
	intent, err := appMCPCanonicalJSON(job.Intent)
	if err != nil || !bytes.Equal(intent, stored.Prepared.Intent) {
		return errors.New("transfer intent differs from sealed approval")
	}
	preview, err := appMCPDecodeObject(stored.Prepared.Preview)
	if err != nil {
		return err
	}
	transferPreview, _ := preview["external_transfer"].(map[string]any)
	provided, err := appMCPCanonicalJSON(job.Preview)
	sealed, sealErr := appMCPCanonicalJSON(transferPreview)
	if err != nil || sealErr != nil || !bytes.Equal(provided, sealed) {
		return errors.New("transfer preview differs from sealed approval")
	}
	encoded, err := json.Marshal(job)
	if err != nil || appMCPOperationDigest("benmore:mcp:transfer-payload:v1", encoded) != authority.PayloadDigest {
		return errors.New("transfer payload digest does not match sealed effect")
	}
	return nil
}

func appMCPManifestTool(manifest *AppMCPManifest, name string) *AppMCPTool {
	if manifest == nil {
		return nil
	}
	for i := range manifest.Tools {
		if manifest.Tools[i].Name == name {
			return &manifest.Tools[i]
		}
	}
	return nil
}

func appMCPDecodeTransferJob(value any) (appMCPTransferJob, error) {
	raw, err := json.Marshal(value)
	var job appMCPTransferJob
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&job) != nil || job.Tool == "" || job.Kind == "" || job.Connection == "" || job.OperationID == "" || job.UpstreamOperationID == "" || job.Intent == nil || job.Preview == nil {
		return appMCPTransferJob{}, errors.New("transfer payload is invalid")
	}
	return job, nil
}

func appMCPDeliverExternalTransfer(app *App, jobID int64, data map[string]any) error {
	job, err := appMCPDecodeTransferJob(data[appMCPTransferPayloadKey])
	if err != nil {
		return jobNotRetryable{errors.New("unknown: transfer payload is invalid")}
	}
	encoded, err := json.Marshal(job)
	digest := appMCPOperationDigest("benmore:mcp:transfer-payload:v1", encoded)
	var stamp appMCPEffectGrant
	stampBytes, stampErr := json.Marshal(data[appMCPEffectKey])
	stampDecoder := json.NewDecoder(bytes.NewReader(stampBytes))
	stampDecoder.DisallowUnknownFields()
	if err != nil || stampErr != nil || stampDecoder.Decode(&stamp) != nil || jobID <= 0 || stamp.OperationID != job.OperationID || stamp.TransferKind != job.Kind || stamp.PayloadDigest != digest {
		return jobNotRetryable{errors.New("unknown: transfer payload does not match its outbox stamp")}
	}
	if err := appMCPVerifyTransferReceiptJob(app, job, jobID, stamp); err != nil {
		return jobNotRetryable{errors.New("unknown: transfer is not bound to a consumed approval receipt")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPExternalTimeout+10*time.Second)
	defer cancel()
	generation := snapshotAppMCPGeneration(app)
	if generation == nil || generation.manifest == nil || generation.manifest.ContractDigest != job.ContractDigest || generation.manifest.ExecutionDigest != job.ExecutionDigest {
		return appMCPBlockedEffect("transfer generation changed")
	}
	tool := appMCPManifestTool(generation.manifest, job.Tool)
	transferOps := generation.manifest.transfers[job.Tool]
	if tool == nil || tool.Transfer == nil || tool.Transfer.Kind != job.Kind || tool.Transfer.OperationID != job.UpstreamOperationID || transferOps == nil {
		return appMCPBlockedEffect("transfer declaration changed")
	}
	ownerState, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !ownerState.Exposed || ownerState.ApprovedWrites == nil || !*ownerState.ApprovedWrites ||
		!SecureCompare(ownerState.Epoch, stamp.OwnerEpoch) || !SecureCompare(ownerState.ApprovedWriteEpoch, stamp.WriteEpoch) {
		return appMCPBlockedEffect("owner or approved-write authority changed")
	}
	grant, err := readAppMCPGrant(app.DB, stamp.GrantID)
	if err != nil || grant.Revoked || grant.ExpiresAt <= time.Now().Unix() || grant.ID != stamp.GrantID || grant.App != ownerState.App ||
		grant.UserID != stamp.ActorID || grant.UserCreated != stamp.ActorCreated || grant.Tenant != stamp.Tenant ||
		grant.Client != stamp.Client || grant.Resource != stamp.Resource || grant.Epoch != stamp.OwnerEpoch {
		return appMCPBlockedEffect("connector grant is unavailable")
	}
	actor, err := appMCPGrantActorForGeneration(ctx, app, generation, grant, time.Now())
	if err != nil || !scopesWithin(actor.Scopes, strings.Join(tool.Permissions, " ")) {
		return appMCPBlockedEffect("transfer permissions are no longer granted")
	}
	connection := appMCPTransferConnection(generation.manifest, job.Connection)
	if connection == nil {
		return appMCPBlockedEffect("transfer connection is unavailable")
	}
	credential := ""
	if connection.Auth.Kind != "none" {
		credential, err = loadAppMCPConnectionSecret(ctx, app, actor.UserID, connection)
		if err != nil {
			return jobNotRetryable{errors.New("transfer credential is unavailable")}
		}
	}
	base, err := url.Parse(connection.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return jobNotRetryable{errors.New("transfer base URL is invalid")}
	}
	if err := appMCPSetTransferState(app, job, jobID, "queued", "", "", ""); err != nil {
		return jobNotRetryable{errors.New("unknown: transfer state could not be initialized")}
	}
	if job.Kind == "push" {
		return appMCPDeliverPush(ctx, app, generation, grant, actor, tool, connection, transferOps, base, credential, job, jobID, stamp)
	}
	return appMCPDeliverPull(ctx, app, generation, grant, actor, tool, connection, transferOps, base, credential, job, jobID, stamp)
}

func appMCPVerifyTransferReceiptJob(app *App, job appMCPTransferJob, jobID int64, stamp appMCPEffectGrant) error {
	ctx, cancel := context.WithTimeout(context.Background(), readOnlyQueryTimeout)
	defer cancel()
	tx, err := app.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return appMCPVerifyTransferReceiptJobTx(ctx, tx, app, snapshotAppMCPGeneration(app), appMCPWriteEffectAuthority{
		OperationID: job.OperationID, JobID: jobID, PayloadDigest: stamp.PayloadDigest,
		ExternalExportEpoch: stamp.ExternalExportEpoch, Grant: stamp, Transfer: job,
	})
}

func appMCPTransferConnection(manifest *AppMCPManifest, name string) *AppMCPConnection {
	if manifest == nil {
		return nil
	}
	for i := range manifest.Connections {
		if manifest.Connections[i].Name == name {
			return &manifest.Connections[i]
		}
	}
	return nil
}

func appMCPTransferRequest(ctx context.Context, connection *AppMCPConnection, operation *appMCPExternalOperation, base *url.URL, input map[string]any, secret string, limit int64) (int, http.Header, []byte, error) {
	url, headers, body, err := buildAppMCPExternalRequestLimit(base, connection, operation, input, secret, int(limit))
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(body)) > limit {
		return 0, nil, nil, appMCPExternalFailure("incomplete_result", "The external transfer request exceeded the size limit.")
	}
	return appMCPExternalDoLimit(ctx, operation.Method, url, headers, body, limit)
}

func appMCPTransferDecodeJSON(header http.Header, body []byte, operation *appMCPExternalOperation) (map[string]any, error) {
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(body) == 0 || operation == nil {
		return nil, errors.New("transfer response has an invalid media type")
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil || result == nil || validateAppMCPSchemaValue(operation.Output, result) != nil {
		return nil, errors.New("transfer response differs from pinned schema")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("transfer response contains trailing JSON")
	}
	return result, nil
}

func appMCPPushIdempotencyKey(job appMCPTransferJob) string {
	return hashBytesSHA256([]byte("benmore:mcp:external-push:v1\x00" + job.OperationID + "\x00" + job.ArtifactID))
}

type appMCPTransferCall func(map[string]any, *appMCPExternalOperation, int64) (int, http.Header, []byte, error)

func appMCPPushOnce(transfer *AppMCPTransfer, operations *appMCPTransferOperations, key, checksum, content string, call appMCPTransferCall) (string, bool) {
	if transfer == nil || operations == nil || operations.Operation == nil || operations.Reconcile == nil || call == nil || key == "" {
		return "", false
	}
	body := map[string]any{transfer.RequestContentField: content, transfer.RequestIdempotencyField: key}
	status, headers, response, sendErr := call(map[string]any{"body": body}, operations.Operation, appMCPTransferWireLimit)
	if sendErr == nil && (status == http.StatusOK || status == http.StatusCreated) {
		if result, decodeErr := appMCPTransferDecodeJSON(headers, response, operations.Operation); decodeErr == nil && appMCPTransferResultMatches(result, transfer.ResultIDField, transfer.ResultChecksumField, checksum) {
			id, _ := result[transfer.ResultIDField].(string)
			return id, true
		}
	}
	return appMCPReconcilePushByKey(transfer, operations.Reconcile, key, checksum, call)
}

func appMCPReconcilePushByKey(transfer *AppMCPTransfer, operation *appMCPExternalOperation, key, checksum string, call appMCPTransferCall) (string, bool) {
	if transfer == nil || operation == nil || call == nil || key == "" {
		return "", false
	}
	location, parameter, ok := strings.Cut(transfer.ReconcileParameter, ".")
	if !ok {
		return "", false
	}
	status, headers, response, reconcileErr := call(appMCPExternalInputWithParameter(location, parameter, key), operation, appMCPResultLimit)
	if reconcileErr == nil && status == http.StatusOK {
		if result, decodeErr := appMCPTransferDecodeJSON(headers, response, operation); decodeErr == nil && appMCPTransferResultMatches(result, transfer.ResultIDField, transfer.ResultChecksumField, checksum) {
			id, _ := result[transfer.ResultIDField].(string)
			return id, true
		}
	}
	return "", false
}

func appMCPDeliverPush(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, tool *AppMCPTool, connection *AppMCPConnection, operations *appMCPTransferOperations, base *url.URL, secret string, job appMCPTransferJob, jobID int64, stamp appMCPEffectGrant) error {
	transfer := tool.Transfer
	artifact, err := appMCPReadArtifactManifest(ctx, app, *actor, job.ArtifactID)
	if err != nil || artifact.SHA256 != job.ArtifactSHA256 || artifact.Size != job.ArtifactSize {
		return jobNotRetryable{errors.New("unknown: approved artifact changed")}
	}
	content, err := readAppMCPArtifact(app, artifact.StorageRef, artifact.Size)
	if err != nil || int64(len(content)) != artifact.Size || hashBytesSHA256(content) != artifact.SHA256 {
		return jobNotRetryable{errors.New("unknown: approved artifact integrity check failed")}
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || !state.ExternalExport || state.ExternalExportEpoch != stamp.ExternalExportEpoch {
		return appMCPBlockedEffect("external export is disabled or changed before delivery")
	}
	key := appMCPPushIdempotencyKey(job)
	if err := appMCPSetTransferState(app, job, jobID, "requesting", key, "", artifact.SHA256); err != nil {
		return jobNotRetryable{errors.New("unknown: push recovery state could not be sealed")}
	}
	// Any ambiguous POST outcome is reconciled with a read-only lookup by our
	// stable key. The helper calls POST once and GET at most once.
	upstreamID, confirmed := appMCPPushOnce(transfer, operations, key, artifact.SHA256, base64.StdEncoding.EncodeToString(content), func(input map[string]any, operation *appMCPExternalOperation, limit int64) (int, http.Header, []byte, error) {
		return appMCPTransferRequest(ctx, connection, operation, base, input, secret, limit)
	})
	if confirmed {
		if err := appMCPSetTransferState(app, job, jobID, "pushed", key, upstreamID, artifact.SHA256); err != nil {
			return jobNotRetryable{errors.New("unknown: push completed but its receipt could not be recorded")}
		}
		return nil
	}
	_ = appMCPSetTransferState(app, job, jobID, "unknown", key, "", artifact.SHA256)
	return jobNotRetryable{fmt.Errorf("unknown: push response was not confirmed; reconciliation did not prove artifact %s", job.ArtifactID)}
}

// appMCPReconcileTransferEffects is invoked only by the authenticated
// operation-status read. It performs GET-only reconciliation for durable
// unknown push outcomes and never replays the POST.
func appMCPReconcileTransferEffects(ctx context.Context, request appMCPCommandRequest, operationID string) {
	if request.app == nil || request.generation == nil || request.origin.connector == nil || ctx.Err() != nil {
		return
	}
	pin := request.origin.connector
	if pin.GrantID == "" || !appMCPOperationHex(operationID, 32) {
		return
	}
	rows, err := request.app.DB.QueryContext(ctx, `SELECT j.id,j.payload,j.status,COALESCE(j.lease_expires_at,'') FROM main._benmore_jobs j
	WHERE j.job_type=? AND json_extract(j.payload,'$._mcp_effect.operation_id')=?`, appMCPTransferJobType, operationID)
	if err != nil {
		return
	}
	type candidate struct {
		id      int64
		payload string
		status  string
		lease   string
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if rows.Scan(&item.id, &item.payload, &item.status, &item.lease) == nil {
			candidates = append(candidates, item)
		}
	}
	_ = rows.Close()
	for _, candidate := range candidates {
		var data map[string]any
		decoder := json.NewDecoder(strings.NewReader(candidate.payload))
		decoder.UseNumber()
		if decoder.Decode(&data) != nil {
			continue
		}
		job, err := appMCPDecodeTransferJob(data[appMCPTransferPayloadKey])
		if err != nil || job.Kind != "push" || job.OperationID != operationID {
			continue
		}
		var stamp appMCPEffectGrant
		stampBytes, _ := json.Marshal(data[appMCPEffectKey])
		if json.Unmarshal(stampBytes, &stamp) != nil || stamp.GrantID != pin.GrantID || stamp.ActorID != pin.UserID ||
			stamp.ActorCreated != pin.UserCreated || stamp.Tenant != pin.Tenant || stamp.Client != pin.Client ||
			stamp.Resource != pin.Resource || stamp.OwnerEpoch != pin.Epoch || stamp.WriteEpoch != pin.WriteEpoch ||
			stamp.TransferKind != "push" || stamp.OperationID != operationID {
			continue
		}
		var phase string
		if request.app.DB.QueryRowContext(ctx, `SELECT phase FROM main._benmore_mcp_transfer_state WHERE job_id=?`, candidate.id).Scan(&phase) != nil || phase != "unknown" && phase != "requesting" {
			continue
		}
		if phase == "requesting" && candidate.status != "failed" && !(candidate.status == "running" && candidate.lease != "" && candidate.lease < time.Now().UTC().Format(sqliteDateTimeLayout)) {
			continue
		}
		if err := appMCPVerifyTransferReceiptJob(request.app, job, candidate.id, stamp); err != nil {
			continue
		}
		generation := snapshotAppMCPGeneration(request.app)
		if generation == nil || generation.manifest == nil || generation.manifest.ContractDigest != job.ContractDigest || generation.manifest.ExecutionDigest != job.ExecutionDigest {
			continue
		}
		state, err := currentAppMCPEpoch(request.app.Dir)
		if err != nil || !state.Exposed || state.ApprovedWrites == nil || !*state.ApprovedWrites || state.App != pin.AppID ||
			!SecureCompare(state.Epoch, stamp.OwnerEpoch) || !SecureCompare(state.ApprovedWriteEpoch, stamp.WriteEpoch) {
			continue
		}
		grant, err := readAppMCPGrant(request.app.DB, stamp.GrantID)
		if err != nil || grant.Revoked || grant.ExpiresAt <= time.Now().Unix() || grant.App != pin.AppID || grant.Epoch != stamp.OwnerEpoch || grant.UserID != stamp.ActorID || grant.UserCreated != stamp.ActorCreated || grant.Tenant != stamp.Tenant || grant.Client != stamp.Client || grant.Resource != stamp.Resource {
			continue
		}
		actor, err := appMCPGrantActorForGeneration(ctx, request.app, generation, grant, time.Now())
		if err != nil || !scopesWithin(actor.Scopes, strings.Join(stamp.Permissions, " ")) {
			continue
		}
		tool := appMCPManifestTool(generation.manifest, job.Tool)
		operations := generation.manifest.transfers[job.Tool]
		connection := appMCPTransferConnection(generation.manifest, job.Connection)
		if tool == nil || tool.Transfer == nil || operations == nil || operations.Reconcile == nil || connection == nil {
			continue
		}
		secret := ""
		if connection.Auth.Kind != "none" {
			secret, err = loadAppMCPConnectionSecret(ctx, request.app, actor.UserID, connection)
			if err != nil {
				continue
			}
		}
		base, err := url.Parse(connection.BaseURL)
		if err != nil || base.Scheme != "https" || base.Host == "" {
			continue
		}
		key := appMCPPushIdempotencyKey(job)
		upstreamID, confirmed := appMCPReconcilePushByKey(tool.Transfer, operations.Reconcile, key, job.ArtifactSHA256, func(input map[string]any, operation *appMCPExternalOperation, limit int64) (int, http.Header, []byte, error) {
			return appMCPTransferRequest(ctx, connection, operation, base, input, secret, limit)
		})
		if !confirmed {
			continue
		}
		_ = appMCPSetTransferState(request.app, job, candidate.id, "pushed", key, upstreamID, job.ArtifactSHA256)
	}
}

func appMCPTransferResultMatches(result map[string]any, idField, checksumField, checksum string) bool {
	id, idOK := result[idField].(string)
	got, hashOK := result[checksumField].(string)
	return idOK && id != "" && hashOK && got == checksum
}

func appMCPDecodePulledFile(result map[string]any, transfer *AppMCPTransfer) ([]byte, string, string, error) {
	encoded, ok := result[transfer.ContentField].(string)
	media, mediaOK := result[transfer.MIMEField].(string)
	wantHash, hashOK := result[transfer.ChecksumField].(string)
	revision, revisionOK := result[transfer.RevisionField].(string)
	if !ok || !mediaOK || !hashOK || !revisionOK || revision == "" || len(revision) > 256 {
		return nil, "", "", errors.New("upstream file mapping is incomplete")
	}
	content, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || int64(len(content)) > appMCPTransferContentLimit {
		return nil, "", "", errors.New("upstream file content is invalid or oversized")
	}
	sum := sha256.Sum256(content)
	actualHash := hex.EncodeToString(sum[:])
	if !appMCPOperationHex(wantHash, 32) || !SecureCompare(actualHash, wantHash) {
		return nil, "", "", errors.New("upstream file checksum did not match")
	}
	mediaType, _, err := mime.ParseMediaType(media)
	if err != nil || !appMCPTransferAllowedMIME(mediaType) || mediaType != transfer.ExpectedMIME || !appMCPTransferContentMatchesMIME(content, mediaType) {
		return nil, "", "", errors.New("upstream file media type is unsupported")
	}
	return content, media, revision, nil
}

func appMCPTransferContentMatchesMIME(content []byte, mediaType string) bool {
	if len(content) == 0 {
		return false
	}
	sniff := http.DetectContentType(content[:min(len(content), 512)])
	switch mediaType {
	case "application/pdf":
		return bytes.HasPrefix(content, []byte("%PDF-")) && strings.HasPrefix(sniff, "application/pdf")
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel.sheet.macroEnabled.12":
		return bytes.HasPrefix(content, []byte("PK\x03\x04")) && strings.HasPrefix(sniff, "application/zip")
	case "text/csv":
		return utf8.Valid(content) && !strings.Contains(strings.ToLower(string(content[:min(len(content), 512)])), "<html") && !strings.Contains(strings.ToLower(string(content[:min(len(content), 512)])), "<?xml")
	default:
		return false
	}
}

func appMCPTransferPullAuthorize(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, actor *Session, transfer *AppMCPTransfer, recordID, digest string) error {
	attach := appMCPUpdateTool(generation.manifest, transfer.AttachTool)
	if attach == nil || !slices.Contains(attach.Permissions, attach.Handler.Table+":write") ||
		!scopesWithin(actor.Scopes, strings.Join(attach.Permissions, " ")) || !SessionCanAccessTable(generation.view, attach.Handler.Table, OpUpdate, actor) {
		return appMCPResultFailure("denied")
	}
	policyCtx, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		return err
	}
	defer release()
	tx, err := app.DB.BeginTx(policyCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := verifyAppMCPRevisionEnrollmentForTx(policyCtx, app, generation, tx, lease); err != nil {
		return err
	}
	if _, err := txAuthorizedRow(appMCPContextTx{tx: tx, ctx: policyCtx, private: true}, generation.view, attach.Handler.Table, recordID, actor, "edit"); err != nil {
		return err
	}
	current, err := appMCPTransferRowDigest(policyCtx, tx, generation.view, attach.Handler.Table, recordID)
	if err != nil || !SecureCompare(current, digest) {
		return appMCPResultFailure("denied")
	}
	return nil
}

func appMCPExternalInputWithParameter(location, name string, value any) map[string]any {
	return map[string]any{location: map[string]any{name: value}}
}

func appMCPDeliverPull(ctx context.Context, app *App, generation *appMCPRuntimeGeneration, grant *appMCPGrant, actor *Session, tool *AppMCPTool, connection *AppMCPConnection, operations *appMCPTransferOperations, base *url.URL, credential string, job appMCPTransferJob, jobID int64, stamp appMCPEffectGrant) error {
	transfer := tool.Transfer
	if err := appMCPTransferPullAuthorize(ctx, app, generation, actor, transfer, job.RecordID, job.RowDigest); err != nil {
		return jobNotRetryable{errors.New("unknown: pull target authority changed before download")}
	}
	location, parameter, ok := strings.Cut(transfer.SelectorParameter, ".")
	if !ok {
		return jobNotRetryable{errors.New("unknown: pull selector mapping is invalid")}
	}
	status, headers, body, err := appMCPTransferRequest(ctx, connection, operations.Operation, base, appMCPExternalInputWithParameter(location, parameter, job.UpstreamFileID), credential, appMCPTransferWireLimit)
	if err != nil || status != http.StatusOK {
		return jobNotRetryable{errors.New("unknown: upstream file download was not confirmed")}
	}
	result, err := appMCPTransferDecodeJSON(headers, body, operations.Operation)
	if err != nil {
		return jobNotRetryable{errors.New("unknown: upstream file response did not match its pinned schema")}
	}
	content, media, revision, err := appMCPDecodePulledFile(result, transfer)
	if err != nil {
		return jobNotRetryable{fmt.Errorf("unknown: %w", err)}
	}
	actualHash := hashBytesSHA256(content)
	if err := appMCPStorePulledFile(app, *actor, job.UploadPath, content, media, actualHash, connection.Name, job.UpstreamFileID, revision); err != nil {
		return jobNotRetryable{fmt.Errorf("unknown: downloaded file could not be stored with provenance: %w", err)}
	}
	if err := appMCPSetTransferState(app, job, jobID, "downloaded", job.UploadPath, job.UpstreamFileID, actualHash); err != nil {
		return jobNotRetryable{fmt.Errorf("unknown: file stored at %s but recovery state failed", job.UploadPath)}
	}
	currentGrant, err := readAppMCPGrant(app.DB, grant.ID)
	if err != nil || currentGrant.Revoked || currentGrant.ExpiresAt <= time.Now().Unix() {
		return jobNotRetryable{errors.New("unknown: target grant changed after download")}
	}
	currentActor, err := appMCPGrantActorForGeneration(ctx, app, generation, currentGrant, time.Now())
	if err != nil || appMCPTransferPullAuthorize(ctx, app, generation, currentActor, transfer, job.RecordID, job.RowDigest) != nil {
		return jobNotRetryable{fmt.Errorf("unknown: file stored at %s but attach authority changed", job.UploadPath)}
	}
	attach := appMCPUpdateTool(generation.manifest, transfer.AttachTool)
	effect := &appMCPWriteEffectAuthority{OperationID: job.OperationID, JobID: jobID, PayloadDigest: stamp.PayloadDigest, ExternalExportEpoch: stamp.ExternalExportEpoch, Grant: stamp, Transfer: job}
	pin := appMCPWriteAuthorityPin{Origin: app, Generation: generation, GrantID: currentGrant.ID, AppID: currentGrant.App, Epoch: currentGrant.Epoch,
		WriteEpoch: stamp.WriteEpoch, ExternalExportEpoch: stamp.ExternalExportEpoch, Resource: currentGrant.Resource, Client: currentGrant.Client, Tenant: currentGrant.Tenant,
		UserID: currentGrant.UserID, UserCreated: currentGrant.UserCreated, Permissions: append([]string(nil), attach.Permissions...), Effect: effect, ExpectedRowDigest: job.RowDigest}
	data := map[string]any{transfer.FileColumn: job.UploadPath}
	var recordID any = job.RecordID
	if attach.InputSchema.Properties["id"].Type == "integer" {
		recordID = json.Number(job.RecordID)
	}
	_, _, err = applyAppMCPCanonicalUpdate(ctx, pin, transfer.AttachTool, map[string]any{"id": recordID, "data": data}, time.Now().UTC())
	if err != nil {
		var authorityErr *appMCPWriteAuthorityError
		if errors.As(err, &authorityErr) {
			return jobNotRetryable{fmt.Errorf("unknown: file stored at %s but canonical attach did not complete: %v", job.UploadPath, authorityErr.cause)}
		}
		return jobNotRetryable{fmt.Errorf("unknown: file stored at %s but canonical attach did not complete: %w", job.UploadPath, err)}
	}
	if err := appMCPSetTransferState(app, job, jobID, "attached", job.UploadPath, job.UpstreamFileID, actualHash); err != nil {
		return jobNotRetryable{fmt.Errorf("unknown: file attached at %s but transfer receipt could not be recorded", job.UploadPath)}
	}
	return nil
}

func appMCPTransferAllowedMIME(mediaType string) bool {
	switch mediaType {
	case "text/csv", "application/pdf", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.ms-excel.sheet.macroEnabled.12":
		return true
	default:
		return false
	}
}

func appMCPStorePulledFile(app *App, actor Session, path string, content []byte, mediaType, checksum, connection, upstreamID, revision string) error {
	logical, err := privateLogicalUploadPath(path)
	if err != nil || !strings.HasPrefix(logical, "uploads/private/mcp/") || int64(len(content)) > appMCPTransferContentLimit {
		return errors.New("private destination is invalid")
	}
	if app == nil {
		return errors.New("upload ownership database unavailable")
	}
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		return err
	}
	// Reserve ownership before any storage write, including an ambiguous
	// remote failure. Retries may reuse their own generated destination,
	// but must never relabel another uploader's existing bytes.
	key, group := uploadRelPath(logical), actor.EffectiveGroupID()
	if _, err := app.DB.Exec(`INSERT INTO _benmore_upload_owners(path,user_id,group_id,uploader_admin) VALUES(?,?,?,0) ON CONFLICT(path) DO NOTHING`, key, actor.UserID, group); err != nil {
		return err
	}
	var owned int
	if err := app.DB.QueryRow(`SELECT 1 FROM _benmore_upload_owners WHERE path=? AND user_id=? AND group_id=? AND uploader_admin=0`, key, actor.UserID, group).Scan(&owned); err != nil {
		return errors.New("private destination ownership could not be verified")
	}
	backend := storageBackendForApp(app)
	if _, err := backend.Save(logical, bytes.NewReader(content)); err != nil {
		return err
	}
	return appMCPRecordExternalFileProcessing(app, actor.UserID, uploadRelPath(logical), checksum, mediaType, connection, upstreamID, revision)
}

func appMCPRecordExternalFileProcessing(app *App, userID int64, fileID, checksum, mediaType, connection, sourceID, revision string) error {
	if err := ensureAppMCPFileProcessingTable(app.DB); err != nil {
		return err
	}
	id, err := appMCPRandomHex(32)
	if err != nil {
		return err
	}
	limits, _ := json.Marshal(map[string]any{"max_file_bytes": appMCPTransferContentLimit, "source": "external_transfer"})
	quality, _ := json.Marshal([]string{})
	_, err = app.DB.Exec(`INSERT INTO _benmore_mcp_file_processings(id,file_id,file_sha256,origin,origin_version,content_type,parser_version,limits_json,complete,quality_flags,created_by,created_at,source_connection,source_file_id,source_revision) VALUES(?,?,?,?,?,?,?,?,1,?,?,datetime('now'),?,?,?)`,
		id, fileID, checksum, "external_transfer", revision, mediaType, "mcp-transfer/1", string(limits), string(quality), userID, connection, sourceID, revision)
	return err
}
