//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

const appMCPCommandApprovalStorageDDL = `CREATE TABLE _benmore_mcp_command_approvals (
	operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id)=64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
	approval_digest TEXT NOT NULL CHECK(length(approval_digest)=64 AND approval_digest NOT GLOB '*[^0-9a-f]*'),
	state_ciphertext TEXT NOT NULL
)`

type appMCPCommandApprovalRecord struct {
	Version               int    `json:"version"`
	Domain                string `json:"domain"`
	ApprovalID            string `json:"approval_id"`
	AppID                 string `json:"app_id"`
	OperationID           string `json:"operation_id"`
	PreparedDigest        string `json:"prepared_digest"`
	DisclosureVersion     string `json:"disclosure_version"`
	OwnerEpoch            string `json:"owner_epoch"`
	WriteEpoch            string `json:"write_epoch"`
	ApproverUserID        int64  `json:"approver_user_id"`
	ApproverCreated       string `json:"approver_created"`
	ApproverSessionID     string `json:"approver_session_id"`
	Tenant                string `json:"tenant"`
	ApprovedAt            int64  `json:"approved_at"`
	ExpiresAt             int64  `json:"expires_at"`
	ReviewChallengeDigest string `json:"review_challenge_digest"`
	// Grant-consented approvals only (domain grant-approval:v1): the basis
	// names the grant whose consent stands in for the browser review, and the
	// owner auto-approve epoch it was synthesized under. omitempty keeps
	// human approvals byte-identical to records written before they existed.
	Basis            string `json:"basis,omitempty"`
	AutoApproveEpoch string `json:"auto_approve_epoch,omitempty"`
}

const (
	appMCPHumanApprovalDomain = "benmore:mcp:human-approval:v1"
	appMCPGrantApprovalDomain = "benmore:mcp:grant-approval:v1"
	appMCPGrantConsentBasis   = "grant_consent:"
)

// appMCPGrantApprovalChallenge binds a grant-domain approval to its operation,
// grant and auto-approve epoch the way a review challenge binds a human one.
func appMCPGrantApprovalChallenge(preparedDigest, grantID, autoApproveEpoch string) string {
	return appMCPOperationDigest("benmore:mcp:grant-approval-challenge:v1", []byte(preparedDigest+"|"+grantID+"|"+autoApproveEpoch))
}

type appMCPCommandApprovalEnvelope struct {
	Version        int                         `json:"version"`
	Domain         string                      `json:"domain"`
	Approval       appMCPCommandApprovalRecord `json:"approval"`
	ApprovalDigest string                      `json:"approval_digest"`
	State          string                      `json:"state"`
	AttemptID      string                      `json:"attempt_id"`
	ConsumedAt     int64                       `json:"consumed_at"`
}

type appMCPCommandApprovalState struct {
	Approval       appMCPCommandApprovalRecord
	ApprovalDigest string
	State          string
	AttemptID      string
	ConsumedAt     int64
	Plaintext      []byte
	Ciphertext     string
}

type appMCPCommandReceiptRecord struct {
	AppID          string            `json:"app_id"`
	ApprovalDigest string            `json:"approval_digest"`
	ApprovalID     string            `json:"approval_id"`
	AttemptID      string            `json:"attempt_id"`
	CommittedAt    int64             `json:"committed_at"`
	Effects        []json.RawMessage `json:"effects"`
	Kind           string            `json:"kind"`
	OperationID    string            `json:"operation_id"`
	PreparedDigest string            `json:"prepared_digest"`
	Result         json.RawMessage   `json:"result"`
	State          string            `json:"state"`
	Version        int               `json:"version"`
}

type appMCPCommandApprovalMaintenanceRow struct {
	operationID    string
	approvalDigest string
	ciphertext     string
}

func appMCPCommandApprovalAAD(value string) bool {
	if !strings.HasPrefix(value, encPrefixV2) {
		return false
	}
	body := strings.TrimPrefix(value, encPrefixV2)
	sep := strings.IndexByte(body, ':')
	if sep < 0 {
		return false
	}
	aad, err := hex.DecodeString(body[:sep])
	if err != nil {
		return false
	}
	table, column, ok := cryptoParseAAD(aad)
	return ok && table == "_benmore_mcp_command_approvals" && column == "state_ciphertext"
}

func appMCPSealCommandApproval(key []byte, plaintext []byte) (string, error) {
	if len(key) != 32 || len(plaintext) == 0 || len(plaintext) > appMCPResultLimit || !utf8.Valid(plaintext) {
		return "", errors.New("command approval envelope is invalid")
	}
	sealed, err := fieldEncryptCtx(key, "_benmore_mcp_command_approvals", "state_ciphertext", string(plaintext))
	if err != nil || !appMCPCommandApprovalAAD(sealed) {
		return "", errors.New("command approval encryption failed")
	}
	return sealed, nil
}

func appMCPOpenCommandApproval(key []byte, sealed string) ([]byte, error) {
	if len(key) != 32 || !appMCPCommandApprovalAAD(sealed) {
		return nil, errors.New("command approval ciphertext context is invalid")
	}
	plain, err := fieldDecryptCtx(key, "state_ciphertext", sealed)
	if err != nil || !utf8.ValidString(plain) || len(plain) > appMCPResultLimit {
		return nil, errors.New("command approval ciphertext authentication failed")
	}
	return []byte(plain), nil
}

func appMCPEncodeCommandApproval(record appMCPCommandApprovalRecord) ([]byte, string, error) {
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > appMCPInputLimit {
		return nil, "", errors.New("command approval immutable record is oversized")
	}
	return encoded, appMCPOperationDigest("benmore:mcp:approval-digest:v1", encoded), nil
}

func appMCPEncodeCommandApprovalState(state appMCPCommandApprovalState) ([]byte, error) {
	_, digest, err := appMCPEncodeCommandApproval(state.Approval)
	if err != nil || !appMCPOperationHex(state.ApprovalDigest, 32) || subtle.ConstantTimeCompare([]byte(digest), []byte(state.ApprovalDigest)) != 1 {
		return nil, errors.New("command approval digest does not match immutable record")
	}
	switch state.State {
	case "approved":
		if state.AttemptID != "" || state.ConsumedAt != 0 {
			return nil, errors.New("approved command approval has consumption fields")
		}
	case "consumed":
		if !appMCPOperationHex(state.AttemptID, 32) || state.ConsumedAt < state.Approval.ApprovedAt || state.ConsumedAt >= state.Approval.ExpiresAt {
			return nil, errors.New("consumed command approval state is invalid")
		}
	default:
		return nil, errors.New("command approval state is unknown")
	}
	envelope := appMCPCommandApprovalEnvelope{Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: state.Approval,
		ApprovalDigest: state.ApprovalDigest, State: state.State, AttemptID: state.AttemptID, ConsumedAt: state.ConsumedAt}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > appMCPResultLimit {
		return nil, errors.New("command approval state envelope is oversized")
	}
	return encoded, nil
}

func appMCPDecodeCommandApproval(plaintext []byte, operation *appMCPStoredOperation, appID string) (*appMCPCommandApprovalState, error) {
	if operation == nil || len(plaintext) == 0 || len(plaintext) > appMCPResultLimit || !utf8.Valid(plaintext) {
		return nil, errors.New("command approval state is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var envelope appMCPCommandApprovalEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("command approval state envelope is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("command approval state has trailing data")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, plaintext) || envelope.Version != 1 || envelope.Domain != "benmore:mcp:command-approval-state:v1" {
		return nil, errors.New("command approval state is not canonical")
	}
	_, digest, err := appMCPEncodeCommandApproval(envelope.Approval)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(envelope.ApprovalDigest)) != 1 || !appMCPOperationHex(envelope.ApprovalDigest, 32) {
		return nil, errors.New("command approval immutable digest is invalid")
	}
	if err := appMCPValidateCommandApprovalRecord(envelope.Approval, operation, appID); err != nil {
		return nil, err
	}
	state := &appMCPCommandApprovalState{Approval: envelope.Approval, ApprovalDigest: envelope.ApprovalDigest,
		State: envelope.State, AttemptID: envelope.AttemptID, ConsumedAt: envelope.ConsumedAt, Plaintext: bytes.Clone(plaintext)}
	if state.State == "approved" {
		if state.AttemptID != "" || state.ConsumedAt != 0 {
			return nil, errors.New("approved command approval has consumption fields")
		}
	} else if state.State == "consumed" {
		if !appMCPOperationHex(state.AttemptID, 32) || state.ConsumedAt < state.Approval.ApprovedAt || state.ConsumedAt >= state.Approval.ExpiresAt {
			return nil, errors.New("consumed command approval state is invalid")
		}
	} else {
		return nil, errors.New("command approval state is unknown")
	}
	return state, nil
}

func appMCPValidateCommandApprovalRecord(record appMCPCommandApprovalRecord, operation *appMCPStoredOperation, appID string) error {
	if operation == nil {
		return errors.New("command approval operation is unavailable")
	}
	prepared := operation.Prepared
	// The approver is always the operation's own actor. A human approval names
	// the browser session that approved it; a grant-domain one names no session
	// and is bound to the preparing grant's consent and the owner epoch instead.
	var domainOK bool
	switch record.Domain {
	case appMCPHumanApprovalDomain:
		domainOK = appMCPStoredSessionID(record.ApproverSessionID) && record.Basis == "" && record.AutoApproveEpoch == ""
	case appMCPGrantApprovalDomain:
		domainOK = record.ApproverSessionID == "" && prepared.Origin.Kind == "connector" && appMCPOperationHex(prepared.Origin.GrantID, 32) &&
			record.Basis == appMCPGrantConsentBasis+prepared.Origin.GrantID && appMCPOperationHex(record.AutoApproveEpoch, 32) &&
			subtle.ConstantTimeCompare([]byte(record.ReviewChallengeDigest), []byte(appMCPGrantApprovalChallenge(operation.PreparedDigest, prepared.Origin.GrantID, record.AutoApproveEpoch))) == 1
	}
	if !domainOK || record.Version != 1 ||
		!appMCPOperationHex(record.ApprovalID, 32) || record.AppID != appID || record.AppID != prepared.AppID ||
		record.OperationID != prepared.OperationID || record.OperationID == "" ||
		subtle.ConstantTimeCompare([]byte(record.PreparedDigest), []byte(operation.PreparedDigest)) != 1 ||
		record.DisclosureVersion != prepared.DisclosureVersion || record.OwnerEpoch != prepared.RuntimeAuthority.OwnerEpoch ||
		record.WriteEpoch != prepared.RuntimeAuthority.WriteEpoch || record.ApproverUserID != prepared.Origin.ActorID ||
		record.ApproverCreated != prepared.Origin.ActorCreated || record.Tenant != prepared.Origin.Tenant ||
		record.ApprovedAt < prepared.CreatedAt || record.ApprovedAt >= prepared.ExpiresAt || record.ExpiresAt != prepared.ExpiresAt ||
		len(record.ApproverCreated) == 0 || len(record.ApproverCreated) > appMCPInputLimit || !utf8.ValidString(record.ApproverCreated) ||
		len(record.Tenant) > appMCPInputLimit || !utf8.ValidString(record.Tenant) ||
		!appMCPOperationHex(record.ReviewChallengeDigest, 32) {
		return errors.New("command approval immutable bindings are invalid")
	}
	encoded, _, err := appMCPEncodeCommandApproval(record)
	if err != nil || len(encoded) > appMCPInputLimit {
		return errors.New("command approval immutable record is oversized")
	}
	return nil
}

func appMCPStoredSessionID(value string) bool {
	return len(value) == len(sessionKeyPrefix)+64 && strings.HasPrefix(value, sessionKeyPrefix) && appMCPOperationHex(strings.TrimPrefix(value, sessionKeyPrefix), 32)
}

func verifyAppMCPCommandApprovalStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid command approval schema context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return fmt.Errorf("command approval database isolation failed: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_approvals").Scan(&count); err != nil || count != 1 {
		return errors.New("command approval schema is missing")
	}
	var name, kind, ddl string
	if err := tx.QueryRowContext(ctx, "SELECT name,type,sql FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_approvals").Scan(&name, &kind, &ddl); err != nil || name != "_benmore_mcp_command_approvals" || kind != "table" || ddl != appMCPCommandApprovalStorageDDL {
		return errors.New("command approval schema definition is altered")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA main.table_info('_benmore_mcp_command_approvals')")
	if err != nil {
		return errors.New("command approval schema inspection failed")
	}
	want := []struct {
		name        string
		typ         string
		notnull, pk int
	}{{"operation_id", "TEXT", 1, 1}, {"approval_digest", "TEXT", 1, 0}, {"state_ciphertext", "TEXT", 1, 0}}
	i := 0
	for rows.Next() {
		var cid, notnull, pk int
		var column, typ string
		var dflt any
		if err := rows.Scan(&cid, &column, &typ, &notnull, &dflt, &pk); err != nil || i >= len(want) || column != want[i].name || strings.ToUpper(typ) != want[i].typ || notnull != want[i].notnull || pk != want[i].pk || dflt != nil {
			_ = rows.Close()
			return errors.New("command approval columns are altered")
		}
		i++
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil || closeErr != nil || i != len(want) {
		return errors.New("command approval columns are incomplete")
	}
	indexes, err := tx.QueryContext(ctx, "PRAGMA main.index_list('_benmore_mcp_command_approvals')")
	if err != nil {
		return errors.New("command approval index inspection failed")
	}
	indexCount := 0
	for indexes.Next() {
		var seq, unique, partial int
		var indexName, origin string
		if err := indexes.Scan(&seq, &indexName, &unique, &origin, &partial); err != nil || indexName != "sqlite_autoindex__benmore_mcp_command_approvals_1" || unique != 1 || origin != "pk" || partial != 0 {
			_ = indexes.Close()
			return errors.New("command approval indexes are altered")
		}
		columns, err := tx.QueryContext(ctx, "PRAGMA main.index_info('sqlite_autoindex__benmore_mcp_command_approvals_1')")
		if err != nil {
			_ = indexes.Close()
			return errors.New("command approval primary index inspection failed")
		}
		columnCount := 0
		for columns.Next() {
			var seqno, cid int
			var column string
			if err := columns.Scan(&seqno, &cid, &column); err != nil || column != "operation_id" {
				_ = columns.Close()
				_ = indexes.Close()
				return errors.New("command approval primary index is altered")
			}
			columnCount++
		}
		columnErr, columnCloseErr := columns.Err(), columns.Close()
		if columnErr != nil || columnCloseErr != nil || columnCount != 1 {
			_ = indexes.Close()
			return errors.New("command approval primary index is altered")
		}
		indexCount++
	}
	indexErr, indexCloseErr := indexes.Err(), indexes.Close()
	if indexErr != nil || indexCloseErr != nil || indexCount != 1 {
		return errors.New("command approval indexes are altered")
	}
	var extras int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type IN ('trigger','view') AND (lower(name)=lower(?) OR lower(tbl_name)=lower(?))", "_benmore_mcp_command_approvals", "_benmore_mcp_command_approvals").Scan(&extras); err != nil || extras != 0 {
		return errors.New("command approval triggers or views are refused")
	}
	return nil
}

func initializeAppMCPCommandApprovalStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid command approval bootstrap context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return fmt.Errorf("command approval database isolation failed: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower(?)", "_benmore_mcp_command_approvals").Scan(&count); err != nil || count != 0 {
		return errors.New("command approval storage already exists or cannot be inspected")
	}
	if _, err := tx.ExecContext(ctx, appMCPCommandApprovalStorageDDL); err != nil {
		return errors.New("command approval storage bootstrap failed")
	}
	return verifyAppMCPCommandApprovalStorage(ctx, tx)
}

func readAppMCPCommandApproval(ctx context.Context, tx *sql.Tx, app *App, operationID string) (*appMCPCommandApprovalState, error) {
	if ctx == nil || tx == nil || app == nil || ctx.Err() != nil || !appMCPOperationHex(operationID, 32) {
		return nil, errors.New("invalid command approval read context")
	}
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	if _, err := verifyAppMCPCommandStorageWithKey(ctx, tx, appID, key); err != nil {
		return nil, err
	}
	operation, err := appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
	if err != nil {
		return nil, err
	}
	return appMCPReadCommandApprovalWithKey(ctx, tx, appID, key, operation)
}

func appMCPReadCommandApprovalWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte, operation *appMCPStoredOperation) (*appMCPCommandApprovalState, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(appID, 32) || len(key) != 32 || operation == nil {
		return nil, errors.New("invalid explicit-key command approval read")
	}
	var operationID, digest, ciphertext string
	err := tx.QueryRowContext(ctx, "SELECT operation_id,approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", operation.Prepared.OperationID).Scan(&operationID, &digest, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || operationID != operation.Prepared.OperationID || !appMCPOperationHex(digest, 32) || !appMCPCommandApprovalAAD(ciphertext) {
		return nil, errors.New("command approval row is unavailable or invalid")
	}
	plaintext, err := appMCPOpenCommandApproval(key, ciphertext)
	if err != nil {
		return nil, err
	}
	state, err := appMCPDecodeCommandApproval(plaintext, operation, appID)
	if err != nil || subtle.ConstantTimeCompare([]byte(state.ApprovalDigest), []byte(digest)) != 1 {
		return nil, errors.New("command approval row integrity failed")
	}
	state.Ciphertext = ciphertext
	return state, nil
}

func appMCPCommandReceiptSafeNumbers(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case json.Number:
			f, err := x.Float64()
			if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return false
			}
			if math.Trunc(f) == f && math.Abs(f) > float64(appMCPCommandSafeIntegerMax) {
				return false
			}
		case []any:
			for _, item := range x {
				if !walk(item) {
					return false
				}
			}
		case map[string]any:
			for _, item := range x {
				if !walk(item) {
					return false
				}
			}
		}
		return true
	}
	return walk(value)
}

func decodeAppMCPCommandReceipt(stored *appMCPStoredOperation, approval *appMCPCommandApprovalState) (*appMCPCommandReceiptRecord, error) {
	if stored == nil || approval == nil || stored.Receipt == nil || approval.State != "consumed" || len(stored.Receipt) > appMCPResultLimit || !utf8.Valid(stored.Receipt) {
		return nil, errors.New("command receipt is unavailable or incoherent")
	}
	decoder := json.NewDecoder(bytes.NewReader(stored.Receipt))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var receipt appMCPCommandReceiptRecord
	if err := decoder.Decode(&receipt); err != nil {
		return nil, errors.New("command receipt is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("command receipt has trailing content")
	}
	canonical, err := json.Marshal(receipt)
	_, preparedDigest, preparedErr := appMCPEncodePrepared(stored.Prepared)
	receiptDigest := appMCPOperationDigest("benmore:mcp:receipt:v1", stored.Receipt)
	if err != nil || !bytes.Equal(canonical, stored.Receipt) || receipt.Version != 1 || receipt.Kind != "command_receipt" || receipt.State != "committed" ||
		!appMCPOperationHex(receipt.AppID, 32) || !appMCPOperationHex(receipt.OperationID, 32) || !appMCPOperationHex(receipt.PreparedDigest, 32) ||
		!appMCPOperationHex(receipt.ApprovalID, 32) || !appMCPOperationHex(receipt.ApprovalDigest, 32) || !appMCPOperationHex(receipt.AttemptID, 32) ||
		receipt.AppID != stored.Prepared.AppID || receipt.OperationID != stored.Prepared.OperationID ||
		preparedErr != nil || appMCPValidateOperationRecord(stored.Prepared, stored.Prepared.AppID) != nil ||
		subtle.ConstantTimeCompare([]byte(preparedDigest), []byte(stored.PreparedDigest)) != 1 || subtle.ConstantTimeCompare([]byte(receipt.PreparedDigest), []byte(stored.PreparedDigest)) != 1 ||
		!appMCPOperationHex(stored.ReceiptDigest, 32) || subtle.ConstantTimeCompare([]byte(receiptDigest), []byte(stored.ReceiptDigest)) != 1 ||
		receipt.ApprovalID != approval.Approval.ApprovalID || subtle.ConstantTimeCompare([]byte(receipt.ApprovalDigest), []byte(approval.ApprovalDigest)) != 1 ||
		receipt.AttemptID != approval.AttemptID || receipt.CommittedAt != approval.ConsumedAt || receipt.CommittedAt < approval.Approval.ApprovedAt || receipt.CommittedAt >= stored.Prepared.ExpiresAt ||
		receipt.Result == nil || appMCPOperationObject(receipt.Result, appMCPResultLimit) != nil || !appMCPCommandReceiptSafeNumbers(receipt.Result) || receipt.Effects == nil {
		return nil, errors.New("command receipt bindings or shape are invalid")
	}
	if _, err := appMCPDecodeEffects(receipt.Effects); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func appMCPReadCommandApprovalRows(ctx context.Context, tx *sql.Tx) ([]appMCPCommandApprovalMaintenanceRow, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return nil, errors.New("invalid command approval inventory context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return nil, errors.New("command approval inventory database isolation failed")
	}
	rows, err := tx.QueryContext(ctx, "SELECT operation_id,approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals ORDER BY operation_id")
	if err != nil {
		return nil, errors.New("command approval inventory failed")
	}
	out := make([]appMCPCommandApprovalMaintenanceRow, 0)
	for rows.Next() {
		var row appMCPCommandApprovalMaintenanceRow
		if err := rows.Scan(&row.operationID, &row.approvalDigest, &row.ciphertext); err != nil {
			_ = rows.Close()
			return nil, errors.New("command approval inventory is invalid")
		}
		out = append(out, row)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil || closeErr != nil {
		return nil, errors.New("command approval inventory could not be read completely")
	}
	return out, nil
}

func appMCPValidateCommandStoreUnion(ctx context.Context, tx *sql.Tx, appID string, key []byte) (map[string]*appMCPStoredOperation, map[string]*appMCPCommandApprovalState, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(appID, 32) || len(key) != 32 {
		return nil, nil, errors.New("invalid command store maintenance context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return nil, nil, err
	}
	if err := verifyAppMCPOperationStorage(ctx, tx); err != nil {
		return nil, nil, err
	}
	if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
		return nil, nil, err
	}
	if err := verifyAppMCPCommandAttemptStorage(ctx, tx); err != nil {
		return nil, nil, err
	}
	state, err := readAppEncryptionState(ctx, tx, appID, key)
	if err != nil || state == nil || state.CommandStorageVersion != 2 || !state.OperationStorageProvisioned {
		return nil, nil, errors.New("command storage marker is not provisioned")
	}
	operationRows, err := tx.QueryContext(ctx, "SELECT operation_id FROM main._benmore_mcp_operations ORDER BY operation_id")
	if err != nil {
		return nil, nil, errors.New("command operation inventory failed")
	}
	operations := make(map[string]*appMCPStoredOperation)
	var ids []string
	for operationRows.Next() {
		var id string
		if err := operationRows.Scan(&id); err != nil {
			_ = operationRows.Close()
			return nil, nil, errors.New("command operation inventory is invalid")
		}
		ids = append(ids, id)
	}
	rowsErr, closeErr := operationRows.Err(), operationRows.Close()
	if rowsErr != nil || closeErr != nil {
		return nil, nil, errors.New("command operation inventory could not be read completely")
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, nil, errors.New("command operation verification was canceled")
		}
		if !appMCPOperationHex(id, 32) {
			return nil, nil, errors.New("command operation inventory contains an invalid identifier")
		}
		operation, err := appMCPReadOperationWithKey(ctx, tx, appID, key, id)
		if err != nil {
			return nil, nil, err
		}
		operations[id] = operation
	}
	approvalRows, err := appMCPReadCommandApprovalRows(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	approvals := make(map[string]*appMCPCommandApprovalState)
	for _, row := range approvalRows {
		operation := operations[row.operationID]
		if operation == nil || !appMCPOperationHex(row.operationID, 32) || !appMCPOperationHex(row.approvalDigest, 32) || !appMCPCommandApprovalAAD(row.ciphertext) {
			return nil, nil, errors.New("command approval is orphaned or malformed")
		}
		plain, err := appMCPOpenCommandApproval(key, row.ciphertext)
		if err != nil {
			return nil, nil, err
		}
		state, err := appMCPDecodeCommandApproval(plain, operation, appID)
		if err != nil || subtle.ConstantTimeCompare([]byte(state.ApprovalDigest), []byte(row.approvalDigest)) != 1 {
			return nil, nil, errors.New("command approval row failed authenticated validation")
		}
		state.Ciphertext = row.ciphertext
		approvals[row.operationID] = state
	}
	for id, operation := range operations {
		approval := approvals[id]
		if operation.Receipt == nil {
			if approval != nil && approval.State != "approved" {
				return nil, nil, errors.New("consumed command approval lacks a committed receipt")
			}
			continue
		}
		if approval == nil || approval.State != "consumed" {
			return nil, nil, errors.New("command receipt lacks a consumed approval")
		}
		if _, err := decodeAppMCPCommandReceipt(operation, approval); err != nil {
			return nil, nil, err
		}
	}
	if err := appMCPValidateAttempts(ctx, tx, appID, key, operations); err != nil {
		return nil, nil, err
	}
	return operations, approvals, nil
}

func verifyAppMCPCommandApprovalsWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte) (int, error) {
	_, approvals, err := appMCPValidateCommandStoreUnion(ctx, tx, appID, key)
	if err != nil {
		return 0, err
	}
	return len(approvals), nil
}

func rotateAppMCPCommandApprovalsTx(ctx context.Context, tx *sql.Tx, appID string, oldKey, newKey []byte) (int, error) {
	if len(oldKey) != 32 || len(newKey) != 32 || subtle.ConstantTimeCompare(oldKey, newKey) == 1 {
		return 0, errors.New("invalid command approval rotation keys")
	}
	_, approvals, err := appMCPValidateCommandStoreUnion(ctx, tx, appID, oldKey)
	if err != nil {
		return 0, err
	}
	rows, err := appMCPReadCommandApprovalRows(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return 0, errors.New("command approval reseal was canceled")
		}
		state := approvals[row.operationID]
		if state == nil || state.Ciphertext != row.ciphertext || state.ApprovalDigest != row.approvalDigest || len(state.Plaintext) == 0 {
			return 0, errors.New("command approval plaintext changed before reseal")
		}
		sealed, err := appMCPSealCommandApproval(newKey, state.Plaintext)
		if err != nil {
			return 0, err
		}
		if err := appMCPResealCommandApprovalCAS(ctx, tx, row, sealed); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

func appMCPResealCommandApprovalCAS(ctx context.Context, tx *sql.Tx, row appMCPCommandApprovalMaintenanceRow, replacement string) error {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(row.operationID, 32) || !appMCPOperationHex(row.approvalDigest, 32) ||
		!appMCPCommandApprovalAAD(row.ciphertext) || !appMCPCommandApprovalAAD(replacement) || row.ciphertext == replacement {
		return errors.New("invalid command approval reseal compare-and-swap")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return errors.New("command approval reseal database isolation failed")
	}
	result, err := tx.ExecContext(ctx, "UPDATE main._benmore_mcp_command_approvals SET state_ciphertext=? WHERE operation_id=? AND approval_digest=? AND state_ciphertext COLLATE BINARY=?", replacement, row.operationID, row.approvalDigest, row.ciphertext)
	if err != nil {
		return errors.New("command approval reseal update failed")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New("command approval reseal compare-and-swap failed")
	}
	return nil
}
