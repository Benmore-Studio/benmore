//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/mattn/go-sqlite3"
)

const appMCPOperationStorageDDL = `CREATE TABLE _benmore_mcp_operations (
	operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id)=64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
	prepared_digest TEXT NOT NULL CHECK(length(prepared_digest)=64 AND prepared_digest NOT GLOB '*[^0-9a-f]*'),
	prepared_ciphertext TEXT NOT NULL,
	receipt_digest TEXT CHECK(receipt_digest IS NULL OR (length(receipt_digest)=64 AND receipt_digest NOT GLOB '*[^0-9a-f]*')),
	receipt_ciphertext TEXT,
	CHECK((receipt_digest IS NULL) = (receipt_ciphertext IS NULL))
)`

type appMCPOperationRuntimeAuthority struct {
	Version             int    `json:"version"`
	OwnerEpoch          string `json:"owner_epoch"`
	WriteEpoch          string `json:"write_epoch"`
	ExternalExportEpoch string `json:"external_export_epoch,omitempty"`
}

type appMCPOperationOriginRecord struct {
	Kind           string   `json:"kind"`
	ActorID        int64    `json:"actor_id"`
	ActorCreated   string   `json:"actor_created"`
	Tenant         string   `json:"tenant"`
	Permissions    []string `json:"permissions"`
	GrantID        string   `json:"grant_id,omitempty"`
	Client         string   `json:"client,omitempty"`
	Resource       string   `json:"resource,omitempty"`
	CredentialHash string   `json:"credential_hash,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
	// ActorRole/ActorAdmin seal the global role bindings (${{ user.role }},
	// ${{ user.is_admin }}) the approved preview ran with. Records written
	// before they existed carry neither and are not compared.
	ActorRole  string `json:"actor_role,omitempty"`
	ActorAdmin bool   `json:"actor_admin,omitempty"`
}

// appMCPPreparedOperationRecord is private persisted input data, never proof
// of authority, approval, or current runtime state.
type appMCPPreparedOperationRecord struct {
	Version           int                             `json:"version"`
	OperationID       string                          `json:"operation_id"`
	AppID             string                          `json:"app_id"`
	Command           string                          `json:"command"`
	ContractDigest    string                          `json:"contract_digest"`
	ExecutionDigest   string                          `json:"execution_digest"`
	DisclosureVersion string                          `json:"disclosure_version"`
	RuntimeAuthority  appMCPOperationRuntimeAuthority `json:"runtime_authority"`
	Origin            appMCPOperationOriginRecord     `json:"origin"`
	CreatedAt         int64                           `json:"created_at"`
	ExpiresAt         int64                           `json:"expires_at"`
	Intent            json.RawMessage                 `json:"intent"`
	Arguments         json.RawMessage                 `json:"arguments"`
	Dependencies      json.RawMessage                 `json:"dependencies"`
	Preview           json.RawMessage                 `json:"preview"`
	// ApprovalReason is the fixed phrase saying why this connector call was not
	// applied without a person (appMCPApprovalReason). Omitted when empty, so
	// the digest of every operation without one is unchanged.
	ApprovalReason string `json:"approval_reason,omitempty"`
}

// appMCPStoredOperation is transaction-local readback. A receipt returned
// before caller COMMIT is only a candidate and does not establish commit.
type appMCPStoredOperation struct {
	Prepared       appMCPPreparedOperationRecord `json:"prepared"`
	PreparedDigest string                        `json:"prepared_digest"`
	Receipt        []byte                        `json:"receipt,omitempty"`
	ReceiptDigest  string                        `json:"receipt_digest,omitempty"`
}

type appMCPStoredReceiptEnvelope struct {
	Version        int             `json:"version"`
	Kind           string          `json:"kind"`
	OperationID    string          `json:"operation_id"`
	PreparedDigest string          `json:"prepared_digest"`
	ReceiptDigest  string          `json:"receipt_digest"`
	Receipt        json.RawMessage `json:"receipt"`
}

func appMCPOperationHex(value string, n int) bool {
	if len(value) != n*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func appMCPOperationOwnerID(dir string) (string, error) {
	appDir, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.New("cannot resolve operation storage application identity")
	}
	return hashBytesSHA256([]byte(realPathForContainment(appDir))), nil
}

func appMCPOperationContext(ctx context.Context, tx *sql.Tx, app *App) (string, []byte, error) {
	if ctx == nil || tx == nil || app == nil || ctx.Err() != nil || strings.TrimSpace(app.Dir) == "" {
		return "", nil, errors.New("invalid operation storage context")
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := q.cleanMain(); err != nil {
		return "", nil, fmt.Errorf("operation storage database isolation failed: %w", err)
	}
	var mainPath string
	if err := tx.QueryRowContext(ctx, "SELECT file FROM main.pragma_database_list WHERE name='main'").Scan(&mainPath); err != nil || mainPath == "" {
		return "", nil, errors.New("operation storage main database is unavailable")
	}
	expected := filepath.Join(app.Dir, "data.db")
	if canonicalDBPath(mainPath) != canonicalDBPath(expected) {
		return "", nil, errors.New("operation storage database does not belong to application")
	}
	keys := cryptoKeysForDBPath(mainPath)
	if keys == nil || len(keys.aes) == 0 || keys.ephemeral {
		return "", nil, errors.New("operation storage requires a registered durable encryption key")
	}
	appID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		return "", nil, err
	}
	return appID, keys.aes, nil
}

func appMCPOperationObject(data []byte, max int) error {
	if len(data) == 0 || len(data) > max || !utf8.Valid(data) {
		return errors.New("operation storage JSON bytes are invalid or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("operation storage JSON is invalid")
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("operation storage JSON root must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("operation storage JSON has trailing content")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("operation storage JSON is not canonical")
	}
	return nil
}

func appMCPValidateOperationRecord(record appMCPPreparedOperationRecord, appID string) error {
	if record.Version != 1 || !appMCPOperationHex(record.OperationID, 32) || record.AppID != appID ||
		record.Command == "" || record.DisclosureVersion == "" || len(record.Command) > appMCPInputLimit || len(record.DisclosureVersion) > appMCPInputLimit ||
		!utf8.ValidString(record.Command) || !utf8.ValidString(record.DisclosureVersion) ||
		!appMCPOperationHex(record.ContractDigest, 32) || !appMCPOperationHex(record.ExecutionDigest, 32) ||
		record.RuntimeAuthority.Version != 1 || !appMCPOperationHex(record.RuntimeAuthority.OwnerEpoch, 32) || !appMCPOperationHex(record.RuntimeAuthority.WriteEpoch, 32) {
		return errors.New("operation storage prepared bindings are invalid")
	}
	if len(record.ApprovalReason) > 256 || !utf8.ValidString(record.ApprovalReason) {
		return errors.New("operation storage approval reason is invalid")
	}
	if record.CreatedAt <= 0 || record.CreatedAt > math.MaxInt64-15*60 || record.ExpiresAt != record.CreatedAt+15*60 {
		return errors.New("operation storage expiry is invalid")
	}
	if record.RuntimeAuthority.ExternalExportEpoch != "" && !appMCPOperationHex(record.RuntimeAuthority.ExternalExportEpoch, 32) {
		return errors.New("operation storage external export binding is invalid")
	}
	o := record.Origin
	// An empty tenant is the workspace of an app without groups; the command
	// authority refuses an empty or "0" tenant whenever the app has groups.
	if o.ActorID <= 0 || o.ActorCreated == "" || len(o.ActorCreated) > appMCPInputLimit || len(o.Tenant) > appMCPInputLimit ||
		!utf8.ValidString(o.ActorCreated) || !utf8.ValidString(o.Tenant) || len(o.Permissions) == 0 {
		return errors.New("operation storage origin is incomplete")
	}
	for _, value := range []string{o.Kind, o.ActorCreated, o.Tenant, o.GrantID, o.Client, o.Resource, o.CredentialHash, o.SessionID, o.ActorRole} {
		if len(value) > appMCPInputLimit || !utf8.ValidString(value) {
			return errors.New("operation storage origin is oversized or invalid")
		}
	}
	if err := validateFlowPermissions(o.Permissions); err != nil {
		return errors.New("operation storage permissions are invalid")
	}
	for i, permission := range o.Permissions {
		if len(permission) > appMCPInputLimit || (i > 0 && o.Permissions[i-1] >= permission) {
			return errors.New("operation storage permissions must be sorted and unique")
		}
	}
	explicitScopes, err := appMCPExplicitScopes(strings.Join(o.Permissions, " "))
	if err != nil || len(explicitScopes) != len(o.Permissions) {
		return errors.New("operation storage permissions are not explicit")
	}
	for i := range explicitScopes {
		if explicitScopes[i] != o.Permissions[i] {
			return errors.New("operation storage permissions must remain sorted")
		}
	}
	switch o.Kind {
	case "connector":
		if o.GrantID == "" || o.Client == "" || o.Resource == "" || !appMCPOperationHex(o.CredentialHash, 32) || o.SessionID != "" {
			return errors.New("operation storage connector origin is incomplete")
		}
	case "app_session":
		if o.GrantID != "" || o.Client != "" || o.Resource != "" || o.CredentialHash != "" || len(o.SessionID) != len(sessionKeyPrefix)+64 || !strings.HasPrefix(o.SessionID, sessionKeyPrefix) || !appMCPOperationHex(strings.TrimPrefix(o.SessionID, sessionKeyPrefix), 32) {
			return errors.New("operation storage app session origin is invalid")
		}
	default:
		return errors.New("operation storage origin kind is invalid")
	}
	for _, item := range []struct {
		value []byte
		max   int
	}{{record.Intent, appMCPInputLimit}, {record.Arguments, appMCPInputLimit}, {record.Dependencies, appMCPResultLimit}, {record.Preview, appMCPResultLimit}} {
		if err := appMCPOperationObject(item.value, item.max); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > appMCPResultLimit {
		return errors.New("operation storage prepared record is oversized")
	}
	return nil
}

func appMCPOperationDigest(domain string, data []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func appMCPOperationAAD(value, column string) bool {
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
	table, gotColumn, ok := cryptoParseAAD(aad)
	return ok && table == "_benmore_mcp_operations" && gotColumn == column
}

func appMCPVerifyOperationStorage(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&count); err != nil || count != 1 {
		return errors.New("operation storage schema is missing")
	}
	var kind, ddl string
	if err := tx.QueryRowContext(ctx, "SELECT type,sql FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&kind, &ddl); err != nil || kind != "table" || ddl != appMCPOperationStorageDDL {
		return errors.New("operation storage schema definition is altered")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA main.table_info('_benmore_mcp_operations')")
	if err != nil {
		return errors.New("operation storage schema inspection failed")
	}
	defer rows.Close()
	want := []struct {
		name, typ   string
		notnull, pk int
	}{{"operation_id", "TEXT", 1, 1}, {"prepared_digest", "TEXT", 1, 0}, {"prepared_ciphertext", "TEXT", 1, 0}, {"receipt_digest", "TEXT", 0, 0}, {"receipt_ciphertext", "TEXT", 0, 0}}
	i := 0
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil || i >= len(want) || name != want[i].name || strings.ToUpper(typ) != want[i].typ || notnull != want[i].notnull || pk != want[i].pk {
			return errors.New("operation storage columns are altered")
		}
		i++
	}
	if err := rows.Err(); err != nil || i != len(want) {
		return errors.New("operation storage columns are incomplete")
	}
	indexes, err := tx.QueryContext(ctx, "PRAGMA main.index_list('_benmore_mcp_operations')")
	if err != nil {
		return errors.New("operation storage index inspection failed")
	}
	indexCount := 0
	for indexes.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := indexes.Scan(&seq, &name, &unique, &origin, &partial); err != nil || name != "sqlite_autoindex__benmore_mcp_operations_1" || unique != 1 || origin != "pk" || partial != 0 {
			indexes.Close()
			return errors.New("operation storage indexes are altered")
		}
		indexColumns, err := tx.QueryContext(ctx, "PRAGMA main.index_info('sqlite_autoindex__benmore_mcp_operations_1')")
		if err != nil {
			indexes.Close()
			return errors.New("operation storage primary index inspection failed")
		}
		var indexColumnCount int
		for indexColumns.Next() {
			var seqno, cid int
			var column string
			if err := indexColumns.Scan(&seqno, &cid, &column); err != nil || column != "operation_id" {
				indexColumns.Close()
				indexes.Close()
				return errors.New("operation storage primary index is altered")
			}
			indexColumnCount++
		}
		columnErr := indexColumns.Err()
		indexColumns.Close()
		if columnErr != nil || indexColumnCount != 1 {
			indexes.Close()
			return errors.New("operation storage primary index is altered")
		}
		indexCount++
	}
	indexErr := indexes.Err()
	indexes.Close()
	if indexErr != nil || indexCount != 1 {
		return errors.New("operation storage indexes are altered")
	}
	var triggers int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name COLLATE NOCASE='_benmore_mcp_operations'").Scan(&triggers); err != nil || triggers != 0 {
		return errors.New("operation storage triggers are refused")
	}
	return nil
}

func initializeAppMCPOperationStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid operation storage bootstrap context")
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := q.cleanMain(); err != nil {
		return fmt.Errorf("operation storage database isolation failed: %w", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&count); err != nil || count != 0 {
		return errors.New("operation storage already exists or cannot be inspected")
	}
	if _, err := tx.ExecContext(ctx, appMCPOperationStorageDDL); err != nil {
		return errors.New("operation storage bootstrap failed")
	}
	return appMCPVerifyOperationStorage(ctx, tx)
}

func verifyAppMCPOperationStorage(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid operation storage verification context")
	}
	if err := (appMCPContextTx{tx: tx, ctx: ctx, private: true}).cleanMain(); err != nil {
		return fmt.Errorf("operation storage database isolation failed: %w", err)
	}
	return appMCPVerifyOperationStorage(ctx, tx)
}

func appMCPReadyOperationStorage(ctx context.Context, tx *sql.Tx, app *App) (string, []byte, error) {
	appID, key, err := appMCPOperationContext(ctx, tx, app)
	if err != nil {
		return "", nil, err
	}
	if err := appMCPVerifyOperationStorage(ctx, tx); err != nil {
		return "", nil, err
	}
	return appID, key, nil
}

func appMCPCopyOperationRecord(record appMCPPreparedOperationRecord) appMCPPreparedOperationRecord {
	record.Intent = bytes.Clone(record.Intent)
	record.Arguments = bytes.Clone(record.Arguments)
	record.Dependencies = bytes.Clone(record.Dependencies)
	record.Preview = bytes.Clone(record.Preview)
	record.Origin.Permissions = append([]string(nil), record.Origin.Permissions...)
	return record
}

func appMCPEncodePrepared(record appMCPPreparedOperationRecord) ([]byte, string, error) {
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > appMCPResultLimit {
		return nil, "", errors.New("operation storage prepared record is oversized")
	}
	return encoded, appMCPOperationDigest("benmore:mcp:prepared:v1", encoded), nil
}

func appMCPSealOperation(key []byte, column string, value []byte) (string, error) {
	sealed, err := fieldEncryptCtx(key, "_benmore_mcp_operations", column, string(value))
	if err != nil || !appMCPOperationAAD(sealed, column) {
		return "", errors.New("operation storage encryption failed")
	}
	return sealed, nil
}

func appMCPOpenOperation(key []byte, column, sealed string) ([]byte, error) {
	if !appMCPOperationAAD(sealed, column) {
		return nil, errors.New("operation storage ciphertext context is invalid")
	}
	plain, err := fieldDecryptCtx(key, column, sealed)
	if err != nil {
		return nil, errors.New("operation storage ciphertext authentication failed")
	}
	return []byte(plain), nil
}

func appMCPReadOperationWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte, operationID string) (*appMCPStoredOperation, error) {
	if !appMCPOperationHex(operationID, 32) {
		return nil, errors.New("operation storage identity is invalid")
	}
	var rowID, digest, preparedCipher string
	var receiptDigest, receiptCipher sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT operation_id,prepared_digest,prepared_ciphertext,receipt_digest,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", operationID).
		Scan(&rowID, &digest, &preparedCipher, &receiptDigest, &receiptCipher)
	if err != nil {
		return nil, errors.New("operation storage record is unavailable")
	}
	if rowID != operationID || !appMCPOperationHex(digest, 32) || receiptDigest.Valid != receiptCipher.Valid {
		return nil, errors.New("operation storage row integrity failed")
	}
	plain, err := appMCPOpenOperation(key, "prepared_ciphertext", preparedCipher)
	if err != nil {
		return nil, err
	}
	var record appMCPPreparedOperationRecord
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.UseNumber()
	if err := decoder.Decode(&record); err != nil {
		return nil, errors.New("operation storage prepared record is invalid")
	}
	encoded, calculated, err := appMCPEncodePrepared(record)
	if err != nil || !bytes.Equal(encoded, plain) || subtle.ConstantTimeCompare([]byte(calculated), []byte(digest)) != 1 || record.OperationID != operationID || record.AppID != appID || appMCPValidateOperationRecord(record, appID) != nil {
		return nil, errors.New("operation storage prepared record integrity failed")
	}
	stored := &appMCPStoredOperation{Prepared: appMCPCopyOperationRecord(record), PreparedDigest: digest}
	if receiptDigest.Valid {
		if !appMCPOperationHex(receiptDigest.String, 32) {
			return nil, errors.New("operation storage receipt digest is invalid")
		}
		receiptPlain, err := appMCPOpenOperation(key, "receipt_ciphertext", receiptCipher.String)
		if err != nil {
			return nil, err
		}
		var envelope appMCPStoredReceiptEnvelope
		dec := json.NewDecoder(bytes.NewReader(receiptPlain))
		dec.UseNumber()
		if err := dec.Decode(&envelope); err != nil {
			return nil, errors.New("operation storage receipt is invalid")
		}
		canonical, marshalErr := json.Marshal(envelope)
		calcReceipt := appMCPOperationDigest("benmore:mcp:receipt:v1", envelope.Receipt)
		if marshalErr != nil || !bytes.Equal(canonical, receiptPlain) || envelope.Version != 1 || envelope.Kind != "committed_receipt" || envelope.OperationID != operationID ||
			subtle.ConstantTimeCompare([]byte(envelope.PreparedDigest), []byte(digest)) != 1 || subtle.ConstantTimeCompare([]byte(envelope.ReceiptDigest), []byte(receiptDigest.String)) != 1 ||
			subtle.ConstantTimeCompare([]byte(calcReceipt), []byte(receiptDigest.String)) != 1 || appMCPOperationObject(envelope.Receipt, appMCPResultLimit) != nil {
			return nil, errors.New("operation storage receipt integrity failed")
		}
		stored.Receipt = bytes.Clone(envelope.Receipt)
		stored.ReceiptDigest = receiptDigest.String
	}
	return stored, nil
}

func readAppMCPStoredOperation(ctx context.Context, tx *sql.Tx, app *App, operationID string) (*appMCPStoredOperation, error) {
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	return appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
}

func insertAppMCPPreparedOperation(ctx context.Context, tx *sql.Tx, app *App, prepared appMCPPreparedOperationRecord) (*appMCPStoredOperation, error) {
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	prepared = appMCPCopyOperationRecord(prepared)
	if err := appMCPValidateOperationRecord(prepared, appID); err != nil {
		return nil, err
	}
	encoded, digest, err := appMCPEncodePrepared(prepared)
	if err != nil {
		return nil, err
	}
	ciphertext, err := appMCPSealOperation(key, "prepared_ciphertext", encoded)
	if err != nil {
		return nil, err
	}
	_, insertErr := tx.ExecContext(ctx, "INSERT INTO main._benmore_mcp_operations(operation_id,prepared_digest,prepared_ciphertext) VALUES(?,?,?)", prepared.OperationID, digest, ciphertext)
	if insertErr == nil {
		return &appMCPStoredOperation{Prepared: appMCPCopyOperationRecord(prepared), PreparedDigest: digest}, nil
	}
	var sqliteErr sqlite3.Error
	if !errors.As(insertErr, &sqliteErr) || sqliteErr.Code != sqlite3.ErrConstraint || sqliteErr.ExtendedCode != sqlite3.ErrConstraintPrimaryKey {
		return nil, errors.New("operation storage insert failed")
	}
	old, readErr := appMCPReadOperationWithKey(ctx, tx, appID, key, prepared.OperationID)
	if readErr != nil {
		return nil, errors.New("operation storage insert failed")
	}
	oldEncoded, _, _ := appMCPEncodePrepared(old.Prepared)
	if subtle.ConstantTimeCompare([]byte(old.PreparedDigest), []byte(digest)) != 1 || !bytes.Equal(oldEncoded, encoded) {
		return nil, errors.New("operation storage identity conflicts with existing content")
	}
	return old, nil
}

func storeAppMCPCommittedReceipt(ctx context.Context, tx *sql.Tx, app *App, operationID, preparedDigest string, receipt []byte) (*appMCPStoredOperation, error) {
	appID, key, err := appMCPReadyOperationStorage(ctx, tx, app)
	if err != nil {
		return nil, err
	}
	if err := appMCPOperationObject(receipt, appMCPResultLimit); err != nil {
		return nil, err
	}
	if !appMCPOperationHex(preparedDigest, 32) {
		return nil, errors.New("operation storage prepared digest is invalid")
	}
	current, err := appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(current.PreparedDigest), []byte(preparedDigest)) != 1 {
		return nil, errors.New("operation storage prepared digest conflicts")
	}
	receiptDigest := appMCPOperationDigest("benmore:mcp:receipt:v1", receipt)
	if current.Receipt != nil {
		if subtle.ConstantTimeCompare([]byte(current.ReceiptDigest), []byte(receiptDigest)) != 1 || !bytes.Equal(current.Receipt, receipt) {
			return nil, errors.New("operation storage receipt conflicts with immutable receipt")
		}
		return current, nil
	}
	envelope := appMCPStoredReceiptEnvelope{Version: 1, Kind: "committed_receipt", OperationID: operationID, PreparedDigest: preparedDigest, ReceiptDigest: receiptDigest, Receipt: bytes.Clone(receipt)}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil || len(envelopeBytes) > appMCPResultLimit {
		return nil, errors.New("operation storage receipt envelope is oversized")
	}
	ciphertext, err := appMCPSealOperation(key, "receipt_ciphertext", envelopeBytes)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE main._benmore_mcp_operations SET receipt_digest=?,receipt_ciphertext=? WHERE operation_id=? AND prepared_digest=? AND receipt_digest IS NULL AND receipt_ciphertext IS NULL", receiptDigest, ciphertext, operationID, preparedDigest)
	if err != nil {
		return nil, errors.New("operation storage receipt attachment failed")
	}
	changed, err := result.RowsAffected()
	if err != nil || changed > 1 {
		return nil, errors.New("operation storage receipt attachment cardinality failed")
	}
	stored, err := appMCPReadOperationWithKey(ctx, tx, appID, key, operationID)
	if err != nil {
		return nil, err
	}
	if changed == 1 && stored.ReceiptDigest == receiptDigest && bytes.Equal(stored.Receipt, receipt) {
		return stored, nil
	}
	if stored.ReceiptDigest == receiptDigest && bytes.Equal(stored.Receipt, receipt) {
		return stored, nil
	}
	return nil, errors.New("operation storage receipt conflicts with immutable receipt")
}

// appMCPOperationMaintenanceRow is the exact row image used for maintenance CAS.
type appMCPOperationMaintenanceRow struct {
	operationID    string
	preparedDigest string
	preparedCipher string
	receiptDigest  sql.NullString
	receiptCipher  sql.NullString
}

func appMCPReadOperationMaintenanceRows(ctx context.Context, tx *sql.Tx) ([]appMCPOperationMaintenanceRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT operation_id,prepared_digest,prepared_ciphertext,receipt_digest,receipt_ciphertext
		FROM main._benmore_mcp_operations ORDER BY operation_id`)
	if err != nil {
		return nil, errors.New("operation storage maintenance inventory failed")
	}
	out := make([]appMCPOperationMaintenanceRow, 0)
	for rows.Next() {
		var row appMCPOperationMaintenanceRow
		if scanErr := rows.Scan(&row.operationID, &row.preparedDigest, &row.preparedCipher, &row.receiptDigest, &row.receiptCipher); scanErr != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return nil, errors.New("operation storage maintenance inventory scan and close failed")
			}
			return nil, errors.New("operation storage maintenance inventory is invalid")
		}
		out = append(out, row)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil || closeErr != nil {
		return nil, errors.New("operation storage maintenance inventory could not be read completely")
	}
	return out, nil
}

func appMCPValidateOperationMaintenanceInputs(ctx context.Context, tx *sql.Tx, appID string, keys ...[]byte) error {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(appID, 32) {
		return errors.New("invalid operation storage maintenance context")
	}
	for _, key := range keys {
		if len(key) != 32 {
			return errors.New("invalid operation storage maintenance key")
		}
	}
	return verifyAppMCPOperationStorage(ctx, tx)
}

func appMCPValidateOperationMaintenanceRow(ctx context.Context, tx *sql.Tx, appID string, key []byte, row appMCPOperationMaintenanceRow) (*appMCPStoredOperation, error) {
	if row.receiptDigest.Valid != row.receiptCipher.Valid {
		return nil, errors.New("operation storage maintenance row integrity failed")
	}
	stored, err := appMCPReadOperationWithKey(ctx, tx, appID, key, row.operationID)
	if err != nil {
		return nil, err
	}
	if stored.PreparedDigest != row.preparedDigest {
		return nil, errors.New("operation storage maintenance row changed during validation")
	}
	if row.receiptDigest.Valid {
		if stored.Receipt == nil || stored.ReceiptDigest != row.receiptDigest.String {
			return nil, errors.New("operation storage maintenance receipt changed during validation")
		}
	} else if stored.Receipt != nil || stored.ReceiptDigest != "" {
		return nil, errors.New("operation storage maintenance receipt changed during validation")
	}
	return stored, nil
}

// verifyAppMCPOperationRowsWithKey authenticates every stored operation using
// the supplied durable generation key. It neither commits nor changes rows.
func verifyAppMCPOperationRowsWithKey(ctx context.Context, tx *sql.Tx, appID string, key []byte) (int, error) {
	if err := appMCPValidateOperationMaintenanceInputs(ctx, tx, appID, key); err != nil {
		return 0, err
	}
	rows, err := appMCPReadOperationMaintenanceRows(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return 0, errors.New("operation storage verification was canceled")
		}
		if _, err := appMCPValidateOperationMaintenanceRow(ctx, tx, appID, key, row); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, errors.New("operation storage verification was canceled")
	}
	return len(rows), nil
}

// rotateAppMCPOperationRowsWithKeys reseals complete authenticated rows under
// newKey in the caller's transaction. Any error requires caller rollback.
func rotateAppMCPOperationRowsWithKeys(ctx context.Context, tx *sql.Tx, appID string, oldKey, newKey []byte) (int, error) {
	if bytes.Equal(oldKey, newKey) {
		return 0, errors.New("operation storage rotation keys are identical")
	}
	if err := appMCPValidateOperationMaintenanceInputs(ctx, tx, appID, oldKey, newKey); err != nil {
		return 0, err
	}
	rows, err := appMCPReadOperationMaintenanceRows(ctx, tx)
	if err != nil {
		return 0, err
	}
	type resealedRow struct {
		old            appMCPOperationMaintenanceRow
		preparedCipher string
		receiptCipher  sql.NullString
	}
	resealed := make([]resealedRow, 0, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return 0, errors.New("operation storage rotation was canceled")
		}
		if _, err := appMCPValidateOperationMaintenanceRow(ctx, tx, appID, oldKey, row); err != nil {
			return 0, err
		}
		preparedPlain, err := appMCPOpenOperation(oldKey, "prepared_ciphertext", row.preparedCipher)
		if err != nil {
			return 0, err
		}
		preparedCipher, err := appMCPSealOperation(newKey, "prepared_ciphertext", preparedPlain)
		if err != nil {
			return 0, err
		}
		newReceipt := sql.NullString{}
		if row.receiptCipher.Valid {
			receiptPlain, err := appMCPOpenOperation(oldKey, "receipt_ciphertext", row.receiptCipher.String)
			if err != nil {
				return 0, err
			}
			receiptCipher, err := appMCPSealOperation(newKey, "receipt_ciphertext", receiptPlain)
			if err != nil {
				return 0, err
			}
			newReceipt = sql.NullString{String: receiptCipher, Valid: true}
		}
		resealed = append(resealed, resealedRow{old: row, preparedCipher: preparedCipher, receiptCipher: newReceipt})
	}
	if err := ctx.Err(); err != nil {
		return 0, errors.New("operation storage rotation was canceled")
	}
	for _, row := range resealed {
		if err := appMCPCASOperationMaintenanceRow(ctx, tx, row.old, row.preparedCipher, row.receiptCipher); err != nil {
			return 0, err
		}
	}
	return len(resealed), nil
}

// appMCPCASOperationMaintenanceRow is the conditional write primitive. Its
// private caller must already verify main/schema, authenticate old, and reseal
// matching v2 ciphertext; any error requires the caller to roll back.
func appMCPCASOperationMaintenanceRow(ctx context.Context, tx *sql.Tx, old appMCPOperationMaintenanceRow, preparedCipher string, receiptCipher sql.NullString) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return errors.New("invalid operation storage rotation context")
	}
	result, err := tx.ExecContext(ctx, `UPDATE main._benmore_mcp_operations
		SET prepared_ciphertext=?,receipt_ciphertext=?
		WHERE operation_id=? AND prepared_digest=? AND prepared_ciphertext=?
		AND receipt_digest IS ? AND receipt_ciphertext IS ?`,
		preparedCipher, receiptCipher, old.operationID, old.preparedDigest,
		old.preparedCipher, old.receiptDigest, old.receiptCipher)
	if err != nil {
		return errors.New("operation storage rotation update failed; caller must roll back")
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("operation storage rotation compare-and-swap failed; caller must roll back")
	}
	return nil
}
