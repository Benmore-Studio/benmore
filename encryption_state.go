//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const appEncryptionStateDDL = `CREATE TABLE _benmore_encryption_state (
	singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
	version INTEGER NOT NULL CHECK(version = 2),
	owner_id TEXT NOT NULL CHECK(length(owner_id) = 64),
	key_generation TEXT NOT NULL CHECK(length(key_generation) = 64),
	operation_storage_provisioned INTEGER NOT NULL CHECK(operation_storage_provisioned IN (0,1)),
	command_storage_version INTEGER NOT NULL CHECK(command_storage_version IN (0,2)),
	last_rotation_id TEXT CHECK(last_rotation_id IS NULL OR length(last_rotation_id) = 64),
	verification_ciphertext TEXT NOT NULL,
	CHECK((command_storage_version=0 AND operation_storage_provisioned=0) OR (command_storage_version=2 AND operation_storage_provisioned=1))
)`

type appEncryptionState struct {
	Version                     int
	OwnerID                     string
	KeyGeneration               string
	OperationStorageProvisioned bool
	CommandStorageVersion       int
	LastRotationID              string
}

type appEncryptionStatePayload struct {
	Domain                      string  `json:"domain"`
	Version                     int     `json:"version"`
	OwnerID                     string  `json:"owner_id"`
	KeyGeneration               string  `json:"key_generation"`
	OperationStorageProvisioned bool    `json:"operation_storage_provisioned"`
	CommandStorageVersion       int     `json:"command_storage_version"`
	LastRotationID              *string `json:"last_rotation_id"`
}

func appEncryptionStatePayloadFor(state appEncryptionState) appEncryptionStatePayload {
	payload := appEncryptionStatePayload{Domain: "benmore:encryption-state:v2", Version: state.Version, OwnerID: state.OwnerID, KeyGeneration: state.KeyGeneration, OperationStorageProvisioned: state.OperationStorageProvisioned, CommandStorageVersion: state.CommandStorageVersion}
	if state.LastRotationID != "" {
		payload.LastRotationID = &state.LastRotationID
	}
	return payload
}

func appEncryptionStateAAD(value string) bool {
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
	return ok && table == "_benmore_encryption_state" && column == "verification_ciphertext"
}

func sealAppEncryptionState(key []byte, state appEncryptionState) (string, error) {
	if state.Version != 2 || (state.CommandStorageVersion != 0 && state.CommandStorageVersion != 2) ||
		state.OperationStorageProvisioned != (state.CommandStorageVersion == 2) || !appMCPOperationHex(state.OwnerID, 32) || !appMCPOperationHex(state.KeyGeneration, 32) ||
		(state.LastRotationID != "" && !appMCPOperationHex(state.LastRotationID, 32)) {
		return "", errors.New("encryption state bindings are invalid")
	}
	data, err := json.Marshal(appEncryptionStatePayloadFor(state))
	if err != nil {
		return "", errors.New("encryption state encoding failed")
	}
	ciphertext, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(data))
	if err != nil || !appEncryptionStateAAD(ciphertext) {
		return "", errors.New("encryption state sealing failed")
	}
	return ciphertext, nil
}

func readAppEncryptionState(ctx context.Context, tx *sql.Tx, ownerID string, key []byte) (*appEncryptionState, error) {
	return readAppEncryptionStateMode(ctx, tx, ownerID, key, false)
}

// readAppEncryptionStateMode optionally tolerates a missing attempts table next
// to complete operation and approval storage: storage provisioned before the
// attempt history existed, which the lifecycle upgrade adds.
func readAppEncryptionStateMode(ctx context.Context, tx *sql.Tx, ownerID string, key []byte, allowMissingAttempts bool) (*appEncryptionState, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(ownerID, 32) || len(key) != 32 {
		return nil, errors.New("invalid encryption state read context")
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := q.cleanMain(); err != nil {
		return nil, fmt.Errorf("encryption state database isolation failed: %w", err)
	}
	objects, err := tx.QueryContext(ctx, "SELECT name,type,tbl_name,sql FROM main.sqlite_schema WHERE lower(name)=lower(?) OR lower(tbl_name)=lower(?)", "_benmore_encryption_state", "_benmore_encryption_state")
	if err != nil {
		return nil, errors.New("encryption state schema object cannot be inspected")
	}
	var objectCount int
	var name, typ, ddl string
	for objects.Next() {
		var objectName, objectType, tableName string
		var objectDDL sql.NullString
		if err := objects.Scan(&objectName, &objectType, &tableName, &objectDDL); err != nil {
			_ = objects.Close()
			return nil, errors.New("encryption state schema object is invalid")
		}
		objectCount++
		if objectCount != 1 || objectName != "_benmore_encryption_state" || tableName != "_benmore_encryption_state" || objectType != "table" || !objectDDL.Valid {
			_ = objects.Close()
			return nil, errors.New("encryption state schema object is invalid")
		}
		name, typ, ddl = objectName, objectType, objectDDL.String
	}
	rowsErr, closeErr := objects.Err(), objects.Close()
	if rowsErr != nil || closeErr != nil {
		return nil, errors.New("encryption state schema object inventory is incomplete")
	}
	if objectCount == 0 {
		return nil, nil
	}
	if name != "_benmore_encryption_state" || typ != "table" || strings.TrimSpace(ddl) != appEncryptionStateDDL {
		return nil, errors.New("encryption state schema object is invalid")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA main.table_info('_benmore_encryption_state')")
	if err != nil {
		return nil, errors.New("encryption state columns cannot be inspected")
	}
	want := []struct {
		name, typ   string
		notnull, pk int
	}{{"singleton", "INTEGER", 1, 1}, {"version", "INTEGER", 1, 0}, {"owner_id", "TEXT", 1, 0}, {"key_generation", "TEXT", 1, 0}, {"operation_storage_provisioned", "INTEGER", 1, 0}, {"command_storage_version", "INTEGER", 1, 0}, {"last_rotation_id", "TEXT", 0, 0}, {"verification_ciphertext", "TEXT", 1, 0}}
	i := 0
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) != nil || i >= len(want) || name != want[i].name || strings.ToUpper(typ) != want[i].typ || notnull != want[i].notnull || pk != want[i].pk || dflt != nil {
			closeErr := rows.Close()
			if closeErr != nil {
				return nil, errors.New("encryption state columns could not be closed")
			}
			return nil, errors.New("encryption state columns are altered")
		}
		i++
	}
	rowsErr = rows.Err()
	closeErr = rows.Close()
	if rowsErr != nil || closeErr != nil || i != len(want) {
		return nil, errors.New("encryption state columns are incomplete")
	}
	var indexes, triggers, views int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='index' AND lower(tbl_name)=lower('_benmore_encryption_state')").Scan(&indexes); err != nil || indexes != 0 {
		return nil, errors.New("encryption state indexes are refused")
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND (lower(name)=lower('_benmore_encryption_state') OR lower(tbl_name)=lower('_benmore_encryption_state'))").Scan(&triggers); err != nil || triggers != 0 {
		return nil, errors.New("encryption state triggers are refused")
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE type='view' AND lower(name)=lower(?)", "_benmore_encryption_state").Scan(&views); err != nil || views != 0 {
		return nil, errors.New("encryption state views are refused")
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main._benmore_encryption_state").Scan(&count); err != nil || count != 1 {
		return nil, errors.New("encryption state must contain exactly one row")
	}
	var singleton, version, provisioned, commandStorageVersion int
	var rowOwner, generation, ciphertext string
	var rotation sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT singleton,version,owner_id,key_generation,operation_storage_provisioned,command_storage_version,last_rotation_id,verification_ciphertext FROM main._benmore_encryption_state").Scan(&singleton, &version, &rowOwner, &generation, &provisioned, &commandStorageVersion, &rotation, &ciphertext); err != nil {
		return nil, errors.New("encryption state row cannot be read")
	}
	if singleton != 1 || version != 2 || rowOwner != ownerID || !appMCPOperationHex(rowOwner, 32) || !appMCPOperationHex(generation, 32) || provisioned < 0 || provisioned > 1 || (commandStorageVersion != 0 && commandStorageVersion != 2) || (provisioned == 1) != (commandStorageVersion == 2) || rotation.Valid && !appMCPOperationHex(rotation.String, 32) || !appEncryptionStateAAD(ciphertext) {
		return nil, errors.New("encryption state row is invalid")
	}
	plain, err := fieldDecryptCtx(key, "verification_ciphertext", ciphertext)
	if err != nil {
		return nil, errors.New("encryption state authentication failed")
	}
	var payload appEncryptionStatePayload
	decoder := json.NewDecoder(strings.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return nil, errors.New("encryption state payload is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("encryption state payload has trailing data")
	}
	canonical, err := json.Marshal(payload)
	expected := appEncryptionStatePayloadFor(appEncryptionState{Version: version, OwnerID: rowOwner, KeyGeneration: generation, OperationStorageProvisioned: provisioned == 1, CommandStorageVersion: commandStorageVersion, LastRotationID: rotation.String})
	rotationID := ""
	if payload.LastRotationID != nil {
		rotationID = *payload.LastRotationID
	}
	if err != nil || !bytes.Equal(canonical, []byte(plain)) || payload.Domain != expected.Domain || payload.Version != expected.Version || payload.OwnerID != expected.OwnerID || payload.KeyGeneration != expected.KeyGeneration || payload.OperationStorageProvisioned != expected.OperationStorageProvisioned || payload.CommandStorageVersion != expected.CommandStorageVersion || rotationID != rotation.String || (payload.LastRotationID == nil) != !rotation.Valid {
		return nil, errors.New("encryption state payload does not match its row")
	}
	state := &appEncryptionState{Version: version, OwnerID: rowOwner, KeyGeneration: generation, OperationStorageProvisioned: provisioned == 1, CommandStorageVersion: commandStorageVersion, LastRotationID: rotation.String}
	operations, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_operations")
	if err != nil {
		return nil, errors.New("operation storage presence cannot be verified")
	}
	approvals, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_approvals")
	if err != nil {
		return nil, errors.New("command approval storage presence cannot be verified")
	}
	attempts, err := appMCPObjectExists(ctx, tx, "_benmore_mcp_command_attempts")
	if err != nil {
		return nil, errors.New("command attempt storage presence cannot be verified")
	}
	if state.CommandStorageVersion == 0 {
		if operations || approvals || attempts {
			return nil, errors.New("unprovisioned command marker has command storage")
		}
	} else {
		if !operations || !approvals || !attempts && !allowMissingAttempts {
			return nil, errors.New("provisioned command marker is missing storage")
		}
		if err := appMCPVerifyOperationStorage(ctx, tx); err != nil {
			return nil, err
		}
		if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
			return nil, err
		}
		if attempts {
			if err := verifyAppMCPCommandAttemptStorage(ctx, tx); err != nil {
				return nil, err
			}
		}
	}
	return state, nil
}

func initializeAppEncryptionState(ctx context.Context, tx *sql.Tx, ownerID string, key []byte) (*appEncryptionState, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil || !appMCPOperationHex(ownerID, 32) || len(key) != 32 {
		return nil, errors.New("invalid encryption state bootstrap context")
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: true}
	if err := q.cleanMain(); err != nil {
		return nil, fmt.Errorf("encryption state database isolation failed: %w", err)
	}
	if err := appMCPVerifyOperationStorage(ctx, tx); err != nil {
		return nil, fmt.Errorf("operation storage is not ready for marker: %w", err)
	}
	if err := verifyAppMCPCommandApprovalStorage(ctx, tx); err != nil {
		return nil, fmt.Errorf("command approval storage is not ready for marker: %w", err)
	}
	var objects int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_encryption_state') OR lower(tbl_name)=lower('_benmore_encryption_state')").Scan(&objects); err != nil || objects != 0 {
		return nil, errors.New("encryption state already exists or cannot be inspected")
	}
	if _, err := tx.ExecContext(ctx, appEncryptionStateDDL); err != nil {
		return nil, errors.New("encryption state table creation failed")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, errors.New("encryption state generation failed")
	}
	generation := hex.EncodeToString(random)
	state := appEncryptionState{Version: 2, OwnerID: ownerID, KeyGeneration: generation, OperationStorageProvisioned: true, CommandStorageVersion: 2}
	ciphertext, err := sealAppEncryptionState(key, state)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO main._benmore_encryption_state(singleton,version,owner_id,key_generation,operation_storage_provisioned,command_storage_version,last_rotation_id,verification_ciphertext) VALUES(1,2,?,?,1,2,NULL,?)", ownerID, generation, ciphertext); err != nil {
		return nil, errors.New("encryption state row creation failed")
	}
	return readAppEncryptionState(ctx, tx, ownerID, key)
}
