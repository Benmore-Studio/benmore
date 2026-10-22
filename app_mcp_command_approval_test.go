//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

type appMCPApprovalFixture struct {
	app       *App
	key       []byte
	appID     string
	operation *appMCPStoredOperation
	approval  appMCPCommandApprovalState
}

func newAppMCPApprovalFixture(t *testing.T, consumed bool) *appMCPApprovalFixture {
	t.Helper()
	app, key := appMCPOperationStoreFixture(t)
	appID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("1", 64)
	prepared := appMCPOperationStoreRecord(app, operationID)
	prepared.CreatedAt = time.Now().Unix() - 3600
	prepared.ExpiresAt = prepared.CreatedAt + 15*60
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := initializeAppMCPCommandAttemptStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := initializeAppEncryptionState(context.Background(), tx, appID, key); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	operation, err := appMCPInsertOperationTest(t, context.Background(), tx, app, prepared)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	approval := appMCPCommandApprovalRecord{
		Version: 1, Domain: "benmore:mcp:human-approval:v1", ApprovalID: strings.Repeat("2", 64),
		AppID: appID, OperationID: operationID, PreparedDigest: operation.PreparedDigest,
		DisclosureVersion: prepared.DisclosureVersion, OwnerEpoch: prepared.RuntimeAuthority.OwnerEpoch,
		WriteEpoch: prepared.RuntimeAuthority.WriteEpoch, ApproverUserID: prepared.Origin.ActorID,
		ApproverCreated: prepared.Origin.ActorCreated, ApproverSessionID: sessionKeyPrefix + strings.Repeat("3", 64),
		Tenant: prepared.Origin.Tenant, ApprovedAt: prepared.CreatedAt + 1, ExpiresAt: prepared.ExpiresAt,
		ReviewChallengeDigest: strings.Repeat("4", 64),
	}
	_, digest, err := appMCPEncodeCommandApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	state := appMCPCommandApprovalState{Approval: approval, ApprovalDigest: digest, State: "approved"}
	if consumed {
		state.State = "consumed"
		state.AttemptID = strings.Repeat("5", 64)
		state.ConsumedAt = approval.ApprovedAt + 1
	}
	state.Plaintext, err = appMCPEncodeCommandApprovalState(state)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := appMCPSealCommandApproval(key, state.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", operationID, digest, ciphertext); err != nil {
		t.Fatal(err)
	}
	state.Ciphertext = ciphertext
	fixture := &appMCPApprovalFixture{app: app, key: key, appID: appID, operation: operation, approval: state}
	if consumed {
		receipt := appMCPCommandReceiptRecord{Version: 1, Kind: "command_receipt", State: "committed", AppID: appID,
			OperationID: operationID, PreparedDigest: operation.PreparedDigest, ApprovalID: approval.ApprovalID,
			ApprovalDigest: digest, AttemptID: state.AttemptID, CommittedAt: state.ConsumedAt,
			Result: json.RawMessage(`{"status":"done"}`), Effects: []json.RawMessage{}}
		receiptJSON, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		tx, err = app.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, app, operationID, operation.PreparedDigest, receiptJSON); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		tx, err = app.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		fixture.operation, err = appMCPReadOperationWithKey(context.Background(), tx, appID, key, operationID)
		_ = tx.Rollback()
		if err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func addAppMCPApprovalFixture(t *testing.T, fixture *appMCPApprovalFixture, operationID string, createdAt int64, consumed bool) (*appMCPStoredOperation, appMCPCommandApprovalState, []byte) {
	t.Helper()
	prepared := appMCPOperationStoreRecord(fixture.app, operationID)
	prepared.CreatedAt = createdAt
	prepared.ExpiresAt = createdAt + 15*60
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := appMCPInsertOperationTest(t, context.Background(), tx, fixture.app, prepared)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	approval := fixture.approval.Approval
	approval.ApprovalID = strings.Repeat("8", 64)
	approval.OperationID = operationID
	approval.PreparedDigest = operation.PreparedDigest
	approval.DisclosureVersion = prepared.DisclosureVersion
	approval.OwnerEpoch = prepared.RuntimeAuthority.OwnerEpoch
	approval.WriteEpoch = prepared.RuntimeAuthority.WriteEpoch
	approval.ApproverUserID = prepared.Origin.ActorID
	approval.ApproverCreated = prepared.Origin.ActorCreated
	approval.Tenant = prepared.Origin.Tenant
	approval.ApprovedAt = createdAt + 1
	approval.ExpiresAt = prepared.ExpiresAt
	_, digest, err := appMCPEncodeCommandApproval(approval)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	state := appMCPCommandApprovalState{Approval: approval, ApprovalDigest: digest, State: "approved"}
	if consumed {
		state.State = "consumed"
		state.AttemptID = strings.Repeat("6", 64)
		state.ConsumedAt = createdAt + 2
	}
	state.Plaintext, err = appMCPEncodeCommandApprovalState(state)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	state.Ciphertext, err = appMCPSealCommandApproval(fixture.key, state.Plaintext)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", operationID, digest, state.Ciphertext); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	var receiptJSON []byte
	if consumed {
		receipt := appMCPCommandReceiptRecord{Version: 1, Kind: "command_receipt", State: "committed", AppID: fixture.appID,
			OperationID: operationID, PreparedDigest: operation.PreparedDigest, ApprovalID: approval.ApprovalID,
			ApprovalDigest: digest, AttemptID: state.AttemptID, CommittedAt: state.ConsumedAt,
			Result: json.RawMessage(`{"status":"committed"}`), Effects: []json.RawMessage{}}
		receiptJSON, err = json.Marshal(receipt)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, fixture.app, operationID, operation.PreparedDigest, receiptJSON); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	operation, err = appMCPReadOperationWithKey(context.Background(), tx, fixture.appID, fixture.key, operationID)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	_ = tx.Rollback()
	return operation, state, receiptJSON
}

func TestAppMCPCommandApprovalStorageCanonicalBindings(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	count, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key)
	_ = tx.Rollback()
	if err != nil || count != 1 {
		t.Fatalf("approved store count=%d err=%v", count, err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, strings.Repeat("f", 64), fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("foreign application owner verified approval storage")
	}
	_ = tx.Rollback()
	if fixture.approval.Approval.ExpiresAt >= time.Now().Unix() {
		t.Fatal("maintenance fixture is not expired")
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRead, err := readAppMCPCommandApproval(context.Background(), tx, fixture.app, fixture.operation.Prepared.OperationID)
	_ = tx.Rollback()
	if err != nil || runtimeRead == nil || runtimeRead.Approval.ApprovalID != fixture.approval.Approval.ApprovalID {
		t.Fatalf("runtime approval read=%+v err=%v", runtimeRead, err)
	}
	if _, err := fixture.app.DB.Exec("DELETE FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err = verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key)
	_ = tx.Rollback()
	if err != nil || count != 0 {
		t.Fatalf("unapproved operation without receipt count=%d err=%v", count, err)
	}
	newKey, err := cryptoDeriveAppKey(strings.Repeat("57", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err = rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey)
	_ = tx.Rollback()
	if err != nil || count != 0 {
		t.Fatalf("zero-row reseal count=%d err=%v", count, err)
	}
	if _, err := fixture.app.DB.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", fixture.operation.Prepared.OperationID, fixture.approval.ApprovalDigest, fixture.approval.Ciphertext); err != nil {
		t.Fatal(err)
	}

	plain, err := appMCPOpenCommandApproval(fixture.key, fixture.approval.Ciphertext)
	if err != nil || !bytes.Equal(plain, fixture.approval.Plaintext) {
		t.Fatalf("approved envelope readback err=%v", err)
	}
	operation := fixture.operation
	base := fixture.approval.Approval
	badRecords := []func(*appMCPCommandApprovalRecord){
		func(r *appMCPCommandApprovalRecord) { r.Version = 2 },
		func(r *appMCPCommandApprovalRecord) { r.Domain = "benmore:mcp:human-approval:wrong" },
		func(r *appMCPCommandApprovalRecord) { r.ApprovalID = "bad" },
		func(r *appMCPCommandApprovalRecord) { r.AppID = strings.Repeat("f", 64) },
		func(r *appMCPCommandApprovalRecord) { r.OperationID = strings.Repeat("f", 64) },
		func(r *appMCPCommandApprovalRecord) { r.PreparedDigest = strings.Repeat("f", 64) },
		func(r *appMCPCommandApprovalRecord) { r.DisclosureVersion += ".other" },
		func(r *appMCPCommandApprovalRecord) { r.OwnerEpoch = strings.Repeat("f", 64) },
		func(r *appMCPCommandApprovalRecord) { r.WriteEpoch = strings.Repeat("f", 64) },
		func(r *appMCPCommandApprovalRecord) { r.ApproverUserID++ },
		func(r *appMCPCommandApprovalRecord) { r.ApproverCreated += ".other" },
		func(r *appMCPCommandApprovalRecord) { r.ApproverSessionID = "sha256:bad" },
		func(r *appMCPCommandApprovalRecord) { r.Tenant = "18" },
		func(r *appMCPCommandApprovalRecord) { r.ApprovedAt = operation.Prepared.ExpiresAt },
		func(r *appMCPCommandApprovalRecord) { r.ExpiresAt-- },
		func(r *appMCPCommandApprovalRecord) { r.ReviewChallengeDigest = "bad" },
	}
	for i, mutate := range badRecords {
		candidate := base
		mutate(&candidate)
		if err := appMCPValidateCommandApprovalRecord(candidate, operation, fixture.appID); err == nil {
			t.Fatalf("immutable binding mutation %d was accepted", i)
		}
	}
	otherKey := append([]byte(nil), fixture.key...)
	otherKey[0] ^= 0xff
	if _, err := appMCPOpenCommandApproval(otherKey, fixture.approval.Ciphertext); err == nil {
		t.Fatal("wrong approval key authenticated ciphertext")
	}
	wrongAAD, err := fieldEncryptCtx(fixture.key, "_benmore_mcp_operations", "prepared_ciphertext", string(fixture.approval.Plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPOpenCommandApproval(fixture.key, wrongAAD); err == nil {
		t.Fatal("operation-field AAD was accepted for approval")
	}

	badEnvelope, _ := json.Marshal(appMCPCommandApprovalEnvelope{Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: base,
		ApprovalDigest: fixture.approval.ApprovalDigest, State: "consumed", AttemptID: "bad", ConsumedAt: base.ApprovedAt + 1})
	if _, err := appMCPDecodeCommandApproval(badEnvelope, operation, fixture.appID); err == nil {
		t.Fatal("malformed consumed state was accepted")
	}
	for name, candidate := range map[string]appMCPCommandApprovalEnvelope{
		"approved with attempt":    {Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: base, ApprovalDigest: fixture.approval.ApprovalDigest, State: "approved", AttemptID: strings.Repeat("5", 64), ConsumedAt: base.ApprovedAt + 1},
		"consumed before approval": {Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: base, ApprovalDigest: fixture.approval.ApprovalDigest, State: "consumed", AttemptID: strings.Repeat("5", 64), ConsumedAt: base.ApprovedAt - 1},
		"consumed at expiry":       {Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: base, ApprovalDigest: fixture.approval.ApprovalDigest, State: "consumed", AttemptID: strings.Repeat("5", 64), ConsumedAt: base.ExpiresAt},
		"unknown state":            {Version: 1, Domain: "benmore:mcp:command-approval-state:v1", Approval: base, ApprovalDigest: fixture.approval.ApprovalDigest, State: "pending"},
	} {
		raw, _ := json.Marshal(candidate)
		if _, err := appMCPDecodeCommandApproval(raw, operation, fixture.appID); err == nil {
			t.Fatalf("%s state was accepted", name)
		}
	}
	unknown := bytes.Replace(fixture.approval.Plaintext, []byte("\"state\":"), []byte("\"extra\":true,\"state\":"), 1)
	if _, err := appMCPDecodeCommandApproval(unknown, operation, fixture.appID); err == nil {
		t.Fatal("unknown state field was accepted")
	}
	duplicate := bytes.Replace(fixture.approval.Plaintext, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if _, err := appMCPDecodeCommandApproval(duplicate, operation, fixture.appID); err == nil {
		t.Fatal("duplicate state field was accepted")
	}
	if _, err := appMCPDecodeCommandApproval(append(bytes.Clone(fixture.approval.Plaintext), []byte(" {}")...), operation, fixture.appID); err == nil {
		t.Fatal("trailing state data was accepted")
	}
	if _, err := appMCPDecodeCommandApproval([]byte(" "+string(fixture.approval.Plaintext)), operation, fixture.appID); err == nil {
		t.Fatal("noncanonical state data was accepted")
	}
	if _, err := appMCPDecodeCommandApproval(bytes.Repeat([]byte("x"), appMCPResultLimit+1), operation, fixture.appID); err == nil {
		t.Fatal("oversized state data was accepted")
	}
	if _, err := appMCPDecodeCommandApproval([]byte(`{"version":1}`), operation, fixture.appID); err == nil {
		t.Fatal("missing approval state fields were accepted")
	}
	if _, err := fixture.app.DB.Exec("CREATE INDEX approval_extra ON _benmore_mcp_command_approvals(approval_digest)"); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err == nil {
		_ = tx.Rollback()
		t.Fatal("extra approval index was accepted")
	}
	_ = tx.Rollback()
	if _, err := fixture.app.DB.Exec("DROP INDEX main.approval_extra"); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("cleaned valid approval baseline rejected: %v", err)
	}
	_ = tx.Rollback()
}

func TestAppMCPCommandApprovalReceiptUnionAndRefusals(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, true)
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key)
	_ = tx.Rollback()
	if err != nil || count != 1 {
		t.Fatalf("consumed receipt union count=%d err=%v", count, err)
	}

	stored := *fixture.operation
	receipt, err := decodeAppMCPCommandReceipt(&stored, &fixture.approval)
	if err != nil || receipt == nil || receipt.Effects == nil || len(receipt.Effects) != 0 {
		t.Fatalf("valid receipt decode=%+v err=%v", receipt, err)
	}
	canonicalReceipt, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonicalReceipt, stored.Receipt) {
		t.Fatalf("receipt codec differs from operation-store canonical bytes: err=%v", err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	readBack, err := appMCPReadOperationWithKey(context.Background(), tx, fixture.appID, fixture.key, stored.Prepared.OperationID)
	if err == nil && (readBack == nil || !bytes.Equal(readBack.Receipt, stored.Receipt) || readBack.ReceiptDigest != stored.ReceiptDigest) {
		err = errors.New("actual operation readback changed receipt bytes or digest")
	}
	_ = tx.Rollback()
	if err != nil {
		t.Fatalf("actual stored receipt readback: %v", err)
	}
	if _, err := fixture.app.DB.Exec("UPDATE main._benmore_mcp_operations SET receipt_digest=NULL,receipt_ciphertext=NULL WHERE operation_id=?", stored.Prepared.OperationID); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("consumed approval without receipt was accepted")
	}
	_ = tx.Rollback()
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, fixture.app, stored.Prepared.OperationID, stored.PreparedDigest, stored.Receipt); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	wrongApproval := fixture.approval
	wrongApproval.AttemptID = strings.Repeat("6", 64)
	if _, err := decodeAppMCPCommandReceipt(&stored, &wrongApproval); err == nil {
		t.Fatal("receipt with a different consumed attempt was accepted")
	}
	for name, mutate := range map[string]func(*appMCPCommandReceiptRecord){
		"nonempty effects": func(r *appMCPCommandReceiptRecord) {
			r.Effects = []json.RawMessage{json.RawMessage(`{"kind":"unreviewed"}`)}
		},
		"null effects":          func(r *appMCPCommandReceiptRecord) { r.Effects = nil },
		"unsafe result integer": func(r *appMCPCommandReceiptRecord) { r.Result = json.RawMessage(`{"value":9007199254740993}`) },
		"wrong attempt":         func(r *appMCPCommandReceiptRecord) { r.AttemptID = strings.Repeat("6", 64) },
		"wrong approval":        func(r *appMCPCommandReceiptRecord) { r.ApprovalID = strings.Repeat("6", 64) },
		"wrong timestamp":       func(r *appMCPCommandReceiptRecord) { r.CommittedAt++ },
	} {
		candidate := *receipt
		mutate(&candidate)
		raw, marshalErr := json.Marshal(candidate)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		badStored := stored
		badStored.Receipt = raw
		badStored.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", raw)
		if _, err := decodeAppMCPCommandReceipt(&badStored, &fixture.approval); err == nil {
			t.Fatalf("%s receipt was accepted", name)
		}
	}
	duplicate := bytes.Replace(stored.Receipt, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	badDuplicate := stored
	badDuplicate.Receipt = duplicate
	badDuplicate.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", duplicate)
	if _, err := decodeAppMCPCommandReceipt(&badDuplicate, &fixture.approval); err == nil {
		t.Fatal("duplicate receipt field was accepted")
	}
	trailing := append(bytes.Clone(stored.Receipt), []byte(" {}")...)
	badTrailing := stored
	badTrailing.Receipt = trailing
	badTrailing.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", trailing)
	if _, err := decodeAppMCPCommandReceipt(&badTrailing, &fixture.approval); err == nil {
		t.Fatal("trailing receipt data was accepted")
	}
	if _, err := decodeAppMCPCommandReceipt(&appMCPStoredOperation{Prepared: stored.Prepared, PreparedDigest: stored.PreparedDigest, Receipt: bytes.Repeat([]byte("x"), appMCPResultLimit+1), ReceiptDigest: strings.Repeat("a", 64)}, &fixture.approval); err == nil {
		t.Fatal("oversized receipt was accepted")
	}
	badMissing := stored
	badMissing.Receipt = []byte(`{"version":1,"kind":"command_receipt","state":"committed"}`)
	badMissing.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", badMissing.Receipt)
	if _, err := decodeAppMCPCommandReceipt(&badMissing, &fixture.approval); err == nil {
		t.Fatal("receipt missing required fields was accepted")
	}
	badSpace := stored
	badSpace.Receipt = append([]byte(" "), stored.Receipt...)
	badSpace.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", badSpace.Receipt)
	if _, err := decodeAppMCPCommandReceipt(&badSpace, &fixture.approval); err == nil {
		t.Fatal("noncanonical receipt was accepted")
	}
	unknownReceipt := bytes.Replace(stored.Receipt, []byte(`"state":"committed"`), []byte(`"state":"committed","extra":true`), 1)
	badUnknown := stored
	badUnknown.Receipt = unknownReceipt
	badUnknown.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", unknownReceipt)
	if _, err := decodeAppMCPCommandReceipt(&badUnknown, &fixture.approval); err == nil {
		t.Fatal("receipt with unknown field was accepted")
	}
	nonObject := *receipt
	nonObject.Result = json.RawMessage(`[]`)
	nonObjectRaw, err := json.Marshal(nonObject)
	if err != nil {
		t.Fatal(err)
	}
	badNonObject := stored
	badNonObject.Receipt = nonObjectRaw
	badNonObject.ReceiptDigest = appMCPOperationDigest("benmore:mcp:receipt:v1", nonObjectRaw)
	if _, err := decodeAppMCPCommandReceipt(&badNonObject, &fixture.approval); err == nil {
		t.Fatal("receipt with non-object result was accepted")
	}

	if _, err := fixture.app.DB.Exec("UPDATE main._benmore_mcp_command_approvals SET approval_digest=?", strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("altered approval digest was accepted")
	}
	_ = tx.Rollback()
	if _, err := fixture.app.DB.Exec("UPDATE main._benmore_mcp_command_approvals SET approval_digest=?", fixture.approval.ApprovalDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.DB.Exec("UPDATE main._benmore_mcp_command_approvals SET state_ciphertext='v2:00:00'"); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("altered approval ciphertext was accepted")
	}
	_ = tx.Rollback()
}

func TestAppMCPCommandApprovalRefusesCaseVariantOperationTriggers(t *testing.T) {
	for _, target := range []string{"_benmore_mcp_operations", "_BENMORE_MCP_OPERATIONS"} {
		t.Run(target, func(t *testing.T) {
			fixture := newAppMCPApprovalFixture(t, false)
			if _, err := fixture.app.DB.Exec("CREATE TABLE trigger_effects(value TEXT NOT NULL)"); err != nil {
				t.Fatal(err)
			}
			trigger := "CREATE TRIGGER operation_case_guard BEFORE INSERT ON " + target + " BEGIN INSERT INTO trigger_effects(value) VALUES('unexpected'); END"
			if _, err := fixture.app.DB.Exec(trigger); err != nil {
				t.Fatalf("install actual trigger: %v", err)
			}
			var triggerName, tableName string
			if err := fixture.app.DB.QueryRow("SELECT name,tbl_name FROM main.sqlite_schema WHERE type='trigger' AND name='operation_case_guard'").Scan(&triggerName, &tableName); err != nil {
				t.Fatal(err)
			}
			if triggerName != "operation_case_guard" || tableName != target {
				t.Fatalf("SQLite did not retain trigger target spelling: name=%q tbl_name=%q want=%q", triggerName, tableName, target)
			}
			var operationsBefore, approvalsBefore, markerBefore string
			if err := fixture.app.DB.QueryRow("SELECT prepared_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&operationsBefore); err != nil {
				t.Fatal(err)
			}
			if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&approvalsBefore); err != nil {
				t.Fatal(err)
			}
			if err := fixture.app.DB.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&markerBefore); err != nil {
				t.Fatal(err)
			}
			tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyAppMCPOperationStorage(context.Background(), tx); err == nil {
				_ = tx.Rollback()
				t.Fatal("operation schema accepted a case-variant trigger")
			}
			_ = tx.Rollback()
			tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyAppMCPCommandStorageWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
				_ = tx.Rollback()
				t.Fatal("V2 readiness accepted a case-variant operation trigger")
			}
			_ = tx.Rollback()
			if _, err := preflightAppMCPOperationLifecycle(context.Background(), fixture.app, &runtimeConfig{}, map[string]string{"ENCRYPTION_KEY": strings.Repeat("42", 32)}, false); err == nil {
				t.Fatal("V2 lifecycle preflight accepted a case-variant operation trigger")
			}
			tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
				_ = tx.Rollback()
				t.Fatal("approval maintenance accepted a case-variant operation trigger")
			}
			_ = tx.Rollback()
			newKey, err := cryptoDeriveAppKey(strings.Repeat("5a", 32))
			if err != nil {
				t.Fatal(err)
			}
			tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey); err == nil {
				_ = tx.Rollback()
				t.Fatal("approval reseal accepted a case-variant operation trigger")
			}
			_ = tx.Rollback()
			var effects int
			if err := fixture.app.DB.QueryRow("SELECT count(*) FROM main.trigger_effects").Scan(&effects); err != nil {
				t.Fatal(err)
			}
			var operationsAfter, approvalsAfter, markerAfter string
			if err := fixture.app.DB.QueryRow("SELECT prepared_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&operationsAfter); err != nil {
				t.Fatal(err)
			}
			if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&approvalsAfter); err != nil {
				t.Fatal(err)
			}
			if err := fixture.app.DB.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&markerAfter); err != nil {
				t.Fatal(err)
			}
			if effects != 0 || operationsAfter != operationsBefore || approvalsAfter != approvalsBefore || markerAfter != markerBefore {
				t.Fatal("trigger refusal changed a business or protected row")
			}
			if _, err := fixture.app.DB.Exec("DROP TRIGGER main.operation_case_guard"); err != nil {
				t.Fatal(err)
			}
			tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
				_ = tx.Rollback()
				t.Fatalf("restored approval baseline rejected: %v", err)
			}
			if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err != nil {
				_ = tx.Rollback()
				t.Fatalf("restored operation/approval baseline rejected: %v", err)
			}
			_ = tx.Rollback()
		})
	}
}

func appMCPApprovalSchemaAccepted(t *testing.T, fixture *appMCPApprovalFixture) error {
	t.Helper()
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	err = verifyAppMCPCommandApprovalStorage(context.Background(), tx)
	rollbackErr := tx.Rollback()
	if err != nil {
		return err
	}
	if rollbackErr != nil && rollbackErr != sql.ErrTxDone {
		return rollbackErr
	}
	return nil
}

func appMCPReplaceApprovalTableForTest(t *testing.T, fixture *appMCPApprovalFixture, ddl string) (string, string) {
	t.Helper()
	id := fixture.operation.Prepared.OperationID
	var digest, ciphertext string
	if err := fixture.app.DB.QueryRow("SELECT approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", id).Scan(&digest, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.DB.Exec("DROP TABLE main._benmore_mcp_command_approvals"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.DB.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.DB.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", id, digest, ciphertext); err != nil {
		t.Fatal(err)
	}
	return digest, ciphertext
}

func appMCPRestoreApprovalTableForTest(t *testing.T, fixture *appMCPApprovalFixture, objectType, objectName, digest, ciphertext string) {
	t.Helper()
	if _, err := fixture.app.DB.Exec("DROP " + objectType + " main." + objectName); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", fixture.operation.Prepared.OperationID, digest, ciphertext); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPCommandApprovalStrictSchemaRefusalsRestoreBaseline(t *testing.T) {
	t.Run("extra column", func(t *testing.T) {
		fixture := newAppMCPApprovalFixture(t, false)
		ddl := strings.Replace(appMCPCommandApprovalStorageDDL, "state_ciphertext TEXT NOT NULL", "state_ciphertext TEXT NOT NULL, extra TEXT", 1)
		digest, ciphertext := appMCPReplaceApprovalTableForTest(t, fixture, ddl)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err == nil {
			t.Fatal("extra approval column was accepted")
		}
		appMCPRestoreApprovalTableForTest(t, fixture, "TABLE", "_benmore_mcp_command_approvals", digest, ciphertext)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
			t.Fatalf("restored baseline refused: %v", err)
		}
	})
	t.Run("default", func(t *testing.T) {
		fixture := newAppMCPApprovalFixture(t, false)
		ddl := strings.Replace(appMCPCommandApprovalStorageDDL, "state_ciphertext TEXT NOT NULL", "state_ciphertext TEXT NOT NULL DEFAULT 'unexpected'", 1)
		digest, ciphertext := appMCPReplaceApprovalTableForTest(t, fixture, ddl)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err == nil {
			t.Fatal("approval column default was accepted")
		}
		appMCPRestoreApprovalTableForTest(t, fixture, "TABLE", "_benmore_mcp_command_approvals", digest, ciphertext)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
			t.Fatalf("restored baseline refused: %v", err)
		}
	})
	t.Run("constraint", func(t *testing.T) {
		fixture := newAppMCPApprovalFixture(t, false)
		ddl := strings.Replace(appMCPCommandApprovalStorageDDL, "\n)", ",\n\tCHECK(approval_digest <> '')\n)", 1)
		digest, ciphertext := appMCPReplaceApprovalTableForTest(t, fixture, ddl)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err == nil {
			t.Fatal("extra approval constraint was accepted")
		}
		appMCPRestoreApprovalTableForTest(t, fixture, "TABLE", "_benmore_mcp_command_approvals", digest, ciphertext)
		if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
			t.Fatalf("restored baseline refused: %v", err)
		}
	})
	for _, object := range []string{"table", "view"} {
		t.Run("wrong-case "+object, func(t *testing.T) {
			fixture := newAppMCPApprovalFixture(t, false)
			var digest, ciphertext string
			if err := fixture.app.DB.QueryRow("SELECT approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&digest, &ciphertext); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.app.DB.Exec("DROP TABLE main._benmore_mcp_command_approvals"); err != nil {
				t.Fatal(err)
			}
			if object == "table" {
				ddl := strings.Replace(appMCPCommandApprovalStorageDDL, "_benmore_mcp_command_approvals", "_BENMORE_MCP_COMMAND_APPROVALS", 1)
				if _, err := fixture.app.DB.Exec(ddl); err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.app.DB.Exec("INSERT INTO main._BENMORE_MCP_COMMAND_APPROVALS(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", fixture.operation.Prepared.OperationID, digest, ciphertext); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := fixture.app.DB.Exec("CREATE VIEW main._BENMORE_MCP_COMMAND_APPROVALS AS SELECT '' AS operation_id, '' AS approval_digest, '' AS state_ciphertext"); err != nil {
					t.Fatal(err)
				}
			}
			var actualName, actualType string
			if err := fixture.app.DB.QueryRow("SELECT name,type FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&actualName, &actualType); err != nil {
				t.Fatal(err)
			}
			if actualName != "_BENMORE_MCP_COMMAND_APPROVALS" || actualType != object {
				t.Fatalf("wrong-case fixture not reached: name=%q type=%q", actualName, actualType)
			}
			if err := appMCPApprovalSchemaAccepted(t, fixture); err == nil {
				t.Fatalf("wrong-case approval %s was accepted", object)
			}
			appMCPRestoreApprovalTableForTest(t, fixture, strings.ToUpper(object), "_BENMORE_MCP_COMMAND_APPROVALS", digest, ciphertext)
			if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
				t.Fatalf("restored baseline refused: %v", err)
			}
		})
	}
	for _, target := range []string{"_benmore_mcp_command_approvals", "_BENMORE_MCP_COMMAND_APPROVALS"} {
		t.Run("trigger "+target, func(t *testing.T) {
			fixture := newAppMCPApprovalFixture(t, false)
			if _, err := fixture.app.DB.Exec("CREATE TABLE approval_trigger_effects(value TEXT NOT NULL)"); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.app.DB.Exec("CREATE TRIGGER approval_schema_guard BEFORE INSERT ON " + target + " BEGIN INSERT INTO approval_trigger_effects(value) VALUES('unexpected'); END"); err != nil {
				t.Fatal(err)
			}
			var triggerName, tableName string
			if err := fixture.app.DB.QueryRow("SELECT name,tbl_name FROM main.sqlite_schema WHERE type='trigger' AND name='approval_schema_guard'").Scan(&triggerName, &tableName); err != nil {
				t.Fatal(err)
			}
			if triggerName != "approval_schema_guard" || tableName != target {
				t.Fatalf("trigger target spelling not reached: name=%q tbl_name=%q", triggerName, tableName)
			}
			if err := appMCPApprovalSchemaAccepted(t, fixture); err == nil {
				t.Fatal("approval trigger was accepted")
			}
			if _, err := fixture.app.DB.Exec("DROP TRIGGER main.approval_schema_guard"); err != nil {
				t.Fatal(err)
			}
			if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
				t.Fatalf("restored trigger-free baseline refused: %v", err)
			}
		})
	}
	t.Run("temporary schema on actual connection", func(t *testing.T) {
		fixture := newAppMCPApprovalFixture(t, false)
		fixture.app.DB.SetMaxOpenConns(1)
		conn, err := fixture.app.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "CREATE TEMP TABLE unexpected_temp(value TEXT)"); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		var tempCount int
		if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM temp.sqlite_schema WHERE name='unexpected_temp'").Scan(&tempCount); err != nil || tempCount != 1 {
			_ = conn.Close()
			t.Fatalf("temp fixture absent: count=%d err=%v", tempCount, err)
		}
		tx, err := conn.BeginTx(context.Background(), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err == nil {
			_ = tx.Rollback()
			_ = conn.Close()
			t.Fatal("temporary schema was accepted")
		}
		if err := tx.Rollback(); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "DROP TABLE temp.unexpected_temp"); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
			t.Fatalf("clean baseline after temp refusal: %v", err)
		}
	})
	t.Run("attached database on actual connection", func(t *testing.T) {
		fixture := newAppMCPApprovalFixture(t, false)
		fixture.app.DB.SetMaxOpenConns(1)
		conn, err := fixture.app.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		attachedPath := filepath.Join(t.TempDir(), "attached.db")
		if _, err := conn.ExecContext(context.Background(), "ATTACH DATABASE ? AS attached_fixture", attachedPath); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		var attachedCount int
		if err := conn.QueryRowContext(context.Background(), "SELECT count(*) FROM pragma_database_list WHERE name='attached_fixture'").Scan(&attachedCount); err != nil || attachedCount != 1 {
			_ = conn.Close()
			t.Fatalf("attached fixture absent: count=%d err=%v", attachedCount, err)
		}
		tx, err := conn.BeginTx(context.Background(), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if err := verifyAppMCPCommandApprovalStorage(context.Background(), tx); err == nil {
			_ = tx.Rollback()
			_ = conn.Close()
			t.Fatal("attached database was accepted")
		}
		if err := tx.Rollback(); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "DETACH DATABASE attached_fixture"); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if err := appMCPApprovalSchemaAccepted(t, fixture); err != nil {
			t.Fatalf("clean baseline after attached refusal: %v", err)
		}
	})
}

func TestAppMCPCommandApprovalUnionRejectsOrphansAndGenericReceipts(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	orphanID := strings.Repeat("9", 64)
	if _, err := fixture.app.DB.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", orphanID, fixture.approval.ApprovalDigest, fixture.approval.Ciphertext); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("orphan approval was accepted")
	}
	_ = tx.Rollback()
	if _, err := fixture.app.DB.Exec("DELETE FROM main._benmore_mcp_command_approvals WHERE operation_id=?", orphanID); err != nil {
		t.Fatal(err)
	}

	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, fixture.app, fixture.operation.Prepared.OperationID,
		fixture.operation.PreparedDigest, []byte(`{"result":{"status":"legacy"}}`)); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("generic receipt paired with approved state was accepted")
	}
	_ = tx.Rollback()
	noApproval := newAppMCPApprovalFixture(t, false)
	if _, err := noApproval.app.DB.Exec("DELETE FROM main._benmore_mcp_command_approvals WHERE operation_id=?", noApproval.operation.Prepared.OperationID); err != nil {
		t.Fatal(err)
	}
	tx, err = noApproval.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeAppMCPCommittedReceipt(context.Background(), tx, noApproval.app, noApproval.operation.Prepared.OperationID,
		noApproval.operation.PreparedDigest, []byte(`{"result":{"status":"legacy"}}`)); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = noApproval.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, noApproval.appID, noApproval.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("receipt without an approval was accepted")
	}
	_ = tx.Rollback()
}

func TestAppMCPCommandApprovalResealRejectsStaleCiphertext(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("57", 32))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := fixture.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	updateAuthorizations := 0
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(action int, table, column, _ string) int {
			if action == sqlite3.SQLITE_UPDATE && table == "_benmore_mcp_command_approvals" && column == "state_ciphertext" {
				updateAuthorizations++
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	rows, err := appMCPReadCommandApprovalRows(context.Background(), tx)
	if err != nil || len(rows) != 1 {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("read real approval row: rows=%d err=%v", len(rows), err)
	}
	old := rows[0]
	firstReplacement, err := appMCPSealCommandApproval(newKey, fixture.approval.Plaintext)
	if err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := appMCPResealCommandApprovalCAS(context.Background(), tx, old, firstReplacement); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("first real conditional update: %v", err)
	}
	secondReplacement, err := appMCPSealCommandApproval(fixture.key, fixture.approval.Plaintext)
	if err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal(err)
	}
	staleErr := appMCPResealCommandApprovalCAS(context.Background(), tx, old, secondReplacement)
	if staleErr == nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal("genuine stale ciphertext compare-and-swap succeeded")
	}
	if staleErr.Error() != "command approval reseal compare-and-swap failed" {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("stale CAS did not reach the exact zero-row branch: %v", staleErr)
	}
	if updateAuthorizations != 2 {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("stale CAS SQL was not reached after the successful update: native update authorizations=%d", updateAuthorizations)
	}
	var inside string
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", old.operationID).Scan(&inside); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal(err)
	}
	if inside != firstReplacement {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal("zero-row CAS changed current ciphertext")
	}
	if err := tx.Rollback(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil); return nil }); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	var actual string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", old.operationID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != fixture.approval.Ciphertext {
		t.Fatal("caller rollback did not restore the original ciphertext")
	}
	// Separate committed positive proves the primitive still succeeds on the current real row.
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = appMCPReadCommandApprovalRows(context.Background(), tx)
	if err != nil || len(rows) != 1 {
		_ = tx.Rollback()
		t.Fatalf("read current positive row: rows=%d err=%v", len(rows), err)
	}
	if err := appMCPResealCommandApprovalCAS(context.Background(), tx, rows[0], firstReplacement); err != nil {
		_ = tx.Rollback()
		t.Fatalf("fresh ciphertext CAS positive: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", old.operationID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != firstReplacement {
		t.Fatal("committed fresh CAS was not read back")
	}
}

func appMCPApprovalResealSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	queries := []string{
		"SELECT operation_id,prepared_digest,prepared_ciphertext,receipt_digest,receipt_ciphertext FROM main._benmore_mcp_operations ORDER BY operation_id",
		"SELECT operation_id,approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals ORDER BY operation_id",
		"SELECT singleton,version,owner_id,key_generation,operation_storage_provisioned,command_storage_version,last_rotation_id,verification_ciphertext FROM main._benmore_encryption_state ORDER BY singleton",
	}
	var snapshot strings.Builder
	for _, query := range queries {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		fmt.Fprintf(&snapshot, "query:%s\x00", query)
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			for _, value := range values {
				fmt.Fprintf(&snapshot, "%T:%v\x00", value, value)
			}
			snapshot.WriteByte('\n')
		}
		rowsErr, closeErr := rows.Err(), rows.Close()
		if rowsErr != nil {
			t.Fatal(rowsErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	return snapshot.String()
}

func TestAppMCPCommandApprovalResealNativeFailureRollsBackAndCancellationRefuses(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	secondOperation, _, _ := addAppMCPApprovalFixture(t, fixture, strings.Repeat("9", 64), time.Now().Unix(), true)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("5c", 32))
	if err != nil {
		t.Fatal(err)
	}
	var secondBefore string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", secondOperation.Prepared.OperationID).Scan(&secondBefore); err != nil {
		t.Fatal(err)
	}
	allRowsBefore := appMCPApprovalResealSnapshot(t, fixture.app.DB)
	fixture.app.DB.SetMaxOpenConns(1)
	conn, err := fixture.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	updates, denied := 0, false
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(action int, table, column, _ string) int {
			if action == sqlite3.SQLITE_UPDATE && table == "_benmore_mcp_command_approvals" && column == "state_ciphertext" {
				updates++
				if updates == 2 {
					denied = true
					return sqlite3.SQLITE_DENY
				}
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if _, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey); err == nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal("native second-row UPDATE denial was ignored")
	}
	if !denied || updates != 2 {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatalf("native fault was not reached on second approval update: updates=%d denied=%v", updates, denied)
	}
	var firstInside, secondInside string
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&firstInside); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", secondOperation.Prepared.OperationID).Scan(&secondInside); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal(err)
	}
	firstInsidePlain, firstInsideErr := appMCPOpenCommandApproval(newKey, firstInside)
	if firstInside == fixture.approval.Ciphertext || firstInsideErr != nil || !bytes.Equal(firstInsidePlain, fixture.approval.Plaintext) || secondInside != secondBefore {
		_ = tx.Rollback()
		_ = conn.Close()
		t.Fatal("fault did not prove first-row success and second-row denial before rollback")
	}
	if err := tx.Rollback(); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil); return nil }); err != nil {
		_ = conn.Close()
		t.Fatalf("clear native authorizer: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	var firstAfter string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&firstAfter); err != nil {
		t.Fatal(err)
	}
	if firstAfter != fixture.approval.Ciphertext || appMCPApprovalResealSnapshot(t, fixture.app.DB) != allRowsBefore {
		t.Fatal("caller rollback did not restore every approval, operation, receipt, and marker byte after reached native update denial")
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err != nil || count != 2 {
		_ = tx.Rollback()
		t.Fatalf("fresh old-key verification after rollback count=%d err=%v", count, err)
	}
	_ = tx.Rollback()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppMCPCommandApprovalsTx(canceled, tx, fixture.appID, fixture.key, newKey); err == nil {
		_ = tx.Rollback()
		t.Fatal("canceled explicit-key reseal was accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	foreign, _ := auditApp(t)
	foreignID, err := appMCPOperationOwnerID(foreign.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if foreignID == fixture.appID {
		t.Fatal("foreign fixture accidentally shares the owning app identity")
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, foreignID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("actual foreign app identity verified the owning approval store")
	}
	_ = tx.Rollback()
}

func TestAppMCPCommandApprovalResealValidatesEveryRowBeforeWriting(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	secondID := strings.Repeat("9", 64)
	prepared := appMCPOperationStoreRecord(fixture.app, secondID)
	prepared.CreatedAt = time.Now().Unix() - 3600
	prepared.ExpiresAt = prepared.CreatedAt + 15*60
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	secondOperation, err := appMCPInsertOperationTest(t, context.Background(), tx, fixture.app, prepared)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	approval := fixture.approval.Approval
	approval.ApprovalID = strings.Repeat("8", 64)
	approval.OperationID = secondID
	approval.PreparedDigest = secondOperation.PreparedDigest
	approval.ApprovedAt = prepared.CreatedAt + 1
	approval.ExpiresAt = prepared.ExpiresAt
	_, digest, err := appMCPEncodeCommandApproval(approval)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	state := appMCPCommandApprovalState{Approval: approval, ApprovalDigest: digest, State: "approved"}
	plain, err := appMCPEncodeCommandApprovalState(state)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	ciphertext, err := appMCPSealCommandApproval(fixture.key, plain)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", secondID, digest, ciphertext); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var firstCipher, secondCipher string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&firstCipher); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", secondID).Scan(&secondCipher); err != nil {
		t.Fatal(err)
	}
	newKey, err := cryptoDeriveAppKey(strings.Repeat("58", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	validCount, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || validCount != 2 {
		_ = tx.Rollback()
		t.Fatalf("valid two-row baseline count=%d err=%v", validCount, err)
	}
	var firstRotated, secondRotated string
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&firstRotated); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", secondID).Scan(&secondRotated); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if firstRotated == firstCipher || secondRotated == secondCipher {
		_ = tx.Rollback()
		t.Fatal("valid two-row baseline did not update both rows")
	}
	firstPlain, firstOpenErr := appMCPOpenCommandApproval(newKey, firstRotated)
	secondPlain, secondOpenErr := appMCPOpenCommandApproval(newKey, secondRotated)
	if firstOpenErr != nil || secondOpenErr != nil || !bytes.Equal(firstPlain, fixture.approval.Plaintext) || !bytes.Equal(secondPlain, plain) {
		_ = tx.Rollback()
		t.Fatalf("valid two-row reseal plaintext mismatch: first=%v second=%v", firstOpenErr, secondOpenErr)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var rolledBackFirst, rolledBackSecond string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&rolledBackFirst); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", secondID).Scan(&rolledBackSecond); err != nil {
		t.Fatal(err)
	}
	if rolledBackFirst != firstCipher || rolledBackSecond != secondCipher {
		t.Fatal("valid baseline rollback did not restore both old ciphertexts")
	}
	if _, err := fixture.app.DB.Exec("UPDATE main._benmore_mcp_command_approvals SET state_ciphertext='malformed-later-row' WHERE operation_id=?", secondID); err != nil {
		t.Fatal(err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey); err == nil {
		_ = tx.Rollback()
		t.Fatal("corrupt later approval row did not refuse reseal")
	}
	var afterCipher string
	if err := tx.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&afterCipher); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if afterCipher != firstCipher {
		_ = tx.Rollback()
		t.Fatal("earlier row changed before later-row validation failed")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&afterCipher); err != nil {
		t.Fatal(err)
	}
	if afterCipher != firstCipher {
		t.Fatal("corrupt later row caused an earlier approval write")
	}
}

func TestAppMCPCommandApprovalResealPreservesImmutableState(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("56", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := readAppEncryptionState(context.Background(), tx, fixture.appID, fixture.key)
	if err != nil || marker == nil {
		_ = tx.Rollback()
		t.Fatalf("read old marker: %v", err)
	}
	var oldDigest string
	var oldReceiptDigest, oldReceiptCipher sql.NullString
	if err := tx.QueryRow("SELECT approval_digest FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&oldDigest); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.QueryRow("SELECT receipt_digest,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&oldReceiptDigest, &oldReceiptCipher); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	count, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || count != 1 {
		_ = tx.Rollback()
		t.Fatalf("reseal count=%d err=%v", count, err)
	}
	operationCount, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || operationCount != 1 {
		_ = tx.Rollback()
		t.Fatalf("operation reseal count=%d err=%v", operationCount, err)
	}
	newMarker, err := sealAppEncryptionState(newKey, *marker)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result, err := tx.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=? WHERE singleton=1 AND verification_ciphertext COLLATE BINARY=?", newMarker, mustReadLifecycleCiphertext(t, tx))
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		_ = tx.Rollback()
		t.Fatalf("marker reseal CAS affected=%d err=%v", affected, err)
	}
	count, err = verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, newKey)
	if err != nil || count != 1 {
		_ = tx.Rollback()
		t.Fatalf("new-key union count=%d err=%v", count, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	var newDigest string
	var newReceiptDigest, newReceiptCipher sql.NullString
	if err := fixture.app.DB.QueryRow("SELECT approval_digest FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&newDigest); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.QueryRow("SELECT receipt_digest,receipt_ciphertext FROM main._benmore_mcp_operations WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&newReceiptDigest, &newReceiptCipher); err != nil {
		t.Fatal(err)
	}
	if oldDigest != newDigest || oldReceiptDigest != newReceiptDigest || oldReceiptCipher != newReceiptCipher {
		t.Fatal("reseal changed approval digest or receipt null distinction")
	}
	plain, err := appMCPOpenCommandApproval(newKey, ciphertext)
	if err != nil || !bytes.Equal(plain, fixture.approval.Plaintext) {
		t.Fatalf("reseal changed approval plaintext: %v", err)
	}
	if ciphertext == fixture.approval.Ciphertext {
		t.Fatal("reseal retained old ciphertext")
	}
	if _, err := appMCPOpenCommandApproval(fixture.key, ciphertext); err == nil {
		t.Fatal("old key opened resealed approval")
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err = verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, newKey)
	_ = tx.Rollback()
	if err != nil || count != 1 {
		t.Fatalf("committed/reopened new-key union count=%d err=%v", count, err)
	}
	tx, err = fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey); err == nil {
		_ = tx.Rollback()
		t.Fatal("second old-key approval rotation was accepted")
	}
	_ = tx.Rollback()
}

func TestAppMCPCommandApprovalConsumedReceiptUsesStorageCanonicalBytes(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, true)
	state := fixture.approval
	wantReceipt := appMCPCommandReceiptRecord{
		Version: 1, Kind: "command_receipt", State: "committed", AppID: fixture.appID,
		OperationID: fixture.operation.Prepared.OperationID, PreparedDigest: fixture.operation.PreparedDigest,
		ApprovalID: state.Approval.ApprovalID, ApprovalDigest: state.ApprovalDigest,
		AttemptID: state.AttemptID, CommittedAt: state.ConsumedAt,
		Result: json.RawMessage(`{"status":"done"}`), Effects: []json.RawMessage{},
	}
	wantBytes, err := json.Marshal(wantReceipt)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := appMCPReadOperationWithKey(context.Background(), tx, fixture.appID, fixture.key, fixture.operation.Prepared.OperationID)
	_ = tx.Rollback()
	if err != nil || operation == nil || !bytes.Equal(operation.Receipt, wantBytes) {
		t.Fatalf("stored receipt bytes differ from canonical shared encoding: %v", err)
	}
	receipt, err := decodeAppMCPCommandReceipt(operation, &fixture.approval)
	if err != nil || receipt.AppID != fixture.appID || receipt.ApprovalID != state.Approval.ApprovalID || receipt.AttemptID != state.AttemptID || receipt.CommittedAt != state.ConsumedAt {
		t.Fatalf("stored consumed receipt binding readback=%+v err=%v", receipt, err)
	}
}

func TestAppMCPCommandApprovalConsumedStateResealsUnchanged(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, true)
	newKey, err := cryptoDeriveAppKey(strings.Repeat("59", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || count != 1 {
		_ = tx.Rollback()
		t.Fatalf("consumed reseal count=%d err=%v", count, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := fixture.app.DB.QueryRow("SELECT state_ciphertext FROM main._benmore_mcp_command_approvals WHERE operation_id=?", fixture.operation.Prepared.OperationID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	plain, err := appMCPOpenCommandApproval(newKey, ciphertext)
	if err != nil || !bytes.Equal(plain, fixture.approval.Plaintext) {
		t.Fatalf("consumed reseal changed exact state: %v", err)
	}
	state, err := appMCPDecodeCommandApproval(plain, fixture.operation, fixture.appID)
	if err != nil || state.State != "consumed" || state.AttemptID != fixture.approval.AttemptID || state.ConsumedAt != fixture.approval.ConsumedAt {
		t.Fatalf("consumed state after reseal=%+v err=%v", state, err)
	}
	if _, err := appMCPOpenCommandApproval(fixture.key, ciphertext); err == nil {
		t.Fatal("old key opened consumed resealed approval")
	}
}

func TestAppMCPCommandApprovalResealMixedUnionCommitAndReopen(t *testing.T) {
	fixture := newAppMCPApprovalFixture(t, false)
	now := time.Now().Unix()
	secondOperation, secondApproval, receiptBytes := addAppMCPApprovalFixture(t, fixture, strings.Repeat("9", 64), now, true)
	if fixture.approval.Approval.ExpiresAt >= now || secondApproval.Approval.ExpiresAt <= now || secondApproval.State != "consumed" || len(receiptBytes) == 0 {
		t.Fatal("mixed reseal fixture does not contain expired approved and live consumed records")
	}
	newKey, err := cryptoDeriveAppKey(strings.Repeat("5b", 32))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oldMarker, err := readAppEncryptionState(context.Background(), tx, fixture.appID, fixture.key)
	if err != nil || oldMarker == nil {
		_ = tx.Rollback()
		t.Fatalf("read original marker: %v", err)
	}
	oldMarkerCipher := mustReadLifecycleCiphertext(t, tx)
	oldOperations, oldApprovals, err := appMCPValidateCommandStoreUnion(context.Background(), tx, fixture.appID, fixture.key)
	if err != nil || len(oldOperations) != 2 || len(oldApprovals) != 2 {
		_ = tx.Rollback()
		t.Fatalf("complete old-key union ops=%d approvals=%d err=%v", len(oldOperations), len(oldApprovals), err)
	}
	firstBefore := oldOperations[fixture.operation.Prepared.OperationID]
	secondBefore := oldOperations[secondOperation.Prepared.OperationID]
	firstApprovalBefore := oldApprovals[fixture.operation.Prepared.OperationID]
	secondApprovalBefore := oldApprovals[secondOperation.Prepared.OperationID]
	firstPreparedJSON, firstPreparedDigest, err := appMCPEncodePrepared(firstBefore.Prepared)
	if err != nil || firstPreparedDigest != firstBefore.PreparedDigest {
		_ = tx.Rollback()
		t.Fatalf("first original prepared bytes invalid: %v", err)
	}
	secondPreparedJSON, secondPreparedDigest, err := appMCPEncodePrepared(secondBefore.Prepared)
	if err != nil || secondPreparedDigest != secondBefore.PreparedDigest {
		_ = tx.Rollback()
		t.Fatalf("second original prepared bytes invalid: %v", err)
	}
	firstApprovalPlain := bytes.Clone(firstApprovalBefore.Plaintext)
	secondApprovalPlain := bytes.Clone(secondApprovalBefore.Plaintext)
	firstDigest, secondDigest := firstApprovalBefore.ApprovalDigest, secondApprovalBefore.ApprovalDigest
	if firstBefore.Receipt != nil || secondBefore.Receipt == nil || !bytes.Equal(secondBefore.Receipt, receiptBytes) {
		_ = tx.Rollback()
		t.Fatal("mixed union lost null/non-null receipt distinction")
	}
	approvalCount, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || approvalCount != 2 {
		_ = tx.Rollback()
		t.Fatalf("approval reseal count=%d err=%v", approvalCount, err)
	}
	operationCount, err := rotateAppMCPOperationRowsWithKeys(context.Background(), tx, fixture.appID, fixture.key, newKey)
	if err != nil || operationCount != 2 {
		_ = tx.Rollback()
		t.Fatalf("operation reseal count=%d err=%v", operationCount, err)
	}
	newMarker, err := sealAppEncryptionState(newKey, *oldMarker)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	result, err := tx.Exec("UPDATE main._benmore_encryption_state SET verification_ciphertext=? WHERE singleton=1 AND verification_ciphertext COLLATE BINARY=?", newMarker, oldMarkerCipher)
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		_ = tx.Rollback()
		t.Fatalf("same-transaction candidate marker update affected=%d err=%v", changed, err)
	}
	newOperations, newApprovals, err := appMCPValidateCommandStoreUnion(context.Background(), tx, fixture.appID, newKey)
	if err != nil || len(newOperations) != 2 || len(newApprovals) != 2 {
		_ = tx.Rollback()
		t.Fatalf("complete new-key union ops=%d approvals=%d err=%v", len(newOperations), len(newApprovals), err)
	}
	markerCheck, err := readAppEncryptionState(context.Background(), tx, fixture.appID, newKey)
	if err != nil || markerCheck == nil || markerCheck.KeyGeneration != oldMarker.KeyGeneration {
		_ = tx.Rollback()
		t.Fatalf("same-transaction candidate marker readback: %+v err=%v", markerCheck, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite3", filepath.Join(fixture.app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	reopened.SetMaxOpenConns(1)
	fixture.app.DB = reopened
	tx, err = reopened.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCount, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, newKey)
	if err != nil || verifiedCount != 2 {
		_ = tx.Rollback()
		t.Fatalf("reopened new-key union count=%d err=%v", verifiedCount, err)
	}
	for id, want := range map[string]struct {
		prepared       []byte
		digest         string
		approval       []byte
		approvalDigest string
		receipt        []byte
	}{
		fixture.operation.Prepared.OperationID: {prepared: firstPreparedJSON, digest: firstPreparedDigest, approval: firstApprovalPlain, approvalDigest: firstDigest, receipt: nil},
		secondOperation.Prepared.OperationID:   {prepared: secondPreparedJSON, digest: secondPreparedDigest, approval: secondApprovalPlain, approvalDigest: secondDigest, receipt: receiptBytes},
	} {
		operation, err := appMCPReadOperationWithKey(context.Background(), tx, fixture.appID, newKey, id)
		if err != nil || operation == nil || operation.Prepared.AppID != fixture.appID {
			_ = tx.Rollback()
			t.Fatalf("reopened operation %s owner/readback: %v", id, err)
		}
		preparedJSON, digest, err := appMCPEncodePrepared(operation.Prepared)
		if err != nil || !bytes.Equal(preparedJSON, want.prepared) || digest != want.digest || !bytes.Equal(operation.Receipt, want.receipt) {
			_ = tx.Rollback()
			t.Fatalf("reopened operation %s changed prepared or receipt bytes: %v", id, err)
		}
		approval, err := appMCPReadCommandApprovalWithKey(context.Background(), tx, fixture.appID, newKey, operation)
		if err != nil || approval == nil || approval.Approval.AppID != fixture.appID || !bytes.Equal(approval.Plaintext, want.approval) || approval.ApprovalDigest != want.approvalDigest {
			_ = tx.Rollback()
			t.Fatalf("reopened approval %s changed owner or immutable/state bytes: %v", id, err)
		}
	}
	_ = tx.Rollback()
	tx, err = reopened.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAppMCPCommandApprovalsWithKey(context.Background(), tx, fixture.appID, fixture.key); err == nil {
		_ = tx.Rollback()
		t.Fatal("old key verified reopened resealed marker and union")
	}
	_ = tx.Rollback()
	tx, err = reopened.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotateAppMCPCommandApprovalsTx(context.Background(), tx, fixture.appID, fixture.key, newKey); err == nil {
		_ = tx.Rollback()
		t.Fatal("old key repeated a reseal after reopen")
	}
	_ = tx.Rollback()
}

func mustReadLifecycleCiphertext(t *testing.T, tx *sql.Tx) string {
	t.Helper()
	var value string
	if err := tx.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
