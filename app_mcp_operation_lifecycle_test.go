//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

func setAppLifecycleEnvironment(app *App, env map[string]string) {
	app.mu.Lock()
	app.environment = env
	storeAppEnv(app.Dir, env)
	app.mu.Unlock()
}

func registerAppLifecycleTestKey(t *testing.T, app *App, source string) []byte {
	t.Helper()
	key, err := cryptoDeriveAppKey(source)
	if err != nil {
		t.Fatalf("derive lifecycle fixture key: %v", err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	return key
}

func appMCPCommandLifecycleFixture(key string) (*runtimeConfig, map[string]string) {
	return &runtimeConfig{
		mcp:   &AppMCPManifest{Tools: []AppMCPTool{{Handler: AppMCPHandler{Kind: "flow", Operation: "command", Flow: "notes.update"}}}},
		flows: []Flow{{Name: "notes.update", Command: &FlowCommand{}}},
	}, map[string]string{"ENCRYPTION_KEY": key}
}

func writeActualLifecycleCommandFixture(t *testing.T, dir string) {
	t.Helper()
	flow := "on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}\n" + strings.ReplaceAll(commandFixtureForManifest, "work_items", "notes")
	writeTestFile(t, dir, "flows/complete_note.yaml", flow)
	manifest := commandManifest()
	manifest.Tools[0].Name = "complete_note"
	manifest.Tools[0].Handler.Flow = "complete_note"
	manifest.Tools[0].Permissions = []string{"notes:write"}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(data))
	reviewAppMCPFixture(t, dir)
}

func appMCPLifecyclePairCounts(t *testing.T, app *App) (int, int) {
	t.Helper()
	var operations, state int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_encryption_state'").Scan(&state); err != nil {
		t.Fatal(err)
	}
	return operations, state
}

func appMCPLifecycleApprovalCount(t *testing.T, app *App) int {
	t.Helper()
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func appMCPLifecycleApprovalSnapshot(t *testing.T, app *App) string {
	t.Helper()
	var exists int
	if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists == 0 {
		return "<absent>"
	}
	var schemaSQL string
	if err := app.DB.QueryRow("SELECT sql FROM main.sqlite_schema WHERE type='table' AND lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&schemaSQL); err != nil {
		t.Fatal(err)
	}
	rows, err := app.DB.Query("SELECT operation_id,approval_digest,state_ciphertext FROM main._benmore_mcp_command_approvals ORDER BY operation_id")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot strings.Builder
	fmt.Fprintf(&snapshot, "schema\x00%s\x00", schemaSQL)
	for rows.Next() {
		var operationID, digest, ciphertext string
		if err := rows.Scan(&operationID, &digest, &ciphertext); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		fmt.Fprintf(&snapshot, "%s\x00%s\x00%s\x00", operationID, digest, ciphertext)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil {
		t.Fatal(rowsErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return snapshot.String()
}

func seedAppMCPLifecycleApprovalFixture(t *testing.T, app *App) (string, string, string, string) {
	t.Helper()
	registry := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
	if registry == nil || registry.ephemeral || len(registry.aes) != 32 {
		t.Fatal("loaded app has no current durable owner key")
	}
	key := append([]byte(nil), registry.aes...)
	appID, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	operationID := strings.Repeat("32", 32)
	prepared := appMCPOperationStoreRecord(app, operationID)
	prepared.CreatedAt = now
	prepared.ExpiresAt = now + 15*60
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := insertAppMCPPreparedOperation(context.Background(), tx, app, prepared)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert approved fixture's prepared operation: %v", err)
	}
	approval := appMCPCommandApprovalRecord{
		Version: 1, Domain: "benmore:mcp:human-approval:v1", ApprovalID: strings.Repeat("4", 64),
		AppID: appID, OperationID: operationID, PreparedDigest: operation.PreparedDigest,
		DisclosureVersion: prepared.DisclosureVersion, OwnerEpoch: prepared.RuntimeAuthority.OwnerEpoch,
		WriteEpoch: prepared.RuntimeAuthority.WriteEpoch, ApproverUserID: prepared.Origin.ActorID,
		ApproverCreated: prepared.Origin.ActorCreated, ApproverSessionID: sessionKeyPrefix + strings.Repeat("6", 64),
		Tenant: prepared.Origin.Tenant, ApprovedAt: now + 1, ExpiresAt: prepared.ExpiresAt,
		ReviewChallengeDigest: strings.Repeat("5", 64),
	}
	_, digest, err := appMCPEncodeCommandApproval(approval)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("encode test-only approval: %v", err)
	}
	state := appMCPCommandApprovalState{Approval: approval, ApprovalDigest: digest, State: "approved"}
	state.Plaintext, err = appMCPEncodeCommandApprovalState(state)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("encode test-only approval state: %v", err)
	}
	state.Ciphertext, err = appMCPSealCommandApproval(key, state.Plaintext)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("seal test-only approval: %v", err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO main._benmore_mcp_command_approvals(operation_id,approval_digest,state_ciphertext) VALUES(?,?,?)", operationID, digest, state.Ciphertext); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert test-only approved row: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit test-only approved row: %v", err)
	}
	readTx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	readOperation, err := appMCPReadOperationWithKey(context.Background(), readTx, appID, key, operationID)
	if err != nil || readOperation == nil || readOperation.Receipt != nil {
		_ = readTx.Rollback()
		t.Fatalf("approved fixture operation readback: %v", err)
	}
	readState, err := appMCPReadCommandApprovalWithKey(context.Background(), readTx, appID, key, readOperation)
	if err := readTx.Rollback(); err != nil && err != sql.ErrTxDone {
		t.Fatalf("rollback approval fixture readback: %v", err)
	}
	if err != nil || readState == nil || readState.Approval.OperationID != operationID || readState.ApprovalDigest != digest || readState.Ciphertext != state.Ciphertext || string(readState.Plaintext) != string(state.Plaintext) {
		t.Fatalf("authenticated approval fixture readback: %v", err)
	}
	return operationID, digest, state.Ciphertext, string(state.Plaintext)
}

func createUnprovisionedLifecycleMarker(t *testing.T, tx *sql.Tx, owner string, key []byte) {
	t.Helper()
	if tx == nil {
		t.Fatal("unprovisioned marker fixture requires an open transaction")
	}
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			t.Errorf("rollback unprovisioned marker fixture: %v", err)
		}
	})
	state := appEncryptionState{Version: 2, OwnerID: owner, KeyGeneration: strings.Repeat("76", 32), CommandStorageVersion: 0}
	ciphertext, err := sealAppEncryptionState(key, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(appEncryptionStateDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO main._benmore_encryption_state(singleton,version,owner_id,key_generation,operation_storage_provisioned,command_storage_version,last_rotation_id,verification_ciphertext) VALUES(1,2,?,?,0,0,NULL,?)", owner, state.KeyGeneration, ciphertext); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPOperationLifecycleProvisionReloadAndCheckOnly(t *testing.T) {
	app, _ := auditApp(t)
	app.DB.SetMaxOpenConns(1)
	keySource := strings.Repeat("ab", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh || !plan.needed {
		t.Fatalf("fresh command preflight plan=%+v err=%v", plan, err)
	}
	key, err := cryptoDeriveAppKey(keySource)
	if err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, true); err != nil {
		t.Fatalf("check-only lifecycle: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("check-only persisted pair: operations=%d state=%d", operations, state)
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("bootstrap lifecycle: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 1 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 1 {
		t.Fatalf("bootstrap trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
	setAppLifecycleEnvironment(app, env)
	var generation, ciphertext string
	if err := app.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&generation, &ciphertext); err != nil {
		t.Fatal(err)
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, config, env, true)
	if err != nil {
		t.Fatalf("same-key reload preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("same-key reload verification: %v", err)
	}
	readOnlyConfig := &runtimeConfig{}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, readOnlyConfig, env, false)
	if err != nil || plan == nil || plan.fresh {
		t.Fatalf("command removal did not preserve and verify pair: plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("verify after command removal: %v", err)
	}
	var afterGeneration, afterCiphertext string
	if err := app.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&afterGeneration, &afterCiphertext); err != nil {
		t.Fatal(err)
	}
	if generation != afterGeneration || ciphertext != afterCiphertext {
		t.Fatal("ordinary verification changed the encryption state marker")
	}
}

func TestAppMCPOperationLifecycleChangedAfterPreflightDoesNotRepair(t *testing.T) {
	app, _ := auditApp(t)
	keySource := strings.Repeat("d1", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("fresh preflight plan=%+v err=%v", plan, err)
	}
	key, _ := cryptoDeriveAppKey(keySource)
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	if _, err := app.DB.Exec("CREATE TABLE _benmore_encryption_state(unreviewed TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("changed storage expectation was silently repaired")
	}
	operations, state := appMCPLifecyclePairCounts(t, app)
	if operations != 0 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("refusal changed storage: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecyclePlanIsBoundToAppAndPath(t *testing.T) {
	keySource := strings.Repeat("d2", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	control, _ := auditApp(t)
	registerAppLifecycleTestKey(t, control, keySource)
	controlPlan, err := preflightAppMCPOperationLifecycle(context.Background(), control, config, env, false)
	if err != nil {
		t.Fatalf("same-app control preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), control, controlPlan, false); err != nil {
		t.Fatalf("same-app control finalization: %v", err)
	}
	a, _ := auditApp(t)
	b, _ := auditApp(t)
	registerAppLifecycleTestKey(t, a, keySource)
	registerAppLifecycleTestKey(t, b, keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), a, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("fresh owner plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), b, plan, false); err == nil {
		t.Fatal("plan from App A was accepted by App B with the same key")
	}
	for name, app := range map[string]*App{"A": a, "B": b} {
		if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
			t.Fatalf("cross-app refusal changed App %s: operations=%d state=%d approvals=%d", name, operations, state, appMCPLifecycleApprovalCount(t, app))
		}
	}
	pathControl, _ := auditApp(t)
	registerAppLifecycleTestKey(t, pathControl, keySource)
	pathControlPlan, err := preflightAppMCPOperationLifecycle(context.Background(), pathControl, config, env, false)
	if err != nil {
		t.Fatalf("same-path control preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), pathControl, pathControlPlan, false); err != nil {
		t.Fatalf("same-path control finalization: %v", err)
	}
	pathApp, _ := auditApp(t)
	registerAppLifecycleTestKey(t, pathApp, keySource)
	pathPlan, err := preflightAppMCPOperationLifecycle(context.Background(), pathApp, config, env, false)
	if err != nil || pathPlan == nil {
		t.Fatalf("path-change control preflight: %v", err)
	}
	original := pathApp.Dir
	pathApp.Dir = t.TempDir()
	if err := finishAppMCPOperationLifecycle(context.Background(), pathApp, pathPlan, false); err == nil {
		t.Fatal("plan was accepted after the app directory changed")
	}
	pathApp.Dir = original
	if operations, state := appMCPLifecyclePairCounts(t, pathApp); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, pathApp) != 0 {
		t.Fatalf("path-change refusal changed database: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, pathApp))
	}
}

func TestAppMCPOperationLifecycleReloadUsesBoundAppEnvironment(t *testing.T) {
	app, _ := auditApp(t)
	keyA := registerAppLifecycleTestKey(t, app, strings.Repeat("a1", 32))
	envA := map[string]string{"ENCRYPTION_KEY": strings.Repeat("a1", 32)}
	setAppLifecycleEnvironment(app, envA)
	storeAppEnv(app.Dir, map[string]string{"ENCRYPTION_KEY": strings.Repeat("b2", 32)})
	config, candidateEnv := appMCPCommandLifecycleFixture(strings.Repeat("a1", 32))
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, candidateEnv, false)
	if err != nil {
		t.Fatalf("bound-key setup preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("bound-key setup finalization: %v", err)
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, config, candidateEnv, true)
	if err != nil || plan == nil || !appMCPKeyMatches(plan.currentKey, keyA) {
		t.Fatalf("reload followed directory store instead of App-bound key A: plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("unchanged App-bound key reload control failed: %v", err)
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, config, candidateEnv, true)
	if err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	app.environment = map[string]string{"ENCRYPTION_KEY": strings.Repeat("b2", 32)}
	app.mu.Unlock()
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("finalization accepted a changed App-bound key after preflight")
	}
	registered := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
	if registered == nil || !appMCPKeyMatches(keyA, registered.aes) {
		t.Fatal("bound-environment refusal changed owning registry")
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{{"nil captured environment", nil}, {"empty captured environment", map[string]string{}}} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, _ := auditApp(t)
			candidateKey := registerAppLifecycleTestKey(t, candidate, strings.Repeat("a1", 32))
			storeAppEnv(candidate.Dir, candidateEnv)
			candidate.mu.Lock()
			candidate.environment = tc.env
			candidate.mu.Unlock()
			if _, err := preflightAppMCPOperationLifecycle(context.Background(), candidate, config, candidateEnv, true); err == nil {
				t.Fatal("reload fell back to the directory-global key without an App-bound key")
			}
			candidate.mu.RLock()
			captured := candidate.environment
			candidate.mu.RUnlock()
			if captured != nil && len(captured) != 0 {
				t.Fatal("negative control unexpectedly has a bound key")
			}
			registered := cryptoKeysForDBPath(filepath.Join(candidate.Dir, "data.db"))
			if registered == nil || !appMCPKeyMatches(candidateKey, registered.aes) {
				t.Fatal("nil-bound-key refusal changed the registered key")
			}
		})
	}
}

func TestAppMCPOperationLifecycleRejectsOperationTableAppearingBesideUnprovisionedState(t *testing.T) {
	keySource := strings.Repeat("65", 32)
	key, err := cryptoDeriveAppKey(keySource)
	if err != nil {
		t.Fatal(err)
	}
	control, _ := auditApp(t)
	RegisterDBEncryptionKey(filepath.Join(control.Dir, "data.db"), key)
	owner, err := appMCPOperationOwnerID(control.Dir)
	if err != nil {
		t.Fatal(err)
	}
	controlTx, err := control.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	createUnprovisionedLifecycleMarker(t, controlTx, owner, key)
	if err := controlTx.Commit(); err != nil {
		_ = controlTx.Rollback()
		t.Fatal(err)
	}
	// The control proves a false marker with no command remains verifiable.
	controlEnv := map[string]string{"ENCRYPTION_KEY": keySource}
	controlPlan, err := preflightAppMCPOperationLifecycle(context.Background(), control, &runtimeConfig{}, controlEnv, false)
	if err != nil {
		t.Fatalf("valid unprovisioned control preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), control, controlPlan, false); err != nil {
		t.Fatalf("valid unprovisioned control finalization: %v", err)
	}

	app, _ := auditApp(t)
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	owner, err = appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	createUnprovisionedLifecycleMarker(t, tx, owner, key)
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, controlEnv, false)
	if err != nil || plan == nil || plan.operationsPresent || !plan.statePresent {
		t.Fatalf("unprovisioned preflight plan=%+v err=%v", plan, err)
	}
	appearanceTx := mustBeginLifecycleTx(t, app)
	if err := initializeAppMCPOperationStorage(context.Background(), appearanceTx); err != nil {
		_ = appearanceTx.Rollback()
		t.Fatal(err)
	}
	if err := appearanceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("operation table appeared after preflight beside a false marker")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 1 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("presence-mismatch refusal changed objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func mustBeginLifecycleTx(t *testing.T, app *App) *sql.Tx {
	t.Helper()
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestAppMCPOperationLifecycleConfiguredKeyCannotReplaceRegisteredKey(t *testing.T) {
	app, _ := auditApp(t)
	oldKey, _ := cryptoDeriveAppKey(strings.Repeat("43", 32))
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), oldKey)
	config, env := appMCPCommandLifecycleFixture(strings.Repeat("54", 32))
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false); err == nil {
		t.Fatal("cold preflight accepted candidate that would overwrite the registered key")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("key mismatch changed storage: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecycleUnprovisionedMarkerNeedsExplicitUpgrade(t *testing.T) {
	app, _ := auditApp(t)
	keySource := strings.Repeat("65", 32)
	key, _ := cryptoDeriveAppKey(keySource)
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	owner, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	createUnprovisionedLifecycleMarker(t, tx, owner, key)
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	env := map[string]string{"ENCRYPTION_KEY": keySource}
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, env, false)
	if err != nil || plan == nil || plan.fresh {
		t.Fatalf("legacy unprovisioned marker verification plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("preserve verified unprovisioned marker: %v", err)
	}
	command, commandEnv := appMCPCommandLifecycleFixture(keySource)
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, command, commandEnv, false); err == nil {
		t.Fatal("new command silently upgraded an unprovisioned marker")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("refused lifecycle upgrade changed storage: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecycleV2ObjectSubsetsAndLegacyRefusal(t *testing.T) {
	keySource := strings.Repeat("71", 32)
	key, err := cryptoDeriveAppKey(keySource)
	if err != nil {
		t.Fatal(err)
	}
	for mask := 1; mask < 16; mask++ {
		t.Run(fmt.Sprintf("subset_%d", mask), func(t *testing.T) {
			app, _ := auditApp(t)
			RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
			owner, err := appMCPOperationOwnerID(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			tx := mustBeginLifecycleTx(t, app)
			if mask&1 != 0 {
				if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if mask&2 != 0 {
				if err := initializeAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if mask&8 != 0 {
				if err := initializeAppMCPCommandAttemptStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if mask&4 != 0 {
				switch mask {
				case 4:
					createUnprovisionedLifecycleMarker(t, tx, owner, key)
				case 15:
					if _, err := initializeAppEncryptionState(context.Background(), tx, owner, key); err != nil {
						_ = tx.Rollback()
						t.Fatal(err)
					}
				default:
					state := appEncryptionState{Version: 2, OwnerID: owner, KeyGeneration: strings.Repeat("81", 32), OperationStorageProvisioned: true, CommandStorageVersion: 2}
					ciphertext, err := sealAppEncryptionState(key, state)
					if err != nil {
						_ = tx.Rollback()
						t.Fatal(err)
					}
					if _, err := tx.Exec(appEncryptionStateDDL); err != nil {
						_ = tx.Rollback()
						t.Fatal(err)
					}
					if _, err := tx.Exec("INSERT INTO main._benmore_encryption_state(singleton,version,owner_id,key_generation,operation_storage_provisioned,command_storage_version,last_rotation_id,verification_ciphertext) VALUES(1,2,?,?,1,2,NULL,?)", owner, state.KeyGeneration, ciphertext); err != nil {
						_ = tx.Rollback()
						t.Fatal(err)
					}
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			config, env := appMCPCommandLifecycleFixture(keySource)
			plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, env, false)
			if mask == 4 || mask == 7 || mask == 15 {
				if err != nil || plan == nil {
					t.Fatalf("complete supported subset %d refused: %v", mask, err)
				}
				if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
					t.Fatalf("supported subset %d verification: %v", mask, err)
				}
				if mask == 7 {
					// Storage provisioned before attempt history: the upgrade adds the empty table.
					var tables int
					if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_command_attempts'").Scan(&tables); err != nil || tables != 1 {
						t.Fatalf("attempts table after the upgrade: %d %v", tables, err)
					}
				}
				if mask == 4 {
					if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false); err == nil {
						t.Fatal("V2/0 marker silently upgraded for a command")
					}
				}
			} else if err == nil {
				t.Fatalf("partial object subset %d was accepted", mask)
			}
		})
	}

	// Preserve the literal published V1 DDL/payload as a compatibility control.
	legacyDDL := appMCPPublishedV1EncryptionStateDDL
	for _, provisioned := range []bool{false, true} {
		t.Run(fmt.Sprintf("published V1 provisioned=%t", provisioned), func(t *testing.T) {
			app, _ := auditApp(t)
			RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
			owner, err := appMCPOperationOwnerID(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			legacyPayload := struct {
				Domain                      string  `json:"domain"`
				Version                     int     `json:"version"`
				OwnerID                     string  `json:"owner_id"`
				KeyGeneration               string  `json:"key_generation"`
				OperationStorageProvisioned bool    `json:"operation_storage_provisioned"`
				LastRotationID              *string `json:"last_rotation_id"`
			}{"benmore:encryption-state:v1", 1, owner, strings.Repeat("82", 32), provisioned, nil}
			legacyPlain, err := json.Marshal(legacyPayload)
			if err != nil {
				t.Fatal(err)
			}
			legacyCipher, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(legacyPlain))
			if err != nil {
				t.Fatal(err)
			}
			tx := mustBeginLifecycleTx(t, app)
			if provisioned {
				if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(legacyDDL); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if _, err := tx.Exec("INSERT INTO main._benmore_encryption_state(singleton,version,owner_id,key_generation,operation_storage_provisioned,last_rotation_id,verification_ciphertext) VALUES(1,1,?,?,?,NULL,?)", owner, legacyPayload.KeyGeneration, provisioned, legacyCipher); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			boundEnv := map[string]string{"ENCRYPTION_KEY": keySource}
			setAppLifecycleEnvironment(app, boundEnv)
			registeredBefore := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
			if !appMCPKeyMatches(appMCPBoundLifecycleKey(app), key) || registeredBefore == nil || registeredBefore.ephemeral || !appMCPKeyMatches(registeredBefore.aes, key) {
				t.Fatal("V1 reload fixture lacks the actual bound and registered owning key")
			}
			wantRefusal := "operation encryption state verification failed"
			if provisioned {
				wantRefusal = "command storage and encryption state are incomplete; reviewed maintenance is required"
			}
			for _, reload := range []bool{false, true} {
				_, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, boundEnv, reload)
				if err == nil || err.Error() != wantRefusal {
					t.Fatalf("published V1 marker provisioned=%t reload=%t refusal=%v want=%q", provisioned, reload, err, wantRefusal)
				}
			}
			var gotDDL, gotCipher string
			if err := app.DB.QueryRow("SELECT sql FROM main.sqlite_schema WHERE name='_benmore_encryption_state'").Scan(&gotDDL); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&gotCipher); err != nil {
				t.Fatal(err)
			}
			if gotDDL != legacyDDL || gotCipher != legacyCipher {
				t.Fatal("V1 refusal changed published schema or authenticated marker ciphertext")
			}
			var operationObjects int
			if err := app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name='_benmore_mcp_operations'").Scan(&operationObjects); err != nil {
				t.Fatal(err)
			}
			if provisioned && operationObjects != 1 || !provisioned && operationObjects != 0 {
				t.Fatalf("V1 refusal changed operation presence: provisioned=%t objects=%d", provisioned, operationObjects)
			}
			if appMCPLifecycleApprovalCount(t, app) != 0 {
				t.Fatal("V1 refusal created command approval storage")
			}
			registered := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
			if registered == nil || !appMCPKeyMatches(registered.aes, key) {
				t.Fatal("V1 refusal changed the owning key")
			}
		})
	}
}

const appMCPPublishedV1EncryptionStateDDL = `CREATE TABLE _benmore_encryption_state (
	singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 1),
	version INTEGER NOT NULL CHECK(version = 1),
	owner_id TEXT NOT NULL CHECK(length(owner_id) = 64),
	key_generation TEXT NOT NULL CHECK(length(key_generation) = 64),
	operation_storage_provisioned INTEGER NOT NULL CHECK(operation_storage_provisioned IN (0,1)),
	last_rotation_id TEXT CHECK(last_rotation_id IS NULL OR length(last_rotation_id) = 64),
	verification_ciphertext TEXT NOT NULL
)`

func TestAppMCPOperationLifecycleV1CheckOnlyLoaderRefusesWithoutMutation(t *testing.T) {
	for _, provisioned := range []bool{false, true} {
		t.Run(fmt.Sprintf("provisioned=%t", provisioned), func(t *testing.T) {
			root := t.TempDir()
			authorityDir := filepath.Join(t.TempDir(), "authority")
			if err := os.Mkdir(authorityDir, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityDir)
			t.Setenv("BENMORE_TEST_BOOT", "1")
			writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
			writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
			keySource := strings.Repeat("83", 32)
			writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+keySource+"\n")
			writeActualLifecycleCommandFixture(t, root)
			key, err := cryptoDeriveAppKey(keySource)
			if err != nil {
				t.Fatal(err)
			}
			RegisterDBEncryptionKey(filepath.Join(root, "data.db"), key)
			owner, err := appMCPOperationOwnerID(root)
			if err != nil {
				t.Fatal(err)
			}
			payload := struct {
				Domain                      string  `json:"domain"`
				Version                     int     `json:"version"`
				OwnerID                     string  `json:"owner_id"`
				KeyGeneration               string  `json:"key_generation"`
				OperationStorageProvisioned bool    `json:"operation_storage_provisioned"`
				LastRotationID              *string `json:"last_rotation_id"`
			}{"benmore:encryption-state:v1", 1, owner, strings.Repeat("82", 32), provisioned, nil}
			plain, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := fieldEncryptCtx(key, "_benmore_encryption_state", "verification_ciphertext", string(plain))
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite3", filepath.Join(root, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			if provisioned {
				if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					_ = db.Close()
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(appMCPPublishedV1EncryptionStateDDL); err != nil {
				_ = tx.Rollback()
				_ = db.Close()
				t.Fatal(err)
			}
			if _, err := tx.Exec("INSERT INTO main._benmore_encryption_state(singleton,version,owner_id,key_generation,operation_storage_provisioned,last_rotation_id,verification_ciphertext) VALUES(1,1,?,?,?,NULL,?)", owner, payload.KeyGeneration, provisioned, ciphertext); err != nil {
				_ = tx.Rollback()
				_ = db.Close()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			// Capture the actual disk schema, marker row and operation/approval presence before the real loader.
			snapshot := func() string {
				t.Helper()
				probe, err := sql.Open("sqlite3", filepath.Join(root, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
				if err != nil {
					t.Fatal(err)
				}
				var result strings.Builder
				rows, err := probe.Query("SELECT type,name,sql FROM main.sqlite_schema WHERE lower(name) IN (lower('_benmore_encryption_state'),lower('_benmore_mcp_operations'),lower('_benmore_mcp_command_approvals')) ORDER BY lower(name),type")
				if err != nil {
					_ = probe.Close()
					t.Fatal(err)
				}
				for rows.Next() {
					var typ, name string
					var ddl sql.NullString
					if err := rows.Scan(&typ, &name, &ddl); err != nil {
						_ = rows.Close()
						_ = probe.Close()
						t.Fatal(err)
					}
					fmt.Fprintf(&result, "schema:%s\x00%s\x00%v\x00", typ, name, ddl)
				}
				rowsErr, closeErr := rows.Err(), rows.Close()
				if rowsErr != nil {
					_ = probe.Close()
					t.Fatal(rowsErr)
				}
				if closeErr != nil {
					_ = probe.Close()
					t.Fatal(closeErr)
				}
				var version int
				var ownerID, generation, marker string
				var provisionedValue int
				var rotation sql.NullString
				if err := probe.QueryRow("SELECT version,owner_id,key_generation,operation_storage_provisioned,last_rotation_id,verification_ciphertext FROM main._benmore_encryption_state WHERE singleton=1").Scan(&version, &ownerID, &generation, &provisionedValue, &rotation, &marker); err != nil {
					_ = probe.Close()
					t.Fatal(err)
				}
				fmt.Fprintf(&result, "marker:%d\x00%s\x00%s\x00%d\x00%v\x00%s\x00", version, ownerID, generation, provisionedValue, rotation, marker)
				var operationObjects, approvalObjects, operationRows int
				if err := probe.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_operations')").Scan(&operationObjects); err != nil {
					_ = probe.Close()
					t.Fatal(err)
				}
				if err := probe.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&approvalObjects); err != nil {
					_ = probe.Close()
					t.Fatal(err)
				}
				if operationObjects == 1 {
					if err := probe.QueryRow("SELECT count(*) FROM main._benmore_mcp_operations").Scan(&operationRows); err != nil {
						_ = probe.Close()
						t.Fatal(err)
					}
				}
				fmt.Fprintf(&result, "objects:%d\x00%d\x00%d\x00", operationObjects, approvalObjects, operationRows)
				if err := probe.Close(); err != nil {
					t.Fatal(err)
				}
				return result.String()
			}
			before := snapshot()
			registeredBefore := cryptoKeysForDBPath(filepath.Join(root, "data.db"))
			if registeredBefore == nil || registeredBefore.ephemeral || !appMCPKeyMatches(registeredBefore.aes, key) {
				t.Fatal("V1 loader fixture lacks the actual durable current owner key")
			}
			if !strings.Contains(before, ciphertext) || !strings.Contains(before, appMCPPublishedV1EncryptionStateDDL) {
				t.Fatal("V1 loader fixture did not establish the authenticated published marker")
			}
			app, loadErr := loadAppWithOptions(root, appLoadOptions{checkOnly: true})
			if app != nil {
				app.Shutdown()
				t.Fatal("refused V1 check-only load returned an App")
			}
			want := "operation lifecycle preflight: operation encryption state verification failed"
			if provisioned {
				want = "operation lifecycle preflight: command storage and encryption state are incomplete; reviewed maintenance is required"
			}
			if loadErr == nil || !strings.Contains(loadErr.Error(), want) {
				t.Fatalf("V1 check-only loader refusal provisioned=%t err=%v want classification containing %q", provisioned, loadErr, want)
			}
			if after := snapshot(); after != before {
				t.Fatal("V1 check-only loader refusal changed schema, marker, generation, operations, or approval presence")
			}
			registeredAfter := cryptoKeysForDBPath(filepath.Join(root, "data.db"))
			if registeredAfter == nil || registeredAfter.ephemeral || !appMCPKeyMatches(registeredAfter.aes, key) {
				t.Fatal("V1 check-only loader refusal changed the registered owner key")
			}
		})
	}
}

func TestAppMCPOperationLifecycleV2ZeroMarkerRejectsCommandTables(t *testing.T) {
	keySource := strings.Repeat("72", 32)
	key, err := cryptoDeriveAppKey(keySource)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"operations", "approvals", "attempts"} {
		t.Run(table, func(t *testing.T) {
			app, _ := auditApp(t)
			RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
			owner, err := appMCPOperationOwnerID(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			tx := mustBeginLifecycleTx(t, app)
			createUnprovisionedLifecycleMarker(t, tx, owner, key)
			if table == "operations" {
				if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			} else if table == "attempts" {
				if err := initializeAppMCPCommandAttemptStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			} else {
				if err := initializeAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
			}
			if _, err := readAppEncryptionState(context.Background(), tx, owner, key); err == nil {
				_ = tx.Rollback()
				t.Fatal("V2/0 marker read accepted a command table")
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, map[string]string{"ENCRYPTION_KEY": keySource}, false); err == nil {
				t.Fatal("V2/0 marker with command storage was accepted")
			}
		})
	}
}

func TestAppMCPOperationLifecycleOrdinaryAppIsNoOp(t *testing.T) {
	app, _ := auditApp(t)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, nil, false)
	if err != nil || plan == nil || plan.needed {
		t.Fatalf("ordinary read-only app preflight plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatal(err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("ordinary app created private storage: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecycleOrdinaryAlternateMainIsNoOp(t *testing.T) {
	app, _ := auditApp(t)
	altPath := filepath.Join(t.TempDir(), "staged.db")
	alt, err := sql.Open("sqlite3", altPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alt.Close() })
	if _, err := alt.Exec("CREATE TABLE notes(id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	app.DB = alt

	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, nil, false)
	if err != nil || plan == nil || plan.needed || plan.db != alt || plan.mainPath != canonicalDBPath(altPath) {
		t.Fatalf("ordinary staged-main plan=%+v err=%v", plan, err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("ordinary staged-main no-op: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("ordinary staged-main created private objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}

	// Main-qualified private storage appearing after the no-op plan is a
	// refusal, even when the name is a view rather than a valid table.
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alt.Exec("CREATE VIEW _benmore_encryption_state AS SELECT 1 AS singleton"); err != nil {
		t.Fatal(err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("late main reserved object was accepted by no-op finalization")
	}
	if _, err := alt.Exec("DROP VIEW _benmore_encryption_state"); err != nil {
		t.Fatal(err)
	}

	// A declared command cannot provision storage on an alternate main.
	command, env := appMCPCommandLifecycleFixture(strings.Repeat("91", 32))
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, command, env, false); err == nil {
		t.Fatal("command on alternate main passed protected ownership check")
	}

	// A pre-existing reserved object also forces the strict protected branch.
	if _, err := alt.Exec("CREATE VIEW _benmore_mcp_operations AS SELECT 1 AS operation_id"); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, env, false); err == nil {
		t.Fatal("existing private object on alternate main was treated as ordinary no-op")
	}
}

func TestAppMCPOperationLifecycleNoOpPlanBindsDatabaseHandle(t *testing.T) {
	app, _ := auditApp(t)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(t.TempDir(), "other.db")
	other, err := sql.Open("sqlite3", otherPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	original := app.DB
	app.DB = other
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("no-op plan accepted a substituted database handle")
	}
	app.DB = original
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("restored original database handle refused: %v", err)
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, &runtimeConfig{}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	originalDir := app.Dir
	app.Dir = t.TempDir()
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
		t.Fatal("no-op plan accepted a changed app directory/owner identity")
	}
	app.Dir = originalDir
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("restored original app identity refused: %v", err)
	}
}

func TestAppMCPOperationLifecycleUsesAcceptedSourceThroughLoadAndReload(t *testing.T) {
	root := t.TempDir()
	authorityDir := filepath.Join(t.TempDir(), "authority")
	if err := os.Mkdir(authorityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityDir)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("91", 32)+"\n")
	writeActualLifecycleCommandFixture(t, root)
	checkEnvBefore, err := os.ReadFile(filepath.Join(root, "env.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	checked, err := loadAppWithOptions(root, appLoadOptions{checkOnly: true})
	if err != nil {
		t.Fatalf("accepted command check-only load: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, checked); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, checked) != 0 {
		t.Fatalf("check-only load persisted pair: operations=%d state=%d", operations, state)
	}
	if appMCPLifecycleApprovalCount(t, checked) != 0 || appMCPLifecycleApprovalSnapshot(t, checked) != "<absent>" {
		t.Fatal("check-only load created approval storage")
	}
	checkEnvAfter, err := os.ReadFile(filepath.Join(root, "env.yaml"))
	if err != nil || string(checkEnvBefore) != string(checkEnvAfter) {
		t.Fatalf("check-only load changed env.yaml: err=%v", err)
	}
	if err := checked.DB.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadApp(root)
	if err != nil {
		t.Fatalf("accepted source cold load: %v", err)
	}
	t.Cleanup(func() { loaded.Shutdown() })
	if operations, state := appMCPLifecyclePairCounts(t, loaded); operations != 1 || state != 1 || appMCPLifecycleApprovalCount(t, loaded) != 1 {
		t.Fatalf("accepted command load pair: operations=%d state=%d", operations, state)
	}
	if appMCPLifecycleApprovalCount(t, loaded) != 1 {
		t.Fatal("accepted command load did not create the approval schema")
	}
	record := appMCPOperationStoreRecord(loaded, strings.Repeat("31", 32))
	record.CreatedAt = time.Now().Unix()
	record.ExpiresAt = record.CreatedAt + 15*60
	opTx, err := loaded.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := insertAppMCPPreparedOperation(context.Background(), opTx, loaded, record)
	if err != nil {
		_ = opTx.Rollback()
		t.Fatalf("seed preserved operation row: %v", err)
	}
	receipt := []byte(`{"result":{"status":"fixture"}}`)
	if _, err := storeAppMCPCommittedReceipt(context.Background(), opTx, loaded, record.OperationID, prepared.PreparedDigest, receipt); err != nil {
		_ = opTx.Rollback()
		t.Fatalf("seed preserved committed receipt: %v", err)
	}
	if err := opTx.Commit(); err != nil {
		t.Fatal(err)
	}
	// This is a privileged fixture for preservation testing, not a human-approval issuance path.
	approvedOperationID, approvedDigest, approvedCiphertext, approvedPlaintext := seedAppMCPLifecycleApprovalFixture(t, loaded)
	var approvalDDL string
	if err := loaded.DB.QueryRow("SELECT sql FROM main.sqlite_schema WHERE type='table' AND lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&approvalDDL); err != nil {
		t.Fatal(err)
	}
	if approvalDDL != appMCPCommandApprovalStorageDDL || approvedPlaintext == "" {
		t.Fatal("preservation fixture did not establish the exact supported approval schema and nonempty authenticated approval")
	}
	approvalBytes := appMCPLifecycleApprovalSnapshot(t, loaded)
	if !strings.Contains(approvalBytes, approvedOperationID+"\x00"+approvedDigest+"\x00"+approvedCiphertext+"\x00") {
		t.Fatal("preservation snapshot does not contain the authenticated approval row")
	}
	var generation, ciphertext string
	if err := loaded.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&generation, &ciphertext); err != nil {
		t.Fatal(err)
	}
	var beforeRows int
	var beforePrepared, beforeReceipt string
	if err := loaded.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&beforeRows, &beforePrepared, &beforeReceipt); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(loaded); err != nil {
		t.Fatalf("accepted source same-key reload: %v", err)
	}
	var afterGeneration, afterCiphertext string
	if err := loaded.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&afterGeneration, &afterCiphertext); err != nil {
		t.Fatal(err)
	}
	if generation != afterGeneration || ciphertext != afterCiphertext {
		t.Fatal("same-key reload changed lifecycle generation or marker")
	}
	if got := appMCPLifecycleApprovalSnapshot(t, loaded); got != approvalBytes {
		t.Fatal("same-key reload changed approval schema rows")
	}
	var afterRows int
	var afterPrepared, afterReceipt string
	if err := loaded.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&afterRows, &afterPrepared, &afterReceipt); err != nil {
		t.Fatal(err)
	}
	if beforeRows != afterRows || beforePrepared != afterPrepared || beforeReceipt != afterReceipt {
		t.Fatal("same-key reload changed prepared operation or receipt records")
	}
	checkedExisting, err := loadAppWithOptions(root, appLoadOptions{checkOnly: true})
	if err != nil {
		t.Fatalf("existing-pair check-only load: %v", err)
	}
	var checkedGeneration, checkedCiphertext string
	if err := checkedExisting.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&checkedGeneration, &checkedCiphertext); err != nil {
		t.Fatal(err)
	}
	var checkedRows int
	var checkedPrepared, checkedReceipt string
	if err := checkedExisting.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&checkedRows, &checkedPrepared, &checkedReceipt); err != nil {
		t.Fatal(err)
	}
	if checkedGeneration != generation || checkedCiphertext != ciphertext || checkedRows != beforeRows || checkedPrepared != beforePrepared || checkedReceipt != beforeReceipt {
		t.Fatal("existing-pair check-only load changed marker or operation/receipt bytes")
	}
	if got := appMCPLifecycleApprovalSnapshot(t, checkedExisting); got != approvalBytes {
		t.Fatal("existing-store check-only load changed approval bytes")
	}
	if err := checkedExisting.DB.Close(); err != nil {
		t.Fatal(err)
	}
	oldGeneration := loaded.mcpGeneration
	oldCapturedKey := appMCPBoundLifecycleKey(loaded)
	changedEnv := "ENCRYPTION_KEY: " + strings.Repeat("92", 32) + "\n"
	writeTestFile(t, root, "env.yaml", changedEnv)
	if err := reloadAppConfig(loaded); err == nil {
		t.Fatal("real reload accepted a changed configured encryption key")
	}
	loaded.mu.RLock()
	stillOldGeneration := loaded.mcpGeneration == oldGeneration
	loaded.mu.RUnlock()
	if !stillOldGeneration || !appMCPKeyMatches(appMCPBoundLifecycleKey(loaded), oldCapturedKey) {
		t.Fatal("rejected key reload published a candidate generation or environment")
	}
	select {
	case <-loaded.Stop:
		t.Fatal("rejected key reload stopped the live worker set")
	default:
	}
	registered := cryptoKeysForDBPath(filepath.Join(loaded.Dir, "data.db"))
	if registered == nil || registered.ephemeral || !appMCPKeyMatches(registered.aes, oldCapturedKey) {
		t.Fatal("rejected key reload replaced the owning registered key")
	}
	var rejectedGeneration, rejectedCiphertext string
	if err := loaded.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&rejectedGeneration, &rejectedCiphertext); err != nil {
		t.Fatal(err)
	}
	var rejectedRows int
	var rejectedPrepared, rejectedReceipt string
	if err := loaded.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&rejectedRows, &rejectedPrepared, &rejectedReceipt); err != nil {
		t.Fatal(err)
	}
	if rejectedGeneration != generation || rejectedCiphertext != ciphertext || rejectedRows != beforeRows || rejectedPrepared != beforePrepared || rejectedReceipt != beforeReceipt {
		t.Fatal("rejected key reload changed marker or operation/receipt bytes")
	}
	if got := appMCPLifecycleApprovalSnapshot(t, loaded); got != approvalBytes {
		t.Fatal("rejected key reload changed approval bytes")
	}
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("91", 32)+"\n")
	if err := reloadAppConfig(loaded); err != nil {
		t.Fatalf("restored same-key source reload: %v", err)
	}
	beforeRemovalGeneration := loaded.mcpGeneration
	if err := os.Remove(filepath.Join(root, "env.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(loaded); err == nil {
		t.Fatal("real reload accepted removal of the configured encryption key")
	}
	loaded.mu.RLock()
	removalKeptGeneration := loaded.mcpGeneration == beforeRemovalGeneration
	loaded.mu.RUnlock()
	if !removalKeptGeneration || !appMCPKeyMatches(appMCPBoundLifecycleKey(loaded), oldCapturedKey) {
		t.Fatal("removed-key reload published a candidate generation or environment")
	}
	select {
	case <-loaded.Stop:
		t.Fatal("removed-key reload stopped the live worker set")
	default:
	}
	registered = cryptoKeysForDBPath(filepath.Join(loaded.Dir, "data.db"))
	if registered == nil || registered.ephemeral || !appMCPKeyMatches(registered.aes, oldCapturedKey) {
		t.Fatal("removed-key reload replaced the owning registered key")
	}
	var removedGeneration, removedCiphertext string
	if err := loaded.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&removedGeneration, &removedCiphertext); err != nil {
		t.Fatal(err)
	}
	var removedRows int
	var removedPrepared, removedReceipt string
	if err := loaded.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&removedRows, &removedPrepared, &removedReceipt); err != nil {
		t.Fatal(err)
	}
	if removedGeneration != generation || removedCiphertext != ciphertext || removedRows != beforeRows || removedPrepared != beforePrepared || removedReceipt != beforeReceipt {
		t.Fatal("removed-key reload changed marker or operation/receipt bytes")
	}
	if got := appMCPLifecycleApprovalSnapshot(t, loaded); got != approvalBytes {
		t.Fatal("removed-key reload changed approval bytes")
	}
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("91", 32)+"\n")
	if err := reloadAppConfig(loaded); err != nil {
		t.Fatalf("restored key after removal reload: %v", err)
	}
	if err := loaded.DB.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadApp(root)
	if err != nil {
		t.Fatalf("repeated same-key cold load: %v", err)
	}
	var coldGeneration, coldCiphertext string
	if err := loaded.DB.QueryRow("SELECT key_generation,verification_ciphertext FROM main._benmore_encryption_state").Scan(&coldGeneration, &coldCiphertext); err != nil {
		t.Fatal(err)
	}
	var coldRows int
	var coldPrepared, coldReceipt string
	if err := loaded.DB.QueryRow("SELECT count(*),max(prepared_ciphertext),max(receipt_ciphertext) FROM main._benmore_mcp_operations").Scan(&coldRows, &coldPrepared, &coldReceipt); err != nil {
		t.Fatal(err)
	}
	if generation != coldGeneration || ciphertext != coldCiphertext || beforeRows != coldRows || beforePrepared != coldPrepared || beforeReceipt != coldReceipt {
		t.Fatal("repeated cold load changed lifecycle generation, marker, or operation records")
	}
	if got := appMCPLifecycleApprovalSnapshot(t, loaded); got != approvalBytes {
		t.Fatal("repeated cold load changed approval bytes")
	}
}

func TestAppMCPOperationLifecycleMissingKeyPrecedesFirstLoadAndDoesNotReplaceOwner(t *testing.T) {
	root := t.TempDir()
	authorityDir := filepath.Join(t.TempDir(), "authority")
	if err := os.Mkdir(authorityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityDir)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeActualLifecycleCommandFixture(t, root)
	writeTestFile(t, root, "env.yaml", "OTHER_VALUE: preserved\n")
	originalEnv, err := os.ReadFile(filepath.Join(root, "env.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _ := cryptoDeriveAppKey(strings.Repeat("93", 32))
	RegisterDBEncryptionKey(filepath.Join(root, "data.db"), oldKey)
	if app, err := loadApp(root); err == nil {
		app.Shutdown()
		t.Fatal("first command load succeeded without a configured encryption key")
	} else if !strings.Contains(err.Error(), "operation lifecycle requires configured ENCRYPTION_KEY") {
		t.Fatalf("missing-key load failed before the configured-key guard: %v", err)
	}
	afterEnv, err := os.ReadFile(filepath.Join(root, "env.yaml"))
	if err != nil || string(afterEnv) != string(originalEnv) {
		t.Fatalf("missing-key load changed env.yaml: err=%v", err)
	}
	registered := cryptoKeysForDBPath(filepath.Join(root, "data.db"))
	if registered == nil || !appMCPKeyMatches(registered.aes, oldKey) {
		t.Fatal("missing-key load replaced existing owner key")
	}
	probe, err := sql.Open("sqlite3", filepath.Join(root, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	var objects int
	err = probe.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE name IN ('_benmore_mcp_operations','_benmore_encryption_state')").Scan(&objects)
	if err != nil || objects != 0 {
		_ = probe.Close()
		t.Fatalf("missing-key first load created private objects=%d err=%v", objects, err)
	}
	var approvals int
	if err := probe.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE lower(name)=lower('_benmore_mcp_command_approvals')").Scan(&approvals); err != nil {
		_ = probe.Close()
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	if approvals != 0 {
		t.Fatalf("missing-key first load created approval storage=%d", approvals)
	}
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("93", 32)+"\n")
	loaded, err := loadApp(root)
	if err != nil {
		t.Fatalf("same accepted source with configured key failed: %v", err)
	}
	loaded.Shutdown()
}

func TestAppMCPOperationLifecycleRealMigrationFailureKeepsGenerationUnpublished(t *testing.T) {
	root := t.TempDir()
	authorityDir := filepath.Join(t.TempDir(), "authority")
	if err := os.Mkdir(authorityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityDir)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("94", 32)+"\n")
	writeActualLifecycleCommandFixture(t, root)
	loaded, err := loadApp(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { loaded.Shutdown() })
	oldGeneration := loaded.mcpGeneration
	var oldCiphertext string
	if err := loaded.DB.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state").Scan(&oldCiphertext); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "migrations/001_break_encryption_marker.sql", "UPDATE _benmore_encryption_state SET verification_ciphertext='corrupted-by-user-migration';\n")
	reviewAppMCPFixture(t, root)
	if err := reloadAppConfig(loaded); err == nil {
		t.Fatal("real post-preflight user migration was not rejected by lifecycle finalization")
	}
	loaded.mu.RLock()
	stillOldGeneration := loaded.mcpGeneration == oldGeneration
	loaded.mu.RUnlock()
	if !stillOldGeneration {
		t.Fatal("migration-corrupted candidate was published")
	}
	var committedCiphertext string
	if err := loaded.DB.QueryRow("SELECT verification_ciphertext FROM main._benmore_encryption_state").Scan(&committedCiphertext); err != nil {
		t.Fatal(err)
	}
	if committedCiphertext == oldCiphertext || committedCiphertext != "corrupted-by-user-migration" {
		t.Fatal("test did not observe the committed user migration's marker mutation")
	}
}

func TestAppMCPOperationLifecycleMarkerCreateFailureRollsBackPair(t *testing.T) {
	keySource := strings.Repeat("95", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	control, _ := auditApp(t)
	registerAppLifecycleTestKey(t, control, keySource)
	controlPlan, err := preflightAppMCPOperationLifecycle(context.Background(), control, config, env, false)
	if err != nil {
		t.Fatalf("valid initialization control preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), control, controlPlan, false); err != nil {
		t.Fatalf("valid initialization control finalization: %v", err)
	}
	controlOps, controlState := appMCPLifecyclePairCounts(t, control)
	if controlOps != 1 || controlState != 1 || appMCPLifecycleApprovalCount(t, control) != 1 {
		t.Fatalf("valid control did not commit trio: operations=%d state=%d approvals=%d", controlOps, controlState, appMCPLifecycleApprovalCount(t, control))
	}

	app, _ := auditApp(t)
	app.DB.SetMaxOpenConns(1)
	registerAppLifecycleTestKey(t, app, keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("fault-control preflight failed: plan=%+v err=%v", plan, err)
	}
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	markerCreateDenied := false
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(action int, arg1, _, _ string) int {
			if action == sqlite3.SQLITE_CREATE_TABLE && arg1 == "_benmore_encryption_state" {
				markerCreateDenied = true
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	finishErr := finishAppMCPOperationLifecycle(context.Background(), app, plan, false)
	cleanup, cleanupErr := app.DB.Conn(context.Background())
	if cleanupErr == nil {
		cleanupErr = cleanup.Raw(func(raw any) error {
			raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil)
			return nil
		})
		_ = cleanup.Close()
	}
	if cleanupErr != nil {
		_ = app.DB.Close()
		t.Fatalf("failed to clear one-connection fixture authorizer; pool discarded: %v", cleanupErr)
	}
	if !markerCreateDenied || finishErr == nil {
		t.Fatal("marker-create authorizer failure was ignored")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("marker-create failure did not roll back trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPApprovalCreateFailureRollsBackFirstTable(t *testing.T) {
	keySource := strings.Repeat("96", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	app, _ := auditApp(t)
	app.DB.SetMaxOpenConns(1)
	registerAppLifecycleTestKey(t, app, keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("approval-create preflight=%+v err=%v", plan, err)
	}
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	denied, operationsCreateReached := false, false
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(action int, arg1, _, _ string) int {
			if action == sqlite3.SQLITE_CREATE_TABLE && arg1 == "_benmore_mcp_operations" {
				operationsCreateReached = true
			}
			if action == sqlite3.SQLITE_CREATE_TABLE && arg1 == "_benmore_mcp_command_approvals" {
				denied = true
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	finishErr := finishAppMCPOperationLifecycle(context.Background(), app, plan, false)
	cleanup, err := app.DB.Conn(context.Background())
	if err != nil {
		_ = app.DB.Close()
		t.Fatal(err)
	}
	cleanupErr := cleanup.Raw(func(raw any) error { raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil); return nil })
	if closeErr := cleanup.Close(); cleanupErr == nil {
		cleanupErr = closeErr
	}
	if cleanupErr != nil {
		_ = app.DB.Close()
		t.Fatalf("failed to clear approval-table authorizer: %v", cleanupErr)
	}
	if !denied || !operationsCreateReached || finishErr == nil {
		t.Fatalf("approval-table fault sequence was not reached: operationsCreate=%v approvalDenied=%v err=%v", operationsCreateReached, denied, finishErr)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("approval-create failure left partial trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
	retry, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil {
		t.Fatalf("valid retry preflight after approval CREATE denial: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, retry, false); err != nil {
		t.Fatalf("valid retry after approval CREATE denial: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 1 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 1 {
		t.Fatalf("valid retry did not commit trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecycleApprovalChangeAfterPreflightRefuses(t *testing.T) {
	keySource := strings.Repeat("9a", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	t.Run("late approval object", func(t *testing.T) {
		app, _ := auditApp(t)
		registerAppLifecycleTestKey(t, app, keySource)
		plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil || plan == nil || !plan.fresh {
			t.Fatalf("fresh preflight=%+v err=%v", plan, err)
		}
		tx := mustBeginLifecycleTx(t, app)
		if err := initializeAppMCPCommandApprovalStorage(context.Background(), tx); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := initializeAppMCPCommandAttemptStorage(context.Background(), tx); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
			t.Fatal("late approval table was silently adopted")
		}
		if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 1 {
			t.Fatalf("late object mismatch changed existing objects: operations=%d state=%d approval=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
		}
	})
	t.Run("approval schema mutation", func(t *testing.T) {
		app, _ := auditApp(t)
		registerAppLifecycleTestKey(t, app, keySource)
		initial, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := finishAppMCPOperationLifecycle(context.Background(), app, initial, false); err != nil {
			t.Fatal(err)
		}
		plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec("CREATE INDEX approval_after_preflight ON _benmore_mcp_command_approvals(approval_digest)"); err != nil {
			t.Fatal(err)
		}
		if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
			t.Fatal("approval schema mutation after preflight was accepted")
		}
	})
}

func TestAppMCPOperationLifecycleCommitRefusalRollsBackPair(t *testing.T) {
	keySource := strings.Repeat("97", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	app, _ := auditApp(t)
	app.DB.SetMaxOpenConns(1)
	key := registerAppLifecycleTestKey(t, app, keySource)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("commit-refusal preflight failed: plan=%+v err=%v", plan, err)
	}
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	commitDenied := false
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(action int, arg1, _, _ string) int {
			if action == sqlite3.SQLITE_TRANSACTION && arg1 == "COMMIT" {
				commitDenied = true
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	finishErr := finishAppMCPOperationLifecycle(context.Background(), app, plan, false)
	cleanup, cleanupErr := app.DB.Conn(context.Background())
	if cleanupErr == nil {
		cleanupErr = cleanup.Raw(func(raw any) error {
			raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(nil)
			return nil
		})
		_ = cleanup.Close()
	}
	if cleanupErr != nil {
		_ = app.DB.Close()
		t.Fatalf("failed to clear commit authorizer; pool discarded: %v", cleanupErr)
	}
	if !commitDenied || finishErr == nil {
		t.Fatalf("expected actual SQLite COMMIT denial; denied=%v err=%v", commitDenied, finishErr)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("denied commit left lifecycle objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
	plan, err = preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil {
		t.Fatalf("retry preflight after denied commit: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err != nil {
		t.Fatalf("valid retry after denied commit: %v", err)
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 1 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 1 {
		t.Fatalf("valid retry did not commit trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
	registered := cryptoKeysForDBPath(filepath.Join(app.Dir, "data.db"))
	if registered == nil || !appMCPKeyMatches(registered.aes, key) {
		t.Fatal("commit denial or valid retry changed the owning key")
	}
}

func TestAppMCPOperationLifecycleRequiresOwningMainAndDurableKey(t *testing.T) {
	keySource := strings.Repeat("98", 32)
	key, err := cryptoDeriveAppKey(keySource)
	if err != nil {
		t.Fatal(err)
	}
	config, env := appMCPCommandLifecycleFixture(keySource)
	positive, _ := auditApp(t)
	registerAppLifecycleTestKey(t, positive, keySource)
	positivePlan, err := preflightAppMCPOperationLifecycle(context.Background(), positive, config, env, false)
	if err != nil {
		t.Fatalf("same-main durable-key positive preflight: %v", err)
	}
	if err := finishAppMCPOperationLifecycle(context.Background(), positive, positivePlan, false); err != nil {
		t.Fatalf("same-main durable-key positive finalization: %v", err)
	}

	t.Run("global-only key", func(t *testing.T) {
		app, _ := auditApp(t)
		registryPath := canonicalDBPath(filepath.Join(app.Dir, "data.db"))
		previous, hadPrevious := dbCryptoRegistry.Load(registryPath)
		dbCryptoRegistry.Delete(registryPath)
		t.Cleanup(func() {
			if hadPrevious {
				dbCryptoRegistry.Store(registryPath, previous)
			} else {
				dbCryptoRegistry.Delete(registryPath)
			}
		})
		oldGlobal := appEncryptionKey
		appEncryptionKey = key
		t.Cleanup(func() { appEncryptionKey = oldGlobal })
		plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil {
			t.Fatalf("global-only negative preflight: %v", err)
		}
		if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
			t.Fatal("global-only key authorized operation lifecycle storage")
		}
		if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
			t.Fatalf("global-only refusal changed objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
		}
	})

	t.Run("ephemeral registry", func(t *testing.T) {
		app, _ := auditApp(t)
		registryPath := canonicalDBPath(filepath.Join(app.Dir, "data.db"))
		previous, hadPrevious := dbCryptoRegistry.Load(registryPath)
		dbCryptoRegistry.Delete(registryPath)
		t.Cleanup(func() {
			if hadPrevious {
				dbCryptoRegistry.Store(registryPath, previous)
			} else {
				dbCryptoRegistry.Delete(registryPath)
			}
		})
		plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil {
			t.Fatalf("unregistered-key control preflight: %v", err)
		}
		registerDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key, true)
		if err := finishAppMCPOperationLifecycle(context.Background(), app, plan, false); err == nil {
			t.Fatal("ephemeral owning key authorized operation lifecycle storage")
		}
		if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
			t.Fatalf("ephemeral-key refusal changed objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
		}
	})

	t.Run("wrong main database", func(t *testing.T) {
		app, _ := auditApp(t)
		other, _ := auditApp(t)
		registerAppLifecycleTestKey(t, app, keySource)
		registerAppLifecycleTestKey(t, other, keySource)
		plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
		if err != nil {
			t.Fatalf("same-main preflight control: %v", err)
		}
		originalDB := app.DB
		app.DB = other.DB
		finishErr := finishAppMCPOperationLifecycle(context.Background(), app, plan, false)
		app.DB = originalDB
		if finishErr == nil {
			t.Fatal("lifecycle plan accepted a different main database at the unchanged App.Dir")
		}
		for label, candidate := range map[string]*App{"owner": app, "other": other} {
			if operations, state := appMCPLifecyclePairCounts(t, candidate); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, candidate) != 0 {
				t.Fatalf("wrong-main refusal changed %s DB: operations=%d state=%d approvals=%d", label, operations, state, appMCPLifecycleApprovalCount(t, candidate))
			}
		}
	})
}

func TestAppMCPOperationLifecycleCanceledFinalizationDoesNotPublish(t *testing.T) {
	app, _ := auditApp(t)
	keySource := strings.Repeat("96", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	key, _ := cryptoDeriveAppKey(keySource)
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	plan, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false)
	if err != nil || plan == nil || !plan.fresh {
		t.Fatalf("valid cancellation control preflight failed: plan=%+v err=%v", plan, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finishAppMCPOperationLifecycle(ctx, app, plan, false); err == nil {
		t.Fatal("canceled finalization published lifecycle storage")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 0 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("canceled finalization changed objects: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
}

func TestAppMCPOperationLifecycleOrphansAndKeyChangeRefuse(t *testing.T) {
	app, _ := auditApp(t)
	keySource := strings.Repeat("cd", 32)
	config, env := appMCPCommandLifecycleFixture(keySource)
	key, _ := cryptoDeriveAppKey(keySource)
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), key)
	setAppLifecycleEnvironment(app, env)
	if _, err := app.DB.Exec("CREATE TABLE _benmore_mcp_operations(operation_id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false); err == nil {
		t.Fatal("operation storage without marker was accepted")
	}
	if _, err := app.DB.Exec("DROP TABLE _benmore_mcp_operations"); err != nil {
		t.Fatal(err)
	}
	owner, err := appMCPOperationOwnerID(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeAppMCPOperationStorage(context.Background(), tx); err != nil {
		_ = tx.Rollback()
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
	if _, err := initializeAppEncryptionState(context.Background(), tx, owner, key); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DROP TABLE main._benmore_mcp_command_approvals"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("DROP TABLE main._benmore_mcp_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, env, false); err == nil {
		t.Fatal("previously provisioned marker without operations was accepted")
	}
	if operations, state := appMCPLifecyclePairCounts(t, app); operations != 0 || state != 1 || appMCPLifecycleApprovalCount(t, app) != 0 {
		t.Fatalf("missing-storage refusal repaired the trio: operations=%d state=%d approvals=%d", operations, state, appMCPLifecycleApprovalCount(t, app))
	}
	changed := map[string]string{"ENCRYPTION_KEY": strings.Repeat("ef", 32)}
	if _, err := preflightAppMCPOperationLifecycle(context.Background(), app, config, changed, true); err == nil {
		t.Fatal("reload key change was accepted")
	}
}
