//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
)

// addTask inserts another open task in the fixture project.
func (h *exposureHarness) addTask(id int) {
	h.t.Helper()
	if _, err := h.app.DB.Exec("INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(?,7,'17','Another task','open')", id); err != nil {
		h.t.Fatal(err)
	}
}

func TestAppMCPExposureKeyRotationResealsCommandStorage(t *testing.T) {
	h := newExposureHarness(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	committed := h.prepare()
	h.approveOK(committed)
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": committed}); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit before rotation: %q %#v", code, out)
	}
	h.addTask(2)
	pending := h.prepareTask(2) // approved but uncommitted across the rotation
	h.approveOK(pending)
	oldKey := cryptoKeyForQuerier(h.app.DB)

	// 2 operations + 2 approvals + 1 attempt (the committed one) + the encryption-state marker.
	if planned, err := RotateEncryptionKey(h.app, "", true); err != nil || planned != 6 {
		t.Fatalf("dry run planned %d rows: %v", planned, err)
	}
	newSource := strings.Repeat("k", 64)
	if n, err := RotateEncryptionKey(h.app, newSource, false); err != nil || n != 6 {
		t.Fatalf("rotation = %d %v", n, err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	appID, _ := appMCPOperationOwnerID(h.app.Dir)
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appMCPValidateCommandStoreUnion(context.Background(), tx, appID, oldKey); err == nil {
		t.Fatal("command storage still authenticates under the old key")
	}
	if _, approvals, err := appMCPValidateCommandStoreUnion(context.Background(), tx, appID, newKey); err != nil || len(approvals) != 2 {
		t.Fatalf("command storage under the new key: %d %v", len(approvals), err)
	}
	_ = tx.Rollback()
	// Everything keeps working: status, replay, and committing the pending approval.
	if state := h.status(committed); state["state"] != "succeeded" {
		t.Fatalf("status after rotation: %#v", state)
	}
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": committed}); code != "" || out["outcome"] != "already_applied" {
		t.Fatalf("replay after rotation: %q %#v", code, out)
	}
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": pending}); code != "" || out["outcome"] != "applied" {
		t.Fatalf("pending commit after rotation: %q %#v", code, out)
	}
	// The next load's lifecycle preflight accepts the rotated store (new key is in env.yaml).
	reloaded, err := loadApp(h.app.Dir)
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	reloaded.Shutdown()
}
