//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAppMCPPurgeScrubsOnlyMatchingTransferJobsAndState(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)
	if err := appMCPEnsureTransferState(app); err != nil {
		t.Fatal(err)
	}
	operationID := strings.Repeat("a", 64)
	otherOperationID := strings.Repeat("b", 64)
	for i, id := range []string{operationID, otherOperationID} {
		payload, _ := json.Marshal(map[string]any{"user_id": 7, "_mcp_effect": map[string]any{"operation_id": id}, appMCPTransferPayloadKey: map[string]any{"intent": map[string]any{"source": "selected"}}})
		if _, err := app.DB.Exec(`INSERT INTO _benmore_jobs(job_type,payload,status) VALUES(?,?, 'pending')`, appMCPTransferJobType, string(payload)); err != nil {
			t.Fatal(err)
		}
		if err := appMCPSetTransferState(app, appMCPTransferJob{OperationID: id}, int64(i+1), "unknown", "recovery", "source-id", strings.Repeat("c", 64)); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := purgeAppMCPTransferStateForOperation(context.Background(), tx, operationID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var status, payload string
	if err := app.DB.QueryRow(`SELECT status,payload FROM _benmore_jobs WHERE json_extract(payload,'$._mcp_effect.operation_id') IS NULL ORDER BY id LIMIT 1`).Scan(&status, &payload); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || payload != "{}" {
		t.Fatalf("matching transfer job was not cancelled and scrubbed: %q %s", status, payload)
	}
	var otherCount, otherState int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_jobs WHERE json_extract(payload,'$._mcp_effect.operation_id')=? AND status='pending'`, otherOperationID).Scan(&otherCount); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_mcp_transfer_state WHERE operation_id=?`, otherOperationID).Scan(&otherState); err != nil {
		t.Fatal(err)
	}
	if otherCount != 1 || otherState != 1 {
		t.Fatalf("purge touched unrelated transfer: jobs=%d state=%d", otherCount, otherState)
	}
}

func TestAppMCPExposureAccountPurgeErasesOnlyTheUsersOperations(t *testing.T) {
	h := newExposureHarness(t)
	mine := h.prepare()
	h.approveOK(mine)
	// A second user of the workspace prepares an operation of their own.
	otherCookie := createCrudScopeSession(t, h.app, "other-user@example.com", "editor", "17", "")
	otherID := GetSessionFromDB(h.app.DB, otherCookie).UserID
	if _, err := h.app.DB.Exec("INSERT INTO members(org_id,email,user_id) VALUES('17','other-user@example.com',?)", otherID); err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), h.app, otherID, "17", "client-other-user", h.resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out, code := h.call(appMCPClient(t, h.server, pair.AccessToken, nil), "complete_item", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		t.Fatalf("other user prepare: %s", code)
	}
	theirs := out["operation_id"].(string)

	purge := func(uid int64) int64 {
		tx, err := h.app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		n, err := purgeAppMCPOperations(context.Background(), h.app, tx, uid)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := purge(999999); n != 0 || h.count("SELECT count(*) FROM _benmore_mcp_operations") != 2 {
		t.Fatalf("a foreign uid purged rows: %d", n)
	}
	if n := purge(h.actorID); n != 2 { // operation row + approval row
		t.Fatalf("purge deleted %d rows, want 2", n)
	}
	if h.count("SELECT count(*) FROM _benmore_mcp_operations WHERE operation_id=?", mine) != 0 ||
		h.count("SELECT count(*) FROM _benmore_mcp_command_approvals WHERE operation_id=?", mine) != 0 ||
		h.count("SELECT count(*) FROM _benmore_mcp_operations WHERE operation_id=?", theirs) != 1 {
		t.Fatal("purge did not erase exactly the user's operation and approval")
	}
}
