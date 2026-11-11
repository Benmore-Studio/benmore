//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// The operation-owner and pending-operation lookups only read. They used
// app.DB's BEGIN IMMEDIATE, so they queued behind any writer for the busy
// timeout (10s); as ReadOnly transactions the framework driver runs them as
// deferred WAL snapshots that answer while another connection holds the lock.
func TestAppMCPOperationLookupsDoNotWaitForTheWriteLock(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	var grantID string
	if err := h.app.DB.QueryRow("SELECT id FROM main._benmore_mcp_grants").Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	// Another process-like pool holds the file's write lock.
	other, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(h.app.Dir, "data.db"), h.app.Dir))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	writer, err := other.Begin() // BEGIN IMMEDIATE
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.Exec("UPDATE projects SET org_id=org_id"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	command, owner, err := appMCPOperationCommandOwner(ctx, h.app, id)
	if err != nil || command != "complete_item" || owner != h.actorID {
		t.Fatalf("owner lookup under a held write lock: %q %d %v (after %v)", command, owner, err, time.Since(started))
	}
	pending, err := appMCPPendingOperations(ctx, h.app, h.actorID, grantID, time.Now())
	if err != nil || len(pending) != 1 || pending[0].ID != id {
		t.Fatalf("pending lookup under a held write lock: %#v %v (after %v)", pending, err, time.Since(started))
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("read lookups waited %v for the write lock", elapsed)
	}
}
