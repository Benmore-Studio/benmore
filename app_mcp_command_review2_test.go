//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppMCPExposureKeyRotationFailureLeavesEverythingOnTheOldKey(t *testing.T) {
	h := newExposureHarness(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	oldKey := cryptoKeyForQuerier(h.app.DB)
	h.app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"tasks": {{Column: "title"}}}}
	sealed, err := fieldEncryptCtx(oldKey, "tasks", "title", "secret title")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.DB.Exec("UPDATE tasks SET title=? WHERE id=1", sealed); err != nil {
		t.Fatal(err)
	}
	id := h.prepare()
	h.approveOK(id)
	var marker string
	if err := h.app.DB.QueryRow("SELECT verification_ciphertext FROM _benmore_encryption_state").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	title := func() string {
		var v string
		if err := h.app.DB.QueryRow("SELECT title FROM tasks WHERE id=1").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// A command-store step fails after the configured columns were visited.
	if _, err := h.app.DB.Exec("UPDATE _benmore_encryption_state SET verification_ciphertext='enc:v2:00:bogus'"); err != nil {
		t.Fatal(err)
	}
	newSource := strings.Repeat("m", 64)
	if n, err := RotateEncryptionKey(h.app, newSource, false); err == nil || n != 0 {
		t.Fatalf("rotation with a broken command store = %d %v", n, err)
	}
	if got := title(); got != sealed {
		t.Fatal("a configured column moved although the rotation failed")
	}
	if plain, err := fieldDecryptCtx(oldKey, "title", title()); err != nil || plain != "secret title" {
		t.Fatalf("column unreadable under the OLD key: %q %v", plain, err)
	}
	if !bytes.Equal(cryptoKeyForQuerier(h.app.DB), oldKey) {
		t.Fatal("the registered key changed although the rotation failed")
	}
	// Repair the marker: the retry then succeeds and everything moves together.
	if _, err := h.app.DB.Exec("UPDATE _benmore_encryption_state SET verification_ciphertext=?", marker); err != nil {
		t.Fatal(err)
	}
	if n, err := RotateEncryptionKey(h.app, newSource, false); err != nil || n != 4 { // title + operation + approval + marker
		t.Fatalf("retry = %d %v", n, err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	if plain, err := fieldDecryptCtx(newKey, "title", title()); err != nil || plain != "secret title" {
		t.Fatalf("column under the NEW key: %q %v", plain, err)
	}
	// The command store authenticates under the new key too.
	if state := h.status(id); state["state"] != "approved" {
		t.Fatalf("status after the retried rotation: %#v", state)
	}
}

func TestAppMCPExposureAuthorityDatabaseFailureIsNotADenial(t *testing.T) {
	h := newExposureHarness(t)
	generation := snapshotAppMCPGeneration(h.app)
	tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := resolveAppMCPAccess(h.app, h.pair.AccessToken, h.resource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	origin, err := appMCPConnectorOrigin(h.app, generation, grant, tool, h.pair.AccessToken, h.resource)
	if err != nil {
		t.Fatal(err)
	}
	pin := *origin.connector
	verify := func(ctx context.Context, tx *sql.Tx) error {
		_, err := appMCPWriteAuthorityForTx(ctx, tx, pin, time.Now())
		return err
	}
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := verify(context.Background(), tx); err != nil {
		t.Fatalf("baseline authority: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verify(canceled, tx); err == nil || errors.Is(err, errAppMCPGrantDenied) || appMCPCommandErrorClass(err) != "unavailable_provider" {
		t.Fatalf("a cancelled context was reported as a denial: %v", err)
	}
	// A missing grant table is an infrastructure failure, not a refusal.
	if _, err := tx.Exec("DROP TABLE main._benmore_mcp_credentials"); err != nil {
		t.Fatal(err)
	}
	if err := verify(context.Background(), tx); err == nil || errors.Is(err, errAppMCPGrantDenied) || appMCPCommandErrorClass(err) != "unavailable_provider" {
		t.Fatalf("a database failure was reported as a denial: %v", err)
	}
	_ = tx.Rollback()
	// A revoked grant is still an honest denial.
	if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET revoked=1"); err != nil {
		t.Fatal(err)
	}
	tx2, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	if err := verify(context.Background(), tx2); !errors.Is(err, errAppMCPGrantDenied) || appMCPCommandErrorClass(err) != "denied" {
		t.Fatalf("a revoked grant: %v", err)
	}
}

func TestAppMCPExposureSessionChecksReportDatabaseFailures(t *testing.T) {
	h := newExposureHarness(t)
	stored := GetSessionFromDB(h.app.DB, h.cookie)
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	cap := &appMCPCommandCapability{ctx: context.Background(), tx: tx}
	if live, err := appMCPApproverSessionLive(cap, stored.ID, stored.UserID); !live || err != nil {
		t.Fatalf("live session: %v %v", live, err)
	}
	if ok, err := directLoginSessionErr(tx, stored, true); !ok || err != nil {
		t.Fatalf("direct login: %v %v", ok, err)
	}
	if live, err := appMCPApproverSessionLive(cap, "sha256:"+strings.Repeat("0", 64), stored.UserID); live || err != nil {
		t.Fatalf("absent session is a plain refusal: %v %v", live, err)
	}
	if ok, err := directLoginSessionErr(tx, &Session{ID: "sha256:" + strings.Repeat("0", 64), UserID: stored.UserID}, true); ok || err != nil {
		t.Fatalf("absent session is a plain refusal: %v %v", ok, err)
	}
	if err := tx.Rollback(); err != nil { // a finished transaction stands in for a failing store
		t.Fatal(err)
	}
	if live, err := appMCPApproverSessionLive(cap, stored.ID, stored.UserID); live || err == nil {
		t.Fatalf("a database failure was folded into a refusal: %v %v", live, err)
	}
	if ok, err := directLoginSessionErr(tx, stored, true); ok || err == nil {
		t.Fatalf("a database failure was folded into a refusal: %v %v", ok, err)
	}
}

func TestAppMCPExposureSweepIsAuditedAndAnUnreadableRowDoesNotBlockPrepare(t *testing.T) {
	h := newExposureHarness(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	h.addTask(2)
	h.addTask(3)
	old := h.prepare()
	_ = h.prepareTask(2)
	// A row that no longer authenticates (here: damaged ciphertext).
	damaged := h.prepareTask(3)
	if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_operations SET prepared_ciphertext='enc:v2:00:bogus' WHERE operation_id=?", damaged); err != nil {
		t.Fatal(err)
	}
	setExposureClock(t, time.Now().UTC().Add(3*time.Hour))
	h.addTask(4)
	if fresh := h.prepareTask(4); !appMCPIsHex(fresh, 32) {
		t.Fatal("prepare was blocked by an unreadable row")
	}
	if !strings.Contains(logs.String(), "class=unreadable_operation") || !strings.Contains(logs.String(), "op="+damaged[:8]) {
		t.Fatalf("the unreadable row was not logged: %s", logs.String())
	}
	var details string
	if err := h.app.DB.QueryRow("SELECT new_values FROM _benmore_audit_log WHERE action='mcp_command_sweep'").Scan(&details); err != nil {
		t.Fatalf("sweep audit row: %v", err)
	}
	if !strings.Contains(details, `"deleted":2`) || !strings.Contains(details, old[:8]) || strings.Contains(details, old) {
		t.Fatalf("sweep audit details: %s", details)
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_sweep'") != 1 {
		t.Fatal("expected exactly one sweep audit row")
	}
}

func TestAppMCPExposureNonLiveDeclarationIsLoggedOncePerGeneration(t *testing.T) {
	h := newExposureHarness(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	generation := *snapshotAppMCPGeneration(h.app) // a copy whose command source no longer matches
	generation.sourceFiles = map[string][]byte{}
	generation.reportedUnlive = new(sync.Map)
	for i := 0; i < 5; i++ {
		if got := appMCPLiveCommands(h.app, &generation); len(got) != 0 {
			t.Fatalf("a broken declaration was listed: %v", got)
		}
	}
	if got := strings.Count(logs.String(), `declaration "complete_item" is not live`); got != 1 {
		t.Fatalf("declaration logged %d times, want once per generation: %s", got, logs.String())
	}
}
