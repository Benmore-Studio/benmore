//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPPolicyLifecycleReloadKeepsSynthesizedHooksAndOldGeneration(t *testing.T) {
	f := newCanonicalUpdateFixtureWithAutoMembership(t, "", "", "", true)
	if _, err := os.Stat(filepath.Join(f.app.Dir, "hooks.yaml")); !os.IsNotExist(err) {
		t.Fatalf("fixture unexpectedly has hooks.yaml: %v", err)
	}

	old := snapshotAppMCPGeneration(f.app)
	if old == nil || old.hooks == nil || len(old.hooks.OnInsert["notes"]) != 1 || !strings.Contains(old.hooks.OnInsert["notes"][0].SQL, autoMembershipMarker("notes")) {
		t.Fatalf("boot did not synthesize the configured membership hook: %+v", old)
	}
	for reload := 1; reload <= 2; reload++ {
		reviewAppMCPFixture(t, f.app.Dir)
		if err := reloadAppConfig(f.app); err != nil {
			t.Fatalf("reload %d: %v", reload, err)
		}
		f.app.mu.RLock()
		hooks := f.app.Hooks
		f.app.mu.RUnlock()
		if hooks == nil || len(hooks.OnInsert["notes"]) != 1 || !strings.Contains(hooks.OnInsert["notes"][0].SQL, autoMembershipMarker("notes")) {
			t.Fatalf("reload %d lost or duplicated synthesized hook: %+v", reload, hooks)
		}
	}
	if old.hooks == nil || len(old.hooks.OnInsert["notes"]) != 1 || old.view.Hooks != old.hooks {
		t.Fatalf("reload mutated the retained old generation: %+v", old)
	}
	var expectedMembers int
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main._benmore_users WHERE deactivated_at IS NULL OR deactivated_at=''`).Scan(&expectedMembers); err != nil || expectedMembers < 1 {
		t.Fatalf("active users fixture: %d (%v)", expectedMembers, err)
	}

	// Run the exact SQL-only after-hook seam used by CRUD inside a real Tx.
	tx, err := f.app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO main.notes(id,user_id,title,updated_at) VALUES(2,?,'second',datetime('now'))`, f.uid); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	f.app.mu.RLock()
	hookOwner := &App{DB: f.app.DB, Hooks: f.app.Hooks}
	f.app.mu.RUnlock()
	if _, err := fireAfterHooksTx(tx, hookOwner, "insert", "notes", map[string]any{"id": int64(2)}); err != nil {
		_ = tx.Rollback()
		t.Fatalf("synthesized hook execution: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var members int
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main.note_members WHERE note_id=2`).Scan(&members); err != nil || members != expectedMembers {
		t.Fatalf("synthesized hook effect count=%d, want active-user count %d: %v", members, expectedMembers, err)
	}
}

func TestAppMCPFailedPartialReloadLeavesWritesDisabledAfterSourceRestore(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	canonicalPositiveThenReset(t, f)
	originalSchema, err := os.ReadFile(filepath.Join(f.app.Dir, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	originalManifest, err := os.ReadFile(filepath.Join(f.app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration := snapshotAppMCPGeneration(f.app)
	partialSchema := strings.Replace(string(originalSchema), "secret TEXT);", "secret TEXT, lifecycle_tag TEXT);", 1)
	if partialSchema == string(originalSchema) {
		t.Fatal("fixture notes schema did not contain expected declaration")
	}
	writeTestFile(t, f.app.Dir, "schema.sql", partialSchema)
	if err := os.MkdirAll(filepath.Join(f.app.Dir, "migrations"), 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, f.app.Dir, "migrations/001.sql", "INSERT INTO lifecycle_markers(id,value) VALUES(1,'first committed migration');\n")
	writeTestFile(t, f.app.Dir, "migrations/002.sql", "INSERT INTO lifecycle_markers(id,value) VALUES(1,'deliberate duplicate');\n")
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err == nil {
		t.Fatal("reload with a failing second data migration succeeded")
	}
	var markerRows, firstMigrationRows, secondMigrationRows int
	columns, err := mainTableColumnsWith(f.app.DB, "notes")
	if err != nil || !hasColumnInList(columns, "lifecycle_tag") {
		t.Fatalf("additive schema change did not commit: %+v (%v)", columns, err)
	}
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main.lifecycle_markers WHERE id=1 AND value='first committed migration'`).Scan(&markerRows); err != nil {
		t.Fatal(err)
	}
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main._benmore_migrations WHERE name='001.sql'`).Scan(&firstMigrationRows); err != nil {
		t.Fatal(err)
	}
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main._benmore_migrations WHERE name='002.sql'`).Scan(&secondMigrationRows); err != nil {
		t.Fatal(err)
	}
	if markerRows != 1 || firstMigrationRows != 1 || secondMigrationRows != 0 {
		t.Fatalf("fixture did not reach partial committed reload state: marker=%d migration-ledger=%d/%d", markerRows, firstMigrationRows, secondMigrationRows)
	}
	failedPath := filepath.Join(f.app.Dir, "migrations", "002.sql.failed.sql")
	if _, err := os.Stat(filepath.Join(f.app.Dir, "migrations", "002.sql")); err != nil {
		t.Fatalf("captured failed migration source was not retained: %v", err)
	}
	if _, err := os.Stat(failedPath); !os.IsNotExist(err) {
		t.Fatalf("failed migration unexpectedly created a renamed artifact: %v", err)
	}
	if snapshotAppMCPGeneration(f.app) != oldGeneration {
		t.Fatal("failed reload published a new runtime generation")
	}
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("partial failed reload retained owner write approval: %+v (%v)", state, err)
	}
	writeTestFile(t, f.app.Dir, "schema.sql", string(originalSchema))
	writeTestFile(t, f.app.Dir, "mcp.yaml", string(originalManifest))
	if err := os.Remove(filepath.Join(f.app.Dir, "migrations", "001.sql")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.app.Dir, "migrations", "002.sql")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(failedPath); !os.IsNotExist(err) {
		t.Fatalf("unexpected failed migration artifact remains: %v", err)
	}
	oldManifest, err := parseAppMCPManifest(originalManifest)
	if err != nil {
		t.Fatal(err)
	}
	contract, execution, err := appMCPDigests(f.app.Dir, oldManifest)
	if err != nil || contract != oldManifest.ContractDigest || execution != oldManifest.ExecutionDigest {
		t.Fatalf("restored source closure differs from the admitted generation: contract=%q execution=%q err=%v", contract, execution, err)
	}
	beforeDenied := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after-restore"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("restoring source files re-enabled the pinned writer: %v", err)
	}
	state, err = currentAppMCPEpoch(f.app.Dir)
	if err != nil || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("owner write-off state was not retained after restoring source: %+v (%v)", state, err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != beforeDenied {
		t.Fatalf("owner write-off denial changed state: before=%s after=%s", beforeDenied, after)
	}
}

func TestAppMCPPolicyLifecycleActualRestoreKeepsWritesDisabled(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	canonicalPositiveThenReset(t, f)
	backupDir := filepath.Join(f.app.Dir, ".benmore", "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "lifecycle-backup.db")
	if _, err := f.app.DB.Exec("INSERT INTO main.lifecycle_markers(id,value) VALUES(1,'snapshot')"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatalf("fixture backup path must be absent before snapshot: %v", err)
	}
	if err := sqliteVacuumInto(filepath.Join(f.app.Dir, "data.db"), backup); err != nil {
		t.Fatalf("create consistent SQLite snapshot: %v", err)
	}
	if _, err := f.app.DB.Exec("UPDATE main.notes SET title='live-after-snapshot' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := f.app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(f.app.Dir, backup); err != nil {
		t.Fatalf("restore actual SQLite snapshot: %v", err)
	}
	db, err := openDBWithEnv(f.app.Dir, f.app.environment)
	if err != nil {
		t.Fatalf("reopen restored database: %v", err)
	}
	f.app.DB = db
	var title, marker string
	if err := db.QueryRow("SELECT title FROM main.notes WHERE id=1").Scan(&title); err != nil || title != "before" {
		t.Fatalf("restored title=%q: %v", title, err)
	}
	if err := db.QueryRow("SELECT value FROM main.lifecycle_markers WHERE id=1").Scan(&marker); err != nil || marker != "snapshot" {
		t.Fatalf("restored marker=%q: %v", marker, err)
	}
	state, err := currentAppMCPEpoch(f.app.Dir)
	if err != nil || state.Exposed || state.ApprovedWrites == nil || *state.ApprovedWrites {
		t.Fatalf("restore re-enabled connector authority: %+v (%v)", state, err)
	}
	beforeDenied := canonicalEffectsSnapshot(t, f.app)
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after-restore"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("pre-restore writer survived actual restore: %v", err)
	}
	if after := canonicalEffectsSnapshot(t, f.app); after != beforeDenied {
		t.Fatalf("stale writer changed restored state: before=%s after=%s", beforeDenied, after)
	}
}

func installCanonicalSQLBarrier(t *testing.T, f appMCPCanonicalUpdateFixture) (<-chan struct{}, func()) {
	t.Helper()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, startedOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	f.app.DB.SetMaxOpenConns(1)
	conn, err := f.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(raw any) error {
		sqliteConn := raw.(*sqlite3.SQLiteConn)
		sqliteConn.RegisterCommitHook(func() int {
			startedOnce.Do(func() { close(started) })
			<-release
			return 0
		})
		return nil
	})
	if closeErr := conn.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return started, closeRelease
}

func TestAppMCPPolicyLifecycleReloadWaitsForCanonicalCommit(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	started, release := installCanonicalSQLBarrier(t, f)
	t.Cleanup(release)
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 15*time.Second)
	writeDone := make(chan error, 1)
	go func() {
		_, _, err := applyAppMCPCanonicalUpdate(writeCtx, f.pin, "notes_update_title", canonicalTitleUpdate("held"), f.now)
		writeDone <- err
	}()
	writeJoined, reloadStarted, reloadJoined := false, false, false
	var reloadDone chan error
	t.Cleanup(func() {
		release()
		cancelWrite()
		if !writeJoined {
			joinLifecycleError(t, "canonical writer", writeDone)
		}
		if reloadStarted && !reloadJoined {
			joinLifecycleError(t, "configuration reload", reloadDone)
		}
	})
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("canonical SQL never entered the SQLite barrier")
	}
	reloadDone = make(chan error, 1)
	reloadAttempted := make(chan struct{})
	reloadStarted = true
	go func() { close(reloadAttempted); reloadDone <- reloadAppConfig(f.app) }()
	select {
	case <-reloadAttempted:
	case <-time.After(5 * time.Second):
		t.Fatal("reload goroutine did not start")
	}
	gateCtx, cancelGate := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _, gateErr := acquireAppMCPPolicyGate(gateCtx, f.app.Dir)
	cancelGate()
	if !errors.Is(gateErr, context.DeadlineExceeded) {
		release()
		t.Fatalf("actual policy-gate acquisition was not blocked by the in-flight commit: %v", gateErr)
	}
	select {
	case err := <-reloadDone:
		reloadJoined = true
		release()
		t.Fatalf("reload completed before canonical transaction committed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	release()
	writeErr := waitLifecycleError(t, "canonical writer", writeDone)
	writeJoined = true
	if writeErr != nil {
		t.Fatalf("canonical write failed before reload: %v", writeErr)
	}
	reloadErr := waitLifecycleError(t, "configuration reload", reloadDone)
	reloadJoined = true
	if reloadErr != nil {
		t.Fatalf("reload after canonical commit: %v", reloadErr)
	}
	if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after-reload"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("old pinned write survived actual reload: %v", err)
	}
}

func TestRebuildContextGraphUsesSinglePooledConnection(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	f.app.DB.SetMaxOpenConns(1)
	done := make(chan struct{})
	joined := false
	go func() {
		RebuildContextGraph(f.app)
		close(done)
	}()
	t.Cleanup(func() {
		if joined {
			return
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("context graph rebuild did not join before app shutdown")
		}
	})
	select {
	case <-done:
		joined = true
	case <-time.After(5 * time.Second):
		t.Fatal("context graph rebuild deadlocked with one pooled connection")
	}
	var metadataJSON string
	if err := f.app.DB.QueryRow(`SELECT metadata FROM main._benmore_context_nodes WHERE node_type='table' AND ref='table:notes'`).Scan(&metadataJSON); err != nil {
		t.Fatalf("read notes graph metadata: %v", err)
	}
	var metadata struct {
		Columns    []string `json:"columns"`
		PrimaryKey []string `json:"primary_key"`
		RowCount   int64    `json:"row_count"`
	}
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("decode notes graph metadata: %v", err)
	}
	if !slices.Contains(metadata.Columns, "title") || !slices.Contains(metadata.Columns, "user_id") || !reflect.DeepEqual(metadata.PrimaryKey, []string{"id"}) || metadata.RowCount != 1 {
		t.Fatalf("incomplete notes graph metadata: %+v", metadata)
	}
	var scopedEdge int
	if err := f.app.DB.QueryRow(`SELECT count(*) FROM main._benmore_context_edges e JOIN main._benmore_context_nodes src ON src.id=e.from_node JOIN main._benmore_context_nodes dst ON dst.id=e.to_node WHERE e.edge_type='scoped_by' AND src.ref='table:members' AND dst.ref='group:org_id'`).Scan(&scopedEdge); err != nil || scopedEdge != 1 {
		t.Fatalf("group scoped_by edge count=%d, want 1: %v", scopedEdge, err)
	}
	var one int
	if err := f.app.DB.QueryRow("SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("database connection was not reusable after graph rebuild: %d (%v)", one, err)
	}
}

func waitLifecycleError(t *testing.T, label string, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not finish before its deadline", label)
		return errors.New("unreachable")
	}
}

func joinLifecycleError(t *testing.T, label string, result <-chan error) {
	t.Helper()
	select {
	case <-result:
	case <-time.After(5 * time.Second):
		t.Errorf("%s did not join during cleanup", label)
	}
}

func TestAppMCPPolicyLifecycleProcessHelper(t *testing.T) {
	if os.Getenv("BENMORE_MCP_POLICY_LIFECYCLE_HELPER") != "1" {
		return
	}
	lockPath := filepath.Join(os.Getenv("BENMORE_MCP_AUTHORITY_DIR"), ".lock")
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	busy := errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
	if err == nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	} else if !busy {
		_ = lock.Close()
		t.Fatalf("native nonblocking flock probe failed: %v", err)
	}
	_ = lock.Close()
	if wantBusy := os.Getenv("BENMORE_MCP_POLICY_LIFECYCLE_EXPECT_BUSY") == "1"; busy != wantBusy {
		t.Fatalf("native nonblocking flock busy=%t, want %t (err=%v)", busy, wantBusy, err)
	}
	marker := os.Getenv("BENMORE_MCP_POLICY_LIFECYCLE_MARKER")
	if err := publishLifecycleMarker(marker, map[bool]string{true: "busy", false: "acquired"}[busy]); err != nil {
		t.Fatal(err)
	}
	appDir := os.Getenv("BENMORE_MCP_POLICY_LIFECYCLE_APP")
	switch os.Getenv("BENMORE_MCP_POLICY_LIFECYCLE_ACTION") {
	case "disable":
		_, err = setAppMCPApprovedWrites(appDir, false)
	case "rotate":
		_, err = updateAppMCPEpoch(appDir, true, true, false)
	case "restore-invalidation":
		err = invalidateAppMCPForRestore(appDir)
	default:
		t.Fatalf("unknown lifecycle action")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPPolicyLifecycleOwnerProcessSerializesActualCanonicalWrite(t *testing.T) {
	for _, action := range []string{"disable", "rotate", "restore-invalidation"} {
		t.Run("write-before-"+action, func(t *testing.T) {
			f := newCanonicalUpdateFixture(t, "", "", "")
			canonicalPositiveThenReset(t, f)
			var auditBefore int
			if err := f.app.DB.QueryRow("SELECT count(*) FROM main._benmore_audit_log").Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			writeStarted, release := installCanonicalSQLBarrier(t, f)
			writeCtx, cancelWrite := context.WithTimeout(context.Background(), 15*time.Second)
			writeDone := make(chan error, 1)
			go func() {
				_, _, err := applyAppMCPCanonicalUpdate(writeCtx, f.pin, "notes_update_title", canonicalTitleUpdate("held"), f.now)
				writeDone <- err
			}()
			writeJoined := false
			var cmd *exec.Cmd
			var processDone chan error
			processJoined := false
			t.Cleanup(func() {
				release()
				cancelWrite()
				if !writeJoined {
					joinLifecycleError(t, "canonical owner-order writer", writeDone)
				}
				if cmd != nil && processDone != nil && !processJoined {
					if cmd.Process != nil {
						_ = cmd.Process.Kill()
					}
					joinLifecycleError(t, "owner transition process", processDone)
				}
			})
			select {
			case <-writeStarted:
			case <-time.After(5 * time.Second):
				release()
				t.Fatal("canonical SQL never entered the SQLite barrier")
			}

			marker := filepath.Join(t.TempDir(), "owner-lock-attempt")
			cmd = lifecycleOwnerCommand(t, action, f.app.Dir, marker, true)
			if err := cmd.Start(); err != nil {
				release()
				t.Fatal(err)
			}
			processDone = make(chan error, 1)
			go func() { processDone <- cmd.Wait() }()
			waitLifecycleMarker(t, marker, "busy")
			select {
			case err := <-processDone:
				processJoined = true
				release()
				t.Fatalf("owner process did not block behind the held canonical write: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			release()
			writeErr := waitLifecycleError(t, "canonical owner-order writer", writeDone)
			writeJoined = true
			if writeErr != nil {
				t.Fatalf("canonical write was not allowed to finish before owner transition: %v", writeErr)
			}
			if got := readCanonicalNote(t, f.app.DB); got != "held" {
				t.Fatalf("known commit row=%q, want held", got)
			}
			var auditAfter int
			if err := f.app.DB.QueryRow("SELECT count(*) FROM main._benmore_audit_log").Scan(&auditAfter); err != nil || auditAfter != auditBefore+1 {
				t.Fatalf("known commit audit count=%d, want %d: %v", auditAfter, auditBefore+1, err)
			}
			if err := waitLifecycleError(t, "owner transition process", processDone); err != nil {
				t.Fatalf("owner process %s: %v", action, err)
			}
			processJoined = true
			beforeDenied := canonicalEffectsSnapshot(t, f.app)
			if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after-transition"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("next canonical write survived %s: %v", action, err)
			}
			if after := canonicalEffectsSnapshot(t, f.app); after != beforeDenied {
				t.Fatalf("stale call after %s changed state: before=%s after=%s", action, beforeDenied, after)
			}
		})

		t.Run(action+"-before-write", func(t *testing.T) {
			f := newCanonicalUpdateFixture(t, "", "", "")
			canonicalPositiveThenReset(t, f)
			marker := filepath.Join(t.TempDir(), "owner-lock-attempt")
			cmd := lifecycleOwnerCommand(t, action, f.app.Dir, marker, false)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("owner process %s failed: %v: %s", action, err, output)
			}
			waitLifecycleMarker(t, marker, "acquired")
			beforeDenied := canonicalEffectsSnapshot(t, f.app)
			if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("denied"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("canonical write survived prior %s: %v", action, err)
			}
			if after := canonicalEffectsSnapshot(t, f.app); after != beforeDenied {
				t.Fatalf("denied write changed state after %s: before=%s after=%s", action, beforeDenied, after)
			}
		})
	}
}

func lifecycleOwnerCommand(t *testing.T, action, appDir, marker string, expectBusy bool) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPPolicyLifecycleProcessHelper$")
	cmd.Env = append(os.Environ(),
		"BENMORE_MCP_POLICY_LIFECYCLE_HELPER=1",
		"BENMORE_MCP_POLICY_LIFECYCLE_ACTION="+action,
		"BENMORE_MCP_POLICY_LIFECYCLE_APP="+appDir,
		"BENMORE_MCP_POLICY_LIFECYCLE_MARKER="+marker,
		"BENMORE_MCP_POLICY_LIFECYCLE_EXPECT_BUSY="+map[bool]string{true: "1", false: "0"}[expectBusy],
	)
	return cmd
}

func waitLifecycleMarker(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := os.ReadFile(path); err == nil {
			if string(got) != want {
				t.Fatalf("owner lock probe=%q, want %q", got, want)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("owner process did not record native lock result %q", want)
}

func publishLifecycleMarker(path, value string) (retErr error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".lifecycle-marker-*")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	closed := false
	published := false
	defer func() {
		if !closed {
			if err := f.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			} else {
				closed = true
			}
		}
		if !published {
			if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, err)
			}
		}
	}()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	payload := []byte(value)
	n, err := f.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return errors.New("short lifecycle marker write")
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	published = true
	return nil
}

func assertLifecycleMarkerFile(t *testing.T, path, want string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("marker mode/type=%v; want regular owner-only 0600", info.Mode())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("marker=%q err=%v; want %q", got, err, want)
	}
}

func lifecycleDirectoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

func TestPublishLifecycleMarkerAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")
	if err := publishLifecycleMarker(path, "busy"); err != nil {
		t.Fatal(err)
	}
	assertLifecycleMarkerFile(t, path, "busy")
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker"}) {
		t.Fatalf("first publication left unexpected entries: %v", names)
	}
	if err := publishLifecycleMarker(path, "acquired"); err != nil {
		t.Fatal(err)
	}
	assertLifecycleMarkerFile(t, path, "acquired")
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker"}) {
		t.Fatalf("replacement left unexpected entries: %v", names)
	}

	type readerResult struct {
		reads int
		err   error
	}
	stop := make(chan struct{})
	started := make(chan struct{})
	observed := make(chan string, 1)
	done := make(chan readerResult, 1)
	var stopOnce sync.Once
	joined := false
	joinAttempted := false
	finalResult := readerResult{}
	stopReader := func() {
		stopOnce.Do(func() { close(stop) })
		if joined || joinAttempted {
			return
		}
		joinAttempted = true
		select {
		case result := <-done:
			finalResult = result
			joined = true
			if result.err != nil {
				t.Errorf("marker observer: %v", result.err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("marker observer did not join within 5s")
		}
	}
	go func() {
		reads := 0
		close(started)
		for {
			select {
			case <-stop:
				done <- readerResult{reads: reads}
				return
			default:
			}
			got, err := os.ReadFile(path)
			if err != nil {
				done <- readerResult{reads: reads, err: err}
				return
			}
			value := string(got)
			if value != "busy" && value != "acquired" {
				done <- readerResult{reads: reads, err: errors.New("reader observed partial lifecycle marker")}
				return
			}
			reads++
			select {
			case observed <- value:
			default:
			}
		}
	}()
	t.Cleanup(stopReader)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("marker observer did not start within 5s")
	}
	for i := 0; i < 64; i++ {
		select {
		case <-observed:
		default:
		}
		want := "busy"
		if i%2 == 1 {
			want = "acquired"
		}
		if err := publishLifecycleMarker(path, want); err != nil {
			t.Fatalf("publish marker replacement %d: %v", i, err)
		}
		observationDeadline := time.NewTimer(5 * time.Second)
		seen := false
		for !seen {
			select {
			case got := <-observed:
				seen = got == want
			case result := <-done:
				finalResult = result
				joined = true
				joinAttempted = true
				t.Fatalf("marker observer stopped during replacement %d: reads=%d err=%v", i, result.reads, result.err)
			case <-observationDeadline.C:
				t.Fatalf("marker observer did not report replacement %d within 5s", i)
			}
		}
		if !observationDeadline.Stop() {
			select {
			case <-observationDeadline.C:
			default:
			}
		}
	}
	stopReader()
	if !joined {
		t.Fatal("marker observer was not joined")
	}
	if finalResult.err != nil {
		t.Fatal(finalResult.err)
	}
	if finalResult.reads < 64 {
		t.Fatalf("reader observed only %d values during 64 replacements", finalResult.reads)
	}
	assertLifecycleMarkerFile(t, path, "acquired")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if names := lifecycleDirectoryNames(t, dir); len(names) != 0 {
		t.Fatalf("successful marker cleanup left entries: %v", names)
	}
}

func TestPublishLifecycleMarkerCreateFailurePreservesSibling(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	if err := publishLifecycleMarker(marker, "busy"); err != nil {
		t.Fatal(err)
	}
	assertLifecycleMarkerFile(t, marker, "busy")
	blocker := filepath.Join(dir, "not-a-directory")
	sentinel := []byte("regular parent sentinel")
	if err := os.WriteFile(blocker, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishLifecycleMarker(filepath.Join(blocker, "marker"), "must not publish"); err == nil {
		t.Fatal("marker publisher accepted a regular file as its parent directory")
	}
	info, err := os.Lstat(blocker)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("blocked parent mode/type=%v err=%v", info.Mode(), err)
	}
	got, err := os.ReadFile(blocker)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatalf("blocked parent sentinel=%q err=%v", got, err)
	}
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker", "not-a-directory"}) {
		t.Fatalf("CreateTemp failure left unexpected entries: %v", names)
	}
	if err := publishLifecycleMarker(marker, "acquired"); err != nil {
		t.Fatalf("valid sibling publication after CreateTemp failure: %v", err)
	}
	assertLifecycleMarkerFile(t, marker, "acquired")
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker", "not-a-directory"}) {
		t.Fatalf("post-failure sibling publication left unexpected entries: %v", names)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
}

func TestPublishLifecycleMarkerRenameFailurePreservesDirectory(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker-directory")
	valid := filepath.Join(dir, "valid-marker")
	if err := publishLifecycleMarker(valid, "busy"); err != nil {
		t.Fatal(err)
	}
	assertLifecycleMarkerFile(t, valid, "busy")
	if err := os.Remove(valid); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0700); err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(marker, "sentinel")
	sentinel := []byte("nonempty destination directory")
	if err := os.WriteFile(sentinelPath, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	directoryBefore, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !directoryBefore.IsDir() || directoryBefore.Mode().Perm() != 0700 {
		t.Fatalf("destination directory mode/type=%v err=%v", directoryBefore.Mode(), err)
	}
	sentinelBefore, err := os.Stat(sentinelPath)
	if err != nil {
		t.Fatal(err)
	}
	if !sentinelBefore.Mode().IsRegular() || sentinelBefore.Mode().Perm() != 0600 {
		t.Fatalf("destination sentinel mode/type=%v", sentinelBefore.Mode())
	}
	if err := publishLifecycleMarker(marker, "cannot replace directory"); err == nil {
		t.Fatal("marker publisher replaced a nonempty directory")
	}
	directoryAfter, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !directoryAfter.IsDir() || directoryAfter.Mode().Perm() != 0700 {
		t.Fatalf("failed rename changed destination directory mode/type=%v err=%v", directoryAfter.Mode(), err)
	}
	sentinelAfter, err := os.Stat(sentinelPath)
	if err != nil {
		t.Fatal(err)
	}
	if !sentinelAfter.Mode().IsRegular() || sentinelAfter.Mode().Perm() != 0600 || !os.SameFile(sentinelBefore, sentinelAfter) {
		t.Fatalf("failed rename changed destination sentinel identity/mode/type=%v", sentinelAfter.Mode())
	}
	got, err := os.ReadFile(sentinelPath)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatalf("destination sentinel=%q err=%v", got, err)
	}
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker-directory"}) {
		t.Fatalf("rename failure left staging residue: %v", names)
	}
	if err := publishLifecycleMarker(valid, "acquired"); err != nil {
		t.Fatalf("valid sibling publication after rename failure: %v", err)
	}
	assertLifecycleMarkerFile(t, valid, "acquired")
	if names := lifecycleDirectoryNames(t, dir); !reflect.DeepEqual(names, []string{"marker-directory", "valid-marker"}) {
		t.Fatalf("post-failure sibling publication entries=%v", names)
	}
	if err := os.Remove(valid); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sentinelPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
}
