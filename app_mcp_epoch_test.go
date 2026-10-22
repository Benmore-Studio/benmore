//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func epochFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", root)
	return root
}

func TestAppMCPEpochRestoreRevokesWithoutReactivation(t *testing.T) {
	epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	mustExec(t, app.DB, "INSERT INTO notes VALUES (1)")
	initial, err := updateAppMCPEpoch(app.Dir, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(app.Dir, initial.Epoch); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(app.Dir, "candidate.db")
	snapshotTo(t, app.DB, candidate)
	mustExec(t, app.DB, "INSERT INTO notes VALUES (2)")
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := installRestoreSnapshot(app.Dir, candidate); err != nil {
		t.Fatal(err)
	}
	current, err := currentAppMCPEpoch(app.Dir)
	if err != nil || current.Exposed || current.Epoch == initial.Epoch {
		t.Fatalf("applied restore retained authority: %+v %v", current, err)
	}
	if err := validateAppMCPEpoch(app.Dir, initial.Epoch); err == nil {
		t.Fatal("old authority survived restore")
	}
	// Even a later explicit enable cannot revive a pre-restore grant epoch.
	if _, err := updateAppMCPEpoch(app.Dir, true, false, false); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(app.Dir, initial.Epoch); err == nil {
		t.Fatal("re-enabling revived pre-restore authority")
	}
	restored := openRO(t, filepath.Join(app.Dir, "data.db"))
	defer restored.Close()
	if count := credCount(t, restored, "SELECT count(*) FROM notes"); count != 1 {
		t.Fatalf("restore did not install snapshot: %d", count)
	}
}

func TestAppMCPEpochMissingUnsafeOrForeignMetadataDenies(t *testing.T) {
	root := epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	dir := app.Dir
	if err := validateAppMCPEpoch(dir, "fixture"); err == nil {
		t.Fatal("missing metadata accepted")
	}
	state, err := updateAppMCPEpoch(dir, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	otherState, err := updateAppMCPEpoch(other, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(other, state.Epoch); err == nil {
		t.Fatal("foreign app authority accepted")
	}
	if err := validateAppMCPEpoch(other, otherState.Epoch); err != nil {
		t.Fatal(err)
	}
	key := hashBytesSHA256([]byte(realPathForContainment(dir)))
	metadata := filepath.Join(root, key+".json")
	if err := os.Chmod(metadata, 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(dir, state.Epoch); err == nil {
		t.Fatal("world-readable authority accepted")
	}
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	mustExec(t, app.DB, "INSERT INTO notes VALUES (1)")
	candidate := filepath.Join(dir, "candidate.db")
	snapshotTo(t, app.DB, candidate)
	mustExec(t, app.DB, "INSERT INTO notes VALUES (2)")
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := installRestoreSnapshot(dir, candidate); err == nil {
		t.Fatal("unsafe authority metadata did not stop installation")
	}
	live := openRO(t, filepath.Join(dir, "data.db"))
	if count := credCount(t, live, "SELECT count(*) FROM notes"); count != 2 {
		t.Fatalf("authority failure installed snapshot: %d", count)
	}
	live.Close()
	if _, err := os.Stat(candidate); err != nil {
		t.Fatal("authority failure moved candidate")
	}
	if err := os.Chmod(metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(dir, state.Epoch); err == nil {
		t.Fatal("corrupt authority accepted")
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", dir)
	if _, err := updateAppMCPEpoch(dir, true, false, true); err == nil {
		t.Fatal("snapshot-local authority allowed")
	}
}

func TestAppMCPEpochAutoRecoveryInvalidatesBeforeSwap(t *testing.T) {
	epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	initial, err := updateAppMCPEpoch(app.Dir, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(app.Dir, "backup.db")
	snapshotTo(t, app.DB, backup)
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := swapInBackup(app.Dir, backup, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(app.Dir, initial.Epoch); err == nil {
		t.Fatal("auto-recovery revived authority")
	}
}

func TestAppMCPEpochRelativeRestoreUsesAbsoluteAuthority(t *testing.T) {
	epochFixture(t)
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	initial, err := updateAppMCPEpoch(app.Dir, true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(app.Dir, "candidate.db")
	snapshotTo(t, app.DB, candidate)
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(app.Dir))
	relative := filepath.Base(app.Dir)
	if err := validateAppMCPEpoch(relative, initial.Epoch); err != nil {
		t.Fatalf("relative identity differs: %v", err)
	}
	if _, err := installRestoreSnapshot(relative, filepath.Join(relative, "candidate.db")); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPEpoch(app.Dir, initial.Epoch); err == nil {
		t.Fatal("relative restore left absolute authority active")
	}
	inside := filepath.Join(app.Dir, "authority")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", inside)
	if _, err := updateAppMCPEpoch(relative, true, false, true); err == nil {
		t.Fatal("relative app allowed snapshot-local authority")
	}
}
