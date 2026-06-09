package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAutoRestoreFromBackup_RecoversCorrupt verifies the v2.7.8
// auto-recovery path: when data.db is unreadable AND a valid
// pre-migrate backup exists, OpenDB swaps the backup in and the
// process keeps running. Pre-fix, the user had to delete + recreate
// the entire app to escape "file is not a database" loops.
func TestAutoRestoreFromBackup_RecoversCorrupt(t *testing.T) {
	dir := t.TempDir()

	// Step 1: write a valid SQLite db that we'll use as the backup.
	// Easiest way: sql.Open on a temp path, run a CREATE TABLE,
	// close. The resulting file is a valid SQLite db.
	backupDir := filepath.Join(dir, ".benmore", "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatalf("mkdir backups: %v", err)
	}
	healthyPath := filepath.Join(backupDir, "pre-migrate-20260101T000000Z.db")
	// Use the real OpenDB to write a healthy file with our schema.
	{
		// Temporarily route OpenDB to this backup path by using its
		// "dir/data.db" convention - write the healthy file under a
		// temp dir, then move it into backupDir.
		seedDir := t.TempDir()
		seedDB, err := OpenDB(seedDir)
		if err != nil {
			t.Fatalf("seed OpenDB: %v", err)
		}
		if _, err := seedDB.Exec("CREATE TABLE health_marker (k TEXT)"); err != nil {
			t.Fatalf("seed exec: %v", err)
		}
		seedDB.Close()
		// Copy seedDir/data.db → backupDir/pre-migrate-*.db
		src, _ := os.Open(filepath.Join(seedDir, "data.db"))
		dst, _ := os.Create(healthyPath)
		_, _ = io.Copy(dst, src)
		src.Close()
		dst.Close()
	}

	// Step 2: write a CORRUPT data.db (random bytes - not SQLite).
	corruptBytes := []byte("THIS IS NOT A VALID SQLITE FILE\x00\x00\x00\x00\x00")
	if err := os.WriteFile(filepath.Join(dir, "data.db"), corruptBytes, 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	// Step 3: OpenDB the corrupt app dir. Expected: auto-recovery
	// kicks in, the corrupt file is moved aside, the backup becomes
	// the new data.db, and OpenDB returns a working *sql.DB.
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatalf("OpenDB should have auto-recovered, got error: %v", err)
	}
	defer db.Close()

	// Verify the table from the backup is queryable - proves the
	// backup was successfully swapped in, not just that OpenDB
	// returned without error.
	var name string
	row := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='health_marker'")
	if err := row.Scan(&name); err != nil {
		t.Fatalf("backup tables not present after restore: %v", err)
	}
	if name != "health_marker" {
		t.Errorf("expected health_marker table, got %q", name)
	}

	// Verify the corrupt original was moved (not deleted) so a
	// human can post-mortem it.
	entries, _ := os.ReadDir(dir)
	foundCorrupt := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "data.db.corrupt-") {
			foundCorrupt = true
			break
		}
	}
	if !foundCorrupt {
		t.Error("expected data.db.corrupt-<ts> to be preserved for post-mortem; nothing matching found")
	}
}

// TestAutoRestoreFromBackup_NoBackupAvailable verifies that when
// data.db is corrupt and NO backups exist, OpenDB returns a clear
// error rather than silently succeeding or recursing. Caller (often
// loadApp at process start) gets a chance to log + bail.
func TestAutoRestoreFromBackup_NoBackupAvailable(t *testing.T) {
	dir := t.TempDir()
	// Corrupt data.db, no backups dir at all.
	if err := os.WriteFile(filepath.Join(dir, "data.db"), []byte("BROKEN"), 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	_, err := OpenDB(dir)
	if err == nil {
		t.Fatal("OpenDB should have returned an error when no backups available")
	}
	if !strings.Contains(err.Error(), "no usable backup") &&
		!strings.Contains(err.Error(), "no backups found") {
		t.Errorf("expected error to mention missing backups, got: %v", err)
	}
}

// TestIsCorruptDBErr_ClassifiesCorrectly pins the heuristic used to
// decide WHEN to auto-recover. Three SQLite-specific messages
// should match; everything else (permissions, missing files,
// locked) should NOT - auto-recovery should be conservative.
func TestIsCorruptDBErr_ClassifiesCorrectly(t *testing.T) {
	corruption := []string{
		"file is not a database",
		"database disk image is malformed",
		"disk I/O error",
		"open database: file is not a database",  // wrapped
	}
	notCorruption := []string{
		"permission denied",
		"no such file",
		"database is locked",
		"foreign key constraint failed",
		"",
	}
	for _, msg := range corruption {
		if !isCorruptDBErr(fakeErr(msg)) {
			t.Errorf("isCorruptDBErr(%q) = false, want true", msg)
		}
	}
	for _, msg := range notCorruption {
		if isCorruptDBErr(fakeErr(msg)) {
			t.Errorf("isCorruptDBErr(%q) = true, want false (auto-recovery should not nuke a fine DB on transient errors)", msg)
		}
	}
}

type fakeErrT struct{ s string }

func (e fakeErrT) Error() string { return e.s }
func fakeErr(s string) error {
	if s == "" {
		return nil
	}
	return fakeErrT{s}
}
