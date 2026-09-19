//go:build !cli

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func restoreFixtureDB(t *testing.T, path, value string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES(?)", value); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
func restoreFixtureValue(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite3", sqliteRestoreURI(path, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err := db.QueryRow("SELECT value FROM fixture").Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDatabaseRestoreRejectsCorruptionBeforeLiveChanges(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("SQLite format 3\x00garbage after a correct header")} {
		dir := t.TempDir()
		live := filepath.Join(dir, "data.db")
		restoreFixtureDB(t, live, "original")
		backup := filepath.Join(dir, "broken.db")
		if err := os.WriteFile(backup, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if err := restoreDatabase(dir, backup); err == nil {
			t.Fatal("corrupt backup accepted")
		}
		if got := restoreFixtureValue(t, live); got != "original" {
			t.Fatalf("live changed: %s", got)
		}
	}
}
func TestDatabaseRestorePreservesPreviousAndInstallsValidatedSnapshot(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "data.db")
	backup := filepath.Join(dir, "selected.db")
	restoreFixtureDB(t, live, "original")
	restoreFixtureDB(t, backup, "restored")
	candidate, cleanup, err := prepareRestoreSnapshot(context.Background(), dir, backup)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	previous, err := installRestoreSnapshot(dir, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if got := restoreFixtureValue(t, live); got != "restored" {
		t.Fatal(got)
	}
	if got := restoreFixtureValue(t, previous); got != "original" {
		t.Fatal(got)
	}
	if got := restoreFixtureValue(t, backup); got != "restored" {
		t.Fatal(got)
	}
	info, err := os.Stat(live)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("restore permissions: %v %v", info, err)
	}
}
func TestDatabaseRestoreInstallFailureRestoresOriginalBundle(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "data.db")
	restoreFixtureDB(t, live, "original")
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(live+suffix, []byte(suffix), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := installRestoreSnapshot(dir, filepath.Join(dir, "missing-candidate")); err == nil {
		t.Fatal("missing candidate installed")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		b, err := os.ReadFile(live + suffix)
		if err != nil || string(b) != suffix {
			t.Fatalf("sidecar lost: %s %v", suffix, err)
		}
		os.Remove(live + suffix)
	}
	if got := restoreFixtureValue(t, live); got != "original" {
		t.Fatal(got)
	}
}
func TestDatabaseRestoreFoldsSelectedWAL(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	db, err := sql.Open("sqlite3", src+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA wal_autocheckpoint=0; CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES('in WAL')"); err != nil {
		t.Fatal(err)
	}
	candidate, cleanup, err := prepareRestoreSnapshot(context.Background(), dir, src)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := restoreFixtureValue(t, candidate); got != "in WAL" {
		t.Fatal(got)
	}
}
