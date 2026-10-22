//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPulledFileRefusesOwnershipWriteFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUploadOwnersTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TRIGGER fixture_refuse_owner BEFORE INSERT ON _benmore_upload_owners BEGIN SELECT RAISE(ABORT, 'fixture ownership write failure'); END`)
	app := &App{Dir: dir, DB: db}
	path := "uploads/private/mcp/" + strings.Repeat("a", 64) + ".pdf"
	content := []byte("%PDF-1.7 fixture")
	if err := appMCPStorePulledFile(app, Session{UserID: 42}, path, content, "application/pdf", hashBytesSHA256(content), "fixture_source", "fixture-id", "rev-1"); err == nil {
		t.Fatal("pulled file succeeded without ownership")
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(path))); !os.IsNotExist(err) {
		t.Fatalf("ownership failure left private file bytes: %v", err)
	}
}

func TestPrivateUploadOwnerNeedsDatabaseAndKeepsExistingOwner(t *testing.T) {
	if err := recordPrivateUploadOwner(&App{}, nil, "uploads/private/fixture.pdf"); err == nil {
		t.Fatal("private ownership accepted without a database")
	}
	if err := recordPrivateUploadOwner(nil, nil, "uploads/public/fixture.pdf"); err != nil {
		t.Fatalf("public upload unexpectedly needs ownership: %v", err)
	}
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUploadOwnersTable(db); err != nil {
		t.Fatal(err)
	}
	path := "uploads/private/mcp/" + strings.Repeat("b", 64) + ".pdf"
	writeTestFile(t, dir, path, "existing fixture bytes")
	if _, err := db.Exec(`INSERT INTO _benmore_upload_owners (path, user_id, group_id) VALUES (?, 9, 'existing')`, strings.TrimPrefix(path, "uploads/")); err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	content := []byte("%PDF-1.7 new fixture")
	if err := appMCPStorePulledFile(app, Session{UserID: 42}, path, content, "application/pdf", hashBytesSHA256(content), "fixture_source", "fixture-id", "rev-1"); err == nil {
		t.Fatal("pulled file reused another owner's destination")
	}
	var uid int64
	if err := db.QueryRow(`SELECT user_id FROM _benmore_upload_owners WHERE path = ?`, strings.TrimPrefix(path, "uploads/")).Scan(&uid); err != nil || uid != 9 {
		t.Fatalf("pre-existing owner changed: uid=%d err=%v", uid, err)
	}
	if body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path))); err != nil || string(body) != "existing fixture bytes" {
		t.Fatalf("pre-existing bytes changed: %q %v", body, err)
	}
}

func TestPulledFileOwnershipReservationAllowsSameActorRetry(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &App{Dir: dir, DB: db}
	path := "uploads/private/mcp/" + strings.Repeat("c", 64) + ".pdf"
	content := []byte("%PDF-1.7 retry fixture")
	for i := 0; i < 2; i++ {
		if err := appMCPStorePulledFile(app, Session{UserID: 42}, path, content, "application/pdf", hashBytesSHA256(content), "fixture_source", "fixture-id", "rev-1"); err != nil {
			t.Fatalf("same-owner store %d failed: %v", i, err)
		}
	}
	if body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path))); err != nil || string(body) != string(content) {
		t.Fatalf("private bytes did not round trip: %q %v", body, err)
	}
}
