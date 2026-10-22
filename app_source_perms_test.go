//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteAppSourceFileIgnoresUmask reproduces the per-app unit's
// UMask=0077: a plain WriteFile(0644) lands 0600, which the router cannot
// read for git history. writeAppSourceFile must end group read/writable.
func TestWriteAppSourceFileIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.sql")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(plain); info.Mode().Perm() != 0o600 {
		t.Skipf("umask not applied on this platform (got %v)", info.Mode().Perm())
	}
	shared := filepath.Join(dir, "shared.sql")
	if err := writeAppSourceFile(shared, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(shared); info.Mode().Perm() != appSourceFileMode {
		t.Fatalf("mode = %v, want %v", info.Mode().Perm(), appSourceFileMode)
	}
}

func TestRepairAppSourceModesWidensOnlyMigrationsAndSchema(t *testing.T) {
	dir := t.TempDir()
	migDir := filepath.Join(dir, "migrations")
	if err := os.MkdirAll(migDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]os.FileMode{
		"migrations/0001_create_notes.sql": 0o600,
		"migrations/README.txt":            0o600,
		"schema.sql":                       0o600,
		"env.yaml":                         0o600,
	}
	for rel, mode := range files {
		p := filepath.Join(dir, rel)
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
	}
	_ = os.Chmod(migDir, 0o700)
	repairAppSourceModes(dir)
	check := func(rel string, want os.FileMode) {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", rel, info.Mode().Perm(), want)
		}
	}
	check("migrations", appSourceDirMode)
	check("migrations/0001_create_notes.sql", appSourceFileMode)
	check("schema.sql", appSourceFileMode)
	// Secrets and unrelated files are never widened.
	check("env.yaml", 0o600)
	check("migrations/README.txt", 0o600)
}

// TestApplyPrismaMigrationWritesSharedModeUnderUmask drives the real boot
// path: the first schema generates migrations/0001_*.sql, which must be
// readable by the router's git history despite the app unit's umask.
func TestApplyPrismaMigrationWritesSharedModeUnderUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	db := openTestSQLite(t, filepath.Join(dir, "data.db"))
	name, err := ApplyPrismaMigration(db, dir, "model Note {\n  id Int @id @default(autoincrement())\n  title String\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		t.Fatal("expected a migration file to be generated")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no migration written: %v", err)
	}
	for _, e := range entries {
		info, _ := os.Stat(filepath.Join(dir, "migrations", e.Name()))
		if info.Mode().Perm() != appSourceFileMode {
			t.Fatalf("%s mode = %v, want %v (router could not index it)", e.Name(), info.Mode().Perm(), appSourceFileMode)
		}
	}
}

func openTestSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
