//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
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

// Review finding (router tenant-data lock): repairAppSourceModes ran os.Chmod
// on schema.sql and migrations/*.sql, which follows a link, so a source file
// linked to data.db widened the database to 0664 at every start. Links are
// left alone now, and writeAppSourceFile refuses to write through one.
func TestAppSourceModesNeverFollowALink(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "data.db")
	if err := os.WriteFile(db, []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0o775); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{"schema.sql", "migrations/0001_init.sql"} {
		if err := os.Symlink(db, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	repairAppSourceModes(dir)
	if info, err := os.Stat(db); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("data.db behind a linked schema.sql/migration became %v (%v), want 600", info.Mode().Perm(), err)
	}

	link := filepath.Join(dir, "migrations", "0001_init.sql")
	if err := writeAppSourceFile(link, []byte("CREATE TABLE x (id INTEGER);")); err == nil {
		t.Fatal("writeAppSourceFile wrote through a link")
	}
	if body, _ := os.ReadFile(db); string(body) != "SQLite format 3\x00" {
		t.Fatalf("data.db behind the link was rewritten: %q", body)
	}
	if info, _ := os.Stat(db); info.Mode().Perm() != 0o600 {
		t.Fatalf("data.db behind the link became %v, want 600", info.Mode().Perm())
	}
}

// The history .gitignore an older router wrote 0600 is widened by the app,
// which owns it under the tenant-data lock; a linked one is left alone.
func TestRepairAppSourceModesWidensHistoryGitignore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(p, []byte(gitignoreContents), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o600)
	repairAppSourceModes(dir)
	if info, err := os.Stat(p); err != nil || info.Mode().Perm() != appSourceFileMode {
		t.Fatalf(".gitignore mode = %v (%v), want %v", info.Mode().Perm(), err, appSourceFileMode)
	}
	other := t.TempDir()
	target := filepath.Join(other, "secret")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(other, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	repairAppSourceModes(other)
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o600 {
		t.Fatalf("a linked .gitignore widened its target to %v", info.Mode().Perm())
	}
}

// The router writes the history .gitignore with the shared source mode, even
// under a narrow umask: an owner-only one is never widened once the tree
// belongs to the app's user.
func TestGitProtectHistoryWritesASharedModeGitignore(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git required")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gitProtectHistory(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, ".gitignore"))
	if err != nil || info.Mode().Perm() != appSourceFileMode {
		t.Fatalf(".gitignore mode = %v (%v), want %v", info.Mode().Perm(), err, appSourceFileMode)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ".gitignore")); !strings.HasPrefix(string(data), "node_modules/\n") || !strings.HasSuffix(string(data), gitignoreContents) {
		t.Fatalf(".gitignore lost the app's rules or the mandatory ones: %q", data)
	}
}
