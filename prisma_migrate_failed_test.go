//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round-2 finding L13: a failed generated migration (NNNN_x.sql.failed) was
// never removed, read as remote_only drift in sync-status and was copied into
// workspaces by pull. It is now left out of the source manifest (listed apart)
// and removed once the schema migrates; the runner's quarantined source file
// (NNNN_x.sql.failed.sql) stays app source.
func TestFailedGeneratedMigrationIsNotSourceAndIsCleared(t *testing.T) {
	const (
		plain = `model Note {
  id   Int    @id @default(autoincrement())
  body String
}`
		unique = `model Note {
  id   Int    @id @default(autoincrement())
  body String @unique
}`
	)
	in := newAdoptInstance(t)
	in.load(t, plain)
	mustExec(t, in.db, `INSERT INTO notes (body) VALUES ('same'), ('same')`)
	if _, err := ApplyPrismaMigration(in.db, in.dir, unique); err == nil {
		t.Fatal("a unique index over duplicate values applied")
	}
	var failed string
	for _, name := range in.files(t) {
		if strings.HasSuffix(name, ".sql.failed") {
			failed = "migrations/" + name
		}
	}
	if failed == "" {
		t.Fatalf("no failed migration kept: %v", in.files(t))
	}
	quarantined := "migrations/0001_zz_backfill.sql.failed.sql"
	if err := os.WriteFile(filepath.Join(in.dir, quarantined), []byte("UPDATE notes SET body = body;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := BuildSourceManifest(in.dir, SourceManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		listed[f.Path] = true
	}
	if listed[failed] {
		t.Fatalf("manifest lists the failed migration %s as source", failed)
	}
	if !listed[quarantined] {
		t.Fatalf("manifest dropped the runner's quarantined source %s", quarantined)
	}
	if len(m.FailedMigrations) != 1 || m.FailedMigrations[0] != failed {
		t.Fatalf("failed migrations = %v, want [%s]", m.FailedMigrations, failed)
	}

	// Still failing: the file stays for inspection, once.
	if _, err := ApplyPrismaMigration(in.db, in.dir, unique); err == nil {
		t.Fatal("retry applied")
	}
	if _, err := os.Stat(filepath.Join(in.dir, failed)); err != nil {
		t.Fatalf("failed migration removed while the change still fails: %v", err)
	}

	// Resolved: the schema migrates and the record of the failure goes.
	mustExec(t, in.db, `DELETE FROM notes WHERE id = 2`)
	if name, err := ApplyPrismaMigration(in.db, in.dir, unique); err != nil || name == "" {
		t.Fatalf("fixed migration = %q, %v", name, err)
	}
	if _, err := os.Stat(filepath.Join(in.dir, failed)); !os.IsNotExist(err) {
		t.Fatalf("failed migration kept after the schema migrated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(in.dir, quarantined)); err != nil {
		t.Fatalf("the runner's quarantined source was removed: %v", err)
	}
	if m, _ := BuildSourceManifest(in.dir, SourceManifestOptions{}); len(m.FailedMigrations) != 0 {
		t.Fatalf("manifest still lists failed migrations: %v", m.FailedMigrations)
	}
}

// A failed migration resolved by reverting schema.prisma (the database is
// back at the declared schema without a new file) is cleared too.
func TestFailedGeneratedMigrationClearedWhenSchemaIsReverted(t *testing.T) {
	const plain = `model Note {
  id   Int    @id @default(autoincrement())
  body String
}`
	in := newAdoptInstance(t)
	in.load(t, plain)
	stale := filepath.Join(in.dir, "migrations", "0002_20260101T000000Z_add_x.sql.failed")
	if err := os.WriteFile(stale, []byte("ALTER TABLE notes ADD COLUMN x DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name := in.load(t, plain); name != "" {
		t.Fatalf("unchanged schema wrote %s", name)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("failed migration kept although the database is at the declared schema: %v", err)
	}
}

func TestIsGeneratedFailedMigration(t *testing.T) {
	for path, want := range map[string]bool{
		"migrations/0003_20261024T000000Z_add_x.sql.failed": true,
		"migrations/0003_hand.sql.failed.sql":               false,
		"migrations/0003_hand.sql":                          false,
		"migrations/sub/0003_x.sql.failed":                  false,
		"0003_x.sql.failed":                                 false,
		"static/migrations/0003_x.sql.failed":               false,
	} {
		if got := isGeneratedFailedMigration(path); got != want {
			t.Errorf("isGeneratedFailedMigration(%q) = %v, want %v", path, got, want)
		}
	}
}
