//go:build !cli

package main

// Regression tests from the router tenant-data audit (router isolation,
// workstream D1). The router opens and prunes files inside directories its
// tenants own; a tenant that turns data.db, .benmore or .benmore/backups
// into a link to another app's must not make the router read or delete
// that app's files.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func auditTestDB(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// check_app's drift layer used to open data.db with a plain sql.Open, which
// follows a link: a tenant could point its data.db at another app's database
// and read that app's table names back as extra_table findings.
func TestDriftCheckRefusesLinkedDatabase(t *testing.T) {
	schema := map[string]string{
		"app.yaml":      "seo:\n  site_name: T",
		"schema.prisma": "model Note {\n  id    Int    @id @default(autoincrement())\n  title String\n}",
	}
	victim := t.TempDir()
	victimDB := filepath.Join(victim, "data.db")
	auditTestDB(t, victimDB,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`,
		`CREATE TABLE secret_ledger (id INTEGER PRIMARY KEY)`)

	// Control: the same database as the app's own regular file is reported.
	own := writeApp(t, schema)
	auditTestDB(t, filepath.Join(own, "data.db"),
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`,
		`CREATE TABLE secret_ledger (id INTEGER PRIMARY KEY)`)
	if !driftNames(tryDriftCheck(own), "secret_ledger") {
		t.Fatal("control: an app's own extra table must be reported")
	}

	linked := writeApp(t, schema)
	if err := os.Symlink(victimDB, filepath.Join(linked, "data.db")); err != nil {
		t.Fatal(err)
	}
	if drifts := tryDriftCheck(linked); len(drifts) != 0 {
		t.Fatalf("drift check followed data.db to another app's database: %+v", drifts)
	}
}

func driftNames(drifts []SchemaDrift, table string) bool {
	for _, d := range drifts {
		if d.Table == table {
			return true
		}
	}
	return false
}

// The router's validation load prunes old pre-migrate snapshots. Reached by
// path, a tenant's linked .benmore or .benmore/backups made it delete (and
// list) another app's snapshots.
func TestForeignBackupPruneStaysInsideApp(t *testing.T) {
	was := foreignAppDirs.Load()
	foreignAppDirs.Store(true)
	t.Cleanup(func() { foreignAppDirs.Store(was) })

	victim := t.TempDir()
	backups := filepath.Join(victim, ".benmore", "backups")
	if err := os.MkdirAll(backups, 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("%s202001%02dT000000Z.db", backupPrefix, i)
		names = append(names, name)
		if err := os.WriteFile(filepath.Join(backups, name), []byte("snapshot"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(filepath.Join(backups, names[11]), now, now); err != nil {
		t.Fatal(err)
	}

	linkedBackups := t.TempDir()
	if err := os.MkdirAll(filepath.Join(linkedBackups, ".benmore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backups, filepath.Join(linkedBackups, ".benmore", "backups")); err != nil {
		t.Fatal(err)
	}
	linkedMeta := t.TempDir()
	if err := os.Symlink(filepath.Join(victim, ".benmore"), filepath.Join(linkedMeta, ".benmore")); err != nil {
		t.Fatal(err)
	}

	for _, attacker := range []string{linkedBackups, linkedMeta} {
		if recentPreMigrateBackup(attacker, time.Hour) {
			t.Fatalf("%s: a linked backups directory counted another app's snapshot as this app's", attacker)
		}
		if got := listBackups(attacker); len(got) != 0 {
			t.Fatalf("%s: listed another app's snapshots: %v", attacker, got)
		}
		cleanupOldBackups(attacker, 2)
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(backups, name)); err != nil {
				t.Fatalf("%s: pruning through a link removed another app's %s: %v", attacker, name, err)
			}
		}
	}

	// The app's own real directory is still listed and pruned.
	if !recentPreMigrateBackup(victim, time.Hour) {
		t.Fatal("own fresh snapshot not seen")
	}
	cleanupOldBackups(victim, 10)
	left, _ := os.ReadDir(backups)
	if len(left) != 10 {
		t.Fatalf("own prune kept %d snapshots, want 10", len(left))
	}
	for _, gone := range names[:2] {
		if _, err := os.Stat(filepath.Join(backups, gone)); !os.IsNotExist(err) {
			t.Fatalf("own prune kept the oldest snapshot %s (err=%v)", gone, err)
		}
	}
	for _, e := range left {
		if !strings.HasPrefix(e.Name(), backupPrefix) {
			t.Fatalf("unexpected entry %s", e.Name())
		}
	}
}

// swapForLinkHook makes the next openCheckDB find a link where its lstat saw
// the regular file: the file moves to target and dbPath becomes a link to it.
func swapForLinkHook(t *testing.T, target string) {
	t.Helper()
	checkDBRaceHook = func(dbPath string) {
		if err := os.Rename(dbPath, target); err != nil {
			t.Errorf("swap: %v", err)
			return
		}
		if err := os.Symlink(target, dbPath); err != nil {
			t.Errorf("swap: %v", err)
		}
	}
	t.Cleanup(func() { checkDBRaceHook = nil })
}

// The lstat in check_app's layers only narrows the window: a data.db swapped
// for a link after it must still be refused by the open itself (openTenantDB),
// for the drift layer and for the unapplied-change layer alike.
func TestCheckLayersRefuseALinkSwappedInAfterTheLstat(t *testing.T) {
	t.Run("drift", func(t *testing.T) {
		dir := writeApp(t, map[string]string{
			"app.yaml":      "seo:\n  site_name: T",
			"schema.prisma": "model Note {\n  id    Int    @id @default(autoincrement())\n  title String\n}",
		})
		auditTestDB(t, filepath.Join(dir, "data.db"),
			`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`,
			`CREATE TABLE secret_ledger (id INTEGER PRIMARY KEY)`)
		if !driftNames(tryDriftCheck(dir), "secret_ledger") {
			t.Fatal("control: the regular file's extra table must be reported")
		}
		swapForLinkHook(t, filepath.Join(t.TempDir(), "elsewhere.db"))
		if drifts := tryDriftCheck(dir); len(drifts) != 0 {
			t.Fatalf("drift check read through a link swapped in after its lstat: %+v", drifts)
		}
	})
	t.Run("unapplied", func(t *testing.T) {
		dir, _ := unappliedFixture(t)
		if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(unappliedSchemaV2), 0o644); err != nil {
			t.Fatal(err)
		}
		if len(schemaUnappliedFindings(dir)) == 0 {
			t.Fatal("control: the regular file's unapplied changes must be reported")
		}
		swapForLinkHook(t, filepath.Join(t.TempDir(), "elsewhere.db"))
		if findings := schemaUnappliedFindings(dir); len(findings) != 0 {
			t.Fatalf("unapplied-change check read through a link swapped in after its lstat: %+v", findings)
		}
	})
	t.Run("already a link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "other.db")
		auditTestDB(t, target, `CREATE TABLE t (id INTEGER PRIMARY KEY)`)
		if err := os.Symlink(target, filepath.Join(dir, "data.db")); err != nil {
			t.Fatal(err)
		}
		if db, err := openCheckDB(filepath.Join(dir, "data.db"), "ro"); err == nil {
			db.Close()
			t.Fatal("openCheckDB opened a linked data.db")
		}
	})
}
