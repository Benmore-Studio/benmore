//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stageFixtureFile writes rel under dir and, with age > 0, makes the file and
// its directory look last changed that long ago.
func stageFixtureFile(t *testing.T, dir, rel string, age time.Duration) {
	t.Helper()
	writeTestFile(t, dir, rel, "SQLite format 3\x00 a copy of the database")
	if age <= 0 {
		return
	}
	when := time.Now().Add(-age)
	path := filepath.Join(dir, filepath.FromSlash(rel))
	for _, p := range []string{path, filepath.Dir(path)} {
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func stageFixtureExists(t *testing.T, dir, rel string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// A restore or refresh-dev that never reached its cleanup (a router restart, a
// cancelled request) leaves full copies of a database in the instance
// directory. The app's next start removes the ones nothing has touched for
// hours, in .benmore and where older releases staged them, and nothing else:
// not a stage a running restore is still using, not the app's own files.
func TestAppStartRemovesOnlyStaleRestoreStages(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	const stale = 3 * time.Hour

	leftover := []string{
		".restore-3354974491/source.db", ".restore-3354974491/candidate.db", ".pitr-1722400911/data.db", ".pitr-1722400911/data.db-wal",
		".benmore/.restore-0a1b2c3d/source.db", ".benmore/.pitr-4e5f6a7b/data.db", ".benmore/.refresh-8c9d0e1f/candidate.db",
	}
	for _, rel := range leftover {
		stageFixtureFile(t, dir, rel, stale)
	}
	kept := []string{
		// A restore, a PITR replay and a refresh-dev that are running now.
		".benmore/.restore-1111aaaa/candidate.db", ".benmore/.refresh-2222bbbb/candidate.db", ".restore-42/source.db",
		// The app's own files that only look like a stage.
		".restore-7/notes.md", ".restore-notes/source.db", "static/.restore-5/source.db", ".refresh-9/candidate.db",
		".benmore/backups/scheduled-20261101T000000Z.db",
	}
	for _, rel := range kept[:3] {
		stageFixtureFile(t, dir, rel, 0)
	}
	for _, rel := range kept[3:] {
		stageFixtureFile(t, dir, rel, stale)
	}
	// An old stage directory whose database is still being written.
	stageFixtureFile(t, dir, ".benmore/.pitr-3333cccc/data.db", stale)
	if err := os.Chtimes(filepath.Join(dir, ".benmore/.pitr-3333cccc/data.db"), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, ".benmore/.pitr-3333cccc/data.db")
	// A link with a stage's name: neither followed nor removed.
	outside := t.TempDir()
	stageFixtureFile(t, outside, "source.db", stale)
	if err := os.Symlink(outside, filepath.Join(dir, ".restore-8")); err != nil {
		t.Fatal(err)
	}

	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)

	for _, rel := range leftover {
		if stageFixtureExists(t, dir, filepath.Dir(rel)) {
			t.Errorf("the start left the stale stage %s", filepath.Dir(rel))
		}
	}
	for _, rel := range kept {
		if !stageFixtureExists(t, dir, rel) {
			t.Errorf("the start removed %s", rel)
		}
	}
	if !stageFixtureExists(t, dir, ".restore-8") || !stageFixtureExists(t, outside, "source.db") {
		t.Error("the start removed a link named like a stage, or what it points at")
	}
}

// A validation load (`benmore check`, serve's boot check) may run as another
// account and is not the app starting: it removes nothing.
func TestCheckLoadLeavesRestoreStages(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	stageFixtureFile(t, dir, ".benmore/.restore-0a1b2c3d/source.db", 3*time.Hour)
	if msg := tryLoadApp(dir); msg != "" {
		t.Fatal(msg)
	}
	if !stageFixtureExists(t, dir, ".benmore/.restore-0a1b2c3d/source.db") {
		t.Error("a check-only load removed a stage")
	}
}

// The local restore (`benmore db restore`) stages in .benmore, removes what an
// earlier restore left behind before it starts, whatever its age, and leaves
// no stage of its own.
func TestLocalRestoreStagesInBenmoreAndRemovesLeftovers(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "data.db")
	backup := filepath.Join(dir, backupDirName, "scheduled-20261101T000000Z.db")
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
		t.Fatal(err)
	}
	restoreFixtureDB(t, live, "original")
	restoreFixtureDB(t, backup, "restored")
	candidate, cleanup, err := prepareRestoreSnapshot(t.Context(), dir, backup)
	if err != nil {
		t.Fatal(err)
	}
	if stage, kind := restoreStageRel(mustRel(t, dir, candidate)); kind != "restore" || filepath.Dir(stage) != ".benmore" || mustRel(t, dir, candidate) != filepath.FromSlash(stage+"/candidate.db") {
		t.Fatalf("the candidate is staged at %s", mustRel(t, dir, candidate))
	}
	cleanup()

	for _, rel := range []string{".restore-3354974491/source.db", ".pitr-1722400911/data.db", ".benmore/.restore-0a1b2c3d/candidate.db", ".benmore/.pitr-4e5f6a7b/data.db"} {
		stageFixtureFile(t, dir, rel, 0)
	}
	stageFixtureFile(t, dir, ".restore-7/notes.md", 0)
	if err := restoreDatabase(dir, backup); err != nil {
		t.Fatal(err)
	}
	if got := restoreFixtureValue(t, live); got != "restored" {
		t.Fatalf("live database holds %q", got)
	}
	for _, parent := range []string{dir, filepath.Join(dir, ".benmore")} {
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			// .restore-7 holds the app's own file, so it is not removed.
			if rel := mustRel(t, dir, filepath.Join(parent, entry.Name())); restoreStagePath(rel) && rel != ".restore-7" {
				t.Errorf("the restore left the stage %s", rel)
			}
		}
	}
	if !stageFixtureExists(t, dir, ".restore-7/notes.md") {
		t.Error("the restore removed the app's own directory")
	}
	if !stageFixtureExists(t, dir, filepath.Join(backupDirName, "scheduled-20261101T000000Z.db")) {
		t.Error("the restore removed the backup it restored from")
	}
}

func mustRel(t *testing.T, dir, path string) string {
	t.Helper()
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}
