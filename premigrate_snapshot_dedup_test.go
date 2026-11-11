//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A schema change whose migration fails (here @unique over duplicate rows)
// fails every start, and systemd restarts the unit several times in a few
// seconds. Each start used to copy the same, unchanged database into a new
// pre-migrate snapshot, so the next successful start's retention (newest 3)
// removed the older, different snapshots, among them the only copy taken
// before an earlier column drop. A retry against an unchanged database must
// not consume retention.
func TestFailingMigrationRetriesKeepOlderDistinctSnapshots(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	os.RemoveAll(filepath.Join(dir, backupDirName))

	// Two earlier schema changes, each with different data, leave two
	// distinct pre-migrate snapshots.
	schema := bootFixturePrisma
	for i, col := range []string{"subtitle", "summary"} {
		app := bootServed(t, dir)
		if _, err := app.DB.Exec(`INSERT INTO authors (name) VALUES (?)`, "author "+col); err != nil {
			t.Fatal(err)
		}
		app.Shutdown()
		schema = strings.Replace(schema, "  total Float?\n", "  total Float?\n  "+col+" String?\n", 1)
		writeTestFile(t, dir, "schema.prisma", schema)
		bootServed(t, dir).Shutdown()
		if got := len(snapshotNames(dir)); got < i+1 {
			t.Fatalf("schema change %d took no snapshot: %v", i, snapshotNames(dir))
		}
	}
	older := snapshotNames(dir)
	if len(older) != 2 {
		t.Fatalf("fixture: want 2 distinct snapshots before the failing change, have %v", older)
	}
	c.take()

	// Duplicate rows, then a schema that adds @unique over them.
	app := bootServed(t, dir)
	if _, err := app.DB.Exec(`INSERT INTO authors (name) VALUES ('dup'), ('dup')`); err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	writeTestFile(t, dir, "schema.prisma", strings.Replace(schema, "  name String\n", "  name String @unique\n", 1))

	// A crash loop: every start fails at schema_load, without a clean stop
	// (each runs quick_check at open, which must not count as a change).
	for i := 0; i < 5; i++ {
		os.Remove(cleanShutdownMarkerPath(dir))
		if app, err := startServedApp(dir); err == nil {
			app.Shutdown()
			t.Fatalf("start %d applied @unique over duplicate rows", i)
		}
	}
	afterLoop := snapshotNames(dir)
	loopSnaps := afterLoop[len(older):]

	// The schema is put back and the next start succeeds; its retention must
	// keep the older, different snapshots.
	writeTestFile(t, dir, "schema.prisma", schema)
	bootServed(t, dir).Shutdown()
	kept := map[string]bool{}
	for _, name := range snapshotNames(dir) {
		kept[name] = true
	}
	for _, name := range older {
		if !kept[name] {
			t.Fatalf("retention after the crash loop removed the older snapshot %s; kept %v (the loop added %v)", name, snapshotNames(dir), loopSnaps)
		}
	}
	if len(loopSnaps) != 1 || !kept[loopSnaps[0]] {
		t.Fatalf("5 failing starts against one unchanged database added %v, want one snapshot, kept", loopSnaps)
	}
	snap, err := sql.Open("sqlite3", filepath.Join(dir, backupDirName, loopSnaps[0])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var dups int
	snap.QueryRow(`SELECT COUNT(*) FROM authors WHERE name = 'dup'`).Scan(&dups)
	snap.Close()
	if dups != 2 {
		t.Fatalf("the failing starts' snapshot holds %d duplicate rows, want the database as it was (2)", dups)
	}
}

// Distinct database states still rotate at maxBackups, newest kept.
func TestDistinctSnapshotsStillRotate(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, db, `INSERT INTO notes (id, body) VALUES (1, 'aaaa')`)

	var taken []string
	for i, body := range []string{"bbbb", "cccc", "dddd", "eeee", "ffff"} {
		path, err := backupDatabase(dir)
		if err != nil || path == "" {
			t.Fatalf("snapshot %d: %q %v", i, path, err)
		}
		for _, prev := range taken {
			if prev == path {
				t.Fatalf("snapshot %d of a changed database reused %s", i, filepath.Base(prev))
			}
		}
		taken = append(taken, path)
		// Same length: the file size does not change, the content does.
		mustExec(t, db, `UPDATE notes SET body = '`+body+`' WHERE id = 1`)
	}
	if got := len(listBackups(dir)); got != len(taken) {
		t.Fatalf("five distinct states kept %d snapshots, want 5", got)
	}
	cleanupOldBackups(dir, maxBackups)
	kept := listBackups(dir)
	if len(kept) != maxBackups {
		t.Fatalf("kept %d snapshots, want %d", len(kept), maxBackups)
	}
	for i, path := range kept {
		if want := taken[len(taken)-maxBackups+i]; path != want {
			t.Fatalf("kept %v, want the newest %d of %v", kept, maxBackups, taken)
		}
	}
}

// An unchanged database reuses the newest snapshot, whatever happened to the
// file in between: uncheckpointed WAL frames, a checkpoint that moves them
// into the main file, a quick_check, or a reopen. A change made after the
// reuse is a new state again.
func TestUnchangedDatabaseReusesNewestSnapshot(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, db, `INSERT INTO notes (body) VALUES ('kept')`)

	first, err := backupDatabase(dir)
	if err != nil || first == "" {
		t.Fatalf("first snapshot: %q %v", first, err)
	}
	if err := sqliteQuickCheck(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `PRAGMA wal_checkpoint(TRUNCATE)`)
	db.Close()
	db, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := sqliteQuickCheck(db); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := backupDatabase(dir)
		if err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("retry %d against an unchanged database returned %s, want the newest snapshot %s", i, filepath.Base(again), filepath.Base(first))
		}
	}
	if got := snapshotNames(dir); len(got) != 1 {
		t.Fatalf("unchanged database kept %v, want one snapshot", got)
	}

	mustExec(t, db, `INSERT INTO notes (body) VALUES ('later')`)
	changed, err := backupDatabase(dir)
	if err != nil || changed == "" || changed == first {
		t.Fatalf("snapshot after a change: %q %v (first %s)", changed, err, first)
	}
	if got := snapshotNames(dir); len(got) != 2 {
		t.Fatalf("after a change: %v, want two snapshots", got)
	}
	if _, err := os.Stat(first); err != nil {
		t.Fatalf("the earlier state's snapshot is gone: %v", err)
	}
}
