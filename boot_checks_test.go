//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Boot-time copies and checks: the pre-migrate snapshot, the post-migration
// integrity_check and the startup quick_check run only when a boot changes
// the database or cannot prove the file is the one a clean shutdown left.

type bootCheckCounts struct{ quick, integrity atomic.Int32 }

// countBootChecks wraps the open-time quick_check and the post-migration
// integrity_check with counters. It also shortens the waits the boot path
// makes (marker settle time, I/O retry backoff) and forgets SQLite faults an
// earlier test provoked on purpose.
func countBootChecks(t *testing.T) *bootCheckCounts {
	t.Helper()
	c := &bootCheckCounts{}
	oldQuick, oldIntegrity := startupQuickCheck, postMigrationIntegrityCheck
	oldSettle, oldBackoff := cleanShutdownSettle, transientIOBackoff
	startupQuickCheck = func(db *sql.DB) error { c.quick.Add(1); return oldQuick(db) }
	postMigrationIntegrityCheck = func(db *sql.DB) error { c.integrity.Add(1); return oldIntegrity(db) }
	cleanShutdownSettle = 30 * time.Millisecond // well above any timestamp tick
	transientIOBackoff = []time.Duration{time.Millisecond}
	resetSQLiteFaultSeen()
	t.Cleanup(func() {
		startupQuickCheck, postMigrationIntegrityCheck = oldQuick, oldIntegrity
		cleanShutdownSettle, transientIOBackoff = oldSettle, oldBackoff
		resetSQLiteFaultSeen()
	})
	return c
}

// take returns and resets the counts.
func (c *bootCheckCounts) take() (quick, integrity int) {
	return int(c.quick.Swap(0)), int(c.integrity.Swap(0))
}

func snapshotNames(dir string) []string {
	var out []string
	for _, p := range listBackups(dir) {
		out = append(out, filepath.Base(p))
	}
	return out
}

const bootFixturePrisma = `model Author {
  id Int @id @default(autoincrement())
  name String
  posts Post[]
}
model Post {
  id Int @id @default(autoincrement())
  title String
  body String?
  secret String?
  quantity Float?
  price Float?
  total Float?
  author_id Int?
  author Author? @relation(fields: [author_id], references: [id])
  updated_at DateTime @updatedAt
  @@index([title])
  @@fulltext([title, body])
}
`

// bootFixture is an app that exercises every boot step that writes schema:
// a Prisma schema with a relation, @updatedAt trigger, index and full-text
// table; encrypted and computed fields; versioning; and a user migration.
// It is booted as a hosted unit boots (no serve boot check).
func bootFixture(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "bootapp")
	writeTestFile(t, dir, "app.yaml", "site_name: bootapp\nversioned:\n  - posts\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("cd", 32)+"\n")
	writeTestFile(t, dir, "schema.prisma", bootFixturePrisma)
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  posts:\n    fields: [secret]\n    blind_index: [secret]\n")
	writeTestFile(t, dir, "computed.yaml", "posts:\n  total:\n    expr: quantity * price\n")
	writeTestFile(t, dir, "migrations/9001_user.sql", "CREATE TABLE IF NOT EXISTS extra_things (id INTEGER PRIMARY KEY, label TEXT);\n")
	hostedBootEnv(t, dir)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) })
	return dir
}

// hostedBootEnv makes startServedApp boot dir as a hosted unit does (no serve
// boot check). A hosted load installs a process-wide storage backstop in the
// platform edition; put it back so later tests see an uncapped process.
func hostedBootEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	oldLimit := processStorageLimit.Load()
	t.Cleanup(func() {
		processStorageLimit.Store(oldLimit)
		dbStorageLimits.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	})
}

func bootServed(t *testing.T, dir string) *App {
	t.Helper()
	app, err := startServedApp(dir)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	return app
}

// settle boots and cleanly stops the app until a restart has nothing left to
// apply or verify (the first boot creates everything; the second checks the
// schema the first one's later steps added).
func settle(t *testing.T, dir string, c *bootCheckCounts) {
	t.Helper()
	for i := 0; i < 2; i++ {
		bootServed(t, dir).Shutdown()
	}
	c.take()
}

func TestCleanRestartSkipsSnapshotIntegrityAndQuickCheck(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)

	app := bootServed(t, dir)
	if q, i := c.take(); q != 1 || i != 1 {
		t.Fatalf("first boot: quick_check=%d integrity_check=%d, want 1 and 1", q, i)
	}
	if _, err := app.DB.Exec(`INSERT INTO posts (title, body, quantity, price) VALUES ('hello', 'world', 3, 7)`); err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err != nil {
		t.Fatalf("a clean stop must leave the marker: %v", err)
	}
	settle(t, dir, c)
	before := snapshotNames(dir)

	for i := 0; i < 3; i++ {
		app := bootServed(t, dir)
		if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
			t.Fatal("the open must consume the marker: a crash of this run would otherwise be vouched for")
		}
		if q, i := c.take(); q != 0 || i != 0 {
			t.Fatalf("clean restart: quick_check=%d integrity_check=%d, want none", q, i)
		}
		var total float64
		if err := app.DB.QueryRow(`SELECT total FROM posts WHERE title = 'hello'`).Scan(&total); err != nil || total != 21 {
			t.Fatalf("data after restart: %v %v", total, err)
		}
		app.Shutdown()
	}
	if after := snapshotNames(dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("restarts that change nothing took snapshots: before %v after %v", before, after)
	}
}

func TestPrismaSchemaChangeTakesOneSnapshotAndIntegrityCheck(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	before := len(snapshotNames(dir))

	writeTestFile(t, dir, "schema.prisma", strings.Replace(bootFixturePrisma, "  total Float?\n", "  total Float?\n  subtitle String?\n", 1))
	app := bootServed(t, dir)
	if !dbColumnExists(app.DB, "posts", "subtitle") {
		t.Fatal("the schema change was not applied")
	}
	app.Shutdown()
	if q, i := c.take(); q != 0 || i != 1 {
		t.Fatalf("schema-change boot: quick_check=%d integrity_check=%d, want 0 and 1", q, i)
	}
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatalf("schema-change boot took %d snapshots, want exactly 1", after-before)
	}

	bootServed(t, dir).Shutdown()
	if q, i := c.take(); q != 0 || i != 0 {
		t.Fatalf("restart after the change: quick_check=%d integrity_check=%d, want none", q, i)
	}
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatalf("restart after the change took a snapshot")
	}
}

// schema.sql apps change through LoadSchema (CREATE TABLE), Migrate (ADD
// COLUMN) and the deferred DDL (indexes), which only the loader's own snapshot
// protects. A new table is created before the loader's snapshot (as before);
// the snapshot then covers the rest of the load.
func TestMigrateAndDeferredDDLChangesTakeLoaderSnapshot(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	dir := filepath.Join(root, "sqlapp")
	writeTestFile(t, dir, "app.yaml", "site_name: sqlapp\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (\n id INTEGER PRIMARY KEY,\n body TEXT\n);\n")
	hostedBootEnv(t, dir)
	c := countBootChecks(t)
	settle(t, dir, c)

	steps := []struct{ name, schema string }{
		{"add column", "CREATE TABLE notes (\n id INTEGER PRIMARY KEY,\n body TEXT,\n tag TEXT\n);\n"},
		{"add index", "CREATE TABLE notes (\n id INTEGER PRIMARY KEY,\n body TEXT,\n tag TEXT\n);\nCREATE INDEX idx_notes_tag ON notes(tag);\n"},
		{"add table", "CREATE TABLE notes (\n id INTEGER PRIMARY KEY,\n body TEXT,\n tag TEXT\n);\nCREATE INDEX idx_notes_tag ON notes(tag);\nCREATE TABLE labels (\n id INTEGER PRIMARY KEY,\n name TEXT\n);\n"},
	}
	for _, step := range steps {
		before := len(snapshotNames(dir))
		writeTestFile(t, dir, "schema.sql", step.schema)
		bootServed(t, dir).Shutdown()
		if q, i := c.take(); q != 0 || i != 1 {
			t.Fatalf("%s: quick_check=%d integrity_check=%d, want 0 and 1", step.name, q, i)
		}
		snaps := snapshotNames(dir)
		if len(snaps) != before+1 {
			t.Fatalf("%s: %d snapshots taken, want 1", step.name, len(snaps)-before)
		}
		// The snapshot holds the database before the change.
		snap, err := sql.Open("sqlite3", filepath.Join(dir, backupDirName, snaps[len(snaps)-1])+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		var n int
		snap.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name = 'idx_notes_tag'`).Scan(&n)
		hasTag := dbColumnExists(snap, "notes", "tag")
		snap.Close()
		if step.name == "add column" && hasTag || step.name == "add index" && n != 0 {
			t.Fatalf("%s: the snapshot already holds the change", step.name)
		}
		bootServed(t, dir).Shutdown()
		if q, i := c.take(); q != 0 || i != 0 || len(snapshotNames(dir)) != before+1 {
			t.Fatalf("%s: the restart after it checked or copied again (quick=%d integrity=%d)", step.name, q, i)
		}
	}
}

func TestPendingUserMigrationTakesSnapshotAndIsVerified(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	before := len(snapshotNames(dir))

	writeTestFile(t, dir, "migrations/9002_backfill.sql", "UPDATE posts SET body = 'backfilled' WHERE body IS NULL;\n")
	bootServed(t, dir).Shutdown()
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatalf("pending user migration took %d snapshots, want 1", after-before)
	}
	// A data-only migration changes no schema, but the boot that ran it
	// verifies the database it wrote.
	if q, i := c.take(); q != 0 || i != 1 {
		t.Fatalf("boot with the migration: quick_check=%d integrity_check=%d, want 0 and 1", q, i)
	}
	bootServed(t, dir).Shutdown()
	if q, i := c.take(); q != 0 || i != 0 {
		t.Fatalf("boot after the migration: quick_check=%d integrity_check=%d, want none", q, i)
	}
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatal("restarts after the migration took snapshots")
	}
}

// DDL made outside a boot (another process, a hot reload, the router) is
// verified by the app's next boot even though that boot applies nothing.
func TestSchemaChangedOutsideBootIsCheckedAtNextBoot(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	time.Sleep(20 * time.Millisecond) // past the marker's timestamp tick

	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, raw, "CREATE INDEX operator_idx ON posts(body)")
	raw.Close()

	before := len(snapshotNames(dir))
	bootServed(t, dir).Shutdown()
	if q, i := c.take(); q != 1 || i != 1 {
		t.Fatalf("boot after outside DDL: quick_check=%d integrity_check=%d, want 1 and 1", q, i)
	}
	if after := len(snapshotNames(dir)); after != before {
		t.Fatal("a boot that applies nothing took a snapshot")
	}
}

func TestStartupQuickCheckRunsWhenCleanShutdownCannotBeProven(t *testing.T) {
	cases := []struct {
		name  string
		after func(t *testing.T, dir, other string)
	}{
		{"no marker (crash, kill -9, first boot after upgrade)", func(t *testing.T, dir, _ string) {
			os.Remove(cleanShutdownMarkerPath(dir))
		}},
		{"marker for another database", func(t *testing.T, dir, other string) {
			data, err := os.ReadFile(cleanShutdownMarkerPath(other))
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, ".benmore/"+cleanShutdownMarkerName, string(data))
		}},
		{"marker with another file's identity", func(t *testing.T, dir, other string) {
			var mine, theirs cleanShutdownMarker
			readMarkerJSON(t, cleanShutdownMarkerPath(dir), &mine)
			readMarkerJSON(t, cleanShutdownMarkerPath(other), &theirs)
			mine.File = theirs.File
			writeMarkerJSON(t, cleanShutdownMarkerPath(dir), mine)
		}},
		{"file written after the marker", func(t *testing.T, dir, _ string) {
			time.Sleep(20 * time.Millisecond)
			raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, raw, "INSERT INTO authors (name) VALUES ('later')")
			raw.Close()
		}},
		{"file replaced after the marker", func(t *testing.T, dir, _ string) {
			db := filepath.Join(dir, "data.db")
			data, err := os.ReadFile(db)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(db, db+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(db, data, 0660); err != nil {
				t.Fatal(err)
			}
		}},
		{"marker past its periodic re-check", func(t *testing.T, dir, _ string) {
			var m cleanShutdownMarker
			readMarkerJSON(t, cleanShutdownMarkerPath(dir), &m)
			m.VerifiedAt = time.Now().Add(-cleanShutdownRecheckAfter - cleanShutdownRecheckJitter - time.Hour)
			writeMarkerJSON(t, cleanShutdownMarkerPath(dir), m)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := bootFixture(t)
			other := bootFixture(t)
			c := countBootChecks(t)
			settle(t, dir, c)
			settle(t, other, c)
			tc.after(t, dir, other)
			bootServed(t, dir).Shutdown()
			if q, _ := c.take(); q != 1 {
				t.Fatalf("quick_check ran %d times, want 1", q)
			}
		})
	}
}

// Frames left in the WAL are commits the main file does not hold yet.
func TestStartupQuickCheckRunsWithWALFrames(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	mustExec(t, raw, "PRAGMA wal_autocheckpoint=0")
	mustExec(t, raw, "INSERT INTO authors (name) VALUES ('in the wal')")
	if info, err := os.Stat(filepath.Join(dir, "data.db-wal")); err != nil || info.Size() == 0 {
		t.Fatalf("expected WAL frames: %v", err)
	}
	app := bootServed(t, dir)
	defer app.Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("quick_check ran %d times with WAL frames present, want 1", q)
	}
}

// A load that never closes cleanly (crash after open) leaves no marker.
func TestCrashAfterOpenLeavesNoMarker(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	app := bootServed(t, dir)
	app.DB.Close() // the process dies: App.Shutdown never runs
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a marker survived a run that did not shut down")
	}
	bootServed(t, dir).Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("quick_check after a crash ran %d times, want 1", q)
	}
}

// serve's boot check (self-hosted) loads the app just before the start-up
// load. For a large database it waits for the file to settle and leaves a
// marker, so the start-up load does not read the whole file again; a small one
// is checked again instead (TestServeBootCheckSkipsHandoffForSmallDatabase).
func TestServeBootCheckHandsVerificationToStartupLoad(t *testing.T) {
	dir := bootFixture(t)
	t.Setenv("BENMORE_BIND_LOOPBACK", "") // self-hosted serve: the boot check runs
	c := countBootChecks(t)
	oldMin := serveBootHandoffMinBytes
	serveBootHandoffMinBytes = 0 // treat the fixture as large
	t.Cleanup(func() { serveBootHandoffMinBytes = oldMin })
	// First start: the boot check's open has no marker and checks; its close
	// waits for the file to settle and hands a marker to the start-up load.
	bootServed(t, dir).Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("first start (boot check + start-up load): quick_check=%d, want 1", q)
	}
	// Clean restarts: the previous stop's marker covers the boot check, and
	// the boot check's hands over to the start-up load.
	for i := 0; i < 3; i++ {
		bootServed(t, dir).Shutdown()
		if q, i := c.take(); q != 0 || i != 0 {
			t.Fatalf("clean restart %d with boot check: quick_check=%d integrity_check=%d, want none", i, q, i)
		}
	}
}

// Below serveBootHandoffMinBytes the boot check does not wait to hand over:
// the start-up load checks the file the boot check just rewrote, at most once
// per start. The boot check itself still skips on the previous stop's marker.
// When the boot check's short load happens not to write data.db at all, its
// close finds the file settled and leaves a valid marker without waiting, and
// the start-up load rightly skips too (CI 2026-10-28 saw quick_check=0); the
// file is then the one the previous stop verified.
func TestServeBootCheckSkipsHandoffForSmallDatabase(t *testing.T) {
	dir := bootFixture(t)
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	c := countBootChecks(t)
	bootServed(t, dir).Shutdown()
	// The boot check always runs; the start-up load checks again unless the
	// boot check's load wrote nothing and left a valid marker (see above).
	if q, _ := c.take(); q < 1 || q > 2 {
		t.Fatalf("first start of a small database: quick_check=%d, want 1 or 2 (the boot check, then at most the start-up load)", q)
	}
	for i := 0; i < 3; i++ {
		bootServed(t, dir).Shutdown()
		if q, _ := c.take(); q > 1 {
			t.Fatalf("clean restart %d of a small database with boot check: quick_check=%d, want at most 1 (the start-up load)", i, q)
		}
	}
}

// The router's validation load (tryLoadApp) copies and checks nothing when
// nothing changed, and keeps its rate limit when something did.
func TestValidationLoadWithoutChangesCopiesAndChecksNothing(t *testing.T) {
	dir := checkLoadFixture(t)
	c := countBootChecks(t)
	before := len(snapshotNames(dir))
	for i := 0; i < 3; i++ {
		if msg := tryLoadApp(dir); msg != "" {
			t.Fatal(msg)
		}
	}
	if _, i := c.take(); i != 0 {
		t.Fatalf("unchanged validation loads ran integrity_check %d times", i)
	}
	if after := len(snapshotNames(dir)); after != before {
		t.Fatalf("unchanged validation loads took %d snapshots", after-before)
	}
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a validation load outside serve's boot check wrote a clean-shutdown marker")
	}
}

func TestStartupQuickCheckRepairsCorruptIndexAfterUncleanShutdown(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	app := bootServed(t, dir)
	for i := 0; i < 200; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO authors (name) VALUES ('author %03d')", i))
	}
	app.Shutdown()
	settle(t, dir, c)
	time.Sleep(20 * time.Millisecond)

	// Point the index at another index's b-tree: "wrong # of entries".
	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	mustExec(t, raw, "CREATE INDEX idx_authors_name ON authors(name)")
	mustExec(t, raw, "CREATE TABLE decoy (id INTEGER PRIMARY KEY, name TEXT)")
	mustExec(t, raw, "INSERT INTO decoy (name) VALUES ('x')")
	mustExec(t, raw, "CREATE INDEX idx_decoy_name ON decoy(name)")
	var a, b int
	raw.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = 'idx_authors_name'").Scan(&a)
	raw.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = 'idx_decoy_name'").Scan(&b)
	mustExec(t, raw, "PRAGMA writable_schema = ON")
	mustExec(t, raw, fmt.Sprintf("UPDATE sqlite_schema SET rootpage = CASE name WHEN 'idx_authors_name' THEN %d ELSE %d END WHERE name IN ('idx_authors_name', 'idx_decoy_name')", b, a))
	mustExec(t, raw, "PRAGMA writable_schema = OFF")
	raw.Close()
	if err := quickCheckFile(t, filepath.Join(dir, "data.db")); err == nil {
		t.Fatal("fixture: the index is not corrupt")
	}

	app = bootServed(t, dir)
	defer app.Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("quick_check ran %d times, want 1", q)
	}
	if err := sqliteIntegrityCheck(app.DB); err != nil {
		t.Fatalf("after REINDEX: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM authors").Scan(&n)
	if n != 200 {
		t.Fatalf("authors = %d after repair, want 200 (no data loss)", n)
	}
}

func TestStartupQuickCheckRestoresCorruptPageAfterUncleanShutdown(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	app := bootServed(t, dir)
	for i := 0; i < 2000; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO authors (name) VALUES ('%s')", strings.Repeat("a", 200)))
	}
	app.Shutdown()
	settle(t, dir, c)
	// A valid recovery point.
	if _, err := backupDatabase(dir); err != nil {
		t.Fatal(err)
	}
	corruptTableRootPage(t, dir, "authors")

	app = bootServed(t, dir)
	defer app.Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("quick_check ran %d times, want 1", q)
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM authors").Scan(&n); err != nil || n != 2000 {
		t.Fatalf("authors after restore = %d (%v), want the backup's 2000", n, err)
	}
	matches, _ := corruptCopies(dir)
	if len(matches) == 0 {
		t.Fatal("the corrupt original was not kept")
	}
	// It is kept with the snapshots, never next to data.db, where it kept the
	// database's mode for good (under the router tenant-data lock, readable
	// by the router if it was copied before the lock).
	for _, m := range matches {
		if filepath.Dir(m) != filepath.Join(dir, backupDirName) {
			t.Fatalf("corrupt original kept at %s, want it in %s", m, backupDirName)
		}
	}
}

// corruptTableRootPage overwrites a table's root page in place: Ping still
// works, quick_check fails, REINDEX cannot fix it.
func corruptTableRootPage(t *testing.T, dir, table string) {
	t.Helper()
	time.Sleep(20 * time.Millisecond) // past the marker's timestamp tick
	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var root, pageSize int
	raw.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = ?", table).Scan(&root)
	raw.QueryRow("PRAGMA page_size").Scan(&pageSize)
	raw.Close()
	if root < 2 || pageSize == 0 {
		t.Fatalf("fixture: root page %d, page size %d", root, pageSize)
	}
	f, err := os.OpenFile(filepath.Join(dir, "data.db"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte(strings.Repeat("\xff\x00\x13", pageSize/3))
	if _, err := f.WriteAt(garbage, int64(root-1)*int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// With no backup to restore, the open reopens the corrupt file degraded. That
// open verified nothing, so the integrity record of the file's last good
// schema must not let the load skip integrity_check: the check runs, REINDEX
// cannot repair page damage, and the load fails. It leaves no marker, so every
// start keeps checking until the file is repaired or restored.
func TestCorruptDatabaseWithoutBackupFailsClosedDespiteLedger(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	app := bootServed(t, dir)
	for i := 0; i < 2000; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO authors (name) VALUES ('%s')", strings.Repeat("b", 200)))
	}
	app.Shutdown()
	settle(t, dir, c)
	if _, err := os.Lstat(integrityLedgerPath(dir)); err != nil {
		t.Fatalf("fixture: no integrity record to ignore: %v", err)
	}
	os.RemoveAll(filepath.Join(dir, backupDirName))
	corruptTableRootPage(t, dir, "authors")

	for i := 0; i < 2; i++ {
		app, err := startServedApp(dir)
		if err == nil {
			app.Shutdown()
			t.Fatalf("boot %d served a corrupt database it could neither repair nor restore", i)
		}
		if q, integrity := c.take(); q != 1 || integrity < 1 {
			t.Fatalf("boot %d on a corrupt database: quick_check=%d integrity_check=%d, want 1 and at least 1", i, q, integrity)
		}
		if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
			t.Fatalf("boot %d left a clean-shutdown marker for a database it never verified", i)
		}
	}
}

func quickCheckFile(t *testing.T, path string) error {
	t.Helper()
	db, err := sql.Open("sqlite3", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return sqliteQuickCheck(db)
}

// retentionFixture holds five pre-migrate snapshots and one scheduled backup,
// all valid databases, after pre-migrate retention ran.
func retentionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	seed := filepath.Join(t.TempDir(), "seed.db")
	db, err := sql.Open("sqlite3", seed)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE marker (n INTEGER)")
	db.Close()
	data, err := os.ReadFile(seed)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{
		"pre-migrate-20261001T000000Z.db",
		"pre-migrate-20261002T000000Z.db",
		"pre-migrate-20261003T000000Z.db",
		"pre-migrate-20261004T000000Z.db",
		"pre-migrate-20261004T000000Z-77-1.db", // same second, taken after the one above
	}
	for _, n := range names {
		writeTestFile(t, dir, filepath.Join(backupDirName, n), string(data))
	}
	writeTestFile(t, dir, filepath.Join(backupDirName, "scheduled-20261001T000000Z.db"), string(data))
	cleanupOldBackups(dir, maxBackups)
	return dir
}

const retentionKept = "pre-migrate-20261003T000000Z.db,pre-migrate-20261004T000000Z.db,pre-migrate-20261004T000000Z-77-1.db"

func TestPreMigrateRetentionKeepsThreeNewest(t *testing.T) {
	if maxBackups != 3 {
		t.Fatalf("maxBackups = %d, want 3", maxBackups)
	}
	dir := retentionFixture(t)
	if got := strings.Join(snapshotNames(dir), ","); got != retentionKept {
		t.Fatalf("kept %s, want %s", got, retentionKept)
	}
	if _, err := os.Stat(filepath.Join(dir, backupDirName, "scheduled-20261001T000000Z.db")); err != nil {
		t.Fatal("pre-migrate retention removed a scheduled backup")
	}
	// `benmore db rollback --list` and its restore pick the newest.
	all := listAllBackups(dir)
	if len(all) != 4 || filepath.Base(all[len(all)-1]) != "pre-migrate-20261004T000000Z-77-1.db" {
		t.Fatalf("rollback list: %v", all)
	}
	// Auto-recovery picks the newest valid snapshot (these are weeks old, so
	// the operator's limit is raised for this check).
	t.Setenv(autoRestoreMaxAgeEnv, "87600h")
	writeTestFile(t, dir, "data.db", "THIS IS NOT A DATABASE")
	if ok, err := autoRestoreFromBackup(dir, fmt.Errorf("test")); err != nil || !ok {
		t.Fatalf("auto-restore: %v %v", ok, err)
	}
}

func TestDeferredDDLObject(t *testing.T) {
	cases := []struct {
		stmt, kind, name string
		ok               bool
	}{
		{"CREATE INDEX IF NOT EXISTS idx_a ON t(a)", "index", "idx_a", true},
		{"create unique index if not exists \"Idx B\" on t(b)", "index", "Idx B", true},
		{"CREATE\n  VIEW IF NOT EXISTS [v1] AS SELECT 1", "view", "v1", true},
		{"CREATE TRIGGER IF NOT EXISTS main.`trg` AFTER UPDATE ON t BEGIN SELECT 1; END", "trigger", "trg", true},
		{"CREATE INDEX IF NOT EXISTS temp.idx ON t(a)", "", "", false},
		{"CREATE INDEX idx_a ON t(a)", "", "", false},
		{"CREATE TABLE IF NOT EXISTS t (a)", "", "", false},
		{"CREATE INDEX IF NOT EXISTS \"a\"\"b\" ON t(a)", "index", "a\"b", true},
	}
	for _, tc := range cases {
		kind, name, ok := deferredDDLObject(tc.stmt)
		if kind != tc.kind || name != tc.name || ok != tc.ok {
			t.Errorf("%q: got (%q, %q, %v), want (%q, %q, %v)", tc.stmt, kind, name, ok, tc.kind, tc.name, tc.ok)
		}
	}
}

func readMarkerJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func writeMarkerJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
