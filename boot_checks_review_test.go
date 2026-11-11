//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bootServedMux starts the app as `benmore serve` does, through buildAppMux,
// whose framework steps (user-table columns, username backfill, session-id
// rekeying, TOTP sealing) also write the database.
func bootServedMux(t *testing.T, dir string) *App {
	t.Helper()
	app := bootServed(t, dir)
	buildAppMux(app, false, "http://localhost")
	return app
}

func settleMux(t *testing.T, dir string, c *bootCheckCounts) {
	t.Helper()
	for i := 0; i < 2; i++ {
		bootServedMux(t, dir).Shutdown()
	}
	c.take()
}

// A new release rewrites data in steps the schema plan does not see; its
// first start takes one snapshot, and only the first.
func TestReleaseChangeTakesOneSnapshotThroughServeMux(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settleMux(t, dir, c)
	before := len(snapshotNames(dir))

	oldBuild := runtimeBuildID
	runtimeBuildID = func() string { return "benmore next-release " + t.Name() }
	t.Cleanup(func() { runtimeBuildID = oldBuild })

	bootServedMux(t, dir).Shutdown()
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatalf("first start of a new build took %d snapshots, want 1", after-before)
	}
	bootServedMux(t, dir).Shutdown()
	if after := len(snapshotNames(dir)); after != before+1 {
		t.Fatalf("second start of the same build took a snapshot")
	}
}

// A config-only change (encrypted.yaml added to a versioned table) rewrites
// history rows and adds the blind-index column. The start that does it must
// first copy the database as it was.
func TestStorageConfigChangeSnapshotsBeforeHistoryIsRewritten(t *testing.T) {
	dir := bootFixture(t)
	if err := os.Remove(filepath.Join(dir, "encrypted.yaml")); err != nil {
		t.Fatal(err)
	}
	c := countBootChecks(t)
	app := bootServedMux(t, dir)
	mustExec(t, app.DB, "INSERT INTO posts (title, secret) VALUES ('first', 'plain-secret')")
	mustExec(t, app.DB, "UPDATE posts SET title = 'second' WHERE title = 'first'")
	app.Shutdown()
	settleMux(t, dir, c)
	before := snapshotNames(dir)

	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  posts:\n    fields: [secret]\n    blind_index: [secret]\n")
	app = bootServedMux(t, dir)
	if !dbColumnExists(app.DB, "posts", "secret_blind") {
		t.Fatal("fixture: encryption was not applied")
	}
	var history string
	if err := app.DB.QueryRow("SELECT secret FROM posts_history ORDER BY rowid LIMIT 1").Scan(&history); err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	if history == "plain-secret" {
		t.Fatal("fixture: the history row was not re-sealed")
	}
	after := snapshotNames(dir)
	if len(after) != len(before)+1 {
		t.Fatalf("encrypted.yaml change took %d snapshots, want 1", len(after)-len(before))
	}
	snap, err := sql.Open("sqlite3", filepath.Join(dir, backupDirName, after[len(after)-1])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var preImage string
	if err := snap.QueryRow("SELECT secret FROM posts_history ORDER BY rowid LIMIT 1").Scan(&preImage); err != nil || preImage != "plain-secret" {
		t.Fatalf("the snapshot does not hold the history as it was: %q %v", preImage, err)
	}
	if dbColumnExists(snap, "posts", "secret_blind") {
		t.Fatal("the snapshot was taken after the blind-index column was added")
	}

	bootServedMux(t, dir).Shutdown()
	if n := len(snapshotNames(dir)); n != len(after) {
		t.Fatal("the restart after the change took another snapshot")
	}
}

// oldSnapshotOnly leaves one valid snapshot, dated long ago, as the only
// recovery point, and corrupts the live database.
func oldSnapshotOnly(t *testing.T, dir string) string {
	t.Helper()
	os.RemoveAll(filepath.Join(dir, backupDirName))
	snap, err := backupDatabase(dir)
	if err != nil || snap == "" {
		t.Fatalf("backup: %v", err)
	}
	stale := time.Now().Add(-48 * time.Hour)
	old := filepath.Join(filepath.Dir(snap), "pre-migrate-"+stale.UTC().Format("20060102T150405Z")+".db")
	if err := os.Rename(snap, old); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(old, stale, stale)
	corruptTableRootPage(t, dir, "authors")
	return old
}

func populatedFixture(t *testing.T, c *bootCheckCounts) string {
	t.Helper()
	dir := bootFixture(t)
	app := bootServed(t, dir)
	for i := 0; i < 2000; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO authors (name) VALUES ('%s')", strings.Repeat("c", 200)))
	}
	app.Shutdown()
	settle(t, dir, c)
	return dir
}

// Auto-recovery swaps in only a recent snapshot. With an old one it leaves the
// corrupt original in place and fails the start for a person to decide.
func TestAutoRecoveryRefusesAnOldSnapshot(t *testing.T) {
	c := countBootChecks(t)
	dir := populatedFixture(t, c)
	old := oldSnapshotOnly(t, dir)
	corrupt, _ := readDBFileIdentity(filepath.Join(dir, "data.db"))

	_, err := startServedApp(dir)
	if err == nil || !errors.Is(err, errAutoRestoreRefused) {
		t.Fatalf("start with only a 48h-old snapshot: %v, want auto-recovery refused", err)
	}
	if matches, _ := corruptCopies(dir); len(matches) != 0 {
		t.Fatalf("the original was moved aside: %v", matches)
	}
	if now, _ := readDBFileIdentity(filepath.Join(dir, "data.db")); now.Ino != corrupt.Ino {
		t.Fatal("data.db was replaced")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("the snapshot was consumed: %v", err)
	}

	// The operator's limit (a platform-reserved key) allows it.
	t.Setenv(autoRestoreMaxAgeEnv, "72h")
	app, err := startServedApp(dir)
	if err != nil {
		t.Fatalf("start with the limit raised: %v", err)
	}
	defer app.Shutdown()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM authors").Scan(&n); err != nil || n != 2000 {
		t.Fatalf("authors after restore = %d (%v)", n, err)
	}
}

// The same policy when the file does not even open.
func TestAutoRecoveryAtOpenRefusesAnOldSnapshot(t *testing.T) {
	c := countBootChecks(t)
	dir := populatedFixture(t, c)
	oldSnapshotOnly(t, dir)
	writeTestFile(t, dir, "data.db", "THIS IS NOT A DATABASE AT ALL, NOT EVEN CLOSE")
	if _, err := OpenDB(dir); err == nil || !errors.Is(err, errAutoRestoreRefused) {
		t.Fatalf("open of an unreadable file with an old snapshot: %v, want refused", err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "data.db")); !strings.HasPrefix(string(data), "THIS IS NOT") {
		t.Fatal("the unreadable original was replaced")
	}
}

func TestAutoRestoreMaxAgeComesFromTheOperator(t *testing.T) {
	t.Setenv(autoRestoreMaxAgeEnv, "")
	if got := autoRestoreMaxAge(); got != 24*time.Hour {
		t.Fatalf("default = %s", got)
	}
	t.Setenv(autoRestoreMaxAgeEnv, "6h")
	if got := autoRestoreMaxAge(); got != 6*time.Hour {
		t.Fatalf("override = %s", got)
	}
	t.Setenv(autoRestoreMaxAgeEnv, "-1h")
	if got := autoRestoreMaxAge(); got != 24*time.Hour {
		t.Fatalf("invalid override = %s, want the default", got)
	}
}

// A disk I/O error is retried before it counts as corruption.
func TestDiskIOErrorsAreRetriedBeforeRecovery(t *testing.T) {
	old := transientIOBackoff
	transientIOBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { transientIOBackoff = old })
	calls := 0
	flaky := func() error {
		calls++
		if calls < 3 {
			return errors.New("disk I/O error")
		}
		return nil
	}
	if err := retryDiskIO("open", "test", flaky); err != nil || calls != 3 {
		t.Fatalf("transient: err=%v calls=%d", err, calls)
	}
	calls = 0
	corrupt := func() error { calls++; return errors.New("database disk image is malformed") }
	if err := retryDiskIO("open", "test", corrupt); err == nil || calls != 1 {
		t.Fatalf("corruption is not retried: err=%v calls=%d", err, calls)
	}
	calls = 0
	stuck := func() error { calls++; return errors.New("disk I/O error") }
	if err := retryDiskIO("open", "test", stuck); err == nil || calls != 4 {
		t.Fatalf("persistent: err=%v calls=%d", err, calls)
	}
}

// Corruption a query meets while the app serves blocks the marker, so the
// next start checks the file.
func TestRuntimeCorruptionBlocksTheMarker(t *testing.T) {
	if _, ok := sqliteFaultSeen(); !ok {
		t.Fatal("the SQLite error log callback is not installed")
	}
	c := countBootChecks(t)
	dir := populatedFixture(t, c)
	app := bootServed(t, dir)
	corruptTableRootPage(t, dir, "authors")
	// A query on a connection with nothing cached meets the damaged page.
	reader, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	queryErr := reader.QueryRow("SELECT COUNT(*) FROM authors WHERE name <> ''").Scan(&n)
	reader.Close()
	if queryErr == nil {
		t.Fatal("fixture: the damaged page was not read")
	}
	if code, _ := sqliteFaultSeen(); code&0xff != 11 && code&0xff != 26 {
		t.Fatalf("SQLite fault code = %d, want corruption", code)
	}
	app.Shutdown()
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a run that met corruption left a clean-shutdown marker")
	}
}

// A job still running past the drain timeout was cut off mid-work: even
// between statements (no connection held), its writes are unaccounted for.
func TestDrainTimeoutLeavesNoMarker(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	app := bootServed(t, dir)
	app.jobDrainTimeout = 20 * time.Millisecond
	release := make(chan struct{})
	app.jobWG.Add(1)
	go func() {
		defer app.jobWG.Done()
		<-release
	}()
	app.Shutdown()
	close(release)
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a shutdown that closed the database under a running job left a marker")
	}
	bootServed(t, dir).Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("start after a drain timeout ran quick_check %d times, want 1", q)
	}
}

// A connection still in use when the pool closes (a request that outlived the
// server's shutdown) also blocks the marker.
func TestOpenConnectionAtCloseLeavesNoMarker(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	app := bootServed(t, dir)
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	conn.Close()
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a shutdown with a connection still open left a marker")
	}
}

// The stamp is taken only once data.db's timestamps have settled, and a
// marker stamped too soon is not trusted.
func TestMarkerStampWaitsForTimestampsToSettle(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	os.Remove(cleanShutdownMarkerPath(dir))
	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, raw, "INSERT INTO authors (name) VALUES ('just now')")
	raw.Close()
	opened := openedIdentity(t, dir)
	if err := writeCleanShutdownMarker(dir, time.Now(), opened, false); err == nil {
		t.Fatal("a marker was stamped right after a write without waiting")
	}
	if err := writeCleanShutdownMarker(dir, time.Now(), opened, true); err != nil {
		t.Fatalf("waiting to settle: %v", err)
	}
	var m cleanShutdownMarker
	readMarkerJSON(t, cleanShutdownMarkerPath(dir), &m)
	if m.StampedAt.Sub(m.File.latestChange()) < cleanShutdownSettle {
		t.Fatalf("stamp %s is within %s of the last change %s", m.StampedAt, cleanShutdownSettle, m.File.latestChange())
	}
	// A forged early stamp is refused.
	m.StampedAt = m.File.latestChange()
	writeMarkerJSON(t, cleanShutdownMarkerPath(dir), m)
	bootServed(t, dir).Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("a marker stamped in the same tick as the last write skipped quick_check (runs=%d)", q)
	}
}

// The integrity record expires on the marker's schedule.
func TestIntegrityRecordExpires(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	var ledger integrityLedger
	readMarkerJSON(t, integrityLedgerPath(dir), &ledger)
	ledger.CheckedAt = time.Now().Add(-cleanShutdownRecheckAfter - cleanShutdownRecheckJitter - time.Hour)
	writeMarkerJSON(t, integrityLedgerPath(dir), ledger)
	bootServed(t, dir).Shutdown()
	if _, i := c.take(); i != 1 {
		t.Fatalf("an expired integrity record: integrity_check ran %d times, want 1", i)
	}
	bootServed(t, dir).Shutdown()
	if _, i := c.take(); i != 0 {
		t.Fatalf("after the periodic check: integrity_check ran %d times, want 0", i)
	}
}

// An index whose entries belong to another table passes quick_check (the
// counts match) but fails integrity_check. With no snapshot to restore, the
// load rebuilds indexes instead of failing.
func TestIntegrityFailureWithoutSnapshotIsRepairedByReindex(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	raw, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	for _, table := range []string{"left_side", "right_side"} {
		mustExec(t, raw, fmt.Sprintf("CREATE TABLE %s (id INTEGER PRIMARY KEY, v TEXT)", table))
		for i := 0; i < 50; i++ {
			mustExec(t, raw, fmt.Sprintf("INSERT INTO %s (v) VALUES ('%s-%02d')", table, table, i))
		}
		mustExec(t, raw, fmt.Sprintf("CREATE INDEX idx_%s_v ON %s(v)", table, table))
	}
	var a, b int
	raw.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = 'idx_left_side_v'").Scan(&a)
	raw.QueryRow("SELECT rootpage FROM sqlite_schema WHERE name = 'idx_right_side_v'").Scan(&b)
	mustExec(t, raw, "PRAGMA writable_schema = ON")
	mustExec(t, raw, fmt.Sprintf("UPDATE sqlite_schema SET rootpage = CASE name WHEN 'idx_left_side_v' THEN %d ELSE %d END WHERE name IN ('idx_left_side_v', 'idx_right_side_v')", b, a))
	mustExec(t, raw, "PRAGMA writable_schema = OFF")
	raw.Close()
	if err := quickCheckFile(t, filepath.Join(dir, "data.db")); err != nil {
		t.Fatalf("fixture: quick_check should pass: %v", err)
	}
	before := len(snapshotNames(dir))

	app, err := startServedApp(dir)
	if err != nil {
		t.Fatalf("start with a repairable index: %v", err)
	}
	defer app.Shutdown()
	if _, i := c.take(); i < 2 {
		t.Fatalf("integrity_check ran %d times, want the check and the re-check after REINDEX", i)
	}
	if err := sqliteIntegrityCheck(app.DB); err != nil {
		t.Fatalf("after the start: %v", err)
	}
	if after := len(snapshotNames(dir)); after != before {
		t.Fatal("fixture: the start took a snapshot")
	}
}

// serve's boot check (self-hosted) applies a schema change and snapshots
// before it; the start-up load that follows restores that snapshot when its
// own integrity_check fails.
func TestServeBootCheckSnapshotReachesStartupLoad(t *testing.T) {
	dir := bootFixture(t)
	t.Setenv("BENMORE_BIND_LOOPBACK", "") // self-hosted serve: the boot check runs
	c := countBootChecks(t)
	settle(t, dir, c)
	os.RemoveAll(filepath.Join(dir, backupDirName)) // no recent snapshot to reuse

	writeTestFile(t, dir, "schema.prisma", strings.Replace(bootFixturePrisma, "  total Float?\n", "  total Float?\n  handoff String?\n", 1))
	failing := postMigrationIntegrityCheck
	postMigrationIntegrityCheck = func(db *sql.DB) error {
		if serveBootCheckActive.Load() {
			return failing(db)
		}
		return errors.New("injected integrity failure")
	}
	_, err := startServedApp(dir)
	postMigrationIntegrityCheck = failing
	if err == nil || !strings.Contains(err.Error(), "auto-restored pre-migrate backup") {
		t.Fatalf("start-up load error = %v, want a restore of the boot check's snapshot", err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if dbColumnExists(db, "posts", "handoff") {
		t.Fatal("the restored database is not the pre-change snapshot")
	}
}

// Every framework path that swaps in another data.db forgets the records
// that described the old one.
func TestRestoreAndRecoveryForgetDatabaseStateFiles(t *testing.T) {
	for _, path := range []string{"restore", "auto-recovery"} {
		t.Run(path, func(t *testing.T) {
			dir := bootFixture(t)
			c := countBootChecks(t)
			settle(t, dir, c)
			// A refusal record exists only after a refused recovery; plant one.
			writeTestFile(t, dir, filepath.Join(".benmore", recoveryRefusedName), "{}")
			for _, name := range dbStateFileNames {
				if _, err := os.Lstat(filepath.Join(dir, ".benmore", name)); err != nil {
					t.Fatalf("fixture: %s missing: %v", name, err)
				}
			}
			snap, err := backupDatabase(dir)
			if err != nil {
				t.Fatal(err)
			}
			if path == "restore" {
				err = restoreDatabase(dir, snap)
			} else {
				_, err = swapInBackup(dir, snap, errors.New("test"))
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range dbStateFileNames {
				if _, err := os.Lstat(filepath.Join(dir, ".benmore", name)); err == nil {
					t.Fatalf("%s survived the swap", name)
				}
			}
		})
	}
}
