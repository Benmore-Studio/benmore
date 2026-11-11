//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// queueFixtureApp opens dir/data.db as an app with the two framework queues.
// What a run leaves behind is data: the `send` flow writes a row to `sent`,
// and a reminder becomes a notification.
func queueFixtureApp(t *testing.T, dir string) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureAuditLogTable(db)
	EnsureNotificationsTable(db)
	EnsureJobsTable(db)
	EnsureSchedulingTables(db)
	mustExec(t, db, `CREATE TABLE IF NOT EXISTS sent (id INTEGER PRIMARY KEY, what TEXT)`)
	mustExec(t, db, `INSERT OR IGNORE INTO _benmore_users (id, username, email, password_hash, created_at) VALUES (1, 'owner', 'owner@x.test', '$2a$12$owner', '2026-01-01 10:00:00')`)
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown) // runs before db.Close above: stops workers first
	app.Flows = []Flow{{Name: "send", Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO sent (what) VALUES (:what)"}}}}
	return app
}

// enqueueFlow queues a run of flow the way `run: enqueue` does.
func enqueueFlow(t *testing.T, app *App, flow, what string, at time.Time) int64 {
	t.Helper()
	id, _, err := EnqueueJob(app.DB, flow, map[string]any{"what": what}, &at)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// scheduleReminder stores a reminder the way POST /api/_schedule does.
func scheduleReminder(t *testing.T, app *App, title string, at time.Time) int64 {
	t.Helper()
	res, err := app.DB.Exec(`INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, message, flow, body, table_name, row_id, run_at, authorization) VALUES (1, 'reminder', ?, '', '', '', '', '', ?, '')`,
		title, at.UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// runQueue does what a started app does with its queues: the worker's
// start-up recovery, every due job, one scheduler sweep.
func runQueue(app *App) {
	jobsRecoverOrphanedJobs(app)
	FlushJobs(app)
	sweepScheduledTasks(app)
}

func queueSpec(t *testing.T, table string) restoreQueueTable {
	t.Helper()
	for _, q := range restoreQueueTables {
		if q.name == table {
			return q
		}
	}
	t.Fatalf("no queue table %s", table)
	return restoreQueueTable{}
}

func queueStatus(t *testing.T, db *sql.DB, table string, id int64) string {
	t.Helper()
	return credString(t, db, "SELECT status FROM "+table+" WHERE id = ?", id)
}

// queueWaits reports whether the queue still acts on a row.
func queueWaits(t *testing.T, db *sql.DB, table string, id int64) bool {
	t.Helper()
	return queueSpec(t, table).isActive(queueStatus(t, db, table, id))
}

// sentList is every run the `send` flow recorded, in order.
func sentList(t *testing.T, db *sql.DB) string {
	t.Helper()
	return credString(t, db, `SELECT COALESCE(group_concat(what), '') FROM (SELECT what FROM sent ORDER BY id)`)
}

func restoreAuditSummary(t *testing.T, db *sql.DB) restoreCredentialSummary {
	t.Helper()
	var summary restoreCredentialSummary
	raw := credString(t, db, `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)
	if err := json.Unmarshal([]byte(raw), &summary); err != nil {
		t.Fatalf("audit row: %v %q", err, raw)
	}
	if summary.Queue == nil {
		t.Fatalf("the restore audit row says nothing about queued work: %s", raw)
	}
	return summary
}

const (
	jobsTable  = "_benmore_jobs"
	tasksTable = "_benmore_scheduled_tasks"
)

// queueAfterSnapshot is a database whose queue moved on after a snapshot was
// taken: what the snapshot has waiting, and where the live database got to.
type queueAfterSnapshot struct {
	snapshot string
	// jobs: ran; ran and failed; ran and was cleaned up; cut off mid-run; not due.
	invoice, broken, receipt, statement, renewal int64
	// reminders: fired; not due.
	reminder, later int64
	live            map[string]string // "<table>#<id>" -> the live status when the restore starts
}

func queueKey(table string, id int64) string { return table + "#" + credText(id) }

// buildQueueAfterSnapshot fills dir/data.db, snapshots it to dir/<name>, then
// lets the real worker and scheduler do the work, and closes the database.
func buildQueueAfterSnapshot(t *testing.T, dir, name string) queueAfterSnapshot {
	t.Helper()
	app := queueFixtureApp(t, dir)
	past, ahead := time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)
	f := queueAfterSnapshot{snapshot: filepath.Join(dir, name), live: map[string]string{}}
	f.statement = enqueueFlow(t, app, "send", "statement", past.Add(-time.Hour))
	f.invoice = enqueueFlow(t, app, "send", "invoice", past)
	f.broken = enqueueFlow(t, app, "no_such_flow", "broken", past)
	f.receipt = enqueueFlow(t, app, "send", "receipt", past)
	f.renewal = enqueueFlow(t, app, "send", "renewal", ahead)
	f.reminder = scheduleReminder(t, app, "Pay invoice", past)
	f.later = scheduleReminder(t, app, "Renew", ahead)
	if err := os.MkdirAll(filepath.Dir(f.snapshot), 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotTo(t, app.DB, f.snapshot)

	// A worker claims the statement job (the head of the line) and is still
	// running it when the restore stops the app.
	var claimed int64
	var jobType, flow, payload string
	var attempts, maxAttempts int
	lease := time.Now().Add(jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
	if err := app.DB.QueryRow(jobClaimAndStartSQL, lease).Scan(&claimed, &jobType, &flow, &payload, &attempts, &maxAttempts); err != nil || claimed != f.statement {
		t.Fatalf("claim: job %d, %v", claimed, err)
	}
	runQueue(app)
	if got := sentList(t, app.DB); got != "invoice,receipt" {
		t.Fatalf("fixture: the live worker sent %q", got)
	}
	if n := credCount(t, app.DB, `SELECT count(*) FROM _benmore_notifications`); n != 1 {
		t.Fatalf("fixture: %d reminders fired live, want 1", n)
	}
	// The receipt job finished long enough ago for the worker's cleanup.
	credExec(t, app.DB, `UPDATE _benmore_jobs SET completed_at = datetime('now', '-8 days') WHERE id = ?`, f.receipt)
	pruneOldJobs(app.DB)
	if n := credCount(t, app.DB, `SELECT count(*) FROM _benmore_jobs WHERE id = ?`, f.receipt); n != 0 {
		t.Fatal("fixture: the cleanup kept a week-old completed job")
	}
	for table, ids := range map[string][]int64{jobsTable: {f.invoice, f.broken, f.statement, f.renewal}, tasksTable: {f.reminder, f.later}} {
		for _, id := range ids {
			f.live[queueKey(table, id)] = queueStatus(t, app.DB, table, id)
		}
	}
	for table, ids := range map[string][]int64{jobsTable: {f.invoice, f.broken}, tasksTable: {f.reminder}} {
		for _, id := range ids {
			if queueWaits(t, app.DB, table, id) {
				t.Fatalf("fixture: %s is still queued live", queueKey(table, id))
			}
		}
	}
	// Shutdown, not DB.Close: a failed job starts the error reporter, whose
	// connection DB.Close leaves open on the old data.db. Once the restore
	// renames that file, the stale connection takes the new database's
	// rollback journal for a crashed one, plays it into the old file and
	// deletes it, and the next commit fails with "disk I/O error".
	app.Shutdown()
	return f
}

// assertFinishedWorkStaysFinished checks the restored database at dir against
// the fixture: the data is the snapshot's, the queue is where the live
// database left it, and a started app runs none of it a second time.
func assertFinishedWorkStaysFinished(t *testing.T, dir string, f queueAfterSnapshot) *restoreQueueSummary {
	t.Helper()
	app := queueFixtureApp(t, dir)
	if got := sentList(t, app.DB); got != "" {
		t.Fatalf("data was not rolled back: sent = %q", got)
	}
	for table, ids := range map[string][]int64{jobsTable: {f.invoice, f.broken, f.statement, f.renewal}, tasksTable: {f.reminder, f.later}} {
		for _, id := range ids {
			if got, want := queueStatus(t, app.DB, table, id), f.live[queueKey(table, id)]; got != want {
				t.Fatalf("%s is %q after the restore; the live database had it %q", queueKey(table, id), got, want)
			}
		}
	}
	// The job the live database had cleaned up is out of the queue, and says why.
	if queueWaits(t, app.DB, jobsTable, f.receipt) {
		t.Fatal("a job the live database had finished and cleaned up is queued again")
	}
	if reason := credString(t, app.DB, `SELECT error FROM _benmore_jobs WHERE id = ?`, f.receipt); !strings.Contains(reason, "not run again") {
		t.Fatalf("held job reason = %q", reason)
	}
	// Work whose time has not come is still queued.
	if !queueWaits(t, app.DB, jobsTable, f.renewal) || !queueWaits(t, app.DB, tasksTable, f.later) {
		t.Fatal("work that is not due yet left the queue")
	}
	summary := restoreAuditSummary(t, app.DB)

	runQueue(app)
	if got := sentList(t, app.DB); got != "" {
		t.Fatalf("the restarted worker ran finished jobs again: sent %q", got)
	}
	if n := credCount(t, app.DB, `SELECT count(*) FROM _benmore_notifications`); n != 0 {
		t.Fatalf("the restarted scheduler fired %d reminder(s) that had already fired", n)
	}
	q := summary.Queue
	if q.Finished[jobsTable] != 2 || q.Finished[tasksTable] != 1 || q.Held[jobsTable] != 1 || q.Held[tasksTable] != 0 ||
		q.Waiting[jobsTable] != 2 || q.Waiting[tasksTable] != 1 || q.LiveError != "" {
		t.Fatalf("queue summary = %+v", q)
	}
	return q
}

// A restore rolls data back, not work that already ran: jobs and scheduled
// tasks the snapshot has waiting, and the live database has since run, are
// not run a second time by the restarted worker and scheduler (lifecycle F3:
// they came back `pending` and the same email went out again).
func TestRestoreKeepsFinishedWorkFinished(t *testing.T) {
	dir := t.TempDir()
	f := buildQueueAfterSnapshot(t, dir, "snapshot.db")
	if err := restoreDatabase(dir, f.snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertFinishedWorkStaysFinished(t, dir, f)
	// The audit row carries counts and nothing a job holds.
	raw := credString(t, openRO(t, filepath.Join(dir, "data.db")), `SELECT new_values FROM _benmore_audit_log WHERE action = 'restore_credentials'`)
	for _, payload := range []string{"invoice", "receipt", "statement"} {
		if strings.Contains(raw, payload) {
			t.Fatalf("audit row holds job data %q: %s", payload, raw)
		}
	}
}

// Boot auto-recovery swaps a backup in for a database that failed its checks.
// When the moved-aside original can still be read, it says what already ran.
func TestAutoRecoveryKeepsFinishedWorkFinished(t *testing.T) {
	dir := t.TempDir()
	f := buildQueueAfterSnapshot(t, dir, "backup.db")
	if _, err := swapInBackup(dir, f.snapshot, nil); err != nil {
		t.Fatal(err)
	}
	assertFinishedWorkStaysFinished(t, dir, f)
}

// With no readable live database nothing says what ran. Work whose time had
// come may have run and is held; work that is not due yet cannot have run and
// stays queued.
func TestRestoreHoldsDueWorkWhenLiveIsUnreadable(t *testing.T) {
	// The third case: the live database reads fine (accounts carry forward)
	// but has no queue tables to say what ran.
	const noLiveQueue = "live database without queue tables"
	for _, mode := range []string{restoreCredentialsUnreadable, restoreCredentialsNoLive, noLiveQueue} {
		t.Run(mode, func(t *testing.T) {
			src := t.TempDir()
			app := queueFixtureApp(t, src)
			past, ahead := time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour)
			due := enqueueFlow(t, app, "send", "invoice", past)
			renewal := enqueueFlow(t, app, "send", "renewal", ahead)
			reminder := scheduleReminder(t, app, "Pay invoice", past)
			later := scheduleReminder(t, app, "Renew", ahead)
			// One due row in every status the queues still act on (a run cut
			// off mid-way, a blocked task).
			held := map[string]int{jobsTable: 1, tasksTable: 1}
			for _, status := range queueSpec(t, jobsTable).active {
				credExec(t, app.DB, `INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, run_at) VALUES ('flow', 'send', '{"what":"cut off"}', ?, datetime('now', '-1 hour'))`, status)
				held[jobsTable]++
			}
			for _, status := range queueSpec(t, tasksTable).active {
				credExec(t, app.DB, `INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, run_at, status) VALUES (1, 'reminder', 'cut off', '2000-01-01T00:00:00Z', ?)`, status)
				held[tasksTable]++
			}
			dir := t.TempDir()
			snapshot := filepath.Join(dir, "snapshot.db")
			snapshotTo(t, app.DB, snapshot)
			app.DB.Close()
			wantMode := mode
			switch mode {
			case restoreCredentialsUnreadable:
				if err := os.WriteFile(filepath.Join(dir, "data.db"), []byte("SQLite format 3\x00this file is damaged beyond reading"), 0o600); err != nil {
					t.Fatal(err)
				}
			case noLiveQueue:
				wantMode = restoreCredentialsCarried
				live := queueFixtureApp(t, dir)
				for _, q := range restoreQueueTables {
					credExec(t, live.DB, "DROP TABLE "+q.name)
				}
				live.DB.Close()
			}
			if err := restoreDatabase(dir, snapshot); err != nil {
				t.Fatal(err)
			}
			restored := queueFixtureApp(t, dir)
			if queueWaits(t, restored.DB, jobsTable, due) || queueWaits(t, restored.DB, tasksTable, reminder) {
				t.Fatal("work that was due is queued again with nothing to say it had not run")
			}
			if reason := credString(t, restored.DB, `SELECT error FROM _benmore_jobs WHERE id = ?`, due); !strings.Contains(reason, "not run again") {
				t.Fatalf("held job reason = %q", reason)
			}
			if reason := credString(t, restored.DB, `SELECT last_error FROM _benmore_scheduled_tasks WHERE id = ?`, reminder); !strings.Contains(reason, "not run again") {
				t.Fatalf("held task reason = %q", reason)
			}
			if !queueWaits(t, restored.DB, jobsTable, renewal) || !queueWaits(t, restored.DB, tasksTable, later) {
				t.Fatal("work that is not due yet, and so cannot have run, left the queue")
			}
			runQueue(restored)
			if got := sentList(t, restored.DB); got != "" {
				t.Fatalf("the restarted worker ran %q", got)
			}
			if n := credCount(t, restored.DB, `SELECT count(*) FROM _benmore_notifications`); n != 0 {
				t.Fatalf("the restarted scheduler fired %d reminder(s)", n)
			}
			for _, q := range restoreQueueTables {
				in, args := q.activeIn()
				if n := credCount(t, restored.DB, "SELECT count(*) FROM "+q.name+" WHERE "+in, args...); n != 1 {
					t.Fatalf("%s: %d rows still queued, want only the one that is not due", q.name, n)
				}
			}
			summary := restoreAuditSummary(t, restored.DB)
			if q := summary.Queue; summary.Mode != wantMode || q.Held[jobsTable] != held[jobsTable] || q.Held[tasksTable] != held[tasksTable] ||
				q.Waiting[jobsTable] != 1 || q.Waiting[tasksTable] != 1 || len(q.Finished) != 0 {
				t.Fatalf("mode %q, queue summary = %+v, want held %v", summary.Mode, q, held)
			}
		})
	}
}

// A row the live database never held is not matched to anything: an id an
// earlier restore let the sequence hand out again is a different job, and an
// id past the live sequence was never there. Nothing ran them, so they stay
// queued and run once.
func TestRestoreLeavesWorkTheLiveDatabaseNeverHad(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	src := t.TempDir()
	old := queueFixtureApp(t, src)
	first := enqueueFlow(t, old, "send", "first", past)
	credExec(t, old.DB, `UPDATE _benmore_jobs SET created_at = '2026-01-01 00:00:00' WHERE id = ?`, first)
	credExec(t, old.DB, `INSERT INTO _benmore_jobs (id, job_type, flow_name, payload, run_at, max_attempts) VALUES (50, 'flow', 'send', '{"what":"later"}', datetime('now', '-1 hour'), 1)`)
	reminder := scheduleReminder(t, old, "Pay invoice", past)
	credExec(t, old.DB, `UPDATE _benmore_scheduled_tasks SET created_at = '2026-01-01 00:00:00' WHERE id = ?`, reminder)

	dir := t.TempDir()
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, old.DB, snapshot)
	old.DB.Close()

	// The live database is another timeline: its job 1 and task 1 are
	// different rows, both finished.
	live := queueFixtureApp(t, dir)
	if other := enqueueFlow(t, live, "send", "other", past); other != first {
		t.Fatalf("fixture: live job id %d, want the reused %d", other, first)
	}
	if other := scheduleReminder(t, live, "Other", past); other != reminder {
		t.Fatalf("fixture: live task id %d, want the reused %d", other, reminder)
	}
	runQueue(live)
	if queueWaits(t, live.DB, jobsTable, first) || queueWaits(t, live.DB, tasksTable, reminder) {
		t.Fatal("fixture: the live rows did not finish")
	}
	live.DB.Close()

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	restored := queueFixtureApp(t, dir)
	if q := restoreAuditSummary(t, restored.DB).Queue; q.Waiting[jobsTable] != 2 || q.Waiting[tasksTable] != 1 || len(q.Finished) != 0 || len(q.Held) != 0 {
		t.Fatalf("queue summary = %+v", q)
	}
	runQueue(restored)
	if got := sentList(t, restored.DB); got != "first,later" {
		t.Fatalf("jobs the live database never had ran as %q, want each once", got)
	}
	if n := credCount(t, restored.DB, `SELECT count(*) FROM _benmore_notifications`); n != 1 {
		t.Fatalf("%d reminders fired, want the one the live database never had", n)
	}
}

// An interval cron schedule counts from its last run. The restored snapshot
// has an older one than the live database, so `every 24h` fired again as soon
// as the app started although it had run an hour before the restore.
func TestRestoreKeepsLiveCronLastFire(t *testing.T) {
	dir := t.TempDir()
	app := queueFixtureApp(t, dir)
	if err := ensureCronStateTable(app); err != nil {
		t.Fatal(err)
	}
	persistCronFire(app, "digest", time.Now().Add(-48*time.Hour))
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, app.DB, snapshot)
	ranAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	persistCronFire(app, "digest", ranAt)
	app.DB.Close()

	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	restored := queueFixtureApp(t, dir)
	restored.Cron = &CronConfig{Jobs: []CronJob{{ID: "digest", Schedule: "every 24h", Flow: "send"}}}
	state := newCronState(restored)
	if got := state.lastFire["digest"]; !got.Equal(ranAt) {
		t.Fatalf("restored last run = %s, want the live %s", got, ranAt)
	}
	state.tick(restored, time.Now())
	if n := credCount(t, restored.DB, `SELECT count(*) FROM _benmore_jobs WHERE job_type = 'cron'`); n != 0 {
		t.Fatalf("an `every 24h` schedule that ran an hour before the restore was queued again (%d run(s))", n)
	}
}

// A snapshot can predate columns the queues have gained since (a lease, a
// last_error). Holding its work names only the columns it has; the restore
// must not fail on the others.
func TestRestoreHoldsWorkInASnapshotOlderThanTheQueueColumns(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "snapshot.db")
	old, err := sql.Open("sqlite3", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	credExec(t, old, `CREATE TABLE _benmore_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, flow_name TEXT NOT NULL DEFAULT '', payload TEXT, status TEXT DEFAULT 'pending',
		attempts INTEGER DEFAULT 0, max_attempts INTEGER DEFAULT 3, error TEXT, run_at DATETIME DEFAULT CURRENT_TIMESTAMP, started_at DATETIME, completed_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	credExec(t, old, `CREATE TABLE _benmore_scheduled_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'reminder', title TEXT NOT NULL DEFAULT 'Reminder',
		message TEXT DEFAULT '', flow TEXT DEFAULT '', body TEXT DEFAULT '', table_name TEXT DEFAULT '', row_id TEXT DEFAULT '', run_at DATETIME NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, fired_at DATETIME)`)
	credExec(t, old, `INSERT INTO _benmore_jobs (flow_name, payload, run_at) VALUES ('send', '{"what":"invoice"}', datetime('now', '-1 hour'))`)
	credExec(t, old, `INSERT INTO _benmore_scheduled_tasks (user_id, title, run_at) VALUES (1, 'Pay invoice', '2000-01-01T00:00:00Z')`)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatalf("restore of an old snapshot: %v", err)
	}
	restored := queueFixtureApp(t, dir)
	if queueWaits(t, restored.DB, jobsTable, 1) || queueWaits(t, restored.DB, tasksTable, 1) {
		t.Fatal("due work from an old snapshot is still queued")
	}
	runQueue(restored)
	if got := sentList(t, restored.DB); got != "" {
		t.Fatalf("the restarted worker ran %q", got)
	}
	if q := restoreAuditSummary(t, restored.DB).Queue; q.Held[jobsTable] != 1 || q.Held[tasksTable] != 1 {
		t.Fatalf("queue summary = %+v", q)
	}
}

// restoreQueueTables says which statuses mean "still queued". Each of them
// must be one the worker or the scheduler still acts on (a row left in it,
// due and with a lapsed claim, does not stay there), and the jobs list must
// be the one the queue's own active-job index is built over. A status that
// is renamed or added in jobs.go / scheduling.go fails here.
func TestRestoreQueueStatusesAreTheOnesTheWorkersActOn(t *testing.T) {
	lapsedLease := time.Now().Add(-time.Hour).UTC().Format(sqliteDateTimeLayout)
	lapsedClaim := time.Now().Add(-24 * time.Hour).UTC().Format(schedTaskStampLayout)
	for _, status := range queueSpec(t, jobsTable).active {
		app := queueFixtureApp(t, t.TempDir())
		credExec(t, app.DB, `INSERT INTO _benmore_jobs (id, job_type, flow_name, payload, status, attempts, max_attempts, run_at, lease_expires_at) VALUES (1, 'flow', 'send', '{"what":"x"}', ?, 0, 1, datetime('now', '-1 hour'), ?)`, status, lapsedLease)
		runQueue(app)
		if got := queueStatus(t, app.DB, jobsTable, 1); got == status {
			t.Fatalf("a due job left %q is not touched by the worker; is it still a queued status?", status)
		}
	}
	for _, status := range queueSpec(t, tasksTable).active {
		app := queueFixtureApp(t, t.TempDir())
		credExec(t, app.DB, `INSERT INTO _benmore_scheduled_tasks (id, user_id, kind, title, run_at, status, claimed_at) VALUES (1, 1, 'reminder', 'x', '2000-01-01T00:00:00Z', ?, ?)`, status, lapsedClaim)
		runQueue(app)
		if got := queueStatus(t, app.DB, tasksTable, 1); got == status {
			t.Fatalf("a due task left %q is not touched by the scheduler; is it still a queued status?", status)
		}
	}
	app := queueFixtureApp(t, t.TempDir())
	index := credString(t, app.DB, `SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_jobs_unique_active'`)
	_, list, ok := strings.Cut(index, "status IN (")
	list, _, closed := strings.Cut(list, ")")
	if !ok || !closed {
		t.Fatalf("the active-job index no longer lists statuses: %q", index)
	}
	var indexed []string
	for _, status := range strings.Split(list, ",") {
		indexed = append(indexed, strings.Trim(strings.TrimSpace(status), "'"))
	}
	want := append([]string(nil), queueSpec(t, jobsTable).active...)
	slices.Sort(indexed)
	slices.Sort(want)
	if !slices.Equal(indexed, want) {
		t.Fatalf("the queue's active-job index covers %v; a restore treats %v as still queued", indexed, want)
	}
}
