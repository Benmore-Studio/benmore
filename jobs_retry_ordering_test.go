//go:build !cli

package main

import (
	"testing"
	"time"
)

// execLogOrder returns the recorded execution order from the test's exec_log
// table (rowid order = execution order).
func execLogOrder(t *testing.T, app *App) []string {
	t.Helper()
	rows, err := app.DB.Query("SELECT who FROM exec_log ORDER BY id ASC")
	if err != nil {
		t.Fatalf("read exec_log: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var w string
		if err := rows.Scan(&w); err != nil {
			t.Fatalf("scan exec_log: %v", err)
		}
		out = append(out, w)
	}
	return out
}

func setupOrderingApp(t *testing.T) *App {
	t.Helper()
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE exec_log (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT NOT NULL)"); err != nil {
		t.Fatalf("create exec_log: %v", err)
	}
	app.Flows = []Flow{
		{
			// Stage A logs its attempt, then fails (missing table) - a transient
			// blip that the queue retries.
			Name: "stage_a",
			Steps: []FlowStep{
				{Type: "sql", SQL: "INSERT INTO exec_log (who) VALUES ('A')"},
				{Type: "sql", SQL: "INSERT INTO nonexistent_table (x) VALUES (1)"},
			},
		},
		{
			Name:  "stage_b",
			Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO exec_log (who) VALUES ('B')"}},
		},
	}
	return app
}

// TestRetryDoesNotReorderStrictChain is the regression for review finding #11.
// Two jobs are queued with strictly increasing PAST run_at (A before B) on the
// single serial worker. A fails on its first attempt. Pre-fix the retry
// rewrote A.run_at = now + backoff (a FUTURE time later than B's stamp), so B
// jumped ahead and ran before A retried - reveal/reconcile on a board missing
// A's facts. With the fix A keeps its run_at and its retry is gated by
// not_before, so B never runs before A reaches a terminal state.
//
// This drives the PRODUCTION claim path (processNextJob) directly rather than
// FlushJobs: the ordering gate being regressed lives in processNextJob, and
// FlushJobs is a test-only drain that (by design) fast-forwards a gated head so
// it can run everything due now - it would not pause on the backoff we want to
// observe here.
func TestRetryDoesNotReorderStrictChain(t *testing.T) {
	app := setupOrderingApp(t)

	runAtA := time.Now().Add(-20 * time.Second)
	runAtB := time.Now().Add(-10 * time.Second) // strictly after A
	// A and B share project_id 1: they model an actual per-project reconcile
	// chain (the ONLY shape strict ordering is required for). The ordering gate
	// is scoped to project_id, so same-project stages must stay strictly ordered.
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_a", map[string]any{"project_id": 1}, &runAtA, jobEnqueueOpts{maxAttempts: 2}); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_b", map[string]any{"project_id": 1}, &runAtB, jobEnqueueOpts{}); err != nil {
		t.Fatalf("enqueue B: %v", err)
	}

	// A runs once and fails into a backoff.
	if !processNextJob(app) {
		t.Fatal("first processNextJob claimed nothing; expected A to run")
	}
	if got := execLogOrder(t, app); len(got) != 1 || got[0] != "A" {
		t.Fatalf("after A's first attempt exec order = %v, want [A]", got)
	}
	// The production claim gate must NOT let B (later run_at) jump ahead while A
	// - the earlier-run_at head of line - is still backing off.
	if processNextJob(app) {
		t.Fatalf("processNextJob claimed a job while the head-of-line predecessor was backing off: exec = %v (B jumped ahead)", execLogOrder(t, app))
	}
	if got := execLogOrder(t, app); len(got) != 1 || got[0] != "A" {
		t.Fatalf("B ran while A was gated: exec order = %v, want [A]", got)
	}

	// Simulate the backoff window elapsing. A retries, fails again, and hits
	// max_attempts (2) -> terminal 'failed', which drops it from the pending
	// set and finally unblocks B.
	if _, err := app.DB.Exec("UPDATE _benmore_jobs SET not_before = NULL WHERE flow_name = 'stage_a'"); err != nil {
		t.Fatalf("clear not_before: %v", err)
	}
	FlushJobs(app)

	got := execLogOrder(t, app)
	// Every A entry must precede the single B entry.
	var sawB bool
	for _, w := range got {
		if w == "B" {
			sawB = true
		}
		if sawB && w == "A" {
			t.Fatalf("A ran after B: order = %v", got)
		}
	}
	if !sawB {
		t.Fatalf("B never ran after A terminated: order = %v", got)
	}

	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE flow_name = 'stage_a'").Scan(&status); err != nil {
		t.Fatalf("read A status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("stage_a status = %q, want failed", status)
	}
}

// TestRetryPreservesRunAtAndSetsNotBefore pins the mechanism: a failed retry
// leaves run_at untouched and instead stamps not_before in the future.
//
// Note: go-sqlite3 reformats DATETIME columns on scan-to-string, so run_at is
// compared before/after (both reads share the same conversion) rather than to a
// literal, and the "in the future" check is done in SQL against the raw stored
// text.
func TestRetryPreservesRunAtAndSetsNotBefore(t *testing.T) {
	app := setupOrderingApp(t)

	runAt := time.Now().Add(-30 * time.Minute)
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_a", map[string]any{"project_id": 1}, &runAt, jobEnqueueOpts{maxAttempts: 3}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var runAtBefore string
	if err := app.DB.QueryRow("SELECT run_at FROM _benmore_jobs WHERE flow_name = 'stage_a'").Scan(&runAtBefore); err != nil {
		t.Fatalf("read run_at before: %v", err)
	}

	// Drive exactly ONE attempt via the production claim path so the job is
	// observed mid-flight in its pending+backoff state. FlushJobs would instead
	// fast-forward the backoff and drain all 3 attempts to a terminal 'failed'
	// (its documented test-only "run everything due now" semantics).
	if !processNextJob(app) {
		t.Fatal("processNextJob claimed nothing; expected the job to run once")
	}

	var runAtAfter, notBefore, status string
	var notBeforeInFuture int
	err := app.DB.QueryRow(`
		SELECT run_at, COALESCE(not_before,''), status,
		       (not_before IS NOT NULL AND not_before > datetime('now')) AS in_future
		FROM _benmore_jobs WHERE flow_name = 'stage_a'`).
		Scan(&runAtAfter, &notBefore, &status, &notBeforeInFuture)
	if err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "pending" {
		t.Fatalf("status = %q, want pending (a retry, not terminal)", status)
	}
	if runAtAfter != runAtBefore {
		t.Fatalf("run_at changed on retry: before=%q after=%q (retry must preserve run_at)", runAtBefore, runAtAfter)
	}
	if notBefore == "" {
		t.Fatal("not_before is empty - the retry backoff gate was not set")
	}
	if notBeforeInFuture != 1 {
		t.Fatalf("not_before %q is not in the future - the retry would be claimable immediately", notBefore)
	}
}

// TestBackingOffChainJobDoesNotBlockUnrelatedJobs is the regression for the
// #186 head-of-line stall. A pipeline job for project 1 fails and drops into a
// retry backoff. As the smallest-run_at row stamped `-1 day`, it is the
// PERPETUAL head of the shared `_benmore_jobs` queue. Pre-fix the ordering gate
// keyed off that GLOBAL head, so it froze the whole queue for the backoff
// window: a DIFFERENT project's chain job and a user-facing hook job (chat /
// notification / email) could not run until the poison job terminated.
//
// The fix scopes the gate to the ordering group (project_id). This test proves
// the backing-off project-1 job gates ONLY project 1: a project-2 chain job and
// a hook job (no project_id) both stay claimable and run while project 1 is
// still pending in backoff.
func TestBackingOffChainJobDoesNotBlockUnrelatedJobs(t *testing.T) {
	app := setupOrderingApp(t) // stage_a: logs 'A' then fails; stage_b: logs 'B'

	// project 1's chain head: earliest run_at, so it is the global head of line.
	// max_attempts=2 keeps it PENDING (a retry, not terminal 'failed') after its
	// first failure, so it sits in backoff for the duration of the assertions.
	runAtPoison := time.Now().Add(-30 * time.Second)
	runAtOther := time.Now().Add(-20 * time.Second) // a different project, later
	runAtHook := time.Now().Add(-10 * time.Second)  // a user-facing hook, later still
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_a",
		map[string]any{"project_id": 1}, &runAtPoison, jobEnqueueOpts{maxAttempts: 2}); err != nil {
		t.Fatalf("enqueue project-1 poison job: %v", err)
	}
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_b",
		map[string]any{"project_id": 2}, &runAtOther, jobEnqueueOpts{}); err != nil {
		t.Fatalf("enqueue project-2 job: %v", err)
	}
	// A hook job carries no project_id (its payload is {_hook, _row}), so it is
	// in the group-less bucket - a different ordering group from project 1.
	hookPayload := `{"_hook":{"sql":"INSERT INTO exec_log (who) VALUES ('HOOK')"},"_row":{}}`
	if _, err := app.DB.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('hook', 'hook', ?, ?)",
		hookPayload, runAtHook.UTC().Format(sqliteDateTimeLayout),
	); err != nil {
		t.Fatalf("enqueue hook job: %v", err)
	}

	// 1) project 1's head runs first (smallest run_at), logs 'A', fails, backs off.
	if !processNextJob(app) {
		t.Fatal("first processNextJob claimed nothing; expected project-1 head to run")
	}
	if got := execLogOrder(t, app); len(got) != 1 || got[0] != "A" {
		t.Fatalf("after project-1 head's first attempt exec = %v, want [A]", got)
	}

	// Confirm project 1 is genuinely mid-backoff (pending, not terminal), i.e.
	// it really is the perpetual head that the pre-fix gate would stall behind.
	var status string
	var inFuture int
	if err := app.DB.QueryRow(`
		SELECT status, (not_before IS NOT NULL AND not_before > datetime('now'))
		FROM _benmore_jobs WHERE flow_name = 'stage_a'`).Scan(&status, &inFuture); err != nil {
		t.Fatalf("read project-1 job: %v", err)
	}
	if status != "pending" || inFuture != 1 {
		t.Fatalf("project-1 job status=%q not_before_in_future=%d, want pending + in-future backoff", status, inFuture)
	}

	// 2) The gate must NOT stall unrelated groups. Drain what is now claimable:
	// the project-2 chain job and the hook job must both run while project 1 is
	// still backing off. Pre-fix, both processNextJob calls would return false.
	if !processNextJob(app) {
		t.Fatalf("processNextJob claimed nothing while project 1 backed off: an unrelated job was stalled behind the poison job (the #186 bug). exec = %v", execLogOrder(t, app))
	}
	if !processNextJob(app) {
		t.Fatalf("processNextJob claimed nothing on the second unrelated job while project 1 backed off. exec = %v", execLogOrder(t, app))
	}

	got := execLogOrder(t, app)
	if !contains(got, "B") {
		t.Fatalf("project-2 job did not run while project 1 backed off: exec = %v (cross-project coupling)", got)
	}
	if !contains(got, "HOOK") {
		t.Fatalf("hook job did not run while project 1 backed off: exec = %v (user-facing surface stalled)", got)
	}

	// project 1 must STILL be pending in backoff - proving the unrelated jobs ran
	// WHILE it was gated, not after it terminated.
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE flow_name = 'stage_a'").Scan(&status); err != nil {
		t.Fatalf("re-read project-1 status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("project-1 job status = %q, want pending (it must still be backing off while unrelated jobs ran)", status)
	}
}

// TestBackingOffGrouplessJobDoesNotBlockHook pins the residual closed. A
// group-less job (NO project_id in its payload) - the shape of a transcribe-brief
// async flow (payload {submission_id,user_id}; ~90s terminal backoff when
// whisper/ffmpeg is missing) or a webhook_subscription delivery (max_attempts=3;
// backs off on a dead/5xx subscriber) - fails and drops into a retry backoff.
// Because it carries no project_id it shares the NULL "group" with every hook /
// notification / email job.
//
// The gate must treat a NULL project_id as "not part of any ordered chain": such
// a job can neither gate nor be gated. This test proves a backing-off group-less
// job does NOT block a hook job (also group-less) - the hook runs while the first
// is still in backoff. The tighter `project_id IS NOT NULL` guards on BOTH the
// candidate and predecessor sides of the claim query are what make this hold.
func TestBackingOffGrouplessJobDoesNotBlockHook(t *testing.T) {
	app := setupOrderingApp(t) // stage_a: logs 'A' then fails; stage_b: logs 'B'

	// A group-less poison job: NO project_id in the payload. max_attempts=2 keeps
	// it PENDING (backing off) after its first failure.
	runAtPoison := time.Now().Add(-30 * time.Second)
	runAtHook := time.Now().Add(-10 * time.Second) // a hook, later
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_a",
		map[string]any{"submission_id": 7, "user_id": 3}, &runAtPoison, jobEnqueueOpts{maxAttempts: 2}); err != nil {
		t.Fatalf("enqueue group-less poison job: %v", err)
	}
	hookPayload := `{"_hook":{"sql":"INSERT INTO exec_log (who) VALUES ('HOOK')"},"_row":{}}`
	if _, err := app.DB.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('hook', 'hook', ?, ?)",
		hookPayload, runAtHook.UTC().Format(sqliteDateTimeLayout),
	); err != nil {
		t.Fatalf("enqueue hook job: %v", err)
	}

	// 1) The group-less job runs first (smallest run_at), logs 'A', fails, backs off.
	if !processNextJob(app) {
		t.Fatal("first processNextJob claimed nothing; expected the group-less job to run")
	}
	if got := execLogOrder(t, app); len(got) != 1 || got[0] != "A" {
		t.Fatalf("after group-less job's first attempt exec = %v, want [A]", got)
	}
	var status string
	var inFuture int
	if err := app.DB.QueryRow(`
		SELECT status, (not_before IS NOT NULL AND not_before > datetime('now'))
		FROM _benmore_jobs WHERE flow_name = 'stage_a'`).Scan(&status, &inFuture); err != nil {
		t.Fatalf("read group-less job: %v", err)
	}
	if status != "pending" || inFuture != 1 {
		t.Fatalf("group-less job status=%q not_before_in_future=%d, want pending + in-future backoff", status, inFuture)
	}

	// 2) The hook (also group-less) must be claimable while the poison job backs
	// off - a NULL group can neither gate nor be gated. Pre-tightening, both
	// shared the NULL bucket and the hook would have been frozen.
	if !processNextJob(app) {
		t.Fatalf("processNextJob claimed nothing while a group-less job backed off: the hook was stalled behind it (the residual). exec = %v", execLogOrder(t, app))
	}
	if got := execLogOrder(t, app); !contains(got, "HOOK") {
		t.Fatalf("hook did not run while the group-less job backed off: exec = %v", got)
	}

	// The group-less job must STILL be pending in backoff.
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE flow_name = 'stage_a'").Scan(&status); err != nil {
		t.Fatalf("re-read group-less job status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("group-less job status = %q, want pending (it must still be backing off while the hook ran)", status)
	}
}

// TestEnsureJobsTableIdempotentBackoffIndex verifies the new partial backoff
// index is created and that EnsureJobsTable is safe to re-run (boot + hot
// reload both call it), i.e. the migration is idempotent.
func TestEnsureJobsTableIdempotentBackoffIndex(t *testing.T) {
	app := newJobsTestApp(t) // calls EnsureJobsTable once
	EnsureJobsTable(app.DB)  // second call must be a no-op, not an error

	var name string
	err := app.DB.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_jobs_backoff'",
	).Scan(&name)
	if err != nil {
		t.Fatalf("idx_jobs_backoff missing after EnsureJobsTable: %v", err)
	}
	if name != "idx_jobs_backoff" {
		t.Fatalf("unexpected index name %q", name)
	}

	// A third call still succeeds and the queue is usable (sanity that the DDL
	// re-run didn't wedge anything).
	EnsureJobsTable(app.DB)
	if _, _, err := EnqueueJob(app.DB, "noop", map[string]any{}, nil); err != nil {
		t.Fatalf("enqueue after repeated EnsureJobsTable: %v", err)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
