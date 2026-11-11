//go:build !cli

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// newWorkflowTimeoutBacklogApp is newWorkflowTimeoutApp whose orders hold one
// row of each state per slot (a unique index), so a timeout into a state the
// slot already holds fails every time it is tried.
func newWorkflowTimeoutBacklogApp(t *testing.T) (*App, *Workflow) {
	t.Helper()
	app, wf := newWorkflowTimeoutApp(t)
	mustExec(t, app.DB, "ALTER TABLE orders ADD COLUMN slot INTEGER")
	mustExec(t, app.DB, "CREATE UNIQUE INDEX orders_slot_status ON orders(slot, status)")
	return app, wf
}

// seedTimeoutRows inserts n timed-out orders in state, slots first..first+n-1,
// all last updated `age` ago, and returns the id of the first (ids ascend
// with the slots).
func seedTimeoutRows(t *testing.T, app *App, state string, first, n int, age string) int64 {
	t.Helper()
	var before int64
	if err := app.DB.QueryRow("SELECT COALESCE(MAX(id), 0) FROM orders").Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, fmt.Sprintf(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < %d)
		INSERT INTO orders (status, slot, updated_at) SELECT '%s', %d + i, datetime('now', '-%s') FROM n`, n-1, state, first, age))
	return before + 1
}

func timeoutRowCount(t *testing.T, app *App, where string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM orders WHERE " + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func timeoutRowStatus(t *testing.T, app *App, id int64) string {
	t.Helper()
	var status string
	if err := app.DB.QueryRow("SELECT status FROM orders WHERE id = ?", id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func timeoutRowKey(app *App, wf *Workflow, id int64) workflowTimeoutKey {
	return workflowTimeoutKey{dir: app.Dir, workflow: wf.Name, id: fmt.Sprint(id)}
}

// timeoutRowFailures is how many times in a row the sweep failed on a row.
func timeoutRowFailures(app *App, wf *Workflow, id int64) int {
	workflowTimeoutBackoff.mu.Lock()
	defer workflowTimeoutBackoff.mu.Unlock()
	return workflowTimeoutBackoff.m[timeoutRowKey(app, wf, id)].failures
}

// One batch of rows whose timeout fails every time sat in front of every
// newer row of the state: the sweep selected the oldest workflowTimeoutBatch
// rows and skipped the ones waiting out a failure inside the loop, so the
// batch was all skips and a healthy newer row never timed out.
func TestWorkflowTimeoutSweepReachesRowsBehindFailingBatch(t *testing.T) {
	app, wf := newWorkflowTimeoutBacklogApp(t)
	// The slots already hold a delivered row, so shipped -> delivered breaks
	// the unique index for each of these.
	seedTimeoutRows(t, app, "delivered", 1, workflowTimeoutBatch, "3 hours")
	seedTimeoutRows(t, app, "shipped", 1, workflowTimeoutBatch, "2 hours")
	healthy := seedTimeoutRows(t, app, "shipped", 1_000_000, 1, "1 hour")

	logged := captureLog(t, func() {
		for sweep := 1; sweep <= 4; sweep++ {
			checkWorkflowTimeouts(app, wf)
		}
	})

	if status := timeoutRowStatus(t, app, healthy); status != "delivered" {
		t.Fatalf("after 4 sweeps the healthy row behind %d failing rows is still %q; want delivered", workflowTimeoutBatch, status)
	}
	if left := timeoutRowCount(t, app, "status = 'shipped'"); left != workflowTimeoutBatch {
		t.Fatalf("%d rows are still shipped; want the %d that cannot move", left, workflowTimeoutBatch)
	}
	var jobs int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'").Scan(&jobs)
	if jobs != 1 {
		t.Fatalf("on_transition hook queued %d times; want once, for the one row that moved", jobs)
	}
	// Each failing row was tried once and is waiting; the later sweeps passed
	// over it instead of running its failing transaction again.
	// Logged as one summary line for the sweep that tried them.
	if n := strings.Count(logged, "WORKFLOW TIMEOUT ERROR"); n != 1 || !strings.Contains(logged, fmt.Sprintf("%d row(s) could not time out", workflowTimeoutBatch)) {
		t.Fatalf("failed attempts logged %d time(s); want one line naming %d rows:\n%s", n, workflowTimeoutBatch, logged)
	}
}

// The reviewer's case on the sweeper's own clock: more failing rows than one
// batch, sweeps a minute apart for over an hour, and a healthy row arriving
// behind them every minute. Every healthy row times out within two sweeps,
// and the failing rows keep being retried on their doubling wait, not every
// minute and not never.
func TestWorkflowTimeoutSweepKeepsUpWhileRowsKeepFailing(t *testing.T) {
	app, wf := newWorkflowTimeoutBacklogApp(t)
	const failing = workflowTimeoutBatch + 100
	seedTimeoutRows(t, app, "delivered", 1, failing, "3 hours")
	firstFailing := seedTimeoutRows(t, app, "shipped", 1, failing, "2 hours")

	start := time.Now()
	var healthy []int64
	logged := captureLog(t, func() {
		for minute := 0; minute < 70; minute++ {
			// Newer than every failing row, and already past its deadline.
			healthy = append(healthy, seedTimeoutRows(t, app, "shipped", 1_000_000+minute, 1, fmt.Sprintf("%d seconds", 3600-minute*10)))
			checkWorkflowTimeoutsAt(app, wf, start.Add(time.Duration(minute)*time.Minute))
			if minute == 0 {
				continue
			}
			if id := healthy[minute-1]; timeoutRowStatus(t, app, id) != "delivered" {
				t.Fatalf("minute %d: the healthy row that arrived a minute ago (id %d) has not timed out", minute, id)
			}
		}
	})

	if left := timeoutRowCount(t, app, "status = 'shipped' AND slot < 1000000"); left != failing {
		t.Fatalf("%d failing rows are still shipped; want all %d", left, failing)
	}
	// 1m, 2m, 4m, 8m, 16m, 32m waits fit in 70 sweeps: seven tries, give or
	// take one for where a row sits in the rotation.
	for _, id := range []int64{firstFailing, firstFailing + workflowTimeoutBatch - 1, firstFailing + failing - 1} {
		if n := timeoutRowFailures(app, wf, id); n < 6 || n > 8 {
			t.Errorf("failing row %d was tried %d times in 70 minutes; want 6-8 (a doubling wait)", id, n)
		}
	}
	// Failures are summarized once per sweep, never one line per row.
	if lines := strings.Count(logged, "WORKFLOW TIMEOUT ERROR"); lines == 0 || lines > 70 {
		t.Errorf("logged %d failure lines over 70 sweeps; want at most one per sweep", lines)
	}
}

// Rows waiting out a failed attempt are read and passed over, not tried and
// not counted against the batch: the rows behind them are reached in the same
// sweep. All rows share one updated_at, so the pages are told apart by id.
func TestWorkflowTimeoutSweepPassesOverWaitingRows(t *testing.T) {
	app, wf := newWorkflowTimeoutBacklogApp(t)
	const waiting = 2*workflowTimeoutBatch + 200
	now := time.Now()
	firstWaiting := seedTimeoutRows(t, app, "shipped", 1, waiting, "1 hour")
	for i := int64(0); i < waiting; i++ {
		workflowTimeoutBackoff.fail(timeoutRowKey(app, wf, firstWaiting+i), now)
	}
	firstHealthy := seedTimeoutRows(t, app, "shipped", 1_000_000, 3, "1 hour")

	captureLog(t, func() { checkWorkflowTimeoutsAt(app, wf, now.Add(time.Second)) })

	for id := firstHealthy; id < firstHealthy+3; id++ {
		if status := timeoutRowStatus(t, app, id); status != "delivered" {
			t.Fatalf("row %d behind %d waiting rows is %q after one sweep; want delivered", id, waiting, status)
		}
	}
	// Nothing stops these moving except the wait: had the sweep tried one, it
	// would be delivered.
	if still := timeoutRowCount(t, app, fmt.Sprintf("status = 'shipped' AND id < %d", firstHealthy)); still != waiting {
		t.Fatalf("%d waiting rows are still shipped; want all %d left alone", still, waiting)
	}
	if _, resuming := workflowTimeoutResume.get(workflowTimeoutStateKey{dir: app.Dir, workflow: wf.Name, state: "shipped"}); resuming {
		t.Fatal("a sweep that read every due row left a position to resume from")
	}
}

// A sweep reads at most workflowTimeoutScanLimit rows of a state. Past that
// it stops and the next sweep continues from the row it stopped at, so a
// backlog larger than the bound delays the rows behind it by a sweep, not for
// good; once the rows run out the following sweep starts from the oldest.
func TestWorkflowTimeoutSweepReadBoundResumesNextSweep(t *testing.T) {
	app, wf := newWorkflowTimeoutBacklogApp(t)
	const waiting = workflowTimeoutScanLimit + 250
	now := time.Now()
	firstWaiting := seedTimeoutRows(t, app, "shipped", 1, waiting, "2 hours")
	for i := int64(0); i < waiting; i++ {
		workflowTimeoutBackoff.fail(timeoutRowKey(app, wf, firstWaiting+i), now)
	}
	healthy := seedTimeoutRows(t, app, "shipped", 1_000_000, 1, "1 hour")
	posKey := workflowTimeoutStateKey{dir: app.Dir, workflow: wf.Name, state: "shipped"}

	captureLog(t, func() { checkWorkflowTimeoutsAt(app, wf, now.Add(time.Second)) })
	if status := timeoutRowStatus(t, app, healthy); status != "shipped" {
		t.Fatalf("the row behind %d waiting rows is %q after one sweep: the sweep read past its %d-row bound", waiting, status, workflowTimeoutScanLimit)
	}
	pos, resuming := workflowTimeoutResume.get(posKey)
	if want := firstWaiting + workflowTimeoutScanLimit - 1; !resuming || pos.id != want {
		t.Fatalf("after the first sweep the position is %v (set=%v); want row %d, the %dth read", pos.id, resuming, want, workflowTimeoutScanLimit)
	}

	captureLog(t, func() { checkWorkflowTimeoutsAt(app, wf, now.Add(2*time.Second)) })
	if status := timeoutRowStatus(t, app, healthy); status != "delivered" {
		t.Fatalf("the second sweep did not continue past the bound: the row behind the backlog is %q", status)
	}
	if _, resuming := workflowTimeoutResume.get(posKey); resuming {
		t.Fatal("the rows ran out but the sweep kept its position")
	}

	// From the oldest again: the first row's wait is over and it moves.
	workflowTimeoutBackoff.clear(timeoutRowKey(app, wf, firstWaiting))
	captureLog(t, func() { checkWorkflowTimeoutsAt(app, wf, now.Add(3*time.Second)) })
	if status := timeoutRowStatus(t, app, firstWaiting); status != "delivered" {
		t.Fatalf("after the rows ran out the next sweep did not start from the oldest: row %d is %q", firstWaiting, status)
	}
	if still := timeoutRowCount(t, app, "status = 'shipped'"); still != waiting-1 {
		t.Fatalf("%d rows are still shipped; want the %d still waiting", still, waiting-1)
	}
}

// A sweep still tries one batch per state, oldest first, and the next sweep
// takes the next batch: a healthy backlog drains 500 a minute as before.
func TestWorkflowTimeoutSweepTriesOneBatchOldestFirst(t *testing.T) {
	app, wf := newWorkflowTimeoutBacklogApp(t)
	const backlog = 2*workflowTimeoutBatch + 100
	// Older rows have the higher ids here, so "oldest first" is not id order.
	newest := seedTimeoutRows(t, app, "shipped", 1, 100, "1 hour")
	middle := seedTimeoutRows(t, app, "shipped", 1_000, workflowTimeoutBatch, "2 hours")
	oldest := seedTimeoutRows(t, app, "shipped", 10_000, workflowTimeoutBatch, "3 hours")

	delivered := func(first int64, n int) int {
		return timeoutRowCount(t, app, fmt.Sprintf("status = 'delivered' AND id >= %d AND id < %d", first, first+int64(n)))
	}
	now := time.Now()
	for sweep, want := range [][3]int{{workflowTimeoutBatch, 0, 0}, {workflowTimeoutBatch, workflowTimeoutBatch, 0}, {workflowTimeoutBatch, workflowTimeoutBatch, 100}} {
		captureLog(t, func() { checkWorkflowTimeoutsAt(app, wf, now.Add(time.Duration(sweep)*time.Minute)) })
		got := [3]int{delivered(oldest, workflowTimeoutBatch), delivered(middle, workflowTimeoutBatch), delivered(newest, 100)}
		if got != want {
			t.Fatalf("after sweep %d delivered (oldest, middle, newest) = %v; want %v", sweep+1, got, want)
		}
	}
	var jobs int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'").Scan(&jobs)
	if jobs != backlog {
		t.Fatalf("on_transition hook queued %d times; want once per row (%d)", jobs, backlog)
	}
}
