//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestExecStepEnqueueUsesActiveTransaction(t *testing.T) {
	app := newJobsTestApp(t)

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{},
		Params: map[string]string{},
		Tx:     tx,
	}
	step := &FlowStep{
		Name: "queued",
		Type: "enqueue",
		Enqueue: &FlowEnqueue{
			Flow: "worker",
			With: map[string]string{"source": "transactional"},
		},
	}
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("enqueue in tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 0 {
		t.Fatalf("rolled-back enqueue left %d job(s), want 0", got)
	}

	tx, err = app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx 2: %v", err)
	}
	ctx.Tx = tx
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("enqueue in tx 2: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("committed enqueue produced %d job(s), want 1", got)
	}
}

func TestExecuteFlowJobHonorsTransactionRollback(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "atomic_job",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('before failure')"},
			{Type: "sql", SQL: "INSERT INTO missing_table (name) VALUES ('boom')"},
		},
	}}

	err := executeFlowJob(app, "atomic_job", map[string]any{})
	if err == nil {
		t.Fatal("executeFlowJob should return the failing SQL error")
	}
	var count int
	if scanErr := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); scanErr != nil {
		t.Fatalf("count events: %v", scanErr)
	}
	if count != 0 {
		t.Fatalf("transactional job left %d committed event(s), want 0", count)
	}
}

func TestExecuteFlowJobHonorsTransactionCommit(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "atomic_job",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('committed')"},
		},
	}}

	if err := executeFlowJob(app, "atomic_job", map[string]any{}); err != nil {
		t.Fatalf("executeFlowJob: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Fatalf("transactional job committed %d event(s), want 1", count)
	}
}

// C-1: the exact double-send scenario. A 'flow' job (which may send an email /
// webhook / mutate rows - NOT idempotent) is claimed, the worker dies
// mid-execution leaving it 'running' with an expired lease. Recovery must NOT
// re-queue it (that would risk a second delivery); it must fail CLOSED. attempts
// stays put so it is never re-run, and the lease is cleared so it no longer
// sticks in 'running' forever.
func TestRecoverStaleRunningJobsFailsClosedNonIdempotent(t *testing.T) {
	app := newJobsTestApp(t)
	expired := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at)
		VALUES ('flow', 'send-email', '{}', 'running', 1, 3, ?)
	`, expired); err != nil {
		t.Fatalf("insert stale running job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status, errMsg string
	var attempts int
	var lease sql.NullString
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,''), attempts, lease_expires_at FROM _benmore_jobs").Scan(&status, &errMsg, &attempts, &lease); err != nil {
		t.Fatalf("query recovered job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status = %q, want failed (non-idempotent orphan must NOT be re-queued: double-send risk)", status)
	}
	if !strings.Contains(errMsg, "not re-run to avoid duplicate side effects") {
		t.Fatalf("error = %q, want the C-1 fail-closed reason", errMsg)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (recovery must not consume/advance an attempt by re-running)", attempts)
	}
	if lease.Valid {
		t.Fatalf("lease should be cleared, got %q", lease.String)
	}
}

// The flip side of C-1: a job type explicitly registered as idempotent IS
// re-queued (with backoff) on recovery, because re-running it is safe.
func TestRecoverStaleRunningJobsRequeuesIdempotentType(t *testing.T) {
	jobRerunSafeTypes["idempotent_test"] = true
	defer delete(jobRerunSafeTypes, "idempotent_test")

	app := newJobsTestApp(t)
	expired := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at)
		VALUES ('idempotent_test', 'safe', '{}', 'running', 1, 3, ?)
	`, expired); err != nil {
		t.Fatalf("insert stale idempotent job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status string
	var lease sql.NullString
	if err := app.DB.QueryRow("SELECT status, lease_expires_at FROM _benmore_jobs").Scan(&status, &lease); err != nil {
		t.Fatalf("query recovered job: %v", err)
	}
	if status != "pending" {
		t.Fatalf("status = %q, want pending (idempotent type should be re-queued)", status)
	}
	if lease.Valid {
		t.Fatalf("lease should be cleared on re-queue, got %q", lease.String)
	}
}

func TestRecoverStaleRunningJobsFailsAtMaxAttempts(t *testing.T) {
	app := newJobsTestApp(t)
	expired := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at)
		VALUES ('flow', 'stuck', '{}', 'running', 3, 3, ?)
	`, expired); err != nil {
		t.Fatalf("insert stale max-attempt job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status, errMsg string
	var lease sql.NullString
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,''), lease_expires_at FROM _benmore_jobs").Scan(&status, &errMsg, &lease); err != nil {
		t.Fatalf("query recovered job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status = %q, want failed", status)
	}
	if !strings.Contains(errMsg, "not re-run to avoid duplicate side effects") {
		t.Fatalf("error = %q, want the C-1 fail-closed reason", errMsg)
	}
	if lease.Valid {
		t.Fatalf("lease should be cleared, got %q", lease.String)
	}
}

func TestEnqueueJobUniqueReturnsExistingActiveJob(t *testing.T) {
	app := newJobsTestApp(t)
	firstID, firstToken, err := EnqueueJobUnique(app.DB, "report:42", "report", map[string]any{"id": 42}, nil)
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	secondID, secondToken, err := EnqueueJobUnique(app.DB, "report:42", "report", map[string]any{"id": 42}, nil)
	if err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	if secondID != firstID {
		t.Fatalf("second enqueue id = %d, want existing %d", secondID, firstID)
	}
	if secondToken != firstToken {
		t.Fatalf("second enqueue token = %q, want existing %q", secondToken, firstToken)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("unique active enqueue inserted %d jobs, want 1", got)
	}
}

func TestEnqueueJobUniqueAllowsNewJobAfterCompletion(t *testing.T) {
	app := newJobsTestApp(t)
	firstID, _, err := EnqueueJobUnique(app.DB, "report:42", "report", map[string]any{"id": 42}, nil)
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := app.DB.Exec("UPDATE _benmore_jobs SET status = 'completed' WHERE id = ?", firstID); err != nil {
		t.Fatalf("complete first job: %v", err)
	}
	secondID, _, err := EnqueueJobUnique(app.DB, "report:42", "report", map[string]any{"id": 42}, nil)
	if err != nil {
		t.Fatalf("second enqueue after completion: %v", err)
	}
	if secondID == firstID {
		t.Fatalf("completed job should not block a new unique enqueue")
	}
	if got := countJobs(t, app.DB); got != 2 {
		t.Fatalf("expected 2 total jobs after completed re-enqueue, got %d", got)
	}
}

func TestExecStepEnqueueUsesUniqueKey(t *testing.T) {
	app := newJobsTestApp(t)
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"user_id": 42},
		Params: map[string]string{},
	}
	step := &FlowStep{
		Name: "queued",
		Type: "enqueue",
		Enqueue: &FlowEnqueue{
			Flow:      "worker",
			With:      map[string]string{"source": "unique"},
			UniqueKey: "worker:${{ user_id }}",
		},
	}
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("first enqueue step: %v", err)
	}
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatalf("second enqueue step: %v", err)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("unique enqueue step inserted %d jobs, want 1", got)
	}
}

// TestEnqueueJobUniqueConcurrentSameKey enqueues the same key from many
// goroutines at once. Exactly one row must be inserted and no goroutine may see
// an error - this is the race the partial UNIQUE index + constraint-violation
// recovery exist to handle.
func TestEnqueueJobUniqueConcurrentSameKey(t *testing.T) {
	app := newWALJobsTestApp(t)
	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := EnqueueJobUnique(app.DB, "report:concurrent", "report", map[string]any{"id": 1}, nil)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent unique enqueue returned error: %v", err)
		}
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("concurrent unique enqueue inserted %d jobs, want 1", got)
	}
}

// TestEnqueueJobTxUniqueDedupesWithinTx exercises the transactional dedup path:
// two enqueues of the same key inside one *sql.Tx must collapse to a single row
// and return the existing job id, not surface a constraint error.
func TestEnqueueJobTxUniqueDedupesWithinTx(t *testing.T) {
	app := newJobsTestApp(t)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	firstID, firstToken, err := EnqueueJobTxUnique(tx, "report:tx", "report", map[string]any{"id": 1}, nil)
	if err != nil {
		t.Fatalf("first tx enqueue: %v", err)
	}
	secondID, secondToken, err := EnqueueJobTxUnique(tx, "report:tx", "report", map[string]any{"id": 1}, nil)
	if err != nil {
		t.Fatalf("second tx enqueue: %v", err)
	}
	if secondID != firstID || secondToken != firstToken {
		t.Fatalf("second tx enqueue = (%d,%q), want existing (%d,%q)", secondID, secondToken, firstID, firstToken)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("tx unique enqueue inserted %d jobs, want 1", got)
	}
}

// TestEnqueueJobTxUniqueCompetingTransactions exercises the cross-transaction
// collision: a competing enqueue commits the winning row for the key, then a
// transactional enqueue races the same key. The transactional enqueue must NOT
// surface a hard error to the flow and must leave exactly one row - whether it
// recovers the winner's id (when the row is visible) or treats the UNIQUE
// collision as an idempotent no-op (when the winner is invisible to the Tx
// snapshot).
//
// MaxOpenConns(1) pins the competitor and the Tx to one SQLite connection so
// the test deterministically reaches the constraint-violation recovery path
// instead of a flaky snapshot-busy ("database is locked") error that SQLite
// raises when a write-upgrading Tx detects another connection wrote after its
// read snapshot. (That snapshot-busy case is a retry-the-transaction condition,
// distinct from the UNIQUE collision this fix handles.)
func TestEnqueueJobTxUniqueCompetingTransactions(t *testing.T) {
	app := newWALJobsTestApp(t)
	app.DB.SetMaxOpenConns(1)

	// The competing enqueue commits the winning row first.
	winnerID, _, err := EnqueueJobUnique(app.DB, "report:race", "report", map[string]any{"id": 1}, nil)
	if err != nil {
		t.Fatalf("competitor enqueue: %v", err)
	}

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	// The transactional enqueue races the same active key. It must be a no-op
	// for the flow (no error) - either returning the winner's id or an
	// idempotent zero id - never a propagated UNIQUE-constraint failure.
	id, _, err := EnqueueJobTxUnique(tx, "report:race", "report", map[string]any{"id": 1}, nil)
	if err != nil {
		t.Fatalf("racing tx enqueue should be an idempotent no-op, got error: %v", err)
	}
	if id != 0 && id != winnerID {
		t.Fatalf("racing tx enqueue returned id %d; want 0 (no-op) or winner %d", id, winnerID)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("competing-transaction unique enqueue left %d jobs, want 1", got)
	}
}

// newWALJobsTestApp opens the jobs DB in WAL mode with a busy_timeout. WAL lets
// a competing connection commit a write while another connection holds an open
// read snapshot; busy_timeout lets concurrent writers serialize so the loser of
// a unique_key race observes the UNIQUE-constraint collision (the path under
// test) instead of a transient "database is locked".
func newWALJobsTestApp(t *testing.T) *App {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jobs.db")
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", path))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	EnsureJobsTable(db)
	return &App{DB: db, Dir: t.TempDir(), Stop: make(chan struct{})}
}

// A future (non-expired) lease is the core guard: recovery must leave such a
// running job completely untouched.
func TestRecoverStaleRunningJobsLeavesNonExpiredLeaseUntouched(t *testing.T) {
	app := newJobsTestApp(t)
	future := time.Now().Add(time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at, lease_owner)
		VALUES ('flow', 'live', '{}', 'running', 1, 3, ?, 'owner-A')
	`, future); err != nil {
		t.Fatalf("insert live running job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status string
	var owner sql.NullString
	if err := app.DB.QueryRow("SELECT status, lease_owner FROM _benmore_jobs").Scan(&status, &owner); err != nil {
		t.Fatalf("query job: %v", err)
	}
	if status != "running" {
		t.Fatalf("status = %q, want running (non-expired lease must not be recovered)", status)
	}
	if !owner.Valid || owner.String != "owner-A" {
		t.Fatalf("lease_owner = %v, want owner-A (untouched)", owner)
	}
}

// A NULL-lease running row (old schema / fresh claim mid-flight) must not be
// recovered: the IS NOT NULL guard protects it.
func TestRecoverStaleRunningJobsLeavesNullLeaseUntouched(t *testing.T) {
	app := newJobsTestApp(t)
	// The migration backfill in EnsureJobsTable only runs at table-creation
	// time, so insert the NULL-lease row afterwards to model a fresh mid-flight
	// claim that hasn't stamped a lease yet.
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at)
		VALUES ('flow', 'fresh', '{}', 'running', 1, 3, NULL)
	`); err != nil {
		t.Fatalf("insert null-lease running job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
		t.Fatalf("query job: %v", err)
	}
	if status != "running" {
		t.Fatalf("status = %q, want running (NULL lease must not be recovered)", status)
	}
}

// The recovery retry path (idempotent types only) must apply the same
// exponential backoff as a normal failure (finding #2), so a crash-looping job
// is not re-queued for immediate pickup. attempts=1 -> backoff = 1<<1 * 30s = 60s.
func TestRecoverStaleRunningJobsAppliesBackoff(t *testing.T) {
	jobRerunSafeTypes["idempotent_test"] = true
	defer delete(jobRerunSafeTypes, "idempotent_test")

	app := newJobsTestApp(t)
	expired := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at, lease_owner)
		VALUES ('idempotent_test', 'crashloop', '{}', 'running', 1, 3, ?, 'owner-A')
	`, expired); err != nil {
		t.Fatalf("insert stale job: %v", err)
	}

	now := time.Now()
	recoverStaleRunningJobs(app.DB, now)

	// The go-sqlite3 driver auto-parses DATETIME columns into time.Time, so
	// scan directly into a time value rather than the raw text.
	var runAt time.Time
	if err := app.DB.QueryRow("SELECT run_at FROM _benmore_jobs").Scan(&runAt); err != nil {
		t.Fatalf("query run_at: %v", err)
	}
	// Expected: now + recoveryBackoff(1) = now + 60s. Allow a few seconds of
	// slack for the now->SQL round-trip (both truncated to whole seconds).
	wantDelay := recoveryBackoff(1)
	gotDelay := runAt.UTC().Sub(now.UTC().Truncate(time.Second))
	if gotDelay < wantDelay-2*time.Second || gotDelay > wantDelay+2*time.Second {
		t.Fatalf("recovery run_at delay = %v, want ~%v (no backoff applied?)", gotDelay, wantDelay)
	}
}

// The claim path in processNextJob must stamp lease_expires_at and lease_owner
// while the job runs. A `sql` step executes *during* the job, so it can snapshot
// the job's own row mid-flight into a side table for a deterministic assertion
// (no blocking/goroutine racing needed). On completion the lease is cleared.
func TestProcessNextJobSetsLease(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE lease_probe (lease TEXT, owner TEXT, status TEXT)"); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	app.Flows = []Flow{{
		Name: "probe_lease",
		Steps: []FlowStep{{
			Type: "sql",
			SQL:  "INSERT INTO lease_probe (lease, owner, status) SELECT COALESCE(lease_expires_at,''), COALESCE(lease_owner,''), status FROM _benmore_jobs WHERE flow_name = 'probe_lease'",
		}},
	}}
	if _, _, err := EnqueueJob(app.DB, "probe_lease", map[string]any{}, nil); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if !processNextJob(app) {
		t.Fatal("processNextJob returned false for a claimed job")
	}

	// Mid-flight snapshot: the job was 'running' with a lease + owner stamped.
	var lease, owner, status string
	if err := app.DB.QueryRow("SELECT lease, owner, status FROM lease_probe").Scan(&lease, &owner, &status); err != nil {
		t.Fatalf("query probe: %v", err)
	}
	if status != "running" {
		t.Fatalf("mid-flight status = %q, want running", status)
	}
	if lease == "" {
		t.Fatal("lease_expires_at was not set on claim")
	}
	if owner == "" {
		t.Fatal("lease_owner was not set on claim")
	}

	// On completion the lease + owner are cleared.
	var finalStatus string
	var leaseAfter, ownerAfter sql.NullString
	if err := app.DB.QueryRow("SELECT status, lease_expires_at, lease_owner FROM _benmore_jobs WHERE flow_name = 'probe_lease'").Scan(&finalStatus, &leaseAfter, &ownerAfter); err != nil {
		t.Fatalf("query completed job: %v", err)
	}
	if finalStatus != "completed" {
		t.Fatalf("status = %q, want completed", finalStatus)
	}
	if leaseAfter.Valid || ownerAfter.Valid {
		t.Fatalf("lease/owner should be cleared after completion, got lease=%v owner=%v", leaseAfter, ownerAfter)
	}
}

// Finding #1: a live long-running worker must not have its job reclaimed. The
// protection is the heartbeat pushing the lease forward. This test drives the
// real startLeaseHeartbeat against a near-expired lease and asserts (a) the
// lease is renewed into the future and (b) a concurrent recovery sweep is then
// a no-op, leaving the job 'running'. Uses a short lease window via the env
// override so the heartbeat (window/3) fires quickly and the test stays fast.
func TestLeaseHeartbeatPreventsReclaim(t *testing.T) {
	app := newJobsTestApp(t)
	t.Setenv("BENMORE_JOB_LEASE_SECONDS", "6") // heartbeat every 2s

	// A job claimed by owner-A whose lease expires in 4s. The first heartbeat
	// (at ~2s) renews it to ~now+6s, comfortably past the original 4s expiry, so
	// a recovery sweep after t=4s must still see a live (future) lease. The
	// generous margins keep the second-granularity SQLite datetime comparison
	// from making this flaky.
	nearExpiry := time.Now().Add(4 * time.Second).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at, lease_owner)
		VALUES ('flow', 'longrun', '{}', 'running', 1, 3, ?, 'owner-A')
	`, nearExpiry); err != nil {
		t.Fatalf("insert running job: %v", err)
	}
	var id int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_jobs").Scan(&id); err != nil {
		t.Fatalf("scan id: %v", err)
	}

	stop := startLeaseHeartbeat(app, id, "owner-A", jobLeaseDurationFor())
	defer stop()

	// Run sweeps until comfortably past the original 5s expiry; the heartbeat
	// must have renewed the lease for the job to survive.
	origExpiry, _ := time.Parse(sqliteDateTimeLayout, nearExpiry)
	deadline := time.Now().Add(6 * time.Second)
	var renewed bool
	for time.Now().Before(deadline) {
		recoverStaleRunningJobs(app.DB, time.Now())
		var status string
		var lease time.Time
		if err := app.DB.QueryRow("SELECT status, lease_expires_at FROM _benmore_jobs").Scan(&status, &lease); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if status != "running" {
			t.Fatalf("live job reclaimed despite active heartbeat: status=%q", status)
		}
		// Renewal is proven by the lease moving strictly past its original
		// expiry - something only the heartbeat does.
		if lease.UTC().After(origExpiry.Add(time.Second)) {
			renewed = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !renewed {
		t.Fatal("heartbeat never renewed the lease past its original expiry")
	}

	// Once the owner stops heartbeating, the lease eventually lapses and
	// recovery reclaims the job - proving recovery still works when the owner
	// is genuinely gone. This 'flow' job is non-idempotent, so C-1 fail-closed
	// recovery moves it to 'failed' (not 'pending') - it is reclaimed out of the
	// stuck 'running' state without risking a duplicate re-run.
	stop()
	// The last heartbeat pushed the lease to ~now+9s (the window), so allow a
	// little over a full window for it to lapse and recovery to reclaim.
	reclaimDeadline := time.Now().Add(9 * time.Second)
	for time.Now().Before(reclaimDeadline) {
		recoverStaleRunningJobs(app.DB, time.Now())
		var status string
		if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if status == "failed" {
			return // reclaimed (fail-closed) as expected
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("job was never reclaimed after the owner stopped heartbeating")
}

// TestExecuteFlowJobParallelSQLInTransaction exercises the combination a
// `parallel:` SQL block inside a `transaction: true` flow. *sql.Tx is not
// safe for concurrent use, so without serialization (FlowContext.TxMu) the
// fan-out goroutines race on the shared transaction. Run under `-race` to
// catch the data race; the functional assertion is that every branch's
// write commits exactly once.
func TestExecuteFlowJobParallelSQLInTransaction(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "parallel_atomic_job",
		Transaction: true,
		Steps: []FlowStep{{
			Type: "parallel",
			Steps: []FlowStep{
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('a')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('b')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('c')"},
				{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('d')"},
			},
		}},
	}}

	if err := executeFlowJob(app, "parallel_atomic_job", map[string]any{}); err != nil {
		t.Fatalf("executeFlowJob: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 4 {
		t.Fatalf("parallel transactional job committed %d row(s), want 4", count)
	}
}

// TestJobStatusEndpointRequiresToken locks in the server-side contract the
// SDK status_url fix depends on the public /api/_jobs/{id}/status endpoint
// returns 404 for an anonymous caller WITHOUT the capability token and 200
// WITH it. Before the SDK fix, the handle polled the bare (token-less) path
// and always got 404 for non-admin callers.
func TestJobStatusEndpointRequiresToken(t *testing.T) {
	app := newJobsTestApp(t)
	mux := http.NewServeMux()
	RegisterJobsAPI(mux, app)

	id, token, err := EnqueueJob(app.DB, "worker", map[string]any{"k": "v"}, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty status token")
	}

	// Without the token an anonymous caller must not be able to read status.
	reqNoToken := httptest.NewRequest("GET", fmt.Sprintf("/api/_jobs/%d/status", id), nil)
	recNoToken := httptest.NewRecorder()
	mux.ServeHTTP(recNoToken, reqNoToken)
	if recNoToken.Code != http.StatusNotFound {
		t.Fatalf("status without token = %d, want 404", recNoToken.Code)
	}

	// With the tokenized status_url the same caller gets the job status.
	reqToken := httptest.NewRequest("GET", fmt.Sprintf("/api/_jobs/%d/status?token=%s", id, token), nil)
	recToken := httptest.NewRecorder()
	mux.ServeHTTP(recToken, reqToken)
	if recToken.Code != http.StatusOK {
		t.Fatalf("status with token = %d, want 200", recToken.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recToken.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	if got, _ := body["job_id"].(float64); int64(got) != id {
		t.Fatalf("status body job_id = %v, want %d", body["job_id"], id)
	}
}

func newJobsTestApp(t *testing.T) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	EnsureJobsTable(db)
	return &App{DB: db, Dir: t.TempDir(), Stop: make(chan struct{})}
}

func countJobs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM _benmore_jobs").Scan(&count); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return count
}
