//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// TestExecuteFlowJobParallelSQLInTransaction exercises a `parallel:` SQL block
// inside a `transaction: true` flow. *sql.Tx is not safe for concurrent use, so
// the framework's H-4 policy (flowValidateParallelTx + the execStepParallel
// runtime backstop from the security-hardening pass) rejects this combination
// fail-closed. The assertion is that the job errors and commits nothing.
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

	if err := executeFlowJob(app, "parallel_atomic_job", map[string]any{}); err == nil {
		t.Fatal("executeFlowJob: expected rejection of parallel SQL inside a transaction, got nil")
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected parallel transactional job committed %d row(s), want 0", count)
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

// TestJobsLeaseTTLEnvOverride covers the BENMORE_JOB_LEASE_SECONDS knob
// (carried over from the original lease-recovery work): a valid positive value
// overrides the 5m default; absent/invalid/non-positive falls back.
func TestJobsLeaseTTLEnvOverride(t *testing.T) {
	cases := []struct {
		val  string
		want time.Duration
	}{
		{"", defaultJobsLeaseTTL},
		{"30", 30 * time.Second},
		{"0", defaultJobsLeaseTTL},
		{"-5", defaultJobsLeaseTTL},
		{"notanumber", defaultJobsLeaseTTL},
	}
	for _, c := range cases {
		t.Setenv("BENMORE_JOB_LEASE_SECONDS", c.val)
		if got := jobsLeaseTTL(); got != c.want {
			t.Fatalf("BENMORE_JOB_LEASE_SECONDS=%q -> jobsLeaseTTL()=%v, want %v", c.val, got, c.want)
		}
	}
	// The heartbeat interval tracks the (overridden) window at one-third, with
	// a 1s floor so a tiny window can't produce a zero ticker.
	t.Setenv("BENMORE_JOB_LEASE_SECONDS", "30")
	if got := jobsHeartbeatInterval(); got != 10*time.Second {
		t.Fatalf("heartbeat = %v, want 10s (window/3)", got)
	}
	t.Setenv("BENMORE_JOB_LEASE_SECONDS", "1")
	if got := jobsHeartbeatInterval(); got != time.Second {
		t.Fatalf("heartbeat = %v, want 1s floor", got)
	}
}
