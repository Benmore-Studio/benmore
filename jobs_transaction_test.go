//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
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

func TestRecoverStaleRunningJobsRetriesBeforeMaxAttempts(t *testing.T) {
	app := newJobsTestApp(t)
	expired := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`
		INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, attempts, max_attempts, lease_expires_at)
		VALUES ('flow', 'stuck', '{}', 'running', 1, 3, ?)
	`, expired); err != nil {
		t.Fatalf("insert stale running job: %v", err)
	}

	recoverStaleRunningJobs(app.DB, time.Now())

	var status, errMsg string
	var lease sql.NullString
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,''), lease_expires_at FROM _benmore_jobs").Scan(&status, &errMsg, &lease); err != nil {
		t.Fatalf("query recovered job: %v", err)
	}
	if status != "pending" {
		t.Fatalf("status = %q, want pending", status)
	}
	if errMsg != "worker lease expired; retrying" {
		t.Fatalf("error = %q", errMsg)
	}
	if lease.Valid {
		t.Fatalf("lease should be cleared, got %q", lease.String)
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
	if errMsg != "worker lease expired after max attempts" {
		t.Fatalf("error = %q", errMsg)
	}
	if lease.Valid {
		t.Fatalf("lease should be cleared, got %q", lease.String)
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
