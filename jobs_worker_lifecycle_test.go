//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// blockingJobType registers a job body that signals when it starts and
// returns only when released, so a test can act while a job is in flight.
func blockingJobType(t *testing.T, name string) (started <-chan struct{}, release func()) {
	t.Helper()
	s, r := make(chan struct{}), make(chan struct{})
	testJobExecutors[name] = func(app *App, flowName string, data map[string]any) error {
		close(s)
		<-r
		return nil
	}
	t.Cleanup(func() { delete(testJobExecutors, name) })
	var released bool
	return s, func() {
		if !released {
			released = true
			close(r)
		}
	}
}

func jobStatus(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var status string
	if err := db.QueryRow("SELECT status FROM _benmore_jobs WHERE id = ?", id).Scan(&status); err != nil {
		t.Fatalf("job %d: %v", id, err)
	}
	return status
}

// A hot reload closes the stop generation the worker was started with; the
// old worker still finishes the job it holds. Its lease must keep being
// extended, or the new generation's recovery sweep treats the live job as
// orphaned (fails it, or requeues a rerun-safe one and runs it twice).
func TestJobLeaseHeartbeatOutlivesHotReload(t *testing.T) {
	t.Setenv("BENMORE_JOB_LEASE_SECONDS", "2") // heartbeat every 1s (floor)
	app := newJobsTestApp(t)
	started, release := blockingJobType(t, "test_block_reload")
	defer release()

	id, _, err := enqueueTypedJob(app.DB, "test_block_reload", "", "slow", map[string]any{}, nil, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	StartJobWorker(app)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker never claimed the job")
	}

	// Hot reload: retire the generation the worker and heartbeat started in.
	app.mu.Lock()
	close(app.Stop)
	app.Stop = make(chan struct{})
	app.mu.Unlock()

	time.Sleep(3500 * time.Millisecond) // well past the 2s lease
	jobsRecoverOrphanedJobs(app)
	if got := jobStatus(t, app.DB, id); got != "running" {
		t.Fatalf("live job was recovered as orphaned after a reload: status %q", got)
	}

	release()
	deadline := time.Now().Add(5 * time.Second)
	for jobStatus(t, app.DB, id) != "completed" {
		if time.Now().After(deadline) {
			t.Fatalf("job never completed: %s", jobStatus(t, app.DB, id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A `serve` process's Shutdown must let the job in progress finish and
// record its outcome before closing the database, rather than failing its
// remaining steps and leaving it 'running' for crash recovery to mark failed.
func TestAppShutdownWaitsForInFlightJob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{DB: db, Dir: t.TempDir(), Stop: make(chan struct{}), jobDrainTimeout: 5 * time.Second}
	EnsureJobsTable(db)
	started, release := blockingJobType(t, "test_block_shutdown")
	defer release()

	id, _, err := enqueueTypedJob(db, "test_block_shutdown", "", "slow", map[string]any{}, nil, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	StartJobWorker(app)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker never claimed the job")
	}

	done := make(chan struct{})
	go func() { app.Shutdown(); close(done) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Shutdown closed the database under a running job")
	default:
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("database closed while the job was still running: %v", err)
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not finish after the job returned")
	}

	reopened, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := jobStatus(t, reopened, id); got != "completed" {
		t.Fatalf("job status after graceful shutdown = %q, want completed", got)
	}
}

// Crash recovery requeues rerun-safe jobs only while they have attempts left
// (attempts counts claims). A job whose body kills the worker every time must
// not be claimed and requeued forever.
func TestJobsRecoverOrphanedJobsStopsCrashLoop(t *testing.T) {
	app := newJobsTestApp(t)
	app.Flows = []Flow{{Name: "replayable", Idempotent: true}}
	expired := time.Now().Add(-2 * jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
	insert := func(jobType, flowName string, attempts, max int) int64 {
		res, err := app.DB.Exec(
			"INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, lease_expires_at, run_at, attempts, max_attempts) VALUES (?, ?, '{}', 'running', ?, datetime('now'), ?, ?)",
			jobType, flowName, expired, attempts, max)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	cases := []struct {
		id   int64
		want string
	}{
		{insert("webhook_subscription", "webhook_subscription", 1, 3), "pending"},
		{insert("webhook_subscription", "webhook_subscription", 3, 3), "failed"},
		{insert("flow", "replayable", 2, 3), "pending"},
		{insert("flow", "replayable", 3, 3), "failed"},
		{insert("cron", "nightly", 3, 3), "failed"},
	}
	jobsRecoverOrphanedJobs(app)
	for _, c := range cases {
		if got := jobStatus(t, app.DB, c.id); got != c.want {
			t.Errorf("job %d status = %q, want %q", c.id, got, c.want)
		}
	}
}

// The drain is bounded, and off unless the process opts in: host mode shuts
// an app down while holding the host's app table lock, which a long job must
// never hold for its whole run.
func TestAppShutdownJobDrainIsBounded(t *testing.T) {
	for _, c := range []struct {
		name    string
		timeout time.Duration
	}{{"host mode does not wait", 0}, {"serve waits at most its timeout", 150 * time.Millisecond}} {
		t.Run(c.name, func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
			if err != nil {
				t.Fatal(err)
			}
			app := &App{DB: db, Dir: t.TempDir(), Stop: make(chan struct{}), jobDrainTimeout: c.timeout}
			EnsureJobsTable(db)
			started, release := blockingJobType(t, "test_block_bounded")
			defer release()
			if _, _, err := enqueueTypedJob(db, "test_block_bounded", "", "slow", map[string]any{}, nil, jobEnqueueOpts{}); err != nil {
				t.Fatal(err)
			}
			StartJobWorker(app)
			<-started
			begin := time.Now()
			done := make(chan struct{})
			go func() { app.Shutdown(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Shutdown waited on a job past its drain timeout")
			}
			if elapsed := time.Since(begin); elapsed < c.timeout {
				t.Fatalf("Shutdown returned after %s, before the %s drain window", elapsed, c.timeout)
			}
		})
	}
}
