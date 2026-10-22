//go:build !cli

package main

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitForJobStatus(t *testing.T, app *App, id int64, want string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for jobStatus(t, app.DB, id) != want {
		select {
		case <-timer.C:
			t.Fatalf("job %d status=%s want=%s", id, jobStatus(t, app.DB, id), want)
		case <-ticker.C:
		}
	}
}

func TestJobOrderingSurvivesActualHotReload(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	EnsureJobsTable(app.DB)
	started, release := blockingJobType(t, "ordering_reload_block")
	defer func() { release(); app.Shutdown() }()
	testJobExecutors["ordering_reload_marker"] = func(*App, string, map[string]any) error { return nil }
	t.Cleanup(func() { delete(testJobExecutors, "ordering_reload_marker") })
	enqueue := func(kind string, group map[string]any, ago time.Duration) int64 {
		t.Helper()
		at := time.Now().Add(-ago)
		id, _, err := enqueueTypedJob(app.DB, kind, "", "stage", group, &at, jobEnqueueOpts{})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := enqueue("ordering_reload_block", map[string]any{"project_id": 1}, 40*time.Second)
	b := enqueue("ordering_reload_marker", map[string]any{"project_id": 1}, 30*time.Second)
	c := enqueue("ordering_reload_marker", map[string]any{"project_id": 2}, 20*time.Second)
	d := enqueue("ordering_reload_marker", nil, 10*time.Second)
	StartJobWorker(app)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first worker never started A")
	}
	previous := hostedHotHandler
	hostedHotHandler = &hotHandler{}
	hostedHotHandler.swap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer func() { hostedHotHandler = previous }()
	writeTestFile(t, app.Dir, "app.yaml", "theme: default\n")
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	waitForJobStatus(t, app, c, "completed")
	waitForJobStatus(t, app, d, "completed")
	if got := jobStatus(t, app.DB, a); got != "running" {
		t.Fatalf("A stopped before release: %s", got)
	}
	if got := jobStatus(t, app.DB, b); got != "pending" {
		t.Fatalf("same-project B overtook running A after reload: %s", got)
	}
	release()
	waitForJobStatus(t, app, a, "completed")
	waitForJobStatus(t, app, b, "completed")
}

func TestJobRunningGateWaitsForLeaseRecoveryTransition(t *testing.T) {
	app := setupOrderingApp(t)
	aTime, bTime := time.Now().Add(-20*time.Second), time.Now().Add(-10*time.Second)
	a, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_a", map[string]any{"project_id": 1}, &aTime, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := enqueueTypedJob(app.DB, "flow", "", "stage_b", map[string]any{"project_id": 1}, &bTime, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_jobs SET status='running', attempts=1, lease_expires_at=datetime('now','-1 hour') WHERE id=?`, a); err != nil {
		t.Fatal(err)
	}
	if processNextJob(app) {
		t.Fatal("expired lease bypassed a still-running predecessor before recovery")
	}
	FlushJobs(app)
	if jobStatus(t, app.DB, b) != "pending" {
		t.Fatal("test drain bypassed a still-running predecessor")
	}
	jobsRecoverOrphanedJobs(app)
	if jobStatus(t, app.DB, a) != "failed" {
		t.Fatal("non-idempotent predecessor was not failed closed")
	}
	if !processNextJob(app) {
		t.Fatal("terminal predecessor did not unblock B")
	}
}

func TestOrderedClaimSerializesConcurrentWorkers(t *testing.T) {
	app := newJobsTestApp(t)
	const workers = 8
	var calls atomic.Int32
	started, gate := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var wg sync.WaitGroup
	testJobExecutors["ordering_concurrent"] = func(*App, string, map[string]any) error {
		if calls.Add(1) == 1 {
			close(started)
			<-gate
		}
		return nil
	}
	t.Cleanup(func() { delete(testJobExecutors, "ordering_concurrent") })
	defer func() { unblock.Do(func() { close(gate) }); wg.Wait() }()
	at := time.Now().Add(-time.Minute)
	for i := 0; i < workers; i++ {
		if _, _, err := enqueueTypedJob(app.DB, "ordering_concurrent", "", "stage", map[string]any{"project_id": 1}, &at, jobEnqueueOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- processNextJob(app) }()
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no claim started")
	}
	for i := 0; i < workers-1; i++ {
		select {
		case <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("competing claim did not finish")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("started %d same-project jobs while the first remained running", got)
	}
	unblock.Do(func() { close(gate) })
	wg.Wait()
	FlushJobs(app)
	var completed int
	if err := app.DB.QueryRow(`SELECT count(*) FROM _benmore_jobs WHERE status='completed' AND attempts=1`).Scan(&completed); err != nil || completed != workers {
		t.Fatalf("completed once=%d want=%d err=%v", completed, workers, err)
	}
}
