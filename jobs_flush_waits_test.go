//go:build !cli

package main

import (
	"testing"
	"time"
)

// A job the app's own worker claimed before a flush could is finished when
// the flush returns. FlushJobs used to find nothing left to claim and return
// while that job was still running, so a test that asserted right after
// `flush: jobs` now and then saw the state from before the job: a task
// recipe test read its notify job as "running", and a fixture app's test
// counted 0 rows where the job writes 1.
func TestFlushJobsWaitsForAJobTheWorkerIsRunning(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)
	started, release := blockingJobType(t, "flush_waits_block")
	defer release()
	id, _, err := enqueueTypedJob(app.DB, "flush_waits_block", "", "stage", nil, nil, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// The worker: another goroutine claims the job and runs it.
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		processNextJob(app)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not start the job")
	}

	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		FlushJobs(app)
	}()
	select {
	case <-flushed:
		t.Fatalf("FlushJobs returned while the worker's job was still %s", jobStatus(t, app.DB, id))
	case <-time.After(200 * time.Millisecond):
	}
	release()
	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("FlushJobs did not return after the worker's job finished")
	}
	if got := jobStatus(t, app.DB, id); got != jobStatusCompleted {
		t.Fatalf("after the flush the job is %s, want %s", got, jobStatusCompleted)
	}
	<-workerDone
}

// A flush does not wait for ever: past its deadline it returns although the
// worker is still inside a job, and with nothing running it returns at once.
func TestFlushJobsGivesUpOnAWorkerThatDoesNotFinish(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureJobsTable(app.DB)

	begin := time.Now()
	FlushJobs(app)
	if idle := time.Since(begin); idle > 2*time.Second {
		t.Fatalf("a flush of an idle app took %s", idle)
	}

	previous := flushWorkerWait
	flushWorkerWait = 150 * time.Millisecond
	t.Cleanup(func() { flushWorkerWait = previous })
	started, release := blockingJobType(t, "flush_gives_up_block")
	if _, _, err := enqueueTypedJob(app.DB, "flush_gives_up_block", "", "stage", nil, nil, jobEnqueueOpts{}); err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		processNextJob(app)
	}()
	<-started
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		FlushJobs(app)
	}()
	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("FlushJobs kept waiting past its deadline for a job that does not finish")
	}
	release()
	<-workerDone
}
