//go:build !cli

package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestCronTickEnqueuesDurableJob(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "daily_digest",
		Schedule: "* * * * *",
		Steps:    []FlowStep{{Type: "sql", SQL: "SELECT 1"}},
	}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatalf("ensure cron state: %v", err)
	}
	state := newCronState(app)
	now := time.Date(2026, 6, 19, 12, 34, 45, 0, time.UTC)

	state.tick(app, now)

	var jobType, flowName, status, uniqueKey, payload string
	if err := app.DB.QueryRow(`
		SELECT job_type, flow_name, status, COALESCE(unique_key, ''), payload
		FROM _benmore_jobs
	`).Scan(&jobType, &flowName, &status, &uniqueKey, &payload); err != nil {
		t.Fatalf("query queued cron job: %v", err)
	}
	if jobType != "cron" {
		t.Fatalf("job_type = %q, want cron", jobType)
	}
	if flowName != "daily_digest" {
		t.Fatalf("flow_name = %q, want cron id", flowName)
	}
	if status != "pending" {
		t.Fatalf("status = %q, want pending", status)
	}
	if uniqueKey != "cron:daily_digest:20260619T1234" {
		t.Fatalf("unique_key = %q", uniqueKey)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if data["fired_at"] != "2026-06-19T12:34:00Z" {
		t.Fatalf("fired_at = %#v", data["fired_at"])
	}
}

func TestCronTickUniqueKeyDedupesSameMinuteAfterCrash(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "sync_carriers",
		Schedule: "* * * * *",
		Steps:    []FlowStep{{Type: "sql", SQL: "SELECT 1"}},
	}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatalf("ensure cron state: %v", err)
	}
	now := time.Date(2026, 6, 19, 12, 34, 45, 0, time.UTC)

	first := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	first.tick(app, now)
	// Simulate a crash/restart before _benmore_cron_state was hydrated or
	// persisted. The stable unique key should collapse the duplicate enqueue.
	second := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	second.tick(app, now)

	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("same-minute cron crash replay queued %d jobs, want 1", got)
	}
}

func TestProcessNextJobRunsCronJob(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "daily_digest",
		Schedule: "* * * * *",
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('cron fired')"},
		},
	}}}
	firedAt := time.Date(2026, 6, 19, 12, 34, 0, 0, time.UTC)
	if _, _, err := EnqueueCronJob(app.DB, "daily_digest", cronUniqueKey("daily_digest", firedAt), cronPayload(app.Cron.Jobs[0], firedAt), nil, 1); err != nil {
		t.Fatalf("enqueue cron job: %v", err)
	}

	if !processNextJob(app) {
		t.Fatal("processNextJob did not claim queued cron job")
	}

	var events int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events WHERE name = 'cron fired'").Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != 1 {
		t.Fatalf("cron job inserted %d events, want 1", events)
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
		t.Fatalf("query job status: %v", err)
	}
	if status != "completed" {
		t.Fatalf("job status = %q, want completed", status)
	}
}

// TestCronTickDedupesSameMinuteAfterCompletion covers review finding #1:
// the same-minute crash-replay guard must hold even after the first
// enqueued job has COMPLETED and last_fire was lost. The original
// active-only dedup index permitted a re-enqueue once the prior row left
// pending/running; cron's any-status dedup must still collapse it to one
// fire for the minute.
func TestCronTickDedupesSameMinuteAfterCompletion(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "sync_carriers",
		Schedule: "* * * * *",
		Steps:    []FlowStep{{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('fired')"}},
	}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatalf("ensure cron state: %v", err)
	}
	now := time.Date(2026, 6, 19, 12, 34, 45, 0, time.UTC)

	// First tick enqueues the job; run it to completion via the worker.
	first := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	first.tick(app, now)
	if !processNextJob(app) {
		t.Fatal("processNextJob did not claim queued cron job")
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "completed" {
		t.Fatalf("first job status = %q, want completed", status)
	}

	// Simulate a restart that lost last_fire (empty in-memory map, hydration
	// failed) within the SAME minute. The any-status cron dedup must prevent
	// a second enqueue even though the prior row is already completed.
	second := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	second.tick(app, now)

	if got := countJobs(t, app.DB); got != 1 {
		t.Fatalf("completed-then-replay same-minute queued %d jobs, want 1", got)
	}
	var fires int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&fires); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if fires != 1 {
		t.Fatalf("cron fired %d times for one minute, want 1", fires)
	}
}

// TestCronJobDefaultsToAtMostOnce covers review finding #2: a cron job
// with no max_attempts is enqueued with max_attempts = 1 so a failing
// step is NOT retried (at-most-once), preserving the pre-durable-queue
// behavior for non-idempotent schedules. A failing first attempt should
// land in `failed`, not loop back to `pending`.
func TestCronJobDefaultsToAtMostOnce(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "billing_run",
		Schedule: "* * * * *",
		Steps:    []FlowStep{{Type: "sql", SQL: "INSERT INTO does_not_exist (x) VALUES (1)"}},
	}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatalf("ensure cron state: %v", err)
	}
	now := time.Date(2026, 6, 19, 12, 34, 45, 0, time.UTC)
	state := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	state.tick(app, now)

	var maxAttempts int
	if err := app.DB.QueryRow("SELECT max_attempts FROM _benmore_jobs").Scan(&maxAttempts); err != nil {
		t.Fatalf("query max_attempts: %v", err)
	}
	if maxAttempts != 1 {
		t.Fatalf("max_attempts = %d, want 1 (at-most-once default)", maxAttempts)
	}

	if !processNextJob(app) {
		t.Fatal("processNextJob did not claim cron job")
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "failed" {
		t.Fatalf("status = %q, want failed (no retry at max_attempts=1)", status)
	}
}

// TestCronJobOptsIntoRetries covers review finding #2: setting
// MaxAttempts > 1 opts a cron into at-least-once retries. A failing first
// attempt should go back to `pending` (scheduled for a backoff retry),
// not straight to `failed`.
func TestCronJobOptsIntoRetries(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:          "idempotent_sync",
		Schedule:    "* * * * *",
		MaxAttempts: 3,
		Steps:       []FlowStep{{Type: "sql", SQL: "INSERT INTO does_not_exist (x) VALUES (1)"}},
	}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatalf("ensure cron state: %v", err)
	}
	now := time.Date(2026, 6, 19, 12, 34, 45, 0, time.UTC)
	state := &cronState{lastFire: map[string]time.Time{}, jobs: app.Cron.Jobs}
	state.tick(app, now)

	if !processNextJob(app) {
		t.Fatal("processNextJob did not claim cron job")
	}
	var status string
	var attempts int
	if err := app.DB.QueryRow("SELECT status, attempts FROM _benmore_jobs").Scan(&status, &attempts); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("status = %q, want pending (retry scheduled)", status)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

// TestExecuteCronJobMissingDefinitionIsNoOp covers review finding #3: a
// cron row whose definition was removed/renamed must complete as a no-op
// instead of erroring (which would retry and produce a spurious failed
// row).
func TestExecuteCronJobMissingDefinitionIsNoOp(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{}}
	if err := executeCronJob(app, "vanished_cron", map[string]any{}); err != nil {
		t.Fatalf("executeCronJob for missing definition returned error %v, want nil (terminal no-op)", err)
	}
}

// TestProcessNextJobRunsFlowBackedCron covers the test-coverage gap (c):
// a `flow:`-backed cron resolves and runs the referenced flow's steps
// through the worker, not just inline steps.
func TestProcessNextJobRunsFlowBackedCron(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create events: %v", err)
	}
	app.Flows = []Flow{{
		Name:  "sync_all",
		Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO events (name) VALUES ('flow cron fired')"}},
	}}
	app.Cron = &CronConfig{Jobs: []CronJob{{
		ID:       "sync_carriers",
		Schedule: "* * * * *",
		Flow:     "sync_all",
	}}}
	firedAt := time.Date(2026, 6, 19, 12, 34, 0, 0, time.UTC)
	if _, _, err := EnqueueCronJob(app.DB, "sync_carriers", cronUniqueKey("sync_carriers", firedAt), cronPayload(app.Cron.Jobs[0], firedAt), nil, 1); err != nil {
		t.Fatalf("enqueue flow-backed cron: %v", err)
	}
	if !processNextJob(app) {
		t.Fatal("processNextJob did not claim flow-backed cron job")
	}
	var fires int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM events WHERE name = 'flow cron fired'").Scan(&fires); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if fires != 1 {
		t.Fatalf("flow-backed cron inserted %d events, want 1", fires)
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "completed" {
		t.Fatalf("status = %q, want completed", status)
	}
}

// TestReloadCronConcurrentAccessRace guards the hot-reload data race fix:
// findCronJob reads app.Cron under app.mu.RLock, so reloadAppConfig must
// publish app.Cron under app.mu.Lock (not a bare assignment). This test drives
// concurrent lock-guarded writes (mirroring reloadAppConfig) against concurrent
// findCronJob reads; run under `-race` it fails if either side drops the lock.
func TestReloadCronConcurrentAccessRace(t *testing.T) {
	app := &App{mu: sync.RWMutex{}, Cron: &CronConfig{Jobs: []CronJob{{ID: "a", Schedule: "* * * * *"}}}}
	done := make(chan struct{})
	var wg sync.WaitGroup

	// Readers: concurrent findCronJob (takes app.mu.RLock).
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					findCronJob(app, "a")
				}
			}
		}()
	}
	// Writer: mirror reloadAppConfig's lock-guarded publish of app.Cron.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			cron := &CronConfig{Jobs: []CronJob{{ID: "a", Schedule: "* * * * *"}}}
			app.mu.Lock()
			app.Cron = cron
			app.mu.Unlock()
		}
		close(done)
	}()

	wg.Wait()
}
