//go:build !cli

package main

import (
	"encoding/json"
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
	if _, _, err := EnqueueCronJob(app.DB, "daily_digest", cronUniqueKey("daily_digest", firedAt), cronPayload(app.Cron.Jobs[0], firedAt), nil); err != nil {
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
