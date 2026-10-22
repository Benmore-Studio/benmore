//go:build !cli

package main

import (
	"testing"
	"time"
)

// Two schedulers on one database (BENMORE_CLUSTER siblings) tick at
// different offsets. An interval job one of them fired must not fire again
// from the other's stale in-memory last_fire just because its tick landed
// in the next minute (the unique key only dedupes the same minute).
func TestCronIntervalJobFiresOnceAcrossSchedulersSharingADatabase(t *testing.T) {
	app := newJobsTestApp(t)
	app.Cron = &CronConfig{Jobs: []CronJob{{ID: "sync", Schedule: "every 15m", Steps: []FlowStep{{Type: "sql", SQL: "SELECT 1"}}}}}
	if err := ensureCronStateTable(app); err != nil {
		t.Fatal(err)
	}
	a, b := newCronState(app), newCronState(app) // both hydrated before any fire
	t0 := time.Date(2026, 9, 29, 12, 0, 59, 0, time.UTC)
	a.tick(app, t0)
	b.tick(app, t0.Add(6*time.Second)) // 12:01:05, the sibling's next tick
	b.tick(app, t0.Add(10*time.Minute))

	var fires int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'cron'").Scan(&fires)
	if fires != 1 {
		t.Fatalf("interval job fired %d times within one interval across two schedulers", fires)
	}
	b.tick(app, t0.Add(16*time.Minute))
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'cron'").Scan(&fires)
	if fires != 2 {
		t.Fatalf("next interval fire missing: %d fires", fires)
	}
}
