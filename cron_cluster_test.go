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

// last_fire only moves forward: a sibling whose clock runs behind cannot
// write an older fire over a newer one (and re-fire an every job early).
func TestPersistCronFireIsMonotonic(t *testing.T) {
	app := newJobsTestApp(t)
	if err := ensureCronStateTable(app); err != nil {
		t.Fatal(err)
	}
	newer := time.Date(2026, 11, 9, 12, 15, 0, 0, time.UTC)
	persistCronFire(app, "digest", newer)
	persistCronFire(app, "digest", newer.Add(-10*time.Minute))
	var got string
	if err := app.DB.QueryRow("SELECT last_fire FROM _benmore_cron_state WHERE job_id = 'digest'").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != newer.Format(time.RFC3339) {
		t.Fatalf("last_fire = %s, want %s", got, newer.Format(time.RFC3339))
	}
}
