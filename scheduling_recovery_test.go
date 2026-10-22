//go:build !cli

package main

import (
	"testing"
	"time"
)

// An orphaned task is put back a bounded number of times: one whose run
// kills the worker every time is failed instead of re-fired forever.
func TestScheduledTaskRecoveryStopsCrashLoop(t *testing.T) {
	app, _ := auditApp(t)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(id,user_id,kind,run_at,status,claimed_at,recoveries) VALUES (1,1,'reminder',?,'running','2000-01-01T00:00:00Z',0)", future)
	auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(id,user_id,kind,run_at,status,claimed_at,recoveries) VALUES (2,1,'reminder',?,'running','2000-01-01T00:00:00Z',?)", future, schedTaskMaxRecoveries)
	sweepScheduledTasks(app)

	var status string
	var recoveries int
	app.DB.QueryRow("SELECT status, recoveries FROM _benmore_scheduled_tasks WHERE id=1").Scan(&status, &recoveries)
	if status != "pending" || recoveries != 1 {
		t.Fatalf("first orphan: status=%s recoveries=%d, want pending/1", status, recoveries)
	}
	var reason string
	app.DB.QueryRow("SELECT status, last_error FROM _benmore_scheduled_tasks WHERE id=2").Scan(&status, &reason)
	if status != "failed" || reason == "" {
		t.Fatalf("repeatedly orphaned task: status=%s last_error=%q, want failed", status, reason)
	}
}

// A task still running (a slow scheduled flow) keeps its claim fresh, so a
// sweeper started by a hot reload does not take it for an orphan and fire
// it a second time.
func TestScheduledTaskHeartbeatKeepsLiveClaim(t *testing.T) {
	old := schedTaskHeartbeatInterval
	schedTaskHeartbeatInterval = 20 * time.Millisecond
	t.Cleanup(func() { schedTaskHeartbeatInterval = old })
	app, _ := auditApp(t)
	stale := time.Now().Add(-2 * schedTaskRecoveryTTL).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(id,user_id,kind,flow,run_at,status,claimed_at) VALUES (7,1,'flow','slow',?,'running',?)", future, stale)

	stop := startScheduledTaskHeartbeat(app, int64(7))
	time.Sleep(150 * time.Millisecond)
	sweepScheduledTasks(app) // the other generation's sweep
	stop()

	var status string
	app.DB.QueryRow("SELECT status FROM _benmore_scheduled_tasks WHERE id=7").Scan(&status)
	if status != "running" {
		t.Fatalf("live task was recovered as an orphan: status %q", status)
	}
}
