//go:build !cli

package main

import (
	"strings"
	"testing"
	"time"
)

// The claim's ordering-gate probe is an index seek on the candidate's
// project, not a walk over every backing-off row.
func TestJobClaimProbeUsesProjectIndex(t *testing.T) {
	app := newJobsTestApp(t)
	plan := queryPlan(t, app.DB, jobClaimSQL)
	if !strings.Contains(plan, "idx_jobs_backoff_project") {
		t.Fatalf("claim NOT EXISTS does not use the project index:\n%s", plan)
	}
	if !strings.Contains(plan, "idx_jobs_running_project") {
		t.Fatalf("running-group exclusion does not use the project index:\n%s", plan)
	}
	// Idempotent across restarts.
	EnsureJobsTable(app.DB)
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_jobs_backoff_project'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index count = %d (%v)", n, err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_jobs_running_project'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("running index count = %d (%v)", n, err)
	}
}

// A malformed payload can neither fail the UPDATE that moves its row into
// backoff (index maintenance) nor break the claim for everyone else.
func TestJobClaimToleratesMalformedPayload(t *testing.T) {
	app := newJobsTestApp(t)
	past := time.Now().Add(-time.Minute).UTC().Format(sqliteDateTimeLayout)
	future := time.Now().Add(time.Hour).UTC().Format(sqliteDateTimeLayout)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('flow', 'broken', 'not json {', ?)`, past); err != nil {
		t.Fatal(err)
	}
	// Moving the malformed row into backoff puts it under the partial index.
	if _, err := app.DB.Exec(`UPDATE _benmore_jobs SET not_before = ? WHERE flow_name = 'broken'`, future); err != nil {
		t.Fatalf("backoff update on malformed payload failed: %v", err)
	}
	later := time.Now().Add(-30 * time.Second)
	if _, _, err := enqueueTypedJob(app.DB, "flow", "", "next", map[string]any{"project_id": 3}, &later, jobEnqueueOpts{}); err != nil {
		t.Fatal(err)
	}
	var flow string
	if err := app.DB.QueryRow(jobClaimSQL).Scan(new(int64), new(string), &flow, new(string), new(int), new(int)); err != nil {
		t.Fatalf("claim query failed with a malformed payload in backoff: %v", err)
	}
	if flow != "next" {
		t.Fatalf("claimed %q, want next", flow)
	}

	// Same-project gating is unchanged: an earlier project-3 job in backoff
	// gates the later project-3 job.
	earlier := time.Now().Add(-50 * time.Second)
	id, _, err := enqueueTypedJob(app.DB, "flow", "", "head", map[string]any{"project_id": 3}, &earlier, jobEnqueueOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_jobs SET not_before = ? WHERE id = ?`, future, id); err != nil {
		t.Fatal(err)
	}
	err = app.DB.QueryRow(jobClaimSQL).Scan(new(int64), new(string), &flow, new(string), new(int), new(int))
	if err == nil {
		t.Fatalf("claimed %q although its project's earlier job is backing off", flow)
	}
}
