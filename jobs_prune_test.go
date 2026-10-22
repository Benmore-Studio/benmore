//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Failed jobs were kept forever: CleanOldJobs pruned only completed jobs
// after 7 days, so every failed job (and its payload, which holds the whole
// written row or the flow's enqueue values) stayed in data.db indefinitely.
// Failed jobs now go after 30 days, except a connector-command effect: its
// row is the only evidence of the effect's outcome (operation status reads
// it, and push reconciliation reads a failed transfer job).
func TestPruneOldJobsRemovesStaleFailedJobs(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	EnsureJobsTable(db)
	insert := func(name, jobType, status, payload, completed, created string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO _benmore_jobs (job_type, flow_name, payload, status, completed_at, created_at) VALUES (?, ?, ?, ?, `+completed+`, `+created+`)`, jobType, name, payload, status); err != nil {
			t.Fatal(err)
		}
	}
	const old, recent, now = "datetime('now', '-31 days')", "datetime('now', '-29 days')", "datetime('now')"
	insert("failed-old", "flow", "failed", `{"user_id":1}`, old, old)
	insert("failed-old-no-completed", "hook", "failed", `{}`, "NULL", old)
	insert("failed-recent", "flow", "failed", `{}`, recent, recent)
	insert("failed-effect", "hook", "failed", `{"_mcp_effect":{"operation_id":"x"}}`, old, old)
	insert("failed-transfer", appMCPTransferJobType, "failed", `not json`, old, old)
	insert("completed-old", "flow", "completed", `{}`, "datetime('now', '-8 days')", old)
	insert("completed-recent", "flow", "completed", `{}`, now, now)
	insert("pending-old", "flow", "pending", `{}`, "NULL", old)

	pruneOldJobs(db)

	rows, err := QueryRows(db, "SELECT flow_name FROM _benmore_jobs ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, r := range rows {
		kept = append(kept, r["flow_name"].(string))
	}
	want := []string{"failed-recent", "failed-effect", "failed-transfer", "completed-recent", "pending-old"}
	if len(kept) != len(want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	for i := range want {
		if kept[i] != want[i] {
			t.Fatalf("kept %v, want %v", kept, want)
		}
	}
}
