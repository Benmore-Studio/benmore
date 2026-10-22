//go:build !cli

package main

import (
	"database/sql"
	"strings"
	"testing"
)

func TestJobWorkerRejectsMalformedPayloadBeforeExecution(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE payload_events(id INTEGER PRIMARY KEY, label TEXT)"); err != nil {
		t.Fatal(err)
	}
	app.Flows = []Flow{{Name: "payload_worker", Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO payload_events(label) VALUES ('executed')"}}}}
	for _, payload := range []string{`not json {`, `[1,2]`, `42`, `"text"`, `{"n":1e999}`} {
		t.Run(payload, func(t *testing.T) {
			res, err := app.DB.Exec("INSERT INTO _benmore_jobs(job_type,flow_name,payload,run_at,max_attempts) VALUES('flow','payload_worker',?,datetime('now','-1 minute'),3)", payload)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := res.LastInsertId()
			if !processNextJob(app) {
				t.Fatal("job not claimed")
			}
			var status, detail string
			var attempts, count int
			var lease sql.NullString
			if err := app.DB.QueryRow("SELECT status, COALESCE(error,''), attempts, lease_expires_at FROM _benmore_jobs WHERE id=?", id).Scan(&status, &detail, &attempts, &lease); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM payload_events").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if status != "failed" || attempts != 1 || lease.Valid || !strings.Contains(detail, "invalid job payload") || count != 0 {
				t.Fatalf("status=%s attempts=%d lease=%v error=%q actions=%d; invalid input must fail once without executing", status, attempts, lease, detail, count)
			}
		})
	}
	// Empty object and nil-map payloads are both produced by the enqueue API.
	// Invalid rows must not stop either valid successor from being executed.
	for _, payload := range []map[string]any{{}, nil, {"label": "valid"}} {
		id, _, err := EnqueueJob(app.DB, "payload_worker", payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !processNextJob(app) {
			t.Fatal("valid successor not claimed")
		}
		var status string
		if err := app.DB.QueryRow("SELECT status FROM _benmore_jobs WHERE id=?", id).Scan(&status); err != nil || status != "completed" {
			t.Fatalf("valid payload status=%s: %v", status, err)
		}
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM payload_events").Scan(&count); err != nil || count != 3 {
		t.Fatalf("valid actions=%d, want 3: %v", count, err)
	}
}
