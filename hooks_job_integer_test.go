//go:build !cli

package main

import (
	"testing"
)

// A queued hook binds a row's integers as integers. The job payload is JSON,
// which the worker decodes as float64, so an on_insert hook (always a job) used
// to store `target = "4.0"` and render 'Invoice #4.0 ...' for row id 4, while
// the same SQL in an on_update hook (run in the write transaction) gave "4".
// A REAL column keeps its float, as it does inline.
func TestHookJobBindsRowIntegersAsIntegers(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE invoices (id INTEGER PRIMARY KEY, amount_cents INTEGER, rate REAL, user_id INTEGER)")
	mustExec(t, app.DB, "CREATE TABLE outbound_logs (target TEXT, detail TEXT, rate_text TEXT, owner TEXT)")
	cols, err := GetTableColumns(app.DB, "invoices")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "invoices", Columns: cols}}

	hook := Hook{SQL: "INSERT INTO outbound_logs (target, detail, rate_text, owner) VALUES ({{id}}, 'Invoice #{{id}} for {{amount_cents}} cents', 'rate {{rate}}', {{user_id}})"}
	// The row as auto-CRUD's create hands it to FireHooks: request values,
	// the new id and the session's user id.
	EnqueueHookJob(app, hook, "invoices", map[string]any{
		"id": int64(4), "amount_cents": "1250", "rate": float64(2), "user_id": int64(7),
	})
	FlushJobs(app)

	var status, jobErr string
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("hook job %s: %s", status, jobErr)
	}
	var target, detail, rateText, owner string
	if err := app.DB.QueryRow("SELECT target, detail, rate_text, owner FROM outbound_logs").Scan(&target, &detail, &rateText, &owner); err != nil {
		t.Fatal(err)
	}
	if target != "4" || detail != "Invoice #4 for 1250 cents" || owner != "7" {
		t.Fatalf("hook stored target=%q detail=%q owner=%q, want 4 / Invoice #4 for 1250 cents / 7", target, detail, owner)
	}
	if rateText != "rate 2.0" {
		t.Fatalf("REAL column rendered %q, want %q as inline", rateText, "rate 2.0")
	}
}
