//go:build !cli

package main

import "testing"

// TestRunCronJobRollsBackTransactionalFlow is the regression for review
// finding #2: the cron applier path (`flow: apply_facts`, which is a
// transaction:true flow) ran the flow's ~30 statements in autocommit, so a
// mid-run failure left the earlier writes (add_tickets / add_deliverables /
// announce_*) committed while the facts stayed unapplied - the next tick then
// re-posted the same client-visible rows ("double board"). With the fix,
// runCronJob honors Transaction: true and a failing late step rolls back the
// earlier step's write.
func TestRunCronJobRollsBackTransactionalFlow(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE applied (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "apply_facts",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO applied (name) VALUES ('early write')"},
			{Type: "sql", SQL: "INSERT INTO missing_table (name) VALUES ('boom')"},
		},
	}}
	app.Cron = &CronConfig{Jobs: []CronJob{{ID: "apply_facts", Schedule: "@hourly", Flow: "apply_facts"}}}

	// Drive through executeCronJob so the flow-resolution path is exercised too.
	err := executeCronJob(app, "apply_facts", map[string]any{})
	if err == nil {
		t.Fatal("executeCronJob should surface the failing SQL error")
	}
	var count int
	if scanErr := app.DB.QueryRow("SELECT COUNT(*) FROM applied").Scan(&count); scanErr != nil {
		t.Fatalf("count applied: %v", scanErr)
	}
	if count != 0 {
		t.Fatalf("cron transactional flow left %d committed row(s), want 0 - transaction:true was dropped on the cron path", count)
	}
}

// A successful transactional cron flow commits its writes (and a terminal
// respond step - Writer is nil off the HTTP path - is a harmless no-op).
func TestRunCronJobCommitsTransactionalFlow(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE applied (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "apply_facts",
		Transaction: true,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO applied (name) VALUES ('a')"},
			{Type: "sql", SQL: "INSERT INTO applied (name) VALUES ('b')"},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "{{done}}"}},
		},
	}}
	app.Cron = &CronConfig{Jobs: []CronJob{{ID: "apply_facts", Schedule: "@hourly", Flow: "apply_facts"}}}

	if err := executeCronJob(app, "apply_facts", map[string]any{}); err != nil {
		t.Fatalf("executeCronJob: %v", err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM applied").Scan(&count); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if count != 2 {
		t.Fatalf("cron transactional flow committed %d row(s), want 2", count)
	}
}

// A non-transactional cron flow keeps autocommit semantics: an early write
// survives a later failure. This proves the transaction wrap is gated on the
// flow's Transaction flag, not applied unconditionally.
func TestRunCronJobNonTransactionalFlowDoesNotRollBack(t *testing.T) {
	app := newJobsTestApp(t)
	if _, err := app.DB.Exec("CREATE TABLE applied (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	app.Flows = []Flow{{
		Name:        "loose",
		Transaction: false,
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO applied (name) VALUES ('early write')"},
			{Type: "sql", SQL: "INSERT INTO missing_table (name) VALUES ('boom')"},
		},
	}}
	app.Cron = &CronConfig{Jobs: []CronJob{{ID: "loose", Schedule: "@hourly", Flow: "loose"}}}

	if err := executeCronJob(app, "loose", map[string]any{}); err == nil {
		t.Fatal("executeCronJob should surface the failing SQL error")
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM applied").Scan(&count); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if count != 1 {
		t.Fatalf("non-transactional cron flow rolled back an autocommit write (%d rows, want 1)", count)
	}
}

func TestGHAScheduledTransactionReachesCronRuntime(t *testing.T) {
	for _, tc := range []struct {
		name        string
		transaction string
		lateStep    string
		wantError   bool
		wantRows    int
	}{
		{name: "commit", transaction: "true", wantRows: 1},
		{name: "rollback", transaction: "true", lateStep: "\n      - run: sql\n        query: INSERT INTO missing_table VALUES (1)", wantError: true},
		{name: "autocommit", transaction: "false", lateStep: "\n      - run: sql\n        query: INSERT INTO missing_table VALUES (1)", wantError: true, wantRows: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := newJobsTestApp(t)
			if _, err := app.DB.Exec("CREATE TABLE applied (id INTEGER PRIMARY KEY)"); err != nil {
				t.Fatalf("create table: %v", err)
			}
			source := `on:
  schedule:
    cron: "@daily"
    transaction: ` + tc.transaction + `
jobs:
  run:
    steps:
      - run: sql
        query: INSERT INTO applied VALUES (1)` + tc.lateStep + "\n"
			flows, err := parseGHAFlowFile("flows/scheduled.yaml", []byte(source))
			if err != nil {
				t.Fatalf("parse scheduled flow: %v", err)
			}
			app.Flows = flows
			mergeFlowCronsIntoConfig(app)
			if len(app.Cron.Jobs) != 1 || app.Cron.Jobs[0].Flow != flows[0].Name {
				t.Fatalf("scheduled flow was not registered: %+v", app.Cron)
			}
			if err := executeCronJob(app, app.Cron.Jobs[0].ID, map[string]any{}); (err != nil) != tc.wantError {
				t.Fatalf("executeCronJob error = %v, want error %t", err, tc.wantError)
			}
			var count int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM applied").Scan(&count); err != nil {
				t.Fatalf("count applied: %v", err)
			}
			if count != tc.wantRows {
				t.Fatalf("scheduled flow left %d committed rows, want %d", count, tc.wantRows)
			}
		})
	}
}
