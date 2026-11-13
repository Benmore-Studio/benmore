//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// Under compliance: hipaa a transactional flow's read events were written
// after its COMMIT. When that write failed the answer was withheld (5xx), as
// it must be, but the flow's writes were already committed: the caller was
// told the request failed, sent it again, and the record existed twice. The
// events are written inside the transaction, so the run's writes and its read
// events commit together or not at all.

const readAuditTxFlow = `on:
  request:
    method: POST
    path: /api/file-note
    auth: required
    transaction: true

jobs:
  file:
    steps:
      - id: seen
        run: sql
        with:
          query: "SELECT COUNT(*) AS n FROM notes WHERE user_id = :user_id"
      - id: made
        run: sql
        with:
          query: "INSERT INTO notes (user_id, title) VALUES (:user_id, :title) RETURNING id"
      - if: ${{ params.break || '' }} == 'yes'
        run: sql
        with:
          query: "INSERT INTO table_that_does_not_exist (v) VALUES (1)"
      - run: respond
        with:
          status: 201
          json: { id: "${{ steps.made.outputs.id }}" }
`

func readAuditTxApp(t *testing.T, hipaa bool) (*App, *Flow, string) {
	t.Helper()
	app, _ := auditApp(t)
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "notes"}}
	if hipaa {
		app.Design.Compliance = complianceHIPAA
	}
	EnsureReadAuditTable(app.DB)
	app.readAudit = &readAuditBuffer{db: app.DB, sync: true}
	flows := notifyFlows(t, "flows/file-note.yaml", readAuditTxFlow)
	app.Flows = flows
	sid := createCrudScopeSession(t, app, "clerk@example.com", "user", "", "")
	// hipaa asks every account for a second factor: this one has enrolled.
	mustExec(t, app.DB, `UPDATE _benmore_users SET totp_secret = 'enrolled'`)
	return app, &app.Flows[0], sid
}

func readAuditTxCounts(t *testing.T, app *App, title string) (notes, readEvents int) {
	t.Helper()
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes WHERE title = ?`, title).Scan(&notes); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_read_audit WHERE table_name = 'notes' AND query_type = 'flow_sql' AND user_email = 'clerk@example.com'`).Scan(&readEvents); err != nil {
		t.Fatal(err)
	}
	return notes, readEvents
}

const readAuditDownTrigger = `CREATE TRIGGER read_audit_down BEFORE INSERT ON _benmore_read_audit BEGIN SELECT RAISE(ABORT, 'read audit down'); END`

func TestHIPAATransactionalFlowCommitsItsReadAuditWithItsWrites(t *testing.T) {
	app, flow, sid := readAuditTxApp(t, true)

	// The audit table takes rows: the note and one read event per statement
	// that returned rows (the SELECT and the INSERT ... RETURNING) are stored.
	if status, out := postFlow(t, app, flow, sid, map[string]any{"title": "first"}); status != http.StatusCreated || out["id"] == nil {
		t.Fatalf("flow with a working read audit: %d %v, want 201 with the id", status, out)
	}
	if notes, events := readAuditTxCounts(t, app, "first"); notes != 1 || events != 2 {
		t.Fatalf("after a committed run: %d note(s), %d read event(s); want 1 and 2 (each event once)", notes, events)
	}

	// The audit table refuses rows: no answer, and nothing of the run is kept.
	mustExec(t, app.DB, readAuditDownTrigger)
	status, out := postFlow(t, app, flow, sid, map[string]any{"title": "second"})
	if status < 500 || out["id"] != nil {
		t.Fatalf("flow whose read could not be audited answered %d %v, want a 5xx without the row", status, out)
	}
	if notes, events := readAuditTxCounts(t, app, "second"); notes != 0 || events != 2 {
		t.Fatalf("a run that was answered %d kept %d note(s) (read events %d): its writes must roll back with the audit row", status, notes, events)
	}

	// The failed attempt left nothing, so sending it again stores it once.
	mustExec(t, app.DB, `DROP TRIGGER read_audit_down`)
	if status, out := postFlow(t, app, flow, sid, map[string]any{"title": "second"}); status != http.StatusCreated {
		t.Fatalf("the request sent again: %d %v, want 201", status, out)
	}
	if notes, events := readAuditTxCounts(t, app, "second"); notes != 1 || events != 4 {
		t.Fatalf("after the request was sent again: %d note(s), %d read event(s); want 1 and 4", notes, events)
	}

	// A run that fails for another reason rolls back, and its reads are still
	// recorded: they happened.
	if status, _ := postFlow(t, app, flow, sid, map[string]any{"title": "third", "break": "yes"}); status < 500 {
		t.Fatalf("flow with a failing step answered %d, want a 5xx", status)
	}
	if notes, events := readAuditTxCounts(t, app, "third"); notes != 0 || events != 6 {
		t.Fatalf("after a rolled-back run: %d note(s), %d read event(s); want 0 and 6", notes, events)
	}
}

// Queued and scheduled runs commit the same way: a hipaa job that cannot
// record its reads fails and keeps nothing, and is retried like any failure.
func TestHIPAATransactionalJobFlowRollsBackWithoutItsReadAudit(t *testing.T) {
	app, flow, sid := readAuditTxApp(t, true)
	uid := notifyUserID(t, app, sid)
	run := func(title string) bool {
		ctx := &FlowContext{App: app, Data: map[string]any{"user_id": uid}, Params: map[string]string{"user_id": itoa64(uid), "title": title}}
		committed := runFlowEventTransaction(ctx, *flow, func(ctx *FlowContext) { executeSteps(ctx, flow.Steps[:2]) })
		announceFlowWrites(ctx, committed) // as every transaction owner does
		return committed
	}
	count := func(title string) (notes, events int) {
		t.Helper()
		app.DB.QueryRow(`SELECT COUNT(*) FROM notes WHERE title = ?`, title).Scan(&notes)
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_read_audit WHERE table_name = 'notes' AND user_email = 'system:flow_sql'`).Scan(&events)
		return notes, events
	}
	if !run("queued") {
		t.Fatal("a sessionless transactional run with a working read audit did not commit")
	}
	if notes, events := count("queued"); notes != 1 || events != 2 {
		t.Fatalf("committed sessionless run: %d note(s), %d read event(s); want 1 and 2", notes, events)
	}
	mustExec(t, app.DB, readAuditDownTrigger)
	if run("queued-unaudited") {
		t.Fatal("a run whose reads could not be audited committed")
	}
	if notes, _ := count("queued-unaudited"); notes != 0 {
		t.Fatalf("a run whose reads could not be audited kept %d note(s)", notes)
	}
}

// Outside hipaa a failed read-audit write never fails a run, in a transaction
// or not: the flow answers and keeps its writes, as before.
func TestNonHIPAATransactionalFlowKeepsItsWritesWhenReadAuditFails(t *testing.T) {
	app, flow, sid := readAuditTxApp(t, false)
	if status, _ := postFlow(t, app, flow, sid, map[string]any{"title": "first"}); status != http.StatusCreated {
		t.Fatalf("flow with a working read audit: %d", status)
	}
	if notes, events := readAuditTxCounts(t, app, "first"); notes != 1 || events != 2 {
		t.Fatalf("after a committed run: %d note(s), %d read event(s); want 1 and 2", notes, events)
	}
	mustExec(t, app.DB, readAuditDownTrigger)
	if status, out := postFlow(t, app, flow, sid, map[string]any{"title": "second"}); status != http.StatusCreated || out["id"] == nil {
		t.Fatalf("non-hipaa flow with a failing read audit: %d %v, want 201 as before", status, out)
	}
	if notes, _ := readAuditTxCounts(t, app, "second"); notes != 1 {
		t.Fatalf("non-hipaa flow with a failing read audit kept %d note(s), want 1", notes)
	}
}
