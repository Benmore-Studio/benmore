//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A data-event flow (on_insert / on_update / on_delete) runs on the row the
// caller just wrote, so the row's columns are request input exactly as they
// were on the write itself. Laundered through a step output they must not
// reach sql_dynamic as raw SQL text, and they must not pick an enqueued flow.
func TestDataEventRowIsRequestInputForSQLDynamic(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, user_id INTEGER)`)
	mustExec(t, app.DB, `CREATE TABLE audit_hits (id INTEGER PRIMARY KEY, v TEXT)`)
	row := map[string]any{"id": 7, "title": "x'); DELETE FROM notes; --", "user_id": 3}

	run := func(steps ...FlowStep) *FlowContext {
		var got *FlowContext
		runFlowEventWith(app, Flow{Name: "on-note", Trigger: FlowTrigger{Type: "on_insert", Table: "notes"}, Steps: steps}, row, func(ctx *FlowContext) { got = ctx })
		return got
	}

	ctx := run(
		FlowStep{Name: "pick", Type: "sql", SQL: "SELECT {{title}} AS t"},
		FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "INSERT INTO audit_hits (v) VALUES ('{{pick.t}}')"},
	)
	if ctx == nil || ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "request-sourced") {
		t.Fatalf("a row column laundered through a step reached sql_dynamic: %v", ctxErr(ctx))
	}

	ctx = run(FlowStep{Name: "q", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "handle-{{title}}"}})
	if ctx == nil || ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "request-sourced") {
		t.Fatalf("a row column picked the enqueued flow: %v", ctxErr(ctx))
	}

	// Framework-owned columns (the row id, the owner) stay usable.
	ctx = run(
		FlowStep{Name: "pick", Type: "sql", SQL: "SELECT {{id}} AS i, {{user_id}} AS u"},
		FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "INSERT INTO audit_hits (v) VALUES ('{{pick.i}}-{{pick.u}}')"},
	)
	if ctx == nil || ctx.Error != nil {
		t.Fatalf("framework-owned row columns must stay trusted: %v", ctxErr(ctx))
	}
}

// The session keys (user_email, user_role, user_roles, user_group_id) are
// trusted because injectSessionContext writes them over the row, but only
// when a session made the write. A table column of the same name holds what a
// sessionless caller sent, so it is request input.
func TestDataEventSessionKeyColumnIsRequestInput(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	mustExec(t, app.DB, `CREATE TABLE leads (id INTEGER PRIMARY KEY, user_email TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE audit_hits (id INTEGER PRIMARY KEY, v TEXT)`)
	app.Tables = append(app.Tables, Table{Name: "leads", Columns: []Column{{Name: "id"}, {Name: "user_email"}}})
	row := map[string]any{"id": 9, "user_email": "x'); DELETE FROM leads; --"}
	injectSessionContext(row, nil) // a public, sessionless create
	var ctx *FlowContext
	runFlowEventWith(app, Flow{Name: "on-lead", Trigger: FlowTrigger{Type: "on_insert", Table: "leads"}, Steps: []FlowStep{
		{Name: "pick", Type: "sql", SQL: "SELECT {{user_email}} AS e"},
		{Name: "dyn", Type: "sql_dynamic", SQL: "INSERT INTO audit_hits (v) VALUES ('{{pick.e}}')"},
	}}, row, func(c *FlowContext) { ctx = c })
	if ctx == nil || ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "request-sourced") {
		t.Fatalf("a caller-written user_email column reached sql_dynamic as trusted: %v", ctxErr(ctx))
	}
	// On a table without such a column the key is the session's and stays trusted.
	if tainted := flowEventRowTaint(app, "notes", map[string]any{"user_email": "a@example.com"}); tainted["user_email"] {
		t.Fatal("user_email injected by the session on a table without that column must stay trusted")
	}
}

func ctxErr(ctx *FlowContext) any {
	if ctx == nil {
		return "no context"
	}
	return ctx.Error
}
