//go:build !cli && !windows

package main

// expect_rows on a connector read flow, whose statements run on one pinned
// read-only connection.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// On a connector read the statement runs on the pinned read-only connection.
// An expect_rows there compares the rows returned and never moves the
// statement to another connection or to Exec.
func TestConnectorReadFlowExpectRowsStaysOnThePinnedConnection(t *testing.T) {
	app, uid, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES (?, 'one')", uid); err != nil {
		t.Fatal(err)
	}
	// One connection in the pool, held by the read flow: a statement sent to
	// the pool instead of the pinned connection would wait forever.
	app.DB.SetMaxOpenConns(1)
	request := httptest.NewRequest(http.MethodGet, "/api/mcp-note/1", nil)
	ctx := &FlowContext{App: app, Request: request, Data: map[string]any{}, Params: map[string]string{}}
	closeConn, err := startAppMCPReadFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	run := func(step *FlowStep) error {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			if step.Type == "sql_dynamic" {
				done <- execStepSQLDynamic(ctx, step)
				return
			}
			done <- execStepSQL(ctx, step)
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatalf("step %q left the pinned connection", step.Name)
			return nil
		}
	}
	for _, kind := range []string{"sql", "sql_dynamic"} {
		if err := run(&FlowStep{Name: "none", Type: kind, SQL: "SELECT id FROM notes WHERE title = 'absent'", ExpectRows: ">0"}); err == nil ||
			!strings.Contains(err.Error(), `expect_rows assertion failed on step "none": 0 row(s) returned, expected >0`) {
			t.Fatalf("%s: connector read did not enforce expect_rows: %v", kind, err)
		}
		if err := run(&FlowStep{Name: "one", Type: kind, SQL: "WITH n AS (SELECT id FROM notes WHERE title = 'one') SELECT id FROM n", ExpectRows: "=1"}); err != nil {
			t.Fatalf("%s: connector read with a holding assertion: %v", kind, err)
		}
		if rows, _ := ctx.Data["one"].([]map[string]any); len(rows) != 1 {
			t.Fatalf("%s: connector read output = %#v", kind, ctx.Data["one"])
		}
		// A write stays refused, with or without the assertion.
		if err := run(&FlowStep{Name: "w", Type: kind, SQL: "UPDATE notes SET title = 'x'", ExpectRows: ">0"}); err == nil ||
			!strings.Contains(err.Error(), "connector SQL must be one read-only statement") {
			t.Fatalf("%s: connector read accepted a write: %v", kind, err)
		}
	}
}
