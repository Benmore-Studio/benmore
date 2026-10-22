//go:build !cli && !windows

package main

// expect_rows in an approved command's apply phase
// (appMCPCommandExecution.executeSQL).

import (
	"strings"
	"testing"
)

// commandTaskFlowWithApplyRead adds a read with expect_rows at the head of
// the fixture's apply phase.
func commandTaskFlowWithApplyRead(t *testing.T, status, expect string) string {
	t.Helper()
	const head = "  apply:\n    steps:\n"
	source := strings.Replace(commandTaskFlowFixture, head, head+`      - id: still_open
        run: sql
        expect_rows: '`+expect+`'
        with:
          query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status = '`+status+`'
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}
`, 1)
	if source == commandTaskFlowFixture {
		t.Fatal("fixture did not change")
	}
	return source
}

// An apply-phase read may carry expect_rows (the compiler admits it on any
// apply SQL). It was accepted and never compared.
func TestCommandApplyReadExpectRowsIsChecked(t *testing.T) {
	t.Run("fails and rolls the command back", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixtureWithSource(t, commandTaskFlowWithApplyRead(t, "archived", "=1"))
		origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
		prepared, err := prepareCommandTask(t, app, origin)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		_, err = applyCommandTask(t, app, origin, prepared)
		if err == nil || !strings.Contains(err.Error(), "command SQL read cardinality check failed") {
			t.Fatalf("apply-phase read assertion was not enforced: %v", err)
		}
		assertCommandTaskUnchanged(t, app)
	})
	t.Run("passes when the rows are there", func(t *testing.T) {
		app, sessionID, _ := newCommandProviderTaskFixtureWithSource(t, commandTaskFlowWithApplyRead(t, "open", "=1"))
		origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
		prepared, err := prepareCommandTask(t, app, origin)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		readback, err := applyCommandTask(t, app, origin, prepared)
		if err != nil || readback["status"] != "done" {
			t.Fatalf("apply with a holding read assertion: %v %#v", err, readback)
		}
	})
}

// A command write is asserted on its own row count even when its text holds
// the word RETURNING without the clause: the keyword scan sent it down the
// row-returning path, where a write returns no rows and every assertion
// compared 0.
func TestCommandWriteMentioningReturningCountsAffectedRows(t *testing.T) {
	const update = "UPDATE tasks SET status = 'done', completed_by"
	source := strings.Replace(commandTaskFlowFixture, update, "UPDATE tasks SET title = 'returning soon', status = 'done', completed_by", 1)
	if source == commandTaskFlowFixture {
		t.Fatal("fixture did not change")
	}
	app, sessionID, _ := newCommandProviderTaskFixtureWithSource(t, source)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("a write that changed one row failed its >0 assertion: %v", err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id = 1`).Scan(&title); err != nil || title != "returning soon" {
		t.Fatalf("title = %q (%v)", title, err)
	}
}
