//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// hookFlowWithApply keeps the fixture's declaration, prepare phase and trusted
// readback shape and replaces only the apply steps.
func hookFlowWithApply(applySteps string) string {
	head := hookTaskFlow[:strings.Index(hookTaskFlow, "  apply:\n")]
	readback := hookTaskFlow[strings.Index(hookTaskFlow, "  readback:\n"):]
	readback = strings.Replace(readback, "SELECT t.id,t.status,t.completed_by,t.completed_at,a.actor_email FROM tasks AS t JOIN activities AS a ON a.task_id=t.id AND a.event='completed' WHERE",
		"SELECT t.id,t.status,1 AS completed_by,'x' AS completed_at,'a@b.c' AS actor_email FROM tasks AS t WHERE", 1)
	return head + "  apply:\n    steps:\n" + applySteps + "      - run: respond\n        with: {status: 200, json: {ok: true}}\n" + readback
}

const hookDeleteApply = `      - id: delete_activities
        run: sql
        expect_rows: '=2'
        with:
          query: DELETE FROM activities WHERE task_id = :id
          params: {id: '${{ params.id }}'}
`

func seedHookActivities(t *testing.T, app *App) {
	t.Helper()
	for _, id := range []int{10, 11} {
		if _, err := app.DB.Exec(`INSERT INTO activities(id,task_id,actor_user_id,actor_email,event) VALUES(?,1,1,'seed@example.com','seed')`, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppMCPCommandDeleteHooksMultiRow(t *testing.T) {
	hooks := `on_delete:
  activities:
    - sql: UPDATE tasks SET title = title || '|d{{id}}' WHERE id = {{task_id}}
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookFlowWithApply(hookDeleteApply), hooks)
	seedHookActivities(t, app)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("multi-row delete with on_delete hook: %v", err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil || title != "Source-backed task|d10|d11" && title != "Source-backed task|d11|d10" {
		t.Fatalf("on_delete hook did not run once per deleted row: %q %v", title, err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 0 {
		t.Fatalf("rows were not deleted: %d", n)
	}
}

func TestAppMCPCommandBeforeDeleteHookRefusalKeepsEveryRow(t *testing.T) {
	hooks := `before_delete:
  activities:
    - sql: SELECT 'seed rows are protected' AS error WHERE {{id}} = 11 AND EXISTS (SELECT 1 FROM activities WHERE id = 10)
on_delete:
  activities:
    - sql: UPDATE tasks SET title = title || '|d{{id}}' WHERE id = {{task_id}}
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookFlowWithApply(hookDeleteApply), hooks)
	seedHookActivities(t, app)
	_, err := runHookedCommand(t, app, sessionID)
	var hookErr *appMCPCommandHookError
	if !errors.As(err, &hookErr) || !hookErr.Refused || hookErr.Message != "seed rows are protected" || hookErr.Table != "activities" || hookErr.Action != "delete" {
		t.Fatalf("before_delete refusal: %#v %v", hookErr, err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil || title != "Source-backed task" {
		t.Fatalf("a refused delete ran on-hooks: %q %v", title, err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 2 {
		t.Fatalf("a refused delete removed rows: %d", n)
	}
}

func TestAppMCPCommandProbeErrorRollsBackEarlierStepsAndPoolStaysUsable(t *testing.T) {
	apply := `      - id: first
        run: sql
        expect_rows: '=1'
        with:
          query: INSERT INTO activities(task_id,actor_user_id,actor_email,event) VALUES(:id,:actor,'a@b.c','first')
          params: {id: '${{ params.id }}', actor: '${{ user.id }}'}
      - id: poisoned
        run: sql
        expect_rows: '=1'
        with:
          query: UPDATE tasks SET status = NULL WHERE id = :id
          params: {id: '${{ params.id }}'}
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookFlowWithApply(apply), hookFiredOnUpdate)
	if _, err := runHookedCommand(t, app, sessionID); err == nil {
		t.Fatal("a probe that violates NOT NULL was accepted")
	}
	assertCommandTaskUnchanged(t, app)
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 0 {
		t.Fatalf("a failed probe left %d rows behind", n)
	}
	// The connection guard and pool recover: a later capability still works.
	if err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) { return false, cap.validateLifetime() }); err != nil {
		t.Fatalf("pool unusable after a failed probe: %v", err)
	}
}

func TestAppMCPCommandHookedWriteMustBeRepeatable(t *testing.T) {
	row := func(id any) map[string]any { return map[string]any{"id": id} }
	probe := []map[string]any{row(int64(1)), row(int64(2))}
	for name, real := range map[string][]map[string]any{
		"fewer rows":     {row(int64(1))},
		"more rows":      {row(int64(1)), row(int64(2)), row(int64(3))},
		"different ids":  {row(int64(1)), row(int64(9))},
		"reordered ids":  {row(int64(2)), row(int64(1))},
		"unusable id":    {row(int64(1)), row(nil)},
		"different type": {row(int64(1)), row("2")},
	} {
		if err := appMCPCommandHookRowsRepeat(probe, real); err == nil {
			t.Errorf("%s: mismatching probe/real runs were accepted", name)
		}
	}
	if err := appMCPCommandHookRowsRepeat(probe, []map[string]any{row(int64(1)), row(int64(2))}); err != nil {
		t.Fatalf("identical runs refused: %v", err)
	}
}

const hookActivityInsert = "INSERT INTO activities(task_id,actor_user_id,actor_email,event) SELECT t.id,:actor,:email,'completed' FROM tasks AS t JOIN members AS m ON m.org_id=t.org_id WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant AND m.user_id=:actor"

func TestAppMCPCommandUpsertOnHookedTableIsRefused(t *testing.T) {
	for name, query := range map[string]string{
		"or replace":   strings.Replace(hookActivityInsert, "INSERT INTO", "INSERT OR REPLACE INTO", 1),
		"replace into": strings.Replace(hookActivityInsert, "INSERT INTO", "REPLACE INTO", 1),
		"on conflict":  hookActivityInsert + " ON CONFLICT(id) DO UPDATE SET event='again'",
	} {
		if !commandSQLUpsertShape(query) {
			t.Fatalf("%s: shape not detected in %q", name, query)
		}
		flow := strings.Replace(hookTaskFlow, hookActivityInsert, query, 1)
		if flow == hookTaskFlow {
			t.Fatal("fixture did not change")
		}
		// Hooks on ANY action of the table make the shape unsafe: only an
		// update hook here, while the statement is an insert.
		hooks := "on_update:\n  activities:\n    - sql: SELECT 1\n"
		app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, flow, hooks)
		_, err := runHookedCommand(t, app, sessionID)
		if err == nil || !strings.Contains(err.Error(), "skip that table's hooks") {
			t.Fatalf("%s: declaration-time refusal missing: %v", name, err)
		}
		assertCommandTaskUnchanged(t, app)
		// Runtime guard, behind a clean declaration: hookedWrite refuses the
		// same statement text on its own.
		clean, cleanSession, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, "on_update:\n  activities:\n    - sql: SELECT 1\n")
		err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
			app: clean, generation: snapshotAppMCPGeneration(clean), toolName: "complete_item", origin: hookFixtureOrigin(cleanSession), now: time.Now().UTC(),
		}, func(cap *appMCPCommandCapability) (bool, error) {
			_, _, _, hooked, err := cap.hookedWrite(query, mustCommandWriteTargets(query))
			if hooked || err == nil {
				t.Errorf("%s: runtime did not refuse the upsert: hooked=%v err=%v", name, hooked, err)
			}
			return false, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if commandSQLUpsertShape("INSERT INTO t(a) VALUES(1)") || commandSQLUpsertShape("UPDATE t SET note='on conflict or replace' WHERE id=1") {
		t.Fatal("plain statements classified as upserts")
	}
}

func TestAppMCPCommandHookKeysMatchExactlyLikeCRUD(t *testing.T) {
	hooks := strings.Replace(hookFiredOnUpdate, "  tasks:", "  Tasks:", 1)
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatal(err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event='hook_fired'`); n != 0 {
		t.Fatalf("a case-different hook key fired (CRUD matches exactly): %d", n)
	}
}

type captureLogs struct{ strings.Builder }

func (c *captureLogs) Write(p []byte) (int, error) { return c.Builder.Write(p) }

func TestAppMCPExposureBroadcastsOnlyAfterConfirmedCommit(t *testing.T) {
	h := newExposureHarnessWithHooks(t, hookFiredOnUpdate)
	sub := subscribeFlowRealtime(t, h.app, h.cookie)
	id := h.prepare()
	h.approveOK(id)
	if sse, ws := sub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("prepare/approve broadcast: %v %v", sse, ws)
	}
	out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, out)
	}
	sse, _ := sub.drain()
	if !strings.Contains(strings.Join(sse, "\n"), `{"table":"tasks","action":"update"}`) {
		t.Fatalf("subscriber did not receive the committed update: %v", sse)
	}
	if again, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || again["outcome"] != "already_applied" {
		t.Fatalf("replay: %q %#v", code, again)
	}
	if sse, ws := sub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("replay broadcast: %v %v", sse, ws)
	}
}

func TestAppMCPExposureExpectRowsMismatchIsRetryableConflict(t *testing.T) {
	returningSQL := "query: UPDATE tasks SET status = 'done', completed_by = :actor, completed_at = datetime('now') WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'"
	for _, tc := range []struct {
		name      string
		hooks     string
		returning bool
	}{
		{name: "ordinary write"},
		{name: "hooked write", hooks: hookFiredOnUpdate},
		{name: "returning write", returning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := strings.Replace(commandTaskFlowFixture, "expect_rows: '>0'", "expect_rows: '=2'", 1)
			if tc.returning {
				flow = strings.Replace(flow, returningSQL, returningSQL+" RETURNING id", 1)
			}
			h := newExposureHarnessWithFlow(t, flow, tc.hooks)
			id := h.prepare()
			h.approveOK(id)
			if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "conflict" {
				t.Fatalf("commit error code = %q, want conflict", code)
			}
			assertConflict := func() map[string]any {
				t.Helper()
				state := h.status(id)
				attempt, _ := state["attempt"].(map[string]any)
				if state["state"] != "conflict" || state["business"] != "not_committed" || state["receipt"] != nil || state["retryable"] != true || attempt["state"] != "conflict" || attempt["error_class"] != "conflict" {
					t.Fatalf("durable conflict status: %#v", state)
				}
				if h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 0 {
					t.Fatal("row-count conflict left business or activity rows")
				}
				return attempt
			}
			firstAttempt := assertConflict()
			if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "conflict" {
				t.Fatalf("retry error code = %q, want conflict", code)
			}
			secondAttempt := assertConflict()
			if firstAttempt["attempt_id"] == secondAttempt["attempt_id"] {
				t.Fatal("retry did not record a new attempt")
			}
		})
	}
}

func TestAppMCPCommandRowCountErrorClassificationIsNarrow(t *testing.T) {
	conflict := &appMCPCommandRowCountConflictError{}
	for name, err := range map[string]error{
		"bare mismatch":     conflict,
		"wrapped mismatch":  fmt.Errorf("apply step: %w", conflict),
		"joined mismatches": errors.Join(conflict, &appMCPCommandRowCountConflictError{}),
	} {
		if got := appMCPCommandErrorClass(err); got != "conflict" {
			t.Errorf("%s class = %q, want conflict", name, got)
		}
	}
	if got := appMCPCommandErrorClass(&appMCPCommandOutcomeUnknownError{cause: conflict}); got != "unknown_execution" {
		t.Fatalf("unknown outcome wrapping a mismatch class = %q, want unknown_execution", got)
	}
	for name, err := range map[string]error{
		"invalid assertion":               func() error { _, err := evalExpectRows("invalid", 0); return err }(),
		"SQL failure":                     errors.New("SQL execution failed"),
		"RowsAffected error":              errors.New("driver could not report RowsAffected"),
		"provider failure":                errors.New("provider unavailable"),
		"joined provider failure":         errors.Join(conflict, errors.New("SQL provider failed")),
		"joined rollback cleanup failure": errors.Join(fmt.Errorf("assertion: %w", conflict), errors.New("rollback cleanup failed")),
	} {
		if got := appMCPCommandErrorClass(err); err == nil || got != "unavailable_provider" {
			t.Errorf("%s class = %q for %v, want unavailable_provider", name, got, err)
		}
	}
}

func TestAppMCPExposureSQLFailureRemainsOperational(t *testing.T) {
	flow := strings.Replace(commandTaskFlowFixture, "status = 'done'", "status = NULL", 1)
	h := newExposureHarnessWithFlow(t, flow, "")
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "unavailable_provider" {
		t.Fatalf("SQL failure code = %q, want unavailable_provider", code)
	}
	state := h.status(id)
	attempt, _ := state["attempt"].(map[string]any)
	if state["state"] != "failed" || state["business"] != "not_committed" || state["receipt"] != nil || state["retryable"] != true || attempt["error_class"] != "unavailable_provider" {
		t.Fatalf("SQL failure status: %#v", state)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 0 {
		t.Fatal("failed SQL left business or activity rows")
	}
}

func TestAppMCPExposureHookRefusalIsDistinctLoggedAndSilent(t *testing.T) {
	h := newExposureHarnessWithHooks(t, `before_update:
  tasks:
    - sql: SELECT 'blocked by policy' AS error WHERE '{{status}}' = 'done'
`)
	sub := subscribeFlowRealtime(t, h.app, h.cookie)
	logs := &captureLogs{}
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	id := h.prepare()
	h.approveOK(id)
	sub.drain()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := h.client.CallTool(ctx, &sdk.CallToolParams{Name: appMCPCommitTool, Arguments: map[string]any{"operation_id": id}})
	if err != nil || !result.IsError || result.Meta["error_code"] != "hook_refused" {
		t.Fatalf("hook refusal result: %v %#v", err, result)
	}
	if text := result.Content[0].(*sdk.TextContent).Text; !strings.Contains(text, "blocked by policy") {
		t.Fatalf("author refusal message not carried: %q", text)
	}
	if line := logs.String(); !strings.Contains(line, "op="+id[:8]) || !strings.Contains(line, "table=tasks") || !strings.Contains(line, "class=hook_refused") || !strings.Contains(line, "refused=true") {
		t.Fatalf("hook refusal was not logged with operation and table: %q", line)
	}
	if sse, ws := sub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("rolled-back command broadcast: %v %v", sse, ws)
	}
}

func TestAppMCPCommandHookWrittenTablesGetRefreshBroadcasts(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hookFiredOnUpdate)
	var writes []appMCPCommandWrite
	var refresh []string
	var actor Session
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		if _, _, err = cap.apply(prepared); err != nil {
			return false, err
		}
		writes, refresh, actor = cap.writes, cap.hookRefresh, cap.actor
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(writes, appMCPCommandWrite{"tasks", "update"}) || !slices.Contains(writes, appMCPCommandWrite{"activities", "insert"}) || !slices.Contains(refresh, "activities") {
		t.Fatalf("effects not recorded: writes=%v refresh=%v", writes, refresh)
	}
	var tables []string
	for _, event := range appMCPCommandBroadcasts(snapshotAppMCPGeneration(app).view, writes, refresh, actor) {
		tables = append(tables, event.Table+":"+event.Action)
	}
	for _, want := range []string{"tasks:update", "activities:insert", "activities:refresh"} {
		if !slices.Contains(tables, want) {
			t.Fatalf("missing broadcast %q in %v", want, tables)
		}
	}
}
