//go:build !cli && !windows

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Connector read-flow SQL runs under the read-only authorizer, which reads a
// framework table's credential columns as NULL. A join by column name is not
// reported to it, so such a statement naming a framework table is refused.
func TestConnectorReadSQLRefusesNamedJoinsOnFrameworkTables(t *testing.T) {
	app, _, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	mustExec(t, app.DB, `CREATE TABLE _benmore_join_probe (email TEXT, code TEXT);
		INSERT INTO _benmore_join_probe VALUES ('a@example.test', '123456')`)
	request := httptest.NewRequest(http.MethodGet, "/api/mcp-note/1", nil)
	ctx := &FlowContext{App: app, Request: request, Data: map[string]any{}, Params: map[string]string{}}
	closeConn, err := startAppMCPReadFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	run := func(kind, statement string) (string, error) {
		step := &FlowStep{Name: "probe", Type: kind, SQL: statement}
		delete(ctx.Data, "probe")
		var err error
		if kind == "sql_dynamic" {
			err = execStepSQLDynamic(ctx, step)
		} else {
			err = execStepSQL(ctx, step)
		}
		return fmt.Sprint(ctx.Data["probe"]), err
	}
	for _, kind := range []string{"sql", "sql_dynamic"} {
		for _, statement := range []string{
			`SELECT code FROM (SELECT NULL AS code WHERE 0) g FULL JOIN _benmore_join_probe USING (code)`,
			`SELECT * FROM (SELECT NULL AS code WHERE 0) g NATURAL FULL JOIN _benmore_join_probe`,
			`SELECT g.code FROM (SELECT '123456' AS code) g JOIN "_benmore_join_probe" USING (code)`,
			`SELECT g.code FROM (SELECT '123456' AS code) g NATURAL JOIN _benmore_join_probe`,
		} {
			out, err := run(kind, statement)
			if strings.Contains(out, "123456") {
				t.Errorf("%s: %s answered the masked column: %s", kind, statement, out)
			}
			if err == nil || !strings.Contains(err.Error(), "write the join with ON") {
				t.Errorf("%s: %s: err=%v, want the join refused", kind, statement, err)
			}
		}
		// Written with ON the statement runs and the column reads as NULL.
		out, err := run(kind, `SELECT a.email, b.code FROM _benmore_join_probe a FULL JOIN _benmore_join_probe b ON a.code = b.code`)
		if err != nil || !strings.Contains(out, "a@example.test") || strings.Contains(out, "123456") {
			t.Errorf("%s: join with ON: out=%s err=%v", kind, out, err)
		}
		// App tables join by name as before.
		if out, err := run(kind, `SELECT count(*) AS n FROM notes a JOIN notes b USING (id)`); err != nil || !strings.Contains(out, "n:") {
			t.Errorf("%s: app tables joined by name: out=%s err=%v", kind, out, err)
		}
	}
	// The flow's declaration says so before any statement runs.
	flow := &Flow{Trigger: FlowTrigger{Type: "http"}, Steps: []FlowStep{{Type: "sql", SQL: `SELECT g.code FROM (SELECT '1' AS code) g NATURAL JOIN _benmore_join_probe`}}}
	if err := appMCPReadFlowPolicy(flow); err == nil || !strings.Contains(err.Error(), "write the join with ON") {
		t.Errorf("read-flow policy: %v", err)
	}
}

const namedJoinHookLeak = `on_update:
  tasks:
    - sql: INSERT INTO activities(task_id,actor_user_id,actor_email,event) SELECT {{id}},{{user_id}},'{{user_email}}','store:' || table_name FROM (SELECT NULL AS table_name WHERE 0) g FULL JOIN _benmore_mcp_revision_tables USING (table_name)
`

// Hook SQL inside an approved command may not read the connector's own stores:
// the hook scope denies every read of a _benmore_mcp_ table. A join by column
// name is not reported to it, so a hook holding one and naming such a table is
// refused before the command writes anything.
func TestCommandHookSQLRefusesNamedJoinsOnConnectorStores(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, namedJoinHookLeak)
	_, err := runHookedCommand(t, app, sessionID)
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event LIKE 'store:%'`); n != 0 {
		t.Errorf("hook SQL copied %d row(s) of a connector store into an app table", n)
	}
	if err == nil || !strings.Contains(err.Error(), "write the join with ON") {
		t.Errorf("command with the hook: err=%v, want the hook refused", err)
	}
	assertCommandTaskUnchanged(t, app)

	schema := map[string][]byte{"schema.prisma": []byte("model Task {\n  id Int @id\n  name String\n  @@map(\"tasks\")\n}")}
	supported := func(hook Hook) error {
		cap := &appMCPCommandCapability{
			generation: &appMCPRuntimeGeneration{sourceFiles: schema, hooks: &HookConfig{OnUpdate: map[string][]Hook{"tasks": {hook}}}},
			enrollment: &appMCPVerifiedRevisionEnrollment{record: &appMCPRevisionEnrollment{TableNames: []string{"tasks"}}},
		}
		return appMCPCommandHookEffectsSupported(cap, "tasks", "update")
	}
	for name, hook := range map[string]Hook{
		"sql using":      {SQL: `UPDATE tasks SET name = (SELECT token_hash FROM (SELECT NULL AS token_hash WHERE 0) g FULL JOIN _benmore_mcp_credentials USING (token_hash) LIMIT 1) WHERE id = {{id}}`},
		"sql natural":    {SQL: `UPDATE tasks SET name = 'seen' WHERE id = {{id}} AND EXISTS (SELECT 1 FROM (SELECT 'x' AS key_hash) g NATURAL JOIN "_BENMORE_MCP_AUTHORIZATIONS")`},
		"schema table":   {SQL: `UPDATE tasks SET name = (SELECT sql FROM (SELECT NULL AS sql WHERE 0) g FULL JOIN sqlite_master USING (sql) LIMIT 1) WHERE id = {{id}}`},
		"when condition": {SQL: `UPDATE tasks SET name = 'seen' WHERE id = {{id}}`, When: `EXISTS (SELECT 1 FROM (SELECT 'x' AS token_hash) g JOIN _benmore_mcp_credentials USING (token_hash))`},
		"delivery when":  {Webhook: "https://hooks.example.test/in", When: `EXISTS (SELECT 1 FROM (SELECT 'x' AS token_hash) g NATURAL JOIN _benmore_mcp_credentials)`},
	} {
		if err := supported(hook); err == nil || !strings.Contains(err.Error(), "write the join with ON") {
			t.Errorf("%s: err=%v, want the hook refused", name, err)
		}
	}
	// A workflow transition's condition is judged in the same scope.
	workflow := &appMCPCommandCapability{generation: &appMCPRuntimeGeneration{workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"task": {
		Name: "task", Table: "tasks", Field: "status",
		Transitions: map[string]map[string]Transition{"open": {"done": {When: `EXISTS (SELECT 1 FROM (SELECT 'x' AS token_hash) g NATURAL JOIN _benmore_mcp_credentials)`}}},
	}}}}}
	if err := appMCPValidateWorkflowTransition(workflow, appMCPContextTx{}, "tasks", map[string]any{"status": "open"}, map[string]any{"status": "done"}); err == nil || !strings.Contains(err.Error(), "write the join with ON") {
		t.Errorf("workflow transition condition: err=%v, want it refused", err)
	}
	for name, hook := range map[string]Hook{
		"join with ON":         {SQL: `UPDATE tasks SET name = 'seen' WHERE id = {{id}} AND EXISTS (SELECT 1 FROM tasks a JOIN tasks b ON b.id = a.id)`},
		"app tables by name":   {SQL: `UPDATE tasks SET name = 'seen' WHERE id = {{id}} AND EXISTS (SELECT 1 FROM tasks a JOIN tasks b USING (id))`},
		"other framework read": {SQL: `UPDATE tasks SET name = 'seen' WHERE id = {{id}} AND EXISTS (SELECT 1 FROM _benmore_users a JOIN _benmore_users b USING (id))`},
	} {
		if err := supported(hook); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// Approved command SQL needs no named-join check: every table of its FROM and
// JOIN clauses is listed from the text and one that is not declared is refused
// before the statement reaches SQLite, whichever way the join is written.
func TestCommandSQLNamedJoinOnUndeclaredTableIsRefusedByTheInventory(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		for _, statement := range []string{
			`SELECT t.id FROM tasks AS t JOIN _benmore_users USING (id) WHERE t.id = :id`,
			`SELECT t.id FROM tasks AS t NATURAL JOIN _benmore_mcp_operations WHERE t.id = :id`,
			`SELECT id FROM (SELECT NULL AS id WHERE 0) AS g FULL JOIN members USING (id)`,
			`SELECT g.id FROM (SELECT 1 AS id) AS g NATURAL JOIN members`,
			`SELECT t.id FROM tasks AS t WHERE EXISTS (SELECT 1 FROM (SELECT 'x' AS email) AS g JOIN members USING (email))`,
		} {
			for _, phase := range []string{"prepare", "apply", "readback"} {
				if err := cap.validateSQLPhase(statement, phase, []string{"tasks"}); err == nil {
					t.Errorf("%s (%s): command SQL reading an undeclared table through a join by name was admitted", statement, phase)
				}
			}
		}
		// Declared tables join by name: the command may read all of both.
		if err := cap.validateSQLPhase(`SELECT t.id FROM tasks AS t NATURAL JOIN activities AS a WHERE t.id = :id`, "prepare", []string{"tasks", "activities"}); err != nil {
			t.Errorf("declared tables joined by name: %v", err)
		}
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
