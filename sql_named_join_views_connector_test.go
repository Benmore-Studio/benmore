//go:build !cli && !windows

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Connector read-flow SQL: a view whose text joins a framework table by
// column name is refused like the join written in the statement.
func TestConnectorReadSQLRefusesViewsThatJoinFrameworkTablesByName(t *testing.T) {
	app, _, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	mustExec(t, app.DB, `CREATE TABLE _benmore_join_probe (email TEXT, code TEXT);
		INSERT INTO _benmore_join_probe VALUES ('a@example.test', '123456');
		CREATE VIEW probe_codes AS SELECT code FROM (SELECT NULL AS code WHERE 0) g FULL JOIN _benmore_join_probe USING (code);
		CREATE VIEW probe_on AS SELECT a.email, b.code FROM _benmore_join_probe a JOIN _benmore_join_probe b ON a.email = b.email;
		CREATE VIEW note_pairs AS SELECT count(*) AS n FROM notes a JOIN notes b USING (id)`)
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
		for _, statement := range []string{`SELECT code FROM probe_codes`, `SELECT substr(code, 1) AS c FROM "PROBE_CODES"`} {
			out, err := run(kind, statement)
			if strings.Contains(out, "123456") {
				t.Errorf("%s: %s answered the masked column: %s", kind, statement, out)
			}
			if err == nil || !strings.Contains(err.Error(), "write the join with ON") || !strings.Contains(err.Error(), "view") {
				t.Errorf("%s: %s: err=%v, want the view refused", kind, statement, err)
			}
		}
		if out, err := run(kind, `SELECT email, code FROM probe_on`); err != nil || !strings.Contains(out, "a@example.test") || strings.Contains(out, "123456") {
			t.Errorf("%s: view with ON: out=%s err=%v", kind, out, err)
		}
		if out, err := run(kind, `SELECT n FROM note_pairs`); err != nil || !strings.Contains(out, "n:") {
			t.Errorf("%s: view over app tables: out=%s err=%v", kind, out, err)
		}
	}
}

const namedJoinViewHookLeak = `on_update:
  tasks:
    - sql: INSERT INTO activities(task_id,actor_user_id,actor_email,event) SELECT {{id}},{{user_id}},'{{user_email}}','store:' || table_name FROM store_names
`

// Hook SQL inside an approved command: the hook scope denies every read of a
// connector store, and a view whose text joins one by column name reads it
// without the scope being asked.
func TestCommandHookSQLRefusesViewsThatJoinConnectorStoresByName(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, namedJoinViewHookLeak)
	mustExec(t, app.DB, `CREATE VIEW store_names AS SELECT table_name FROM (SELECT NULL AS table_name WHERE 0) g FULL JOIN _benmore_mcp_revision_tables USING (table_name)`)
	_, err := runHookedCommand(t, app, sessionID)
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event LIKE 'store:%'`); n != 0 {
		t.Errorf("hook SQL copied %d row(s) of a connector store into an app table", n)
	}
	if err == nil || !strings.Contains(err.Error(), "write the join with ON") || !strings.Contains(err.Error(), "view") {
		t.Errorf("command with the hook: err=%v, want the hook refused", err)
	}
	assertCommandTaskUnchanged(t, app)
}
