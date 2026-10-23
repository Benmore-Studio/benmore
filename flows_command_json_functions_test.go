//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

const commandJSONAggregate = `(SELECT json_group_array(json_array(title, NULL, json_array_length(json_array(id, NULL)), json_array('nested', id)) ORDER BY id) FROM tasks WHERE project_id = :project_id AND org_id = :tenant)`

func TestCommandJSONArraysPrepareApplyKeepEscapesNullsOrderAndTenant(t *testing.T) {
	source := strings.Replace(commandTaskFlowFixture, "maxLength: 32", "maxLength: 2048", 1)
	source = strings.Replace(source, "SELECT id, status FROM tasks", "SELECT id, "+commandJSONAggregate+" AS status FROM tasks", 1)
	source = strings.Replace(source, "UPDATE tasks SET status = 'done'", "UPDATE tasks SET title = "+commandJSONAggregate+", status = 'done'", 1)
	app, sid, _ := newCommandProviderTaskFixtureWithSource(t, source)
	escaped := "a\"quote\nline\\slash"
	if _, err := app.DB.Exec(`UPDATE tasks SET title=? WHERE id=1`, escaped); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(2,7,'17','second','open'),(3,7,'29','foreign secret','open')`); err != nil {
		t.Fatal(err)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sid}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatal(err)
	}
	expected := []any{[]any{escaped, nil, float64(2), []any{"nested", float64(1)}}, []any{"second", nil, float64(2), []any{"nested", float64(2)}}}
	var preview any
	if err := json.Unmarshal([]byte(prepared.Preview["status"].(string)), &preview); err != nil || !reflect.DeepEqual(preview, expected) {
		t.Fatalf("prepare JSON facts=%#v (%v), want %#v", preview, err, expected)
	}
	readback, err := applyCommandTask(t, app, origin, prepared)
	if err != nil || readback["status"] != "done" {
		t.Fatalf("apply: %#v %v", readback, err)
	}
	var title, foreign string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil {
		t.Fatal(err)
	}
	var applied any
	if err := json.Unmarshal([]byte(title), &applied); err != nil || !reflect.DeepEqual(applied, expected) {
		t.Fatalf("applied JSON=%#v (%v)", applied, err)
	}
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=3`).Scan(&foreign); err != nil || foreign != "foreign secret" {
		t.Fatalf("foreign task changed: %q %v", foreign, err)
	}
}

func TestCommandJSONArrayMalformedJSONRollsBackAppliedMutation(t *testing.T) {
	const marker = "      - id: add_activity\n"
	source := strings.Replace(commandTaskFlowFixture, marker, `      - id: malformed_json
        run: sql
        with:
          query: SELECT json_array_length('{') AS n
`+marker, 1)
	app, sid, _ := newCommandProviderTaskFixtureWithSource(t, source)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sid}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = applyCommandTask(t, app, origin, prepared); err == nil || !strings.Contains(err.Error(), "malformed JSON") {
		t.Fatalf("malformed JSON not refused: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}

func TestCommandJSONArrayFunctionsDoNotExpandTableOrFunctionAuthority(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE tasks(id INTEGER,title TEXT); CREATE TABLE not_enrolled(id INTEGER,title TEXT); INSERT INTO tasks VALUES(1,'ok'); INSERT INTO not_enrolled VALUES(1,'private');`); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	guard := &appMCPCommandExecution{phase: "prepare", allowedReads: commandTableSet([]string{"tasks"})}
	err = conn.Raw(func(raw any) error {
		sqlite := raw.(*sqlite3.SQLiteConn)
		// Harmless test functions make SQLite consult the real authorizer even if a host lacks these extensions.
		for _, name := range []string{"readfile", "load_extension", "unknown_function"} {
			if err := sqlite.RegisterFunc(name, func(s string) string { return "must never run" }, true); err != nil {
				return err
			}
		}
		sqlite.RegisterAuthorizer(guard.authorize)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"prepare", "apply"} {
		guard.phase = phase
		var count int
		if err := conn.QueryRowContext(context.Background(), `SELECT json_array_length(json_group_array(title)) FROM main.tasks`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s admitted functions failed: %d %v", phase, count, err)
		}
		for _, query := range []string{
			`SELECT json_group_array(title) FROM main.not_enrolled`,
			`SELECT json_group_array(name) FROM main.sqlite_master`,
			`SELECT json_group_object('x',title) FROM main.tasks`,
			`SELECT readfile('synthetic-fixture')`, `SELECT load_extension('synthetic-fixture')`, `SELECT unknown_function('synthetic-fixture')`,
			`SELECT value FROM json_each('[1]')`,
		} {
			rows, err := conn.QueryContext(context.Background(), query)
			if rows != nil {
				rows.Close()
			}
			if err == nil {
				t.Fatalf("%s widened authority for %s", phase, query)
			}
		}
	}
}
