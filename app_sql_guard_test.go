//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// appSQLGuardApp is an app on the served driver with both audit tables, one
// audit row, a framework table with an index and an app table. hipaa installs
// the append-only triggers.
func appSQLGuardApp(t *testing.T, hipaa bool) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	// One connection: a TEMP object or a pragma an earlier statement left
	// behind is seen by the checks below.
	db.SetMaxOpenConns(1)
	app := &App{Dir: dir, DB: db, Design: &DesignConfig{}}
	t.Cleanup(app.Shutdown)
	for _, stmt := range []string{
		`CREATE TABLE _benmore_audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, table_name TEXT NOT NULL, row_id TEXT, user_email TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE _benmore_read_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT NOT NULL, row_id TEXT, query_type TEXT NOT NULL, user_id INTEGER NOT NULL, user_email TEXT NOT NULL)`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email) VALUES ('insert', 'notes', '1', 'a@example.com')`,
		`CREATE TABLE _benmore_users (id INTEGER PRIMARY KEY, email TEXT)`,
		`CREATE INDEX _benmore_users_email ON _benmore_users (email)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`,
		`CREATE TRIGGER _benmore_ver_notes_update BEFORE UPDATE ON notes BEGIN SELECT 1; END`,
	} {
		mustExec(t, db, stmt)
	}
	if hipaa {
		app.Design.Compliance = complianceHIPAA
		if err := ensureAuditAppendOnly(app); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

func appSQLGuardText(t *testing.T, app *App, query string) string {
	t.Helper()
	var s sql.NullString
	if err := app.DB.QueryRow(query).Scan(&s); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return s.String
}

// appSQLGuardSchema is every schema object, main and temp, with its text.
func appSQLGuardSchema(t *testing.T, app *App) string {
	t.Helper()
	return appSQLGuardText(t, app, `SELECT group_concat(type || ' ' || name || ' ' || COALESCE(sql, ''), char(10)) FROM (SELECT type, name, sql FROM sqlite_master UNION ALL SELECT 'temp ' || type, name, sql FROM sqlite_temp_master ORDER BY 1, 2)`)
}

// sqlStepYAML is one SQL step whose query is a YAML block scalar, so quotes
// and comments in it need no escaping.
func sqlStepYAML(id, run, query string) string {
	return "      - id: " + id + "\n        run: " + run + "\n        with:\n          query: |-\n            " + strings.ReplaceAll(query, "\n", "\n            ") + "\n"
}

// The builder's flow: one step drops the append-only UPDATE trigger, the next
// rewrites an audit row. It answered 200 with one row changed, and the trigger
// stayed gone for every later write until the next reload.
func TestAppSQLCannotDropAuditTriggerThenRewriteHistory(t *testing.T) {
	app := appSQLGuardApp(t, true)
	steps := sqlStepYAML("drop1", "sql", `DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`) +
		sqlStepYAML("last", "sql", `UPDATE _benmore_audit_log SET user_email = 'tampered@example.com' WHERE id = 1`)
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", steps))
	if err == nil || rr.Code != http.StatusInternalServerError {
		t.Fatalf("flow answered %d (err %v), want it refused", rr.Code, err)
	}
	if !strings.Contains(err.Error(), "may not drop the trigger _benmore_audit_log_no_update on the framework table _benmore_audit_log") {
		t.Errorf("refusal = %v, want it to name the trigger and the table", err)
	}
	if got := appSQLGuardText(t, app, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "a@example.com" {
		t.Errorf("audit row 1 user_email = %q, want it unchanged", got)
	}
	if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = '_benmore_audit_log_no_update'`); got != "1" {
		t.Errorf("append-only UPDATE trigger present = %s, want 1", got)
	}
}

// Every statement here changes a framework object, or would let plain DML do
// so. Each is refused whatever its spelling, through `run: sql`, through
// `run: sql_dynamic` and inside a `transaction: true` flow, on a hipaa app and
// on any other, and leaves the schema exactly as it was.
func TestAppSQLRefusesDDLOnFrameworkObjects(t *testing.T) {
	statements := map[string]string{
		"drop trigger":                  `DROP TRIGGER _benmore_audit_log_no_delete`,
		"drop trigger, quoted + main.":  `DROP TRIGGER main."_benmore_audit_log_no_update"`,
		"drop trigger, brackets":        `DROP TRIGGER [_benmore_audit_log_no_overwrite]`,
		"drop trigger behind comments":  "/* tidy */ DROP /* x */ TRIGGER -- y\n IF EXISTS `_BENMORE_audit_log_no_update`",
		"second statement of a script":  `INSERT INTO notes (body) VALUES ('x'); DROP TRIGGER _benmore_audit_log_no_update`,
		"trigger on an audit table":     `CREATE TRIGGER sink BEFORE INSERT ON _benmore_audit_log BEGIN DELETE FROM notes; END`,
		"temp trigger on audit table":   `CREATE TEMP TRIGGER sink BEFORE INSERT ON main._benmore_read_audit BEGIN DELETE FROM notes; END`,
		"trigger with a framework name": `CREATE TRIGGER _benmore_mine AFTER INSERT ON notes BEGIN SELECT 1; END`,
		"drop a framework trigger":      `DROP TRIGGER _benmore_ver_notes_update`,
		"temp table shadowing":          `CREATE TEMP TABLE _benmore_audit_log (id INTEGER PRIMARY KEY, action TEXT)`,
		"create table as":               `CREATE TABLE "_benmore_copy" AS SELECT * FROM notes`,
		"create view":                   `CREATE VIEW _benmore_v AS SELECT * FROM notes`,
		"drop table":                    `DROP TABLE IF EXISTS _benmore_read_audit`,
		"alter table add column":        `ALTER TABLE _benmore_users ADD COLUMN extra TEXT`,
		"alter table rename":            `ALTER TABLE _benmore_audit_log RENAME TO audit_old`,
		"rename into the namespace":     `ALTER TABLE notes RENAME TO "_benmore_notes"`,
		"index on a framework table":    `CREATE UNIQUE INDEX one_action ON _benmore_audit_log (action)`,
		"index with a framework name":   `CREATE INDEX _benmore_notes_body ON notes (body)`,
		"drop a framework index":        `DROP INDEX _benmore_users_email`,
		"writable_schema":               `PRAGMA writable_schema = ON`,
		"writable_schema, main.":        `PRAGMA main.writable_schema(1)`,
	}
	for _, hipaa := range []bool{true, false} {
		for name, stmt := range statements {
			for _, mode := range []string{"sql", "sql_dynamic", "transaction"} {
				label := name + "/" + mode
				if hipaa {
					label += "/hipaa"
				}
				t.Run(label, func(t *testing.T) {
					app := appSQLGuardApp(t, hipaa)
					if !hipaa { // the triggers of an app that was hipaa once
						if err := installAuditAppendOnly(app.DB); err != nil {
							t.Fatal(err)
						}
					}
					before := appSQLGuardSchema(t, app)
					run, onRequest := mode, ""
					if mode == "transaction" {
						run, onRequest = "sql", "    transaction: true\n"
					}
					rr, err := runExpectRowsFlow(t, app, expectRowsFlow(onRequest, sqlStepYAML("s", run, stmt)))
					if err == nil || rr.Code != http.StatusInternalServerError || !strings.Contains(err.Error(), "app SQL may not") {
						t.Fatalf("flow answered %d (err %v), want the app SQL refusal", rr.Code, err)
					}
					if after := appSQLGuardSchema(t, app); after != before {
						t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
					}
					if got := appSQLGuardText(t, app, `PRAGMA writable_schema`); got != "0" {
						t.Errorf("writable_schema = %s after the refused statement", got)
					}
				})
			}
		}
	}
}

// Under compliance: hipaa, flow SQL cannot update or delete an audit row even
// when a trigger is not there: append-only does not rest on the triggers.
func TestAppSQLCannotRewriteAuditRowsWithoutTriggers(t *testing.T) {
	statements := map[string]string{
		"update":                `UPDATE _benmore_audit_log SET user_email = 'tampered@example.com' WHERE id = 1`,
		"update, quoted + main": `UPDATE main."_BENMORE_audit_log" SET user_email = 'tampered@example.com'`,
		"update or replace":     `UPDATE OR REPLACE [_benmore_audit_log] SET user_email = 'tampered@example.com'`,
		"cte update":            `WITH x AS (SELECT 1 AS id) UPDATE _benmore_audit_log SET user_email = 'tampered@example.com' WHERE id IN (SELECT id FROM x)`,
		"delete":                `DELETE FROM _benmore_audit_log`,
		"delete matching none":  `DELETE FROM _benmore_audit_log WHERE 0`,
		"cte delete":            `WITH x AS (SELECT 1 AS id) DELETE FROM _benmore_audit_log WHERE id IN (SELECT id FROM x)`,
		"read audit":            `DELETE /* all */ FROM _benmore_read_audit`,
		"replace into":          `REPLACE INTO _benmore_audit_log (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com')`,
		"insert or replace":     "WITH v AS (SELECT 1 AS id) INSERT /* x */ OR REPLACE INTO main.[_benmore_audit_log] (id, action, table_name, user_email) SELECT id, 'x', 'y', 'tampered@example.com' FROM v",
		"upsert":                `INSERT INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'x', 'y') ON CONFLICT (id) DO UPDATE SET user_email = 'tampered@example.com'`,
		"through an app trigger": `CREATE TRIGGER notes_rewrite AFTER INSERT ON notes BEGIN UPDATE _benmore_audit_log SET user_email = 'tampered@example.com'; END;
INSERT INTO notes (body) VALUES ('x')`,
	}
	for name, stmt := range statements {
		for _, run := range []string{"sql", "sql_dynamic"} {
			t.Run(name+"/"+run, func(t *testing.T) {
				app := appSQLGuardApp(t, true)
				// The triggers are gone (a path this guard does not cover).
				for _, trigger := range auditTriggerNames() {
					mustExec(t, app.DB, `DROP TRIGGER `+trigger)
				}
				rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", run, stmt)))
				if err == nil || rr.Code != http.StatusInternalServerError || !strings.Contains(err.Error(), "is append-only under compliance: hipaa") {
					t.Fatalf("flow answered %d (err %v), want the append-only refusal", rr.Code, err)
				}
				if got := appSQLGuardText(t, app, `SELECT group_concat(id || ':' || user_email) FROM _benmore_audit_log`); got != "1:a@example.com" {
					t.Errorf("audit rows = %q, want the one row unchanged", got)
				}
			})
		}
	}

	// Adding a row stays allowed, as documented.
	app := appSQLGuardApp(t, true)
	insert := `INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email) VALUES ('sign', 'notes', '1', 'b@example.com')`
	if rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", insert))); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("audit INSERT by flow SQL answered %d (err %v), want 200", rr.Code, err)
	}
	if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM _benmore_audit_log`); got != "2" {
		t.Errorf("audit rows = %s, want 2", got)
	}

	// An app that is not hipaa keeps what it had: its flow SQL may change
	// audit rows, and rows of any other framework table.
	plain := appSQLGuardApp(t, false)
	steps := sqlStepYAML("a", "sql", `UPDATE _benmore_audit_log SET user_email = 'fixed@example.com' WHERE id = 1`) +
		sqlStepYAML("b", "sql", `INSERT INTO _benmore_users (email) VALUES ('u@example.com')`) +
		sqlStepYAML("c", "sql", `UPDATE _benmore_users SET email = 'v@example.com'`)
	if rr, err := runExpectRowsFlow(t, plain, expectRowsFlow("", steps)); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("row writes on a non-hipaa app answered %d (err %v), want 200", rr.Code, err)
	}
	if got := appSQLGuardText(t, plain, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "fixed@example.com" {
		t.Errorf("audit row = %q, want the update applied on a non-hipaa app", got)
	}
}

// DDL on the app's own objects keeps working, with and without hipaa.
func TestAppSQLKeepsDDLOnAppObjects(t *testing.T) {
	for _, hipaa := range []bool{true, false} {
		app := appSQLGuardApp(t, hipaa)
		steps := ""
		for i, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS my_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT UNIQUE, v TEXT)`,
			`CREATE INDEX IF NOT EXISTS my_cache_v ON my_cache (v)`,
			`CREATE TRIGGER my_cache_touch AFTER INSERT ON my_cache BEGIN UPDATE my_cache SET v = upper(NEW.v) WHERE id = NEW.id; END`,
			`ALTER TABLE my_cache ADD COLUMN note TEXT`,
			`INSERT INTO my_cache (k, v) VALUES ('a', 'b')`,
			`ALTER TABLE my_cache RENAME COLUMN note TO _benmore_note`,
			`ALTER TABLE my_cache RENAME TO my_cache2`,
			`CREATE VIEW my_view AS SELECT k, v FROM my_cache2`,
			`CREATE TEMP TABLE scratch AS SELECT * FROM my_cache2; INSERT INTO notes (body) SELECT v FROM scratch; DROP TABLE scratch`,
			`ANALYZE`,
			`DELETE FROM sqlite_sequence WHERE name = 'my_cache2'`,
			`DROP TRIGGER my_cache_touch`,
			`DROP INDEX my_cache_v`,
			`DROP VIEW my_view`,
			// An app table goes with the framework's triggers on it.
			`DROP TABLE notes`,
			`CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`,
		} {
			steps += sqlStepYAML("s"+string(rune('a'+i)), "sql", stmt)
		}
		rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", steps))
		if err != nil || rr.Code != http.StatusOK {
			t.Fatalf("hipaa=%t: app DDL answered %d (err %v), want 200", hipaa, rr.Code, err)
		}
		if got := appSQLGuardText(t, app, `SELECT v FROM my_cache2 WHERE k = 'a'`); got != "B" {
			t.Errorf("hipaa=%t: my_cache2.v = %q, want B (table, trigger and rename applied)", hipaa, got)
		}
		if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE name = '_benmore_ver_notes_update'`); got != "0" {
			t.Errorf("hipaa=%t: the dropped table's trigger is still there", hipaa)
		}
	}
}

// A framework trigger on an app table goes only with its table. Dropping the
// table and taking that back in the same script does not open the trigger to
// a DROP TRIGGER.
func TestAppSQLDropTableDoesNotOpenItsFrameworkTriggers(t *testing.T) {
	for name, script := range map[string]string{
		"rolled back to a savepoint": `SAVEPOINT s; DROP TABLE notes; ROLLBACK TO s; DROP TRIGGER _benmore_ver_notes_update; RELEASE s`,
		// A text with RETURNING runs through Query, which compiles every
		// statement and runs only the last.
		"compiled, not run":        `DROP TABLE notes; DROP TRIGGER _benmore_ver_notes_update /* RETURNING */`,
		"a temp table of the name": `CREATE TEMP TABLE notes (x); DROP TABLE notes; DROP TRIGGER _benmore_ver_notes_update`,
		"another table":            `CREATE TABLE other (x); DROP TABLE other; DROP TRIGGER _benmore_ver_notes_update`,
	} {
		t.Run(name, func(t *testing.T) {
			app := appSQLGuardApp(t, false)
			before := appSQLGuardSchema(t, app)
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow("    transaction: true\n", sqlStepYAML("s", "sql", script)))
			if err == nil || rr.Code != http.StatusInternalServerError || !strings.Contains(err.Error(), "may not drop the framework trigger _benmore_ver_notes_update") {
				t.Fatalf("flow answered %d (err %v), want the trigger drop refused", rr.Code, err)
			}
			if after := appSQLGuardSchema(t, app); after != before {
				t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// SQLite itself keeps its own objects from DDL once writable_schema cannot be
// set, so the scope has no rule for sqlite_* names.
func TestAppSQLLeavesSQLiteObjectsToTheEngine(t *testing.T) {
	app := appSQLGuardApp(t, false)
	before := appSQLGuardSchema(t, app)
	for _, stmt := range []string{
		`CREATE TABLE sqlite_mine (id INTEGER)`,
		`DROP TABLE sqlite_master`,
		`DROP TABLE sqlite_sequence`,
		`CREATE TRIGGER t AFTER INSERT ON sqlite_sequence BEGIN SELECT 1; END`,
		`DELETE FROM sqlite_master WHERE name = '_benmore_ver_notes_update'`,
		`UPDATE sqlite_master SET sql = '' WHERE name = '_benmore_ver_notes_update'`,
	} {
		if rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", stmt))); err == nil {
			t.Errorf("%s answered %d, want an error", stmt, rr.Code)
		}
	}
	if after := appSQLGuardSchema(t, app); after != before {
		t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// Hook SQL runs in the same scope: a before-hook, an after-hook in the
// write's transaction and a queued hook job.
func TestHookSQLRefusesDDLOnFrameworkObjects(t *testing.T) {
	const drop = `DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`
	const rewrite = `UPDATE _benmore_audit_log SET user_email = 'tampered@example.com'`
	row := map[string]any{"id": int64(1), "body": "x"}
	for _, stmt := range []string{drop, rewrite} {
		app := appSQLGuardApp(t, true)
		if stmt == rewrite {
			mustExec(t, app.DB, `DROP TRIGGER _benmore_audit_log_no_update`)
		}
		before := appSQLGuardSchema(t, app)
		hooks := []Hook{{SQL: stmt}}

		app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"notes": hooks}}
		if err := fireBeforeHooksWith(app.DB, app, "insert", "notes", row); err == nil {
			t.Errorf("before-hook %q was not refused", stmt)
		}

		tx, err := app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		_, err = fireHookListTx(tx, app, "insert", "notes", row, hooks)
		tx.Rollback()
		if err == nil || !strings.Contains(err.Error(), "app SQL may not") && !strings.Contains(err.Error(), "is append-only under compliance: hipaa") {
			t.Errorf("after-hook %q in the write's transaction = %v, want the refusal", stmt, err)
		}

		if err := executeHookResult(app, hooks[0], "notes", row); err == nil {
			t.Errorf("queued hook %q was not refused", stmt)
		}

		if after := appSQLGuardSchema(t, app); after != before {
			t.Errorf("%q changed the schema:\nbefore:\n%s\nafter:\n%s", stmt, before, after)
		}
		if got := appSQLGuardText(t, app, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "a@example.com" {
			t.Errorf("%q: audit row = %q, want it unchanged", stmt, got)
		}
	}

	// Hook SQL on the app's own tables, and an audit INSERT, still run.
	app := appSQLGuardApp(t, true)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ok := []Hook{{SQL: `CREATE TABLE IF NOT EXISTS hook_log (note TEXT)`}, {SQL: `INSERT INTO hook_log (note) VALUES ('{{body}}')`},
		{SQL: `INSERT INTO _benmore_audit_log (action, table_name, row_id) VALUES ('hook', 'notes', '{{id}}')`}}
	if _, err := fireHookListTx(tx, app, "insert", "notes", row, ok); err != nil {
		t.Fatalf("hook SQL on app tables: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := appSQLGuardText(t, app, `SELECT note FROM hook_log`); got != "x" {
		t.Errorf("hook_log.note = %q, want x", got)
	}
}

// A page <query> runs under its own authorizer, which applies the same scope;
// when it hands the connection back, the connection's default still does.
func TestPageQueryRefusesDDLOnFrameworkObjects(t *testing.T) {
	app := appSQLGuardApp(t, true)
	before := appSQLGuardSchema(t, app)
	for _, stmt := range []string{
		`DROP TRIGGER _benmore_audit_log_no_update`,
		`UPDATE _benmore_audit_log SET user_email = 'tampered@example.com' RETURNING id`,
		`ALTER TABLE notes RENAME TO _benmore_notes`,
	} {
		_, _, err := runPageQuery(context.Background(), app, nil, nil, newPageQueryPolicy(app, nil, nil, false), stmt)
		if err == nil || !strings.Contains(err.Error(), "app SQL may not") && !strings.Contains(err.Error(), "is append-only under compliance: hipaa") {
			t.Errorf("page query %q = %v, want the refusal", stmt, err)
		}
	}
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('seen')`)
	rows, _, err := queryPageRows(context.Background(), app.DB, newPageQueryPolicy(app, nil, nil, false), &appSQLScope{hipaa: true}, `SELECT body FROM notes`)
	if err != nil || len(rows) != 1 || rows[0]["body"] != "seen" {
		t.Fatalf("page SELECT = %v, err %v", rows, err)
	}
	// The same pooled connection, after the page query's authorizer ended.
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", `DROP TRIGGER _benmore_audit_log_no_update`)))
	if err == nil || rr.Code != http.StatusInternalServerError {
		t.Fatalf("flow after a page query answered %d (err %v), want it refused", rr.Code, err)
	}
	if after := appSQLGuardSchema(t, app); after != before {
		t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := appSQLGuardText(t, app, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "a@example.com" {
		t.Errorf("audit row = %q, want it unchanged", got)
	}
}

// The framework's own statements on the same connections are not in the
// scope: the privileged audit maintenance still lifts and restores the
// triggers, and an unmarked statement that starts with the marker text of
// another kind is just SQL.
func TestAppSQLScopeLeavesFrameworkStatementsAlone(t *testing.T) {
	app := appSQLGuardApp(t, true)
	if _, err := execAuditMutable(app.DB, `UPDATE _benmore_audit_log SET user_email = 'scrubbed' WHERE id = 1`); err != nil {
		t.Fatalf("framework audit maintenance: %v", err)
	}
	if got := appSQLGuardText(t, app, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "scrubbed" {
		t.Errorf("audit row = %q, want the framework's change", got)
	}
	// App text cannot leave the scope by carrying a marker of its own.
	rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", appSQLMark+`DROP TRIGGER _benmore_audit_log_no_update`)))
	if err == nil || rr.Code != http.StatusInternalServerError {
		t.Fatalf("flow whose text starts with the marker answered %d (err %v), want it refused", rr.Code, err)
	}
}

// A missing append-only trigger is recreated at the next load, and that is
// logged as SECURITY. The first install of an app is not.
func TestAuditAppendOnlyLogsARecreatedTrigger(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	app := appSQLGuardApp(t, true) // first install
	if strings.Contains(buf.String(), "SECURITY") {
		t.Fatalf("the first install logged a SECURITY line:\n%s", buf.String())
	}
	mustExec(t, app.DB, `DROP TRIGGER _benmore_audit_log_no_update`)
	if err := ensureAuditAppendOnly(app); err != nil {
		t.Fatal(err)
	}
	if want := "SECURITY: audit trigger _benmore_audit_log_no_update was missing; restoring it"; !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want %q", buf.String(), want)
	}
	if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = '_benmore_audit_log'`); got != "3" {
		t.Errorf("triggers on the audit log = %s, want 3", got)
	}

	// All of one table's triggers gone while the process runs: also logged.
	buf.Reset()
	for _, kind := range auditAppendOnlyKinds {
		mustExec(t, app.DB, `DROP TRIGGER `+auditTriggerName("_benmore_read_audit", kind))
	}
	if err := ensureAuditAppendOnly(app); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(buf.String(), "was missing; restoring it"); got != 3 {
		t.Errorf("logged %d missing triggers, want 3:\n%s", got, buf.String())
	}
}

// The write gate and `benmore check` refuse flow and hook SQL that is DDL on
// a framework object; SQL that only reads or writes rows, or changes the
// app's own objects, passes.
func TestWriteGateRefusesFrameworkDDLInFlowAndHookSQL(t *testing.T) {
	for query, want := range map[string]string{
		`DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`:                                       "_benmore_audit_log_no_update",
		"-- x\nDROP /* y */ TRIGGER main.\"_benmore_audit_log_no_update\"":                          "_benmore_audit_log_no_update",
		`SELECT 1; CREATE TEMP TRIGGER t BEFORE INSERT ON [_benmore_audit_log] BEGIN SELECT 1; END`: "_benmore_audit_log",
		`CREATE UNIQUE INDEX IF NOT EXISTS i ON _benmore_users (email)`:                             "_benmore_users",
		`CREATE TABLE IF NOT EXISTS _benmore_cache (k TEXT)`:                                        "_benmore_cache",
		`ALTER TABLE _benmore_users ADD COLUMN plan TEXT`:                                           "_benmore_users",
		`ALTER TABLE notes RENAME TO _benmore_notes`:                                                "_benmore_notes",
		`DROP VIEW _BENMORE_v`: "_BENMORE_v",
		`INSERT INTO _benmore_audit_log (action, table_name) VALUES ('x', 'DROP TABLE _benmore_x')`:                                   "",
		`UPDATE _benmore_users SET role = 'admin' WHERE id = :id`:                                                                     "",
		`CREATE TABLE IF NOT EXISTS my_benmore_cache (k TEXT)`:                                                                        "",
		`CREATE TRIGGER t AFTER INSERT ON notes BEGIN INSERT INTO _benmore_audit_log (action, table_name) VALUES ('i', 'notes'); END`: "",
		`CREATE INDEX i ON notes (_benmore_ref)`:                                                                                      "",
		`ALTER TABLE notes RENAME COLUMN a TO _benmore_a`:                                                                             "",
		`SELECT * FROM _benmore_audit_log WHERE action = 'drop'`:                                                                      "",
	} {
		if got := sqlFrameworkDDLTarget(query); got != want {
			t.Errorf("sqlFrameworkDDLTarget(%q) = %q, want %q", query, got, want)
		}
	}

	dir := t.TempDir()
	flow := expectRowsFlow("", sqlStepYAML("drop1", "sql", `DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`))
	if msg := validateOnWriteIn(dir, "flows/tamper.yaml", flow, true); !strings.Contains(msg, "_benmore_audit_log_no_update, a framework object") {
		t.Errorf("write gate on the flow = %q, want the framework-object refusal", msg)
	}
	ok := expectRowsFlow("", sqlStepYAML("a", "sql", `CREATE TABLE IF NOT EXISTS my_cache (k TEXT)`)+
		sqlStepYAML("b", "sql", `INSERT INTO _benmore_audit_log (action, table_name) VALUES ('sign', 'notes')`))
	if msg := validateOnWriteIn(dir, "flows/ok.yaml", ok, true); msg != "" {
		t.Errorf("write gate refused app DDL and an audit INSERT: %s", msg)
	}
	hooks := "on_insert:\n  notes:\n    - sql: \"DROP TRIGGER IF EXISTS _benmore_audit_log_no_update\"\n"
	if msg := validateOnWriteIn(dir, "hooks.yaml", hooks, true); !strings.Contains(msg, "hooks.yaml: on_insert.notes[0]") || !strings.Contains(msg, "a framework object") {
		t.Errorf("write gate on hooks.yaml = %q, want the framework-object refusal", msg)
	}
	if msg := validateOnWriteIn(dir, "hooks.yaml", "on_insert:\n  notes:\n    - sql: \"INSERT INTO _benmore_audit_log (action, table_name) VALUES ('i', 'notes')\"\n", true); msg != "" {
		t.Errorf("write gate refused a hook that adds an audit row: %s", msg)
	}
}
