//go:build !cli

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// hipaaAppWithoutAuditTriggers is a `compliance: hipaa` app whose append-only
// triggers are not there: a restored database file, or the time before the
// first hipaa load installs them.
func hipaaAppWithoutAuditTriggers(t *testing.T) *App {
	t.Helper()
	app := appSQLGuardApp(t, false)
	app.Design.Compliance = complianceHIPAA
	return app
}

func auditTriggerCount(t *testing.T, app *App) string {
	t.Helper()
	return appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = '_benmore_audit_log'`)
}

// A trigger of the app that writes an audit table is refused on a hipaa app,
// from flow SQL and from a migration, with the append-only triggers missing.
// Each of these was created before: a plain INSERT is not a rewrite by its
// text, but it takes the conflict policy of the statement that fires the
// trigger, and the body scan stopped at an alias called `end` or started at a
// column called `begin`. The write that fires the trigger is the framework's
// own, outside any scope, so the audit row was replaced, updated or deleted.
func TestAppSQLCannotCreateATriggerThatWritesAuditRows(t *testing.T) {
	const tamper = `UPDATE _benmore_audit_log SET user_email = 'tampered@example.com'`
	triggers := map[string]string{
		"plain insert of an existing id": "CREATE TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  INSERT INTO _benmore_audit_log (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com');\nEND",
		"insert or ignore":               "CREATE TEMP TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  INSERT OR IGNORE INTO main.\"_benmore_audit_log\" (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com');\nEND",
		"alias named end":                "CREATE TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  SELECT 1 AS end;\n  " + tamper + ";\nEND",
		"columns named begin and end":    "CREATE TRIGGER notes_audit AFTER INSERT ON notes WHEN (SELECT 1 AS begin) AND (SELECT 1 AS end) BEGIN\n  " + tamper + ";\nEND",
		"trigger named begin":            "CREATE TRIGGER IF NOT EXISTS begin AFTER INSERT ON notes BEGIN\n  SELECT 1 AS \"end\"; SELECT 2 AS end;\n  DELETE FROM _benmore_audit_log;\nEND",
		"trigger named trigger":          "CREATE TRIGGER trigger AFTER INSERT ON notes BEGIN\n  UPDATE OR REPLACE '_benmore_audit_log' SET user_email = 'tampered@example.com';\nEND",
		"case in the body":               "CREATE TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  SELECT CASE WHEN NEW.id > 0 THEN 1 END;\n  DELETE FROM [_benmore_read_audit];\nEND",
		"instead of trigger on a view":   "CREATE VIEW audit_v AS SELECT * FROM _benmore_audit_log;\nCREATE TRIGGER audit_v_delete INSTEAD OF DELETE ON audit_v BEGIN\n  DELETE FROM _benmore_audit_log WHERE id = OLD.id;\nEND",
	}
	for name, stmt := range triggers {
		for _, migration := range []bool{false, true} {
			label := name + "/flow"
			if migration {
				label = name + "/migration"
			}
			t.Run(label, func(t *testing.T) {
				var app *App
				var err error
				if migration {
					app = guardMigrationApp(t, false)
					app.Design.Compliance = complianceHIPAA
				} else {
					app = hipaaAppWithoutAuditTriggers(t)
				}
				before := appSQLGuardSchema(t, app)
				if migration {
					err = guardMigrationFile(t, app, true, stmt+";\n")
				} else {
					rr, flowErr := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", stmt)))
					if err = flowErr; rr.Code != http.StatusInternalServerError {
						t.Errorf("flow answered %d, want 500", rr.Code)
					}
				}
				if err == nil || !strings.Contains(err.Error(), "is append-only under compliance: hipaa") || !strings.Contains(err.Error(), "may not create a trigger that writes to it") {
					t.Fatalf("error = %v, want the trigger refused", err)
				}
				if after := appSQLGuardSchema(t, app); after != before {
					t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
				}
				// What an auto-CRUD write of the app would do next.
				mustExec(t, app.DB, `INSERT OR REPLACE INTO notes (id, body) VALUES (7, 'x')`)
				if got := appSQLGuardText(t, app, `SELECT group_concat(id || ':' || user_email) FROM _benmore_audit_log`); got != "1:a@example.com" {
					t.Errorf("audit rows = %q, want the one row unchanged", got)
				}
			})
		}
	}

	// Not a trigger that writes an audit table: a trigger that reads one, a
	// column named like one, and an audit INSERT of the same step that comes
	// after a trigger's END or after a DROP TRIGGER.
	fine := []string{
		"CREATE TRIGGER notes_read AFTER INSERT ON notes BEGIN\n  UPDATE notes SET body = (SELECT action FROM _benmore_audit_log WHERE id = 1) WHERE id = NEW.id;\nEND",
		"CREATE TRIGGER notes_col AFTER UPDATE OF body ON notes BEGIN\n  SELECT 1 AS end;\n  UPDATE notes SET body = 'into _benmore_audit_log' WHERE id = NEW.id;\nEND;\nINSERT INTO _benmore_audit_log (action, table_name) VALUES ('trigger added', 'notes')",
		"DROP TRIGGER IF EXISTS notes_gone;\nINSERT INTO _benmore_audit_log (action, table_name) VALUES ('trigger dropped', 'notes')",
	}
	app := hipaaAppWithoutAuditTriggers(t)
	for i, stmt := range fine {
		if got := sqlTriggerBodyAuditWrite(sqlTokenize(stmt)); got != "" {
			t.Errorf("sqlTriggerBodyAuditWrite(%q) = %q, want none", stmt, got)
		}
		if rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", stmt))); err != nil || rr.Code != http.StatusOK {
			t.Errorf("step %d answered %d (err %v), want 200", i, rr.Code, err)
		}
	}
	if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action LIKE 'trigger %'`); got != "2" {
		t.Errorf("audit rows the steps added = %s, want 2", got)
	}
}

// SQLite compiles a statement again when it is first stepped after another
// connection changed the schema, and asks the authorizer again. A query's
// rows are stepped after the driver call that compiled them has returned,
// where no scope applied: `DROP TRIGGER IF EXISTS` compiled to nothing while
// the trigger was not installed yet, and dropped it at the step.
func TestAppSQLScopeCoversRecompilationAtTheFirstStep(t *testing.T) {
	const drop = `DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`
	ctx := context.Background()

	// The driver's statement cache hands a compiled statement to the next
	// call with the same text, which the authorizer then never sees.
	if dsn := sqliteAppDSN("data.db", "."); strings.Contains(dsn, "_stmt_cache_size") {
		t.Errorf("app connections turn the driver's statement cache on (%s); marked SQL would run without its scope", dsn)
	}

	t.Run("rows of a query", func(t *testing.T) {
		app := hipaaAppWithoutAuditTriggers(t)
		app.DB.SetMaxOpenConns(2)
		conn, err := app.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// A step that starts with SELECT runs through Query, last statement.
		rows, err := conn.QueryContext(ctx, appSQL(app, "SELECT 1; "+drop))
		if err != nil {
			t.Fatalf("compiling the drop of a trigger that is not there: %v", err)
		}
		defer rows.Close()
		if err := ensureAuditAppendOnly(app); err != nil { // on the pool's other connection
			t.Fatal(err)
		}
		for rows.Next() {
		}
		var refused *appSQLRefusedError
		if err := rows.Err(); !errors.As(err, &refused) || !strings.Contains(err.Error(), "may not drop the trigger _benmore_audit_log_no_update") {
			t.Errorf("step error = %v, want the refusal", err)
		}
		rows.Close()
		conn.Close()
		if got := auditTriggerCount(t, app); got != "3" {
			t.Errorf("triggers on the audit log after the step = %s, want 3", got)
		}
	})

	t.Run("prepared statement", func(t *testing.T) {
		app := hipaaAppWithoutAuditTriggers(t)
		app.DB.SetMaxOpenConns(2)
		conn, err := app.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		stmt, err := conn.PrepareContext(ctx, appSQL(app, drop))
		if err != nil {
			t.Fatalf("preparing the drop of a trigger that is not there: %v", err)
		}
		defer stmt.Close()
		if err := ensureAuditAppendOnly(app); err != nil {
			t.Fatal(err)
		}
		var refused *appSQLRefusedError
		if _, err := stmt.ExecContext(ctx); !errors.As(err, &refused) {
			t.Errorf("Exec error = %v, want the refusal", err)
		}
		rows, err := stmt.QueryContext(ctx)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
		if !errors.As(err, &refused) {
			t.Errorf("Query error = %v, want the refusal", err)
		}
		stmt.Close()
		conn.Close()
		if got := auditTriggerCount(t, app); got != "3" {
			t.Errorf("triggers on the audit log after the runs = %s, want 3", got)
		}
	})

	// Rows of app SQL read as before, and a DROP TABLE that reaches its step
	// through Query still takes the table's framework trigger along.
	app := appSQLGuardApp(t, true)
	mustExec(t, app.DB, `INSERT INTO notes (id, body) VALUES (1, 'one'), (2, 'two')`)
	rows, err := app.DB.QueryContext(ctx, appSQL(app, `SELECT id, body FROM notes ORDER BY id`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var id int
		var body string
		if err := rows.Scan(&id, &body); err != nil {
			t.Fatal(err)
		}
		got = append(got, body)
	}
	if err := rows.Err(); err != nil || strings.Join(got, ",") != "one,two" {
		t.Errorf("rows = %v (err %v), want one,two", got, err)
	}
	rows.Close()
	rows, err = app.DB.QueryContext(ctx, appSQL(app, "SELECT 1; DROP TABLE notes"))
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		t.Errorf("DROP TABLE of an app table through Query: %v", err)
	}
	rows.Close()
	if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('notes', '_benmore_ver_notes_update')`); got != "0" {
		t.Errorf("%s of the dropped table and its trigger are still there", got)
	}
}

// cron.yaml SQL gets the write-time finding flow SQL gets: DDL on a framework
// object is refused when the file is written, in a job's `sql:` and in an
// inline step at any depth. The scheduler already refuses the statement each
// time the job runs.
func TestWriteGateRefusesFrameworkDDLInCronSQL(t *testing.T) {
	dir := t.TempDir()
	const drop = `DROP TRIGGER IF EXISTS _benmore_audit_log_no_update`
	files := map[string]string{
		"cron.yaml tidy.sql: ":                           "tidy:\n  schedule: \"every 15m\"\n  sql: \"" + drop + "\"\n",
		"cron.yaml jobs[0] (tidy).sql: ":                 "jobs:\n  - id: tidy\n    schedule: \"every 15m\"\n    sql: \"ALTER TABLE _benmore_users ADD COLUMN plan TEXT\"\n",
		"cron.yaml jobs[0] (tidy).run[0].steps[0].sql: ": "jobs:\n  - id: tidy\n    schedule: \"every 15m\"\n    run:\n      - if: \"1 = 1\"\n        steps:\n          - sql: \"CREATE INDEX i ON _benmore_users (email)\"\n",
		"cron.yaml tidy.steps[1].sql: ":                  "tidy:\n  schedule: \"@daily\"\n  steps:\n    - sql: \"DELETE FROM notes WHERE body IS NULL\"\n    - sql: \"" + drop + "\"\n",
	}
	for where, content := range files {
		msg := validateOnWriteIn(dir, "cron.yaml", content, true)
		if !strings.Contains(msg, where) || !strings.Contains(msg, "a framework object, and the runtime refuses that statement when it runs") {
			t.Errorf("write gate on\n%s= %q, want the framework-object refusal at %q", content, msg, where)
		}
	}
	ok := "tidy:\n  schedule: \"every 15m\"\n  run:\n    - sql: \"CREATE TABLE IF NOT EXISTS my_cache (k TEXT)\"\n    - sql: \"INSERT INTO _benmore_audit_log (action, table_name) VALUES ('tidy', 'notes')\"\n"
	if msg := validateOnWriteIn(dir, "cron.yaml", ok, true); msg != "" {
		t.Errorf("write gate refused app DDL and an audit INSERT in cron.yaml: %s", msg)
	}

	// The run-time control the finding announces.
	app := appSQLGuardApp(t, true)
	cfg, err := parseCronYAML([]byte(files["cron.yaml tidy.sql: "]))
	if err != nil || len(cfg.Jobs) != 1 {
		t.Fatalf("parse cron.yaml: %v", err)
	}
	if err := runCronJob(app, cfg.Jobs[0], nil); err == nil || !strings.Contains(err.Error(), "may not drop the trigger _benmore_audit_log_no_update") {
		t.Errorf("cron job error = %v, want the drop refused", err)
	}
	if got := auditTriggerCount(t, app); got != "3" {
		t.Errorf("triggers on the audit log after the job = %s, want 3", got)
	}

	// A flows.yaml in the old `trigger:` + `steps:` shape is refused whole by
	// the write gate, whatever its SQL.
	legacy := "tamper:\n  trigger: POST /api/tamper\n  steps:\n    - sql: \"" + drop + "\"\n"
	if msg := validateOnWriteIn(dir, "flows.yaml", legacy, true); !strings.Contains(msg, "That shape is no longer accepted at write time") {
		t.Errorf("write gate on a legacy flows.yaml = %q, want the file refused", msg)
	}
}
