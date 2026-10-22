//go:build !cli && !windows

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const appTriggerSchema = `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);
CREATE TABLE task_log (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, note TEXT NOT NULL);
`

const appTriggerMigration = `CREATE TRIGGER task_done_log AFTER UPDATE ON tasks FOR EACH ROW WHEN NEW.status = 'done'
BEGIN
  INSERT INTO task_log(task_id, note) VALUES (NEW.id, CASE WHEN NEW.completed_by IS NULL THEN 'anon' ELSE 'actor' END);
END;
`

func appTriggerFlow(declare bool) string {
	if !declare {
		return commandTaskFlowFixture
	}
	return strings.Replace(commandTaskFlowFixture, "  writes: [tasks, activities]\n", "  writes: [tasks, activities]\n  app_triggers:\n    - {table: tasks, name: task_done_log}\n", 1)
}

func newAppTriggerFixture(t *testing.T, migration string, declare bool) (*App, string) {
	t.Helper()
	app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, appTriggerFlow(declare), "", func(_ *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "schema.sql", appTriggerSchema)
		writeTestFile(t, dir, "migrations/0001_task_log_trigger.sql", migration)
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	return app, sessionID
}

func initializeAppTriggerEnrollment(app *App) (*appMCPRevisionEnrollment, error) {
	return initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app))
}

func TestAppMCPDeclaredAppTriggerIsAcceptedEnrollsItsWritesAndFires(t *testing.T) {
	app, sessionID := newAppTriggerFixture(t, appTriggerMigration, true)
	var sqlText string
	if err := app.DB.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name='task_done_log'`).Scan(&sqlText); err != nil || sqlText == "" {
		t.Fatalf("fixture migration did not create the trigger: %q %v", sqlText, err)
	}
	enrollment, err := initializeAppTriggerEnrollment(app)
	if err != nil {
		t.Fatalf("declared, unchanged app trigger was refused: %v", err)
	}
	if !reflect.DeepEqual(enrollment.TableNames, []string{"activities", "members", "task_log", "tasks"}) {
		t.Fatalf("the table the trigger writes was not enrolled: %v", enrollment.TableNames)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("enable writes with an enrolled app trigger: %v", err)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("command apply through the declared trigger: %v", err)
	}
	var note string
	if err := app.DB.QueryRow(`SELECT note FROM task_log WHERE task_id=1`).Scan(&note); err != nil || note != "actor" {
		t.Fatalf("declared trigger did not write its enrolled table: %q %v", note, err)
	}
}

func TestAppMCPAppTriggerThatIsChangedUndeclaredOrReservedStaysRefused(t *testing.T) {
	t.Run("modified after review", func(t *testing.T) {
		app, _ := newAppTriggerFixture(t, appTriggerMigration, true)
		if _, err := app.DB.Exec(`DROP TRIGGER task_done_log`); err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec(`CREATE TRIGGER task_done_log AFTER UPDATE ON tasks FOR EACH ROW WHEN NEW.status = 'done'
BEGIN
  INSERT INTO task_log(task_id, note) VALUES (NEW.id, 'actor');
  DELETE FROM members;
END`); err != nil {
			t.Fatal(err)
		}
		if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), "unrecognized or changed trigger") {
			t.Fatalf("a trigger that differs from the reviewed migration was accepted: %v", err)
		}
	})
	t.Run("undeclared", func(t *testing.T) {
		app, _ := newAppTriggerFixture(t, appTriggerMigration, false)
		if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), "unrecognized or changed trigger") {
			t.Fatalf("an undeclared app trigger was accepted: %v", err)
		}
	})
	t.Run("declared but never created by a migration", func(t *testing.T) {
		app, _ := newAppTriggerFixture(t, "SELECT 1;\n", true)
		if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), "not created by the reviewed migrations") {
			t.Fatalf("a declaration with no reviewed CREATE TRIGGER was accepted: %v", err)
		}
	})
	t.Run("writes a framework table", func(t *testing.T) {
		migration := strings.Replace(appTriggerMigration, "INSERT INTO task_log(task_id, note) VALUES (NEW.id, CASE WHEN NEW.completed_by IS NULL THEN 'anon' ELSE 'actor' END)", "INSERT INTO _benmore_users(email) VALUES ('x@example.com')", 1)
		app, _ := newAppTriggerFixture(t, migration, true)
		if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), "reserved table") {
			t.Fatalf("a trigger writing a framework table was accepted: %v", err)
		}
	})
	t.Run("writes with OR REPLACE", func(t *testing.T) {
		migration := strings.Replace(appTriggerMigration, "INSERT INTO", "INSERT OR REPLACE INTO", 1)
		app, _ := newAppTriggerFixture(t, migration, true)
		if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), "OR REPLACE") {
			t.Fatalf("a trigger body that replaces rows was accepted: %v", err)
		}
	})
}

func TestAppMCPMigrationTriggersUseTheLastStatementAndOnlyMainTriggers(t *testing.T) {
	sources := map[string][]byte{
		"migrations/0001_a.sql":   []byte("CREATE TABLE t(id INTEGER);\nCREATE TRIGGER IF NOT EXISTS a_trg AFTER INSERT ON t BEGIN SELECT CASE WHEN 1 THEN 2 END; END;\nCREATE TEMP TRIGGER tmp_trg AFTER INSERT ON t BEGIN SELECT 1; END;\n-- DOWN --\nCREATE TRIGGER down_trg AFTER INSERT ON t BEGIN SELECT 1; END;"),
		"migrations/0002_b.sql":   []byte("DROP TRIGGER a_trg;\nCREATE TRIGGER b_trg AFTER DELETE ON t BEGIN DELETE FROM t2 WHERE id = OLD.id; UPDATE t3 SET n = n + 1; END;\n"),
		"migrations/0003_c.sql":   []byte("DROP TRIGGER IF EXISTS b_trg;"),
		"migrations/x.failed.sql": []byte("CREATE TRIGGER failed_trg AFTER INSERT ON t BEGIN SELECT 1; END;"),
		"schema.sql":              []byte("CREATE TRIGGER schema_trg AFTER INSERT ON t BEGIN SELECT 1; END;"),
	}
	got, err := appMCPMigrationTriggers(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !got["a_trg"].dropped || !got["b_trg"].dropped {
		t.Fatalf("a later DROP must end a trigger's source: %+v", got)
	}
	for _, absent := range []string{"tmp_trg", "down_trg", "failed_trg", "schema_trg"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("%s is not a main-schema trigger the runtime creates from a migration", absent)
		}
	}
	sources["migrations/0003_c.sql"] = []byte("SELECT 1;")
	got, err = appMCPMigrationTriggers(sources)
	if err != nil {
		t.Fatal(err)
	}
	b := got["b_trg"]
	if b.err != nil || b.dropped || b.table != "t" || !reflect.DeepEqual(b.events, []string{"delete"}) ||
		!reflect.DeepEqual(b.writes, []sqlWrite{{Table: "t2", Action: "delete"}, {Table: "t3", Action: "update"}}) {
		t.Fatalf("trigger effects misread: %+v", b)
	}
	if !strings.HasPrefix(b.sql, "CREATE TRIGGER b_trg") || !strings.HasSuffix(b.sql, "END") {
		t.Fatalf("trigger SQL must be the exact statement without its terminator: %q", b.sql)
	}
}

func TestFlowCommandAppTriggersShapeIsClosed(t *testing.T) {
	tables := map[string]bool{"tasks": true, "activities": true, "members": true, "projects": true, "_hidden": true}
	parse := func(entries string) error {
		source := strings.Replace(commandTaskFlowFixture, "  writes: [tasks, activities]\n", "  writes: [tasks, activities]\n  app_triggers:\n"+entries, 1)
		_, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), tables)
		return err
	}
	if err := parse("    - {table: tasks, name: task_done_log}\n"); err != nil {
		t.Fatalf("valid declaration refused: %v", err)
	}
	for name, entries := range map[string]string{
		"unknown table":    "    - {table: nope, name: a}\n",
		"underscore table": "    - {table: _hidden, name: a}\n",
		"framework name":   "    - {table: tasks, name: _benmore_enc_x}\n",
		"sqlite name":      "    - {table: tasks, name: sqlite_x}\n",
		"non identifier":   "    - {table: tasks, name: 'a b'}\n",
		"duplicate":        "    - {table: tasks, name: A}\n    - {table: activities, name: a}\n",
		"extra key":        "    - {table: tasks, name: a, sql: 'x'}\n",
		"missing name":     "    - {table: tasks}\n",
		"scalar entry":     "    - task_done_log\n",
	} {
		if err := parse(entries); err == nil {
			t.Fatalf("%s: declaration accepted", name)
		}
	}
}

func TestAppMCPAppTriggerThatReadsALookupTableEnrollsItAndFires(t *testing.T) {
	migration := `CREATE TRIGGER task_done_log AFTER UPDATE ON tasks FOR EACH ROW WHEN NEW.status = 'done' AND EXISTS (SELECT 1 FROM projects WHERE projects.id = NEW.project_id)
BEGIN
  INSERT INTO task_log(task_id, note) SELECT NEW.id, 'org ' || org_id FROM projects WHERE id = NEW.project_id;
END;
`
	app, sessionID := newAppTriggerFixture(t, migration, true)
	enrollment, err := initializeAppTriggerEnrollment(app)
	if err != nil {
		t.Fatalf("a trigger that reads a lookup table was refused: %v", err)
	}
	if !reflect.DeepEqual(enrollment.TableNames, []string{"activities", "members", "projects", "task_log", "tasks"}) {
		t.Fatalf("the table the trigger reads was not enrolled: %v", enrollment.TableNames)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("enable writes: %v", err)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("command apply through a trigger that reads a lookup table: %v", err)
	}
	var note string
	if err := app.DB.QueryRow(`SELECT note FROM task_log WHERE task_id=1`).Scan(&note); err != nil || note != "org 17" {
		t.Fatalf("trigger did not read its lookup table: %q %v", note, err)
	}
}

func TestAppMCPAppTriggerReadsAndFunctionsAreCheckedAtEnrollment(t *testing.T) {
	for name, tc := range map[string]struct{ from, to, want string }{
		"reads a framework table":  {"NEW.status = 'done'", "EXISTS (SELECT 1 FROM _benmore_users)", "reserved table"},
		"reads a non-app table":    {"NEW.status = 'done'", "EXISTS (SELECT 1 FROM sqlite_schema)", "reserved table"},
		"unlisted function":        {"NEW.status = 'done'", "randomblob(4) IS NOT NULL", "calls function \"randomblob\""},
		"unlisted function (body)": {"NEW.completed_by IS NULL", "random() > 0", "calls function \"random\""},
		"bare current_date":        {"NEW.status = 'done'", "current_date IS NOT NULL", "current_date"},
		"comma join":               {"NEW.status = 'done'", "EXISTS (SELECT 1 FROM projects, members)", "comma joins"},
	} {
		t.Run(name, func(t *testing.T) {
			migration := strings.Replace(appTriggerMigration, tc.from, tc.to, 1)
			app, _ := newAppTriggerFixture(t, migration, true)
			if _, err := initializeAppTriggerEnrollment(app); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal mentioning %q at enrollment, got %v", tc.want, err)
			}
		})
	}
}

func TestAppMCPTriggerFunctionErrorReadsCallsNotKeywords(t *testing.T) {
	ok := []string{
		"AFTER INSERT ON t BEGIN INSERT INTO main.t2(a, b) VALUES (1, 2) ON CONFLICT(a) DO UPDATE SET b = 3; END",
		"AFTER INSERT ON t WHEN NEW.a IN (1, 2) AND NOT EXISTS (SELECT 1 FROM u) BEGIN SELECT RAISE(ABORT, 'x') WHERE CAST(NEW.a AS TEXT) = coalesce(NEW.b, datetime('now', current_timestamp)); END",
		"AFTER INSERT ON t WHEN benmore_today('America/New_York') IS NOT NULL BEGIN SELECT 1; END",
	}
	for _, sql := range ok {
		if err := appMCPTriggerFunctionError(sqlTokenize(sql)); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if err := appMCPTriggerFunctionError(sqlTokenize("AFTER INSERT ON t BEGIN SELECT load_extension('x'); END")); err == nil {
		t.Fatal("an unlisted function call was accepted")
	}
}
