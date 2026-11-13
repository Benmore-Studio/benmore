//go:build !cli

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// guardMigrationFile runs sqlText as the one pending file of the app's
// migrations/ directory through the runner a start and a reload use. hipaa
// writes `compliance: hipaa` to the app's app.yaml: that, not the triggers,
// is what the runner goes by.
func guardMigrationFile(t *testing.T, app *App, hipaa bool, sqlText string) error {
	t.Helper()
	yaml := "site_name: guard\n"
	if hipaa {
		yaml += "compliance: hipaa\n"
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "app.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(app.Dir, "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "migrations", "0001_change.sql"), []byte(sqlText), 0o644); err != nil {
		t.Fatal(err)
	}
	return RunMigrations(app.DB, app.Dir)
}

// guardMigrationApp is appSQLGuardApp with a framework trigger on a framework
// table, as the MFA and connector tables carry.
func guardMigrationApp(t *testing.T, hipaa bool) *App {
	t.Helper()
	app := appSQLGuardApp(t, hipaa)
	mustExec(t, app.DB, `CREATE TRIGGER _benmore_users_probe AFTER INSERT ON _benmore_users BEGIN SELECT 1; END`)
	// The runner's ledger, so a refused file leaves the schema as it found it.
	mustExec(t, app.DB, `CREATE TABLE _benmore_migrations (name TEXT PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	return app
}

// runGuardMigration runs one migration file's text the way the runner does,
// in one transaction that commits only when every statement ran.
func runGuardMigration(t *testing.T, app *App, sqlText string) error {
	t.Helper()
	tx, err := app.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runMigrationStatementsTx(context.Background(), tx, []byte(sqlText)); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return nil
}

// A user migration took the append-only triggers out through the schema
// table and then rewrote an audit row: the text check on audit tables applies
// only while the triggers exist, and nothing refused writable_schema.
func TestMigrationCannotUnseatAuditTriggersThroughWritableSchema(t *testing.T) {
	app := appSQLGuardApp(t, true)
	before := appSQLGuardSchema(t, app)
	err := runGuardMigration(t, app, `PRAGMA writable_schema=ON;
DELETE FROM sqlite_master WHERE type='trigger' AND (name LIKE '%no_update' OR name LIKE '%no_delete' OR name LIKE '%no_overwrite');
PRAGMA writable_schema=RESET;
UPDATE _benmore_audit_log SET user_email='tampered@example.com';`)
	if err == nil || !strings.Contains(err.Error(), "writable_schema") {
		t.Errorf("migration error = %v, want the writable_schema refusal", err)
	}
	if after := appSQLGuardSchema(t, app); after != before {
		t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := appSQLGuardText(t, app, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "a@example.com" {
		t.Errorf("audit row 1 user_email = %q, want it unchanged", got)
	}
}

// What takes a framework control away is refused in a migration of every
// app, whatever the statement looks like, and the file changes nothing.
func TestMigrationRefusesToRemoveFrameworkControls(t *testing.T) {
	statements := map[string]string{
		"writable_schema":                    `PRAGMA writable_schema = 1;`,
		"writable_schema, main.":             "/* tidy */ PRAGMA main.writable_schema(ON);",
		"second statement":                   "CREATE TABLE extra (id INTEGER PRIMARY KEY);\nPRAGMA writable_schema = ON;",
		"trigger under a framework name":     `CREATE TRIGGER "_benmore_enc_notes_body_insert" AFTER INSERT ON notes BEGIN SELECT 1; END;`,
		"framework trigger, framework table": `DROP TRIGGER main.[_benmore_users_probe];`,
		"framework table with its trigger":   `DROP TABLE _benmore_users;`,
		"temp table of a framework name":     `CREATE TEMP TABLE _benmore_users (id INTEGER PRIMARY KEY, email TEXT);`,
		"temp view of a framework name":      `CREATE TEMP VIEW _benmore_jobs AS SELECT 1 AS id;`,
	}
	for _, hipaa := range []bool{true, false} {
		for name, stmt := range statements {
			label := name
			if hipaa {
				label += "/hipaa"
			}
			t.Run(label, func(t *testing.T) {
				app := guardMigrationApp(t, hipaa)
				before := appSQLGuardSchema(t, app)
				err := guardMigrationFile(t, app, hipaa, stmt)
				if err == nil || !strings.Contains(err.Error(), "a migration may not") || !strings.Contains(err.Error(), `api(at:"schema.framework_tables")`) {
					t.Fatalf("migration error = %v, want the refusal in words with its docs address", err)
				}
				if after := appSQLGuardSchema(t, app); after != before {
					t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
				}
				if got := appSQLGuardText(t, app, `PRAGMA writable_schema`); got != "0" {
					t.Errorf("writable_schema = %s after the refused file", got)
				}
			})
		}
	}
}

// For a hipaa app a migration cannot change the audit tables or their rows.
// The decision comes from the app's app.yaml: the triggers are gone here, so
// neither they nor the text check that depends on them can be what refuses.
func TestMigrationCannotRewriteAuditHistoryOfAHIPAAApp(t *testing.T) {
	statements := map[string]string{
		"update":             `UPDATE _benmore_audit_log SET user_email = 'tampered@example.com';`,
		"update, quoted":     `UPDATE main."_BENMORE_audit_log" SET user_email = 'tampered@example.com' WHERE id = 1;`,
		"delete":             `DELETE FROM _benmore_audit_log;`,
		"cte delete":         `WITH x AS (SELECT 1 AS id) DELETE FROM _benmore_audit_log WHERE id IN (SELECT id FROM x);`,
		"replace into":       `REPLACE INTO _benmore_audit_log (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com');`,
		"insert or replace":  `INSERT OR REPLACE INTO [_benmore_audit_log] (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com');`,
		"upsert":             `INSERT INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'x', 'y') ON CONFLICT (id) DO UPDATE SET user_email = 'tampered@example.com';`,
		"alter":              `ALTER TABLE _benmore_audit_log ADD COLUMN note TEXT;`,
		"rename away":        `ALTER TABLE _benmore_audit_log RENAME TO audit_old;`,
		"drop":               `DROP TABLE _benmore_read_audit;`,
		"trigger on it":      `CREATE TRIGGER sink BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(IGNORE); END;`,
		"temp trigger on it": `CREATE TEMP TRIGGER sink BEFORE INSERT ON main._benmore_read_audit BEGIN SELECT RAISE(IGNORE); END;`,
		"unique index on it": `CREATE UNIQUE INDEX one_action ON _benmore_audit_log (action);`,
		"trigger body updates": `CREATE TRIGGER notes_rewrite AFTER INSERT ON notes BEGIN UPDATE _benmore_audit_log SET user_email = 'tampered@example.com'; END;
INSERT INTO notes (body) VALUES ('x');`,
		"trigger body replaces": `CREATE TRIGGER notes_rewrite AFTER INSERT ON notes WHEN CASE WHEN NEW.id > 0 THEN 1 END BEGIN
  INSERT INTO notes (body) SELECT CASE WHEN 1 THEN 'a' END;
  INSERT OR REPLACE INTO main._benmore_audit_log (id, action, table_name, user_email) VALUES (1, 'x', 'y', 'tampered@example.com');
END;`,
	}
	for name, stmt := range statements {
		t.Run(name, func(t *testing.T) {
			app := guardMigrationApp(t, false) // no triggers: a restored file, or a first hipaa start
			before := appSQLGuardSchema(t, app)
			err := guardMigrationFile(t, app, true, stmt)
			if err == nil || !strings.Contains(err.Error(), "is append-only under compliance: hipaa: a migration may not") || !strings.Contains(err.Error(), `api(at:"schema.framework_tables")`) {
				t.Fatalf("migration error = %v, want the append-only refusal with its docs address", err)
			}
			if after := appSQLGuardSchema(t, app); after != before {
				t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if got := appSQLGuardText(t, app, `SELECT group_concat(id || ':' || user_email) FROM _benmore_audit_log`); got != "1:a@example.com" {
				t.Errorf("audit rows = %q, want the one row unchanged", got)
			}
		})
	}

	// An app that is not hipaa keeps what its migrations could do to the
	// audit log.
	plain := guardMigrationApp(t, false)
	if err := guardMigrationFile(t, plain, false, `UPDATE _benmore_audit_log SET user_email = 'fixed@example.com' WHERE id = 1;`); err != nil {
		t.Fatalf("audit UPDATE in a migration of a non-hipaa app: %v", err)
	}
	if got := appSQLGuardText(t, plain, `SELECT user_email FROM _benmore_audit_log WHERE id = 1`); got != "fixed@example.com" {
		t.Errorf("audit row = %q, want the update applied on a non-hipaa app", got)
	}
}

// What live migrations do to framework objects keeps working, hipaa or not:
// a column and an index on a framework table, an app-named trigger on one,
// row writes, dropping a framework trigger from an app table, a table rebuild
// that takes such triggers along, and a view over a framework table.
func TestMigrationKeepsItsSchemaWorkOnFrameworkTables(t *testing.T) {
	const file = `ALTER TABLE _benmore_users ADD COLUMN plan TEXT;
CREATE INDEX IF NOT EXISTS users_plan ON _benmore_users (plan);
CREATE TRIGGER trg_users_signup AFTER INSERT ON _benmore_users BEGIN
  INSERT INTO notes (body) VALUES (NEW.email);
END;
INSERT INTO _benmore_users (email, plan) VALUES ('m@example.com', 'pro');
UPDATE _benmore_users SET plan = 'free' WHERE email = 'm@example.com';
DROP TRIGGER trg_users_signup;
DROP TRIGGER IF EXISTS _benmore_ver_notes_update;
CREATE TABLE notes_new (id INTEGER PRIMARY KEY, body TEXT, extra TEXT);
INSERT INTO notes_new (id, body) SELECT id, body FROM notes;
DROP TABLE notes;
ALTER TABLE notes_new RENAME TO notes;
DROP TABLE docs;
CREATE VIEW user_emails AS SELECT email FROM _benmore_users;
CREATE TEMP TABLE scratch (x);
DROP TABLE scratch;
CREATE TABLE _benmore_app_cache (k TEXT PRIMARY KEY);
`
	for _, hipaa := range []bool{true, false} {
		app := guardMigrationApp(t, hipaa)
		mustExec(t, app.DB, `CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT)`)
		mustExec(t, app.DB, `CREATE TRIGGER _benmore_enc_docs_body_insert AFTER INSERT ON docs BEGIN SELECT 1; END`)
		if err := guardMigrationFile(t, app, hipaa, file); err != nil {
			t.Fatalf("hipaa=%t: %v", hipaa, err)
		}
		if got := appSQLGuardText(t, app, `SELECT plan FROM _benmore_users WHERE email = 'm@example.com'`); got != "free" {
			t.Errorf("hipaa=%t: plan = %q, want free", hipaa, got)
		}
		if got := appSQLGuardText(t, app, `SELECT body || ':' || COALESCE(extra, '-') FROM notes`); got != "m@example.com:-" {
			t.Errorf("hipaa=%t: rebuilt notes row = %q, want the trigger's row with the new column", hipaa, got)
		}
		if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('_benmore_ver_notes_update', '_benmore_enc_docs_body_insert', 'docs', 'trg_users_signup')`); got != "0" {
			t.Errorf("hipaa=%t: %s of the dropped objects are still there", hipaa, got)
		}
		if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('users_plan', 'user_emails', '_benmore_app_cache', '_benmore_users_probe')`); got != "4" {
			t.Errorf("hipaa=%t: %s of 4 expected objects exist", hipaa, got)
		}
		if got := appSQLGuardText(t, app, `SELECT COUNT(*) FROM _benmore_migrations WHERE name = '0001_change.sql'`); got != "1" {
			t.Errorf("hipaa=%t: the file was not recorded as applied", hipaa)
		}
	}
}

// Under hipaa, flow SQL cannot create a trigger whose body would write audit
// rows when a later write fires it: that write is the framework's own and
// runs outside the app SQL scope. Any trigger of an app that is not hipaa is
// fine.
func TestAppSQLCannotCreateATriggerThatRewritesAuditRows(t *testing.T) {
	bodies := map[string]string{
		"insert or replace": `INSERT OR REPLACE INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'x', 'y')`,
		"replace":           `REPLACE INTO main."_benmore_audit_log" (id, action, table_name) VALUES (1, 'x', 'y')`,
		"update":            `UPDATE OR IGNORE _benmore_read_audit SET user_email = 'x'`,
		"delete":            `DELETE FROM [_benmore_audit_log] WHERE id = 1`,
		"upsert":            `INSERT INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'x', 'y') ON CONFLICT (id) DO UPDATE SET action = 'z'`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			app := appSQLGuardApp(t, true)
			before := appSQLGuardSchema(t, app)
			stmt := "CREATE TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  INSERT INTO notes (body) VALUES ('copy');\n  " + body + ";\nEND"
			rr, err := runExpectRowsFlow(t, app, expectRowsFlow("", sqlStepYAML("s", "sql", stmt)))
			if err == nil || rr.Code != http.StatusInternalServerError || !strings.Contains(err.Error(), "may not create a trigger that writes to it") {
				t.Fatalf("flow answered %d (err %v), want the trigger refused", rr.Code, err)
			}
			if after := appSQLGuardSchema(t, app); after != before {
				t.Errorf("the schema changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
	// An app that is not hipaa keeps its triggers, one that adds an audit row
	// included.
	adds := "CREATE TRIGGER notes_added AFTER INSERT ON notes BEGIN\n  INSERT INTO _benmore_audit_log (action, table_name, row_id) VALUES ('note', 'notes', NEW.id);\nEND"
	plain := appSQLGuardApp(t, false)
	rewrites := "CREATE TRIGGER notes_audit AFTER INSERT ON notes BEGIN\n  " + bodies["update"] + ";\nEND"
	if rr, err := runExpectRowsFlow(t, plain, expectRowsFlow("", sqlStepYAML("s", "sql", rewrites)+sqlStepYAML("a", "sql", adds))); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("the triggers on a non-hipaa app answered %d (err %v), want 200", rr.Code, err)
	}

	for text, want := range map[string]string{
		`CREATE TRIGGER t AFTER UPDATE OF body ON notes BEGIN SELECT 1; END`:                                                                                                                 "",
		`CREATE TRIGGER t AFTER INSERT ON notes BEGIN SELECT 'UPDATE _benmore_audit_log SET x = 1'; END`:                                                                                     "",
		`CREATE TRIGGER t AFTER INSERT ON notes BEGIN INSERT INTO notes (body) VALUES ('x') ON CONFLICT DO UPDATE SET body = 'y'; INSERT INTO _benmore_audit_log (action) VALUES ('a'); END`: "_benmore_audit_log",
		`CREATE TRIGGER t AFTER INSERT ON notes BEGIN UPDATE notes SET body = (SELECT action FROM _benmore_audit_log); END`:                                                                  "",
		`CREATE TRIGGER t AFTER INSERT ON notes BEGIN SELECT CASE WHEN 1 THEN 2 END; DELETE /* x */ FROM "_benmore_read_audit"; END`:                                                         "_benmore_read_audit",
		`CREATE TEMP TRIGGER t AFTER INSERT ON notes WHEN CASE WHEN 1 THEN 1 END BEGIN UPDATE main._benmore_audit_log SET action = 'x'; END`:                                                 "_benmore_audit_log",
	} {
		if got := sqlTriggerBodyAuditWrite(sqlTokenize(text)); got != want {
			t.Errorf("sqlTriggerBodyAuditWrite(%q) = %q, want %q", text, got, want)
		}
	}
}
