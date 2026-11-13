//go:build !cli

package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A file in migrations/ may put a trigger on a framework table, write its
// rows or read it. The start used to create those tables after the files, so
// such an app loaded on every database that already had them and on no new
// one: `benmore test`, a dev database built again, a first promote.

const (
	frameworkTablesSchema = "model Order {\n  id Int @id @default(autoincrement())\n  name String\n  audited Int @default(0)\n}\n"
	frameworkTablesAuth   = "name: orders\nauth:\n  session_duration: 7d\n  signup_fields: company\n"
	frameworkTablesFile   = "0004_framework_tables.sql"
)

// frameworkTablesAuthBody names the tables of an app with sign-in: a trigger
// on the reset links, a role grant for a user the file adds, a column that
// auth.signup_fields declares, and a read of the audit log.
var frameworkTablesAuthBody = strings.Join([]string{
	"CREATE TRIGGER reset_link_quarter_hour AFTER INSERT ON _benmore_password_resets WHEN NEW.type = 'reset' BEGIN",
	"  UPDATE _benmore_password_resets SET expires_at = datetime('now', '+15 minutes') WHERE token = NEW.token;",
	"END;",
	"INSERT INTO _benmore_users (username, email, company) VALUES ('lead', 'lead@example.test', 'Orders Ltd');",
	"INSERT OR IGNORE INTO _benmore_user_roles (user_id, role) SELECT id, 'manager' FROM _benmore_users WHERE email = 'lead@example.test';",
	"INSERT INTO orders (name, audited) SELECT 'first', COUNT(*) FROM _benmore_audit_log;",
	"UPDATE _benmore_users SET totp_secret = NULL;",
	"DELETE FROM _benmore_sessions;",
	"INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission) VALUES ('orders', '1', 'user', 'lead@example.test', 'view');",
	"",
}, "\n")

func frameworkTablesOpen(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationFileNamingFrameworkTablesLoadsOnANewDatabase(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", frameworkTablesAuth)
	writeTestFile(t, dir, "schema.prisma", frameworkTablesSchema)
	writeTestFile(t, dir, "migrations/"+frameworkTablesFile, frameworkTablesAuthBody)
	logged, err := dropFreshLoad(t, dir)
	if err != nil {
		t.Fatalf("a new database does not load: %v\n%s", err, logged)
	}
	if warnings := typeChangeWarnings(logged); len(warnings) != 0 {
		t.Fatalf("a statement was skipped: %v", warnings)
	}
	db := frameworkTablesOpen(t, dir)
	if n := dropFreshLedgerCount(t, db, frameworkTablesFile); n != 1 {
		t.Fatalf("ledger records the file %d times, want 1", n)
	}
	var on string
	if err := db.QueryRow(`SELECT tbl_name FROM sqlite_master WHERE type = 'trigger' AND name = 'reset_link_quarter_hour'`).Scan(&on); err != nil || on != "_benmore_password_resets" {
		t.Fatalf("the trigger is not on the reset links: %q %v", on, err)
	}
	var role, company string
	if err := db.QueryRow(`SELECT r.role, u.company FROM _benmore_user_roles r JOIN _benmore_users u ON u.id = r.user_id WHERE u.email = 'lead@example.test'`).Scan(&role, &company); err != nil || role != "manager" || company != "Orders Ltd" {
		t.Fatalf("the role grant did not land: role=%q company=%q err=%v", role, company, err)
	}
	var orders int
	if err := db.QueryRow(`SELECT COUNT(*) FROM orders WHERE name = 'first' AND audited = 0`).Scan(&orders); err != nil || orders != 1 {
		t.Fatalf("the statement that reads the audit log did not run: %d %v", orders, err)
	}
	// The trigger works on the table as the framework writes it.
	mustExec(t, db, `INSERT INTO _benmore_password_resets (token, email, expires_at) VALUES ('t1', 'lead@example.test', datetime('now', '+1 day'))`)
	var short int
	if err := db.QueryRow(`SELECT datetime(expires_at) < datetime('now', '+1 hour') FROM _benmore_password_resets WHERE token = 't1'`).Scan(&short); err != nil || short != 1 {
		t.Fatalf("the trigger did not fire: %d %v", short, err)
	}

	// The second load of the same source finds everything in place.
	if logged, err := dropFreshLoad(t, dir); err != nil {
		t.Fatalf("second load: %v\n%s", err, logged)
	}
	if n := dropFreshLedgerCount(t, db, frameworkTablesFile); n != 1 {
		t.Fatalf("after the second load the ledger records the file %d times", n)
	}
}

// An app that never gets the sign-in tables still fails on a file that names
// one: the table is not there after the start either. What every app gets
// (the audit log, jobs) is there for it too.
func TestMigrationFileNamingSignInTablesStillFailsWithoutAuth(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for stmt, want := range map[string]string{
		"INSERT OR IGNORE INTO _benmore_user_roles (user_id, role) SELECT id, 'manager' FROM orders;": "no such table: _benmore_user_roles",
		"CREATE TRIGGER reset_seen AFTER INSERT ON _benmore_password_resets BEGIN\n  SELECT 1;\nEND;": "no such table: main._benmore_password_resets",
		"INSERT INTO _benmore_users (username, email) VALUES ('lead', 'lead@example.test');":          "no such table: _benmore_users",
		"DELETE FROM _benmore_sessions;":                                                       "no such table: _benmore_sessions",
		"INSERT INTO orders (name) SELECT 'tokens' FROM _benmore_api_tokens;":                  "no such table: _benmore_api_tokens",
		"INSERT INTO orders (name, audited) SELECT 'first', COUNT(*) FROM _benmore_audit_log;": "",
		"INSERT INTO _benmore_jobs (flow_name, payload) VALUES ('backfill_orders', '{}');":     "",
		// Created for every app, but its rows refer to users: without the
		// users table SQLite refuses a write to it, on any database.
		"DELETE FROM _benmore_permissions WHERE resource_type = 'orders';":                                 "no such table: main._benmore_users",
		"INSERT INTO orders (name) SELECT resource_id FROM _benmore_permissions;":                          "",
		"DELETE FROM _benmore_upload_owners WHERE user_id = 0;":                                            "",
		"UPDATE _benmore_webhooks SET active = 0;":                                                         "",
		"DELETE FROM _benmore_custom_fields WHERE table_name = 'orders';":                                  "",
		"DELETE FROM _benmore_notifications WHERE type = 'job_failed';":                                    "",
		"INSERT INTO orders (name) SELECT 'ledger' WHERE EXISTS (SELECT 1 FROM _benmore_migrations) OR 1;": "",
	} {
		dir := t.TempDir()
		writeTestFile(t, dir, "app.yaml", "name: orders\n")
		writeTestFile(t, dir, "schema.prisma", frameworkTablesSchema)
		writeTestFile(t, dir, "migrations/"+frameworkTablesFile, stmt+"\n")
		logged, err := dropFreshLoad(t, dir)
		if want == "" {
			if err != nil {
				t.Errorf("%s: a table every app gets was not there: %v\n%s", stmt, err, logged)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want a failure naming %q, got %v\n%s", stmt, want, err, logged)
			continue
		}
		if strings.Contains(logged, "skipping") {
			t.Errorf("%s: the statement was skipped\n%s", stmt, logged)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "migrations", frameworkTablesFile+".failed.sql")); statErr != nil {
			t.Errorf("%s: the failed file was not set aside: %v", stmt, statErr)
		}
		db := frameworkTablesOpen(t, dir)
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('_benmore_users', '_benmore_user_roles', '_benmore_password_resets', '_benmore_sessions', '_benmore_api_tokens', '_benmore_login_attempts')`).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: an app without sign-in got %d sign-in tables (%v)", stmt, n, err)
		}
		db.Close()
	}
}

// frameworkTablesState is every framework object of the database with its
// SQL, and the rows of the tables the test filled.
func frameworkTablesState(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT type || ' ' || name || ': ' || COALESCE(sql, '') FROM sqlite_master WHERE tbl_name LIKE '\_benmore\_%' ESCAPE '\' AND tbl_name <> '_benmore_migrations' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT 'user ' || id || ' ' || username || ' ' || email || ' ' || role FROM _benmore_users ORDER BY id`,
		`SELECT 'grant ' || user_id || ' ' || role || ' ' || COALESCE(group_id, '-') FROM _benmore_user_roles ORDER BY 1`,
		`SELECT 'reset ' || token || ' ' || email || ' ' || type || ' ' || used FROM _benmore_password_resets ORDER BY 1`,
		`SELECT 'audit ' || id || ' ' || action || ' ' || table_name FROM _benmore_audit_log ORDER BY id`,
		`SELECT 'session ' || id || ' ' || user_id FROM _benmore_sessions ORDER BY 1`,
	} {
		r, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			var line string
			if err := r.Scan(&line); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
		}
		r.Close()
	}
	return strings.Join(lines, "\n")
}

// A database that already served the app holds these tables with rows in
// them. Creating them before the files instead of after changes neither.
func TestExistingDatabaseKeepsItsFrameworkTablesAsTheyAre(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", frameworkTablesAuth)
	writeTestFile(t, dir, "schema.prisma", frameworkTablesSchema)
	if logged, err := dropFreshLoad(t, dir); err != nil {
		t.Fatalf("first load: %v\n%s", err, logged)
	}
	// What serving it leaves behind: the tables as route registration makes
	// them, and rows.
	db := frameworkTablesOpen(t, dir)
	served := &App{Dir: dir, DB: db, Design: &DesignConfig{Auth: map[string]string{"signup_fields": "company"}}}
	if err := ensureFrameworkTablesBeforeMigrations(db, served.Design, nil, true); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO _benmore_users (username, email, role, company) VALUES ('owner', 'owner@example.test', 'admin', 'Orders Ltd')`)
	mustExec(t, db, `INSERT INTO _benmore_user_roles (user_id, role) VALUES (1, 'manager')`)
	mustExec(t, db, `INSERT INTO _benmore_password_resets (token, email, expires_at) VALUES ('live', 'owner@example.test', datetime('now', '+1 day'))`)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id) VALUES ('create', 'orders', '1')`)
	mustExec(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES ('sha256:`+strings.Repeat("a", 64)+`', 1, 'owner@example.test', datetime('now', '+1 day'))`)
	mustExec(t, db, `INSERT INTO orders (name) VALUES ('kept')`)
	before := frameworkTablesState(t, db)
	if !strings.Contains(before, "user 1 owner") || !strings.Contains(before, "table _benmore_password_resets") {
		t.Fatalf("the fixture is not a served database:\n%s", before)
	}

	// The next start brings a file that names them.
	writeTestFile(t, dir, "migrations/"+frameworkTablesFile, "INSERT OR IGNORE INTO _benmore_user_roles (user_id, role) SELECT id, 'reviewer' FROM _benmore_users WHERE role = 'admin';\n")
	if logged, err := dropFreshLoad(t, dir); err != nil {
		t.Fatalf("load of the existing database: %v\n%s", err, logged)
	}
	after := frameworkTablesState(t, db)
	want := strings.Split(before, "\n")
	want = append(want, "grant 1 reviewer -")
	got := strings.Split(after, "\n")
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the existing database changed beyond the file's own row:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	var kept int
	if err := db.QueryRow(`SELECT COUNT(*) FROM orders WHERE name = 'kept'`).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("application rows changed: %d %v", kept, err)
	}
}

// The names the dry run reads (frameworkTableBeforeMigrations) are the tables
// the start creates, for an app with sign-in and for one without.
func TestFrameworkTablesBeforeMigrationsMatchTheirNames(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for _, auth := range []bool{false, true} {
		dir := t.TempDir()
		db := frameworkTablesOpen(t, dir)
		if err := ensureFrameworkTablesBeforeMigrations(db, nil, nil, auth); err != nil {
			t.Fatal(err)
		}
		for _, name := range frameworkTablesForEveryApp {
			if ok, err := tableExists(db, name); err != nil || !ok {
				t.Errorf("auth=%v: %s was not created (%v)", auth, name, err)
			}
			if !frameworkTableBeforeMigrations(strings.ToUpper(name), false) {
				t.Errorf("%s is not reported as created for an app without sign-in", name)
			}
		}
		for _, name := range frameworkTablesForSignIn {
			if ok, err := tableExists(db, name); err != nil || ok != auth {
				t.Errorf("auth=%v: %s exists=%v (%v)", auth, name, ok, err)
			}
			if frameworkTableBeforeMigrations(name, false) || !frameworkTableBeforeMigrations(name, true) {
				t.Errorf("%s must be reported only for an app with sign-in", name)
			}
		}
		// Nothing but what the lists name.
		rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			if !frameworkTableBeforeMigrations(name, auth) {
				t.Errorf("auth=%v: %s was created and is in no list", auth, name)
			}
		}
		rows.Close()
		db.Close()
	}
	if frameworkTableBeforeMigrations("_benmore_locks", true) || frameworkTableBeforeMigrations("orders", true) {
		t.Error("a table the start creates later, or an application table, is reported")
	}
}

// A reload that brings sign-in together with a file that names its tables:
// the running app never had them.
func TestReloadCreatesFrameworkTablesBeforeItsMigrationFiles(t *testing.T) {
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: orders\n")
	writeTestFile(t, dir, "schema.prisma", frameworkTablesSchema)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.DB.Close() })
	if ok, _ := tableExists(app.DB, "_benmore_user_roles"); ok {
		t.Fatal("an app without sign-in has the role grants table")
	}
	writeTestFile(t, dir, "app.yaml", frameworkTablesAuth)
	writeTestFile(t, dir, "migrations/"+frameworkTablesFile, frameworkTablesAuthBody)
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload: %v", err)
	}
	var role string
	if err := app.DB.QueryRow(`SELECT r.role FROM _benmore_user_roles r JOIN _benmore_users u ON u.id = r.user_id WHERE u.email = 'lead@example.test'`).Scan(&role); err != nil || role != "manager" {
		t.Fatalf("the role grant did not land: %q %v", role, err)
	}
	if n := dropFreshLedgerCount(t, app.DB, frameworkTablesFile); n != 1 {
		t.Fatalf("ledger records the file %d times, want 1", n)
	}
}
