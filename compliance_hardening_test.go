//go:build !cli

package main

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appendOnlyAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE _benmore_audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, table_name TEXT NOT NULL, row_id TEXT, user_email TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE _benmore_read_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT NOT NULL, row_id TEXT, query_type TEXT NOT NULL, user_id INTEGER NOT NULL, user_email TEXT NOT NULL)`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email) VALUES ('insert', 'notes', '1', 'a@example.com')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := installAuditAppendOnly(db); err != nil {
		t.Fatal(err)
	}
	return db
}

// A migration could drop an append-only trigger and create a no-op under the
// same name (or add one that discards new rows); the next install, which runs
// at every start and reload, restores the framework's triggers exactly.
func TestAuditAppendOnlyRestoresReplacedTriggers(t *testing.T) {
	db := appendOnlyAuditTestDB(t)
	for _, stmt := range []string{
		`DROP TRIGGER "_benmore_audit_log_no_update"`,
		`CREATE TRIGGER "_benmore_audit_log_no_update" BEFORE UPDATE ON "_benmore_audit_log" BEGIN SELECT 1; END`,
		`CREATE TRIGGER audit_sink BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(IGNORE); END`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE _benmore_audit_log SET user_email = 'x'`); err != nil {
		t.Fatalf("setup: the no-op trigger should let the update through: %v", err)
	}
	if err := installAuditAppendOnly(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE _benmore_audit_log SET user_email = 'y'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("replaced trigger not restored: %v", err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='audit_sink'`).Scan(&n)
	if n != 0 {
		t.Fatal("foreign trigger on an append-only table was kept")
	}
	if _, err := db.Exec(`INSERT INTO _benmore_audit_log (action, table_name) VALUES ('insert', 'notes')`); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log`).Scan(&n)
	if n != 2 {
		t.Fatalf("audit rows = %d, want 2", n)
	}
	for _, table := range auditAppendOnlyTables {
		for _, kind := range auditAppendOnlyKinds {
			var stored string
			if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, auditTriggerName(table, kind)).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != auditTriggerSQL(table, kind) {
				t.Fatalf("stored trigger text %q differs from %q: every install would recreate it", stored, auditTriggerSQL(table, kind))
			}
		}
	}
}

// REPLACE deletes the conflicting row through conflict resolution, which fires
// no DELETE trigger; the BEFORE INSERT trigger refuses it first.
func TestAuditAppendOnlyRefusesReplaceByID(t *testing.T) {
	db := appendOnlyAuditTestDB(t)
	for _, stmt := range []string{
		`REPLACE INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'forged', 'notes')`,
		`INSERT OR REPLACE INTO _benmore_audit_log (id, action, table_name) VALUES (1, 'forged', 'notes')`,
	} {
		if _, err := db.Exec(stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	var action string
	db.QueryRow(`SELECT action FROM _benmore_audit_log WHERE id = 1`).Scan(&action)
	if action != "insert" {
		t.Fatalf("audit row overwritten: %q", action)
	}
	if _, err := db.Exec(`INSERT INTO _benmore_audit_log (action, table_name) VALUES ('update', 'notes')`); err != nil {
		t.Fatalf("an ordinary insert was refused: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO _benmore_audit_log (id, action, table_name) VALUES (100, 'update', 'notes')`); err != nil {
		t.Fatalf("an insert with a new explicit id was refused: %v", err)
	}
	// The framework's maintenance path still deletes and rewrites.
	if _, err := execAuditMutable(db, `DELETE FROM _benmore_audit_log WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM _benmore_audit_log`); err == nil {
		t.Fatal("triggers not restored after the maintenance path")
	}
}

// Once the triggers exist, a user migration or seeds.sql may not name an
// audit table.
func TestAuditAppendOnlyRefusesMigrationAndSeedStatements(t *testing.T) {
	db := appendOnlyAuditTestDB(t)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = runMigrationStatementsTx(context.Background(), tx, []byte(`DROP TRIGGER "_benmore_audit_log_no_update";`))
	tx.Rollback()
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("migration naming an audit trigger: %v", err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "seeds.sql"), []byte(`CREATE TRIGGER s BEFORE INSERT ON _benmore_read_audit BEGIN SELECT RAISE(IGNORE); END;`), 0o644)
	// resetAppDataLocked is the one path that runs seeds.sql (app_reset.go).
	if _, err := resetAppDataLocked(context.Background(), db, dir); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("seed naming an audit table: %v", err)
	}
	// A seed that only reads an audit table names it too.
	os.WriteFile(filepath.Join(dir, "seeds.sql"), []byte(`INSERT INTO copies (action) SELECT action FROM _benmore_audit_log;`), 0o644)
	if _, err := resetAppDataLocked(context.Background(), db, dir); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("seed reading an audit table: %v", err)
	}
	// Without the triggers (an app that is not hipaa) nothing changes.
	plain, err := sql.Open("sqlite3_benmore", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	plain.SetMaxOpenConns(1)
	plain.Exec(`CREATE TABLE _benmore_audit_log (id INTEGER PRIMARY KEY, action TEXT)`)
	if err := refuseAuditTableStatement(plain, `DELETE FROM _benmore_audit_log`); err != nil {
		t.Fatal(err)
	}
}

func idleTestApp(t *testing.T, timeout string) (*App, string) {
	t.Helper()
	app := ipv6LockoutApp(t)
	app.Design.Auth["idle_timeout"] = timeout
	if _, err := app.DB.Exec(`INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('idle', 'idle@example.com', 'x', 'user', 1)`); err != nil {
		t.Fatal(err)
	}
	var uid int64
	app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email = 'idle@example.com'`).Scan(&uid)
	token := CreateSession(app.DB, uid, "idle@example.com", "", time.Hour)
	if token == "" {
		t.Fatal("no session")
	}
	return app, token
}

// A tab's own polling (a live query's refetch, a heartbeat) is marked by
// bm.js and must not keep an unattended session alive.
func TestIdleTimeoutIgnoresBackgroundRequests(t *testing.T) {
	app, token := idleTestApp(t, "15m")
	s := GetSessionFromDB(app.DB, token)
	if s == nil {
		t.Fatal("session not found")
	}
	old := time.Now().Add(-10 * time.Minute).Unix()
	app.DB.Exec(`UPDATE _benmore_sessions SET last_seen_at = ? WHERE id = ?`, old, s.ID)
	lastSeen := func() int64 {
		var v int64
		app.DB.QueryRow(`SELECT last_seen_at FROM _benmore_sessions WHERE id = ?`, s.ID).Scan(&v)
		return v
	}

	bg := httptest.NewRequest("POST", "/api/_query", nil)
	bg.Header.Set(backgroundRequestHeader, "1")
	if getAppSession(app, bg, token) == nil {
		t.Fatal("a background request within the timeout lost the session")
	}
	if lastSeen() != old {
		t.Fatal("a background request counted as activity")
	}
	if getAppSession(app, httptest.NewRequest("GET", "/api/notes", nil), token) == nil {
		t.Fatal("an active session was refused")
	}
	if lastSeen() <= old {
		t.Fatal("an ordinary request did not count as activity")
	}

	// Past the timeout a background request ends the session like any other.
	app.DB.Exec(`UPDATE _benmore_sessions SET last_seen_at = ? WHERE id = ?`, time.Now().Add(-20*time.Minute).Unix(), s.ID)
	if getAppSession(app, bg, token) != nil {
		t.Fatal("an idle session survived a background request")
	}
}

// Activity is written at most once per idleTouchInterval.
func TestIdleTimeoutTouchIsThrottled(t *testing.T) {
	app, token := idleTestApp(t, "15m")
	s := GetSessionFromDB(app.DB, token)
	recent := time.Now().Add(-10 * time.Second).Unix()
	app.DB.Exec(`UPDATE _benmore_sessions SET last_seen_at = ? WHERE id = ?`, recent, s.ID)
	getAppSession(app, httptest.NewRequest("GET", "/", nil), token)
	var v int64
	app.DB.QueryRow(`SELECT last_seen_at FROM _benmore_sessions WHERE id = ?`, s.ID).Scan(&v)
	if v != recent {
		t.Fatal("last_seen_at written again within the touch interval")
	}
}

// auth.idle_timeout is validated for every app, not only hipaa ones, and a
// malformed value never reads as "off".
func TestIdleTimeoutValidatedForEveryApp(t *testing.T) {
	for _, bad := range []string{"90s", "soon", "-5m"} {
		doc := "auth:\n  idle_timeout: " + bad + "\n"
		if msg := validateAppYAML(doc); !strings.Contains(msg, "idle_timeout") {
			t.Errorf("write gate accepted idle_timeout %q: %q", bad, msg)
		}
		appDir := t.TempDir()
		os.WriteFile(filepath.Join(appDir, "app.yaml"), []byte(doc), 0o644)
		if _, err := stageRuntimeConfig(appDir, nil, false); err == nil || !strings.Contains(err.Error(), "idle_timeout") {
			t.Errorf("loader accepted idle_timeout %q: %v", bad, err)
		}
	}
	for _, good := range []string{"2m", "1h", "1d", "0"} {
		if msg := validateAppYAML("auth:\n  idle_timeout: " + good + "\n"); strings.Contains(msg, "idle_timeout") {
			t.Errorf("write gate refused idle_timeout %q: %q", good, msg)
		}
	}
	// Should a malformed value reach the runtime anyway, a hipaa app keeps
	// its 15m ceiling.
	app := &App{Design: &DesignConfig{Auth: map[string]string{"idle_timeout": "garbage"}, Compliance: complianceHIPAA}}
	if got := idleTimeoutFor(app); got != hipaaMaxIdleTimeout {
		t.Fatalf("malformed idle_timeout under hipaa read as %s, want %s", got, hipaaMaxIdleTimeout)
	}
}

// Under compliance: hipaa every account must enroll MFA at sign-in; without a
// page at the enrollment redirect every account is locked out.
func TestMFASetupPageWarning(t *testing.T) {
	dir := t.TempDir()
	hipaa := []byte("compliance: hipaa\nauth:\n  redirect: /\n")
	if msg := mfaSetupPageWarning(dir, hipaa); !strings.Contains(msg, "/mfa-setup") {
		t.Fatalf("no warning without a setup page: %q", msg)
	}
	os.MkdirAll(filepath.Join(dir, "static"), 0o755)
	os.WriteFile(filepath.Join(dir, "static", "mfa-setup.html"), []byte("<html></html>"), 0o644)
	if msg := mfaSetupPageWarning(dir, hipaa); msg != "" {
		t.Fatalf("warned although static/mfa-setup.html serves the page: %q", msg)
	}
	if msg := mfaSetupPageWarning(dir, []byte("compliance: hipaa\nauth:\n  mfa_setup_redirect: /enroll\n")); !strings.Contains(msg, "/enroll") {
		t.Fatalf("custom redirect not checked: %q", msg)
	}
	if msg := mfaSetupPageWarning(dir, []byte("auth:\n  mfa_setup_redirect: /enroll\n")); msg != "" {
		t.Fatalf("warned for an app that requires no enrollment: %q", msg)
	}
	if msg := mfaSetupPageWarning(t.TempDir(), []byte("compliance: hipaa\n")); msg != "" {
		t.Fatalf("warned for a hipaa app without sign-in: %q", msg)
	}
	if msg := mfaSetupPageWarning(dir, []byte("auth:\n  require_mfa_for_roles: admin\n  mfa_setup_redirect: https://id.example.com/enroll\n")); msg != "" {
		t.Fatalf("absolute redirect should not be checked: %q", msg)
	}
}

// The sticky record refuses an app.yaml that drops the key, through the one
// check the write gate and `benmore check` share.
func TestComplianceRemovalRefusedWhenRecorded(t *testing.T) {
	old := hipaaStickyForAppDir
	t.Cleanup(func() { hipaaStickyForAppDir = old })
	recorded := map[string]bool{}
	hipaaStickyForAppDir = func(dir string) bool { return recorded[dir] }
	dir := t.TempDir()
	if msg := validateOnWriteIn(dir, "app.yaml", "name: x\n", true); strings.Contains(msg, "recorded as `compliance: hipaa`") {
		t.Fatalf("refused for an unrecorded app: %q", msg)
	}
	recorded[dir] = true
	if msg := validateOnWriteIn(dir, "app.yaml", "name: x\n", true); !strings.Contains(msg, "recorded as `compliance: hipaa`") {
		t.Fatalf("removal accepted for a recorded app: %q", msg)
	}
	if msg := validateOnWriteIn(dir, "app.yaml", "name: x\ncompliance: hipaa\n", true); strings.Contains(msg, "recorded as `compliance: hipaa`") {
		t.Fatalf("an app.yaml keeping the key was refused: %q", msg)
	}
}

// Under compliance: hipaa auth.read_audit is "*" or a list of declared
// tables: a value that names no table would audit nothing (write gate,
// `benmore check` and loader share the shape check; the write gate and check
// compare names with the schema; at run time an unknown name audits all).
func TestHIPAAReadAuditValueMustNameTables(t *testing.T) {
	for _, v := range []any{",", false, "", " , ", "notes;drop"} {
		doc := map[string]any{"compliance": "hipaa", "auth": map[string]any{"read_audit": v}}
		if complianceAppYAMLProblem(doc) == "" {
			t.Errorf("read_audit %#v accepted", v)
		}
	}
	for _, v := range []any{"*", "notes", "notes, tasks"} {
		doc := map[string]any{"compliance": "hipaa", "auth": map[string]any{"read_audit": v}}
		if msg := complianceAppYAMLProblem(doc); msg != "" {
			t.Errorf("read_audit %#v refused: %s", v, msg)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  @@map(\"notes\")\n}\n")
	if msg := hipaaReadAuditTablesProblem(dir, "compliance: hipaa\nauth:\n  read_audit: notse\n"); !strings.Contains(msg, `"notse"`) {
		t.Fatalf("unknown table accepted: %q", msg)
	}
	if msg := hipaaReadAuditTablesProblem(dir, "compliance: hipaa\nauth:\n  read_audit: notes\n"); msg != "" {
		t.Fatalf("declared table refused: %s", msg)
	}
	if msg := hipaaReadAuditTablesProblem(dir, "auth:\n  read_audit: notse\n"); msg != "" {
		t.Fatalf("non-hipaa app refused: %s", msg)
	}
	app := &App{Design: &DesignConfig{Compliance: complianceHIPAA, Auth: map[string]string{"read_audit": "notse"}}, Tables: []Table{{Name: "notes"}}}
	if !IsReadAudited(app, "notes") {
		t.Fatal("hipaa read_audit naming no table left notes unaudited")
	}
	app.Design.Compliance = ""
	if IsReadAudited(app, "notes") {
		t.Fatal("non-hipaa app audits a table read_audit does not list")
	}
}

// A hipaa app whose append-only audit triggers cannot be installed does not
// start: ensureAuditAppendOnly returns the failure (the served build refuses
// it in buildAppMuxChecked). It only logged, and the app served with audit
// history that could be rewritten.
func TestHIPAAAuditTriggersFailClosed(t *testing.T) {
	db := appendOnlyAuditTestDB(t)
	// A trigger the framework does not own, which install must drop, on a
	// connection that refuses writes: the install cannot finish.
	if _, err := db.Exec(`CREATE TRIGGER audit_sink BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA query_only = ON`); err != nil {
		t.Fatal(err)
	}
	app := &App{DB: db, Design: &DesignConfig{Compliance: complianceHIPAA}}
	if err := ensureAuditAppendOnly(app); err == nil || !strings.Contains(err.Error(), "append-only audit triggers") {
		t.Fatalf("ensureAuditAppendOnly on a database that refuses the install = %v, want the failure", err)
	}
	app.Design.Compliance = ""
	if err := ensureAuditAppendOnly(app); err != nil {
		t.Fatalf("a non-hipaa app is not checked: %v", err)
	}
}
