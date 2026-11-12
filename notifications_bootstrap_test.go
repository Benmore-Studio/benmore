//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These first/last migrations are copied from a hosted app's fixture at
// migrations/0038_20260803T034150Z_create_platform_operators.sql and
// migrations/0112_20261019T170000Z_purge_job_failed_from_tenant_bells.sql.
const notificationPlatformOperatorsMigration = `-- Migration: create_platform_operators
-- Generated: 20260803T034150Z
--
-- UP --
CREATE TABLE IF NOT EXISTS platform_operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_platform_operators_is_active ON platform_operators(is_active);
CREATE TRIGGER IF NOT EXISTS trg_platform_operators_updated_at_updated
AFTER UPDATE ON platform_operators
FOR EACH ROW BEGIN
  UPDATE platform_operators SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;
END;

-- DOWN --
DROP TABLE IF EXISTS platform_operators;
`

const notificationCleanupMigration = `-- Migration: purge_job_failed_from_tenant_bells
-- Hand-written. EXEC-051 / NTF-010 / UX-032 / CAP-067.
-- flows/job-failure-alert.yaml used to fan operator alerts out to every framework
-- admin (users.role='admin'), who are real tenant users. It now targets active
-- platform_operators only; this removes the rows already delivered to anyone else.
-- Operator rows (active platform_operators) are retained.

-- UP --
DELETE FROM _benmore_notifications
 WHERE type = 'job_failed'
   AND user_id NOT IN (SELECT user_id FROM platform_operators WHERE is_active = 1);

-- DOWN --
-- Deleted notifications are not restored (operator noise by definition).
SELECT 1;
`

const notificationSeedMigration = `-- Migration: notification_bootstrap_test_seed
-- UP --
INSERT INTO platform_operators(user_id, is_active) VALUES (101, 1), (202, 0);
INSERT INTO _benmore_notifications(user_id,title,type) VALUES
  (101, 'active operator', 'job_failed'),
  (202, 'inactive operator', 'job_failed'),
  (303, 'ordinary user', 'job_failed'),
  (303, 'unrelated notification', 'info');
-- DOWN --
SELECT 1;
`

func writeNotificationBootstrapMigrations(t *testing.T, dir string) {
	t.Helper()
	writeTestFile(t, dir, "migrations/0038_20260803T034150Z_create_platform_operators.sql", notificationPlatformOperatorsMigration)
	writeTestFile(t, dir, "migrations/0111_notification_bootstrap_test_seed.sql", notificationSeedMigration)
	writeTestFile(t, dir, "migrations/0112_20261019T170000Z_purge_job_failed_from_tenant_bells.sql", notificationCleanupMigration)
}

func assertNotificationBootstrapRows(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, tc := range []struct {
		title string
		want  int
	}{
		{"active operator", 1},
		{"inactive operator", 0},
		{"ordinary user", 0},
		{"unrelated notification", 1},
	} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_notifications WHERE title=?`, tc.title).Scan(&count); err != nil || count != tc.want {
			t.Fatalf("notification %q count=%d err=%v, want %d", tc.title, count, err, tc.want)
		}
	}
}

func TestLoadAppBootstrapsNotificationsBeforeUserMigrations(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("fixture must start without data.db, stat err=%v", err)
	}
	writeNotificationBootstrapMigrations(t, dir)

	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("fresh load with notification cleanup migration: %v", err)
	}
	assertNotificationBootstrapRows(t, app.DB)
	app.Shutdown()

	app, err = loadApp(dir)
	if err != nil {
		t.Fatalf("repeated load was not idempotent: %v", err)
	}
	defer app.Shutdown()
	assertNotificationBootstrapRows(t, app.DB)
	for _, name := range []string{
		"0038_20260803T034150Z_create_platform_operators.sql",
		"0111_notification_bootstrap_test_seed.sql",
		"0112_20261019T170000Z_purge_job_failed_from_tenant_bells.sql",
	} {
		var applied int
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name=?`, name).Scan(&applied); err != nil || applied != 1 {
			t.Fatalf("migration %s ledger count=%d err=%v, want 1", name, applied, err)
		}
	}
}

func TestReloadBootstrapsNotificationsBeforeUserMigrations(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if _, err := app.DB.Exec(`DROP TABLE IF EXISTS _benmore_notifications`); err != nil {
		t.Fatal(err)
	}
	writeNotificationBootstrapMigrations(t, app.Dir)

	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("reload with notification cleanup migration: %v", err)
	}
	assertNotificationBootstrapRows(t, app.DB)
}

func TestNotificationBootstrapDoesNotHideUnrelatedMigrationFailure(t *testing.T) {
	dir := t.TempDir()
	// On a database that already holds the app's tables: one that is new in
	// the load skips a statement that only names a table the schema lacks
	// (migrate_new_database.go).
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	first, err := loadApp(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if _, err := first.DB.Exec(`DROP TABLE IF EXISTS _benmore_notifications`); err != nil {
		t.Fatal(err)
	}
	first.Shutdown()
	writeTestFile(t, dir, "migrations/0999_missing_dependency.sql", `-- UP --
DELETE FROM unrelated_missing_table;
-- DOWN --
SELECT 1;
`)
	if app, err := loadApp(dir); err == nil {
		app.Shutdown()
		t.Fatal("migration against an unrelated missing table was accepted")
	} else if !strings.Contains(err.Error(), "unrelated_missing_table") {
		t.Fatalf("unexpected migration failure: %v", err)
	}

	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if exists, err := tableExists(db, notificationsTable); err != nil || !exists {
		t.Fatalf("notifications bootstrap missing after unrelated migration failure: exists=%v err=%v", exists, err)
	}
}
