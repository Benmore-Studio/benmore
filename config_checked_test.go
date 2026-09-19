//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigRejectedBeforeStartupAndReloadMutation(t *testing.T) {
	cases := []struct{ name, path, source string }{
		{"app syntax", "app.yaml", "auth: ["},
		{"app documents", "app.yaml", "theme: blue\n---\nauth: ["},
		{"auth shape", "app.yaml", "auth: [required]"},
		{"auth value", "app.yaml", "auth: {oauth_only: [true]}"},
		{"access shape", "app.yaml", "access: {notes: [admin]}"},
		{"roles shape", "app.yaml", "roles: {admin: {scopes: {all: true}}}"},
		{"groups incomplete", "app.yaml", "groups: {table: members}"},
		{"backup interval", "app.yaml", "backup: {interval: hourly}"},
		{"backup too fast", "app.yaml", "backup: {interval: 1s}"},
		{"backup retention", "app.yaml", "backup: {interval: 1h, keep: 0}"},
		{"backup typo", "app.yaml", "backup: {interval: 1h, kepp: 3}"},
		{"hooks syntax", "hooks.yaml", "before_insert: ["},
		{"hooks shape", "hooks.yaml", "before_insert: {notes: false}"},
		{"hooks nested", "hooks.yaml", "before_insert: {notes: [{email: []}]}"},
		{"flows syntax", "flows.yaml", "on: ["},
		{"flow partial", "flows/broken.yaml", "on: {request: {path: /api/broken}}\njobs: ["},
		{"cron shape", "cron.yaml", "jobs: {cleanup: {schedule: '@daily', flow: cleanup}}"},
		{"cron partial", "cron.yaml", "good: {schedule: '@daily', sql: 'SELECT 1'}\nbroken: {flow: cleanup}"},
		{"cron schedule", "cron.yaml", "cleanup: {schedule: '90 * * * *', sql: 'SELECT 1'}"},
		{"cron action", "cron.yaml", "cleanup: {schedule: '@daily', run: [{query_typo: 'SELECT 1'}]}"},
		{"encryption shape", "encrypted.yaml", "tables: {notes: {field: [body]}}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, tc.path, tc.source)
			if msg := ValidateOnWriteIn(dir, tc.path, tc.source); msg == "" {
				t.Fatal("write validator accepted malformed config")
			}
			if report := RunCompleteCheck(dir, tc.path); report.Clean() {
				t.Fatal("app check accepted malformed config")
			}
			if _, err := loadApp(dir); err == nil {
				t.Fatal("startup accepted malformed config")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("invalid config reached DB initialization: %v", err)
			}
			app, cleanup := newTestApp(t)
			defer cleanup()
			app.Stop = make(chan struct{})
			defer close(app.Stop)
			oldDesign := &DesignConfig{CSS: "existing"}
			oldBackup := &BackupConfig{Interval: time.Hour, Keep: 9}
			app.Design, app.Backup = oldDesign, oldBackup
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist(id INTEGER);")
			writeTestFile(t, app.Dir, tc.path, tc.source)
			if err := hotReloadApp(app, false); err == nil {
				t.Fatal("reload accepted malformed config")
			}
			if app.Design != oldDesign || app.Backup != oldBackup {
				t.Fatal("invalid config replaced working settings")
			}
			select {
			case <-app.Stop:
				t.Fatal("invalid config stopped existing workers")
			default:
			}
			var count int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid config reached migration: count=%d err=%v", count, err)
			}
		})
	}
}

func TestConfigCompatibilityAndIntentionalRemoval(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "app.yaml", "theme: blue\nroles: {viewer: [notes:read]}\nbackup: {interval: 2h, keep: 7}\n")
	writeTestFile(t, app.Dir, "hooks.yaml", "before_insert: {notes: [{sql: 'SELECT 1'}]}")
	writeTestFile(t, app.Dir, "flows.yaml", "legacy:\n  trigger: POST /api/legacy\n  steps:\n    - sql: SELECT 1\n")
	writeTestFile(t, app.Dir, "flows/modern.yaml", "on: {request: {method: POST, path: /api/modern}}\njobs: {execute: {steps: [{query: 'SELECT 1'}]}}")
	writeTestFile(t, app.Dir, "cron.yaml", "cleanup: {schedule: '@daily', sql: 'SELECT 1'}")
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.Backup == nil || app.Backup.Keep != 7 || app.Backup.Interval != 2*time.Hour || app.Design.Colors["_theme"] != "blue" {
		t.Fatal("app or backup settings lost")
	}
	if len(app.Flows) != 2 || app.Hooks == nil || app.Cron == nil || len(app.Cron.Jobs) != 1 {
		t.Fatal("legacy and modern configuration were not both loaded")
	}
	for _, path := range []string{"app.yaml", "hooks.yaml", "flows.yaml", "flows/modern.yaml", "cron.yaml"} {
		if err := os.Remove(filepath.Join(app.Dir, path)); err != nil {
			t.Fatal(err)
		}
	}
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.Design != nil || app.Backup != nil || app.Hooks != nil || len(app.Flows) != 0 || app.Cron != nil {
		t.Fatal("intentional removal retained stale settings")
	}
}

func TestConfigUnreadableIsNotMissing(t *testing.T) {
	for _, path := range []string{"app.yaml", "hooks.yaml", "cron.yaml", "workflows.yaml", "encrypted.yaml", "flows"} {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			if path == "flows" {
				writeTestFile(t, dir, path, "not a directory")
			} else if err := os.Mkdir(filepath.Join(dir, path), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("read failure treated as missing: %v", err)
			}
		})
	}
}
