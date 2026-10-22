//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ceilingGuardApp opens an app database with a 128 KiB ceiling the way a
// hosted app process does.
func ceilingGuardApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	withDBStorageLimit(t, dir, 128<<10)
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	return app
}

// The ceiling is a per-connection pragma, and app SQL runs on those same
// connections. A transactional flow keeps every step on one connection, so a
// step that raised max_page_count let the next step write past the ceiling.
func TestFlowSQLCannotLiftStorageCeiling(t *testing.T) {
	app := ceilingGuardApp(t)
	flow := &Flow{
		Name:        "save-note",
		Transaction: true,
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/save-note"},
		Steps: []FlowStep{
			{Name: "lift", Type: "sql", SQL: "PRAGMA max_page_count = 1000000"},
			{Name: "big", Type: "sql", SQL: "INSERT INTO notes (body) VALUES (:body)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	payload, _ := json.Marshal(map[string]string{"body": strings.Repeat("n", 512<<10)})
	req := httptest.NewRequest(http.MethodPost, "/api/save-note", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rec, req)
	var n int
	if err := app.DB.QueryRow("SELECT count(*) FROM notes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 || rec.Code == http.StatusOK {
		t.Fatalf("flow lifted the ceiling and wrote 512 KiB past 128 KiB: status=%d rows=%d", rec.Code, n)
	}
}

// Every pragma that would lift or reset the ceiling is refused on every
// schema; reading them still works.
func TestStorageCeilingPragmasCannotBeSet(t *testing.T) {
	app := ceilingGuardApp(t)
	app.DB.SetMaxOpenConns(1)
	for _, stmt := range []string{
		"PRAGMA max_page_count = 1000000",
		"PRAGMA main.max_page_count = 1000000",
		"PRAGMA temp.max_page_count = 1000000",
		"PRAGMA page_size = 65536",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA temp_store = 1",
		"pragma MAX_PAGE_COUNT=1000000",
	} {
		if _, err := app.DB.Exec(stmt); err == nil || !strings.Contains(err.Error(), "not authorized") {
			t.Errorf("%s: got %v, want not authorized", stmt, err)
		}
	}
	var pages int64
	if err := app.DB.QueryRow("PRAGMA max_page_count").Scan(&pages); err != nil {
		t.Fatalf("reading max_page_count: %v", err)
	}
	if pageSize := storagePragma(t, app.DB, "page_size"); pages*pageSize > 128<<10 {
		t.Fatalf("ceiling moved: %d pages of %d bytes", pages, pageSize)
	}
	if err := app.DB.QueryRow("SELECT max_page_count FROM pragma_max_page_count").Scan(&pages); err != nil {
		t.Fatalf("pragma_max_page_count read: %v", err)
	}
}

// TEMP tables live in a separate file the main ceiling does not count; they
// are bounded per connection too.
func TestTempSchemaIsBoundedUnderCeiling(t *testing.T) {
	app := ceilingGuardApp(t)
	app.DB.SetMaxOpenConns(1)
	mustExec(t, app.DB, "CREATE TEMP TABLE scratch (v TEXT)")
	var err error
	for i := 0; i < 1000; i++ {
		if _, err = app.DB.Exec("INSERT INTO scratch (v) VALUES (?)", strings.Repeat("t", 4000)); err != nil {
			break
		}
	}
	if !isStorageFullError(err) {
		t.Fatalf("temp table grew past the ceiling: last error %v", err)
	}
}

// Connections to a database with no limit get no authorizer: nothing
// changes for self-hosted and framework-edition apps.
func TestUncappedDatabaseKeepsPragmas(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA temp_store = MEMORY"); err != nil {
		t.Fatalf("uncapped database refused a pragma: %v", err)
	}
}
