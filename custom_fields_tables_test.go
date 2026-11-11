//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The custom-field API adds columns only to the app's own model tables, the
// tables auto-CRUD serves. A version-history table took the column (201,
// altering <table>_history behind the versioning triggers), and a full-text
// index or sqlite_sequence failed inside ALTER TABLE with a 500.
func TestCustomFieldsRefuseFrameworkDerivedTables(t *testing.T) {
	app, _ := newCrudScopeTestApp(t)
	admin := createCrudScopeSession(t, app, "fields-admin@example.com", "admin", "", "")
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"records"}}); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, "CREATE VIRTUAL TABLE notes_fts USING fts5(title)")
	mux := http.NewServeMux()
	RegisterCustomFieldRoutes(mux, app)
	add := func(table string) (int, map[string]any) {
		t.Helper()
		w := crudScopeRequest(t, mux, http.MethodPost, "/api/_schema/"+table+"/fields", admin, map[string]any{"name": "extra", "type": "TEXT"})
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: non-JSON answer %d %q", table, w.Code, w.Body.String())
		}
		return w.Code, out
	}
	hasExtra := func(table string) bool {
		t.Helper()
		cols, err := GetTableColumns(app.DB, table)
		if err != nil {
			t.Fatal(err)
		}
		return versionHasColumn(cols, "extra")
	}

	for _, table := range []string{"records_history", "notes_fts", "notes_fts_data", "sqlite_sequence"} {
		code, out := add(table)
		msg, _ := out["error"].(string)
		if code != http.StatusBadRequest || !strings.Contains(msg, "only to the app's own model tables") {
			t.Errorf("%s: %d %v, want 400 naming the app-table rule", table, code, out)
		}
		if hasExtra(table) {
			t.Errorf("%s was altered", table)
		}
	}
	if code, _ := add("ghosts"); code != http.StatusNotFound {
		t.Errorf("missing table: %d, want 404", code)
	}
	if code, _ := add("_benmore_users"); code != http.StatusForbidden {
		t.Errorf("framework table: %d, want 403", code)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_custom_fields"); n != "0" {
		t.Fatalf("refused fields were tracked: %s", n)
	}

	// An app table still takes the field, and its history follows it.
	if code, out := add("records"); code != http.StatusCreated {
		t.Fatalf("records: %d %v", code, out)
	}
	if !hasExtra("records") || !hasExtra("records_history") {
		t.Fatal("app table field did not reach the table and its history")
	}
}
