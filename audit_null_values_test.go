//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// An insert has no prior row and a delete no resulting one. Those columns
// held an empty string, neither absent nor JSON: `old_values IS NULL` missed
// them and json_extract(old_values, ...) raised "malformed JSON".
func TestAuditAbsentValuesAreNull(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, flag TEXT)")
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Tables:          []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "flag"}}}},
	}
	t.Cleanup(func() {
		app.Shutdown()
		db.Close()
	})
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")

	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", token, map[string]any{"flag": "a"}); rec.Code >= 300 {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", token, map[string]any{"flag": "b"}); rec.Code >= 300 {
		t.Fatalf("update: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodDelete, "/api/notes/1", token, nil); rec.Code >= 300 {
		t.Fatalf("delete: status %d body %s", rec.Code, rec.Body.String())
	}

	want := map[string]struct{ oldNull, newNull bool }{
		"insert": {oldNull: true, newNull: false},
		"update": {oldNull: false, newNull: false},
		"delete": {oldNull: false, newNull: true},
	}
	rows, err := db.Query("SELECT action, old_values, new_values FROM _benmore_audit_log WHERE table_name = 'notes'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var action string
		var oldValues, newValues sql.NullString
		if err := rows.Scan(&action, &oldValues, &newValues); err != nil {
			t.Fatal(err)
		}
		w, ok := want[action]
		if !ok {
			t.Fatalf("unexpected audit action %q", action)
		}
		seen[action] = true
		for _, c := range []struct {
			name     string
			value    sql.NullString
			wantNull bool
		}{{"old_values", oldValues, w.oldNull}, {"new_values", newValues, w.newNull}} {
			if c.wantNull {
				if c.value.Valid {
					t.Errorf("%s %s = %q, want NULL", action, c.name, c.value.String)
				}
				continue
			}
			if !c.value.Valid || !json.Valid([]byte(c.value.String)) {
				t.Errorf("%s %s = %#v, want a JSON row", action, c.name, c.value)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for action := range want {
		if !seen[action] {
			t.Errorf("no %s audit row was written", action)
		}
	}
}

// Every writer shares one insert, the impersonated branch included.
func TestAuditWritersStoreNullForAbsentRow(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)
	impersonated := &Session{UserID: 2, Email: "user@example.com", ImpersonatorUserID: 1, ImpersonatorEmail: "admin@example.com"}
	row := map[string]any{"a": 1}

	LogAudit(app, "w1", "t", "1", nil, nil, row)
	LogAuditDB(app.DB, "w2", "t", "1", nil, row, nil)
	if err := insertAuditRowChecked(app.DB, "w3", "t", "1", impersonated, "", `{"a":1}`); err != nil {
		t.Fatal(err)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := LogAuditTx(tx, app, "w4", "t", "1", nil, row, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	for action, wantOldNull := range map[string]bool{"w1": true, "w2": false, "w3": true, "w4": false} {
		var oldNull, newNull bool
		if err := app.DB.QueryRow("SELECT old_values IS NULL, new_values IS NULL FROM _benmore_audit_log WHERE action = ?", action).Scan(&oldNull, &newNull); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if oldNull != wantOldNull || newNull == wantOldNull {
			t.Errorf("%s: old IS NULL = %v, new IS NULL = %v, want the absent side only", action, oldNull, newNull)
		}
	}
}
