//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A before-update row holds the columns the request writes, never other
// body keys: `old_<col>`, `user_role` and friends are context the framework
// supplies, and a body that names them must not satisfy a `when:` guard such
// as `stage = 'held' AND old_stage IS NOT 'held'` (old_ values are unset in
// a before-hook, so the guard applies unless the caller claims otherwise).
func TestBeforeUpdateHookRowIgnoresUnknownBodyKeys(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureAuditLogTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsurePermissionsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, stage TEXT, note TEXT)")
	app.Tables = []Table{{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "stage"}, {Name: "note"}}}}
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{
		"notes": {{SQL: "SELECT 'held notes need approval' AS error", When: "stage = 'held' AND old_stage IS NOT 'held'"}},
	}}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('solo', 'solo@example.com', 'user', 1)")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	mustExec(t, app.DB, "INSERT INTO notes (id, user_id, stage, note) VALUES (1, "+strconv.FormatInt(uid, 10)+", 'open', 'x')")
	sid := CreateSession(app.DB, uid, "solo@example.com", "", time.Hour)

	for _, body := range []string{
		`{"stage":"held","old_stage":"held"}`,
		`{"stage":"held","old_stage":"held","extra":"x"}`,
	} {
		r := httptest.NewRequest("PATCH", "https://app.example.com/api/notes/1", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handleUpdate(w, r, app, "notes")
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("body %s skipped the guard: %d %s", body, w.Code, w.Body.String())
		}
	}
	var stage string
	app.DB.QueryRow("SELECT stage FROM notes WHERE id = 1").Scan(&stage)
	if stage != "open" {
		t.Fatalf("guarded update applied: stage = %q", stage)
	}

	// Batch update takes the same row shape.
	r := httptest.NewRequest("PATCH", "https://app.example.com/api/notes/batch", strings.NewReader(`{"ids":[1],"fields":{"stage":"held","old_stage":"held"}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	handleBatchUpdate(w, r, app, "notes")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("batch body skipped the guard: %d %s", w.Code, w.Body.String())
	}
}
