//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// {{user_group_id}} is session context: the request never chooses it. An
// update body carries arbitrary keys into the before-hook row, so a caller
// with no tenant could otherwise name one, and a stepped-in admin saw their
// native tenant instead of the one they act as.
func TestInjectSessionContextOwnsGroupID(t *testing.T) {
	row := map[string]any{"user_group_id": "victim-tenant"}
	injectSessionContext(row, &Session{UserID: 7, Email: "u@example.com", Role: "user"})
	if v, ok := row["user_group_id"]; ok {
		t.Fatalf("group-less session kept a request-supplied user_group_id %v", v)
	}

	row = map[string]any{"user_group_id": "victim-tenant"}
	injectSessionContext(row, &Session{UserID: 7, Email: "u@example.com", Role: "user", GroupID: "A"})
	if row["user_group_id"] != "A" {
		t.Fatalf("member of A: user_group_id = %v", row["user_group_id"])
	}

	row = map[string]any{}
	injectSessionContext(row, &Session{UserID: 1, Email: "a@example.com", Role: "admin", GroupID: "home", ActingAsGroup: "T"})
	if row["user_group_id"] != "T" {
		t.Fatalf("admin acting as T: user_group_id = %v", row["user_group_id"])
	}
}

// End to end: a before_update guard that admits only tenant B's members
// must not be satisfied by a PATCH body that names tenant B.
func TestBeforeUpdateHookGroupIDNotForgeable(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureAuditLogTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsurePermissionsTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT NOT NULL, user_id INTEGER NOT NULL)")
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)")
	app.Tables = []Table{
		{Name: "members", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}}},
		{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}}},
	}
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{
		"notes": {{SQL: "SELECT 'tenant B members only' AS error WHERE NOT ({{user_group_id}} = 'B')"}},
	}}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('solo', 'solo@example.com', 'user', 1)")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	if _, err := app.DB.Exec("INSERT INTO notes (id, user_id, title) VALUES (1, ?, 'mine')", uid); err != nil {
		t.Fatalf("insert note: %v", err)
	}
	sid := CreateSession(app.DB, uid, "solo@example.com", "", time.Hour)

	r := httptest.NewRequest("PATCH", "https://app.example.com/api/notes/1", strings.NewReader(`{"title":"changed","user_group_id":"B"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	handleUpdate(w, r, app, "notes")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("forged user_group_id passed the tenant guard: %d %s", w.Code, w.Body.String())
	}
	var title string
	app.DB.QueryRow("SELECT title FROM notes WHERE id = 1").Scan(&title)
	if title != "mine" {
		t.Fatalf("guarded update applied: title = %q", title)
	}
}
