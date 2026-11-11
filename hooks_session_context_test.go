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

func TestInjectSessionContextOwnsActAsAndAdminBypass(t *testing.T) {
	cases := []struct {
		name         string
		session      *Session
		actAsGroupID string
		adminBypass  bool
	}{
		{
			name:        "ordinary group member",
			session:     &Session{UserID: 7, Email: "member@example.com", Role: "user", GroupID: "tenant-a"},
			adminBypass: false,
		},
		{
			name:        "unbound platform admin",
			session:     &Session{UserID: 1, Email: "admin@example.com", Role: "admin", GroupID: "platform-home"},
			adminBypass: true,
		},
		{
			name:         "platform admin acting as tenant",
			session:      &Session{UserID: 1, Email: "admin@example.com", Role: "admin", GroupID: "platform-home", ActingAsGroup: "tenant-a"},
			actAsGroupID: "tenant-a",
			adminBypass:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]any{
				"user_act_as_group_id": "spoofed-tenant",
				"user_admin_bypass":    true,
			}
			injectSessionContext(row, tc.session)
			if got, ok := row["user_act_as_group_id"].(string); !ok || got != tc.actAsGroupID {
				t.Fatalf("user_act_as_group_id = %#v, want %q", row["user_act_as_group_id"], tc.actAsGroupID)
			}
			if got, ok := row["user_admin_bypass"].(bool); !ok || got != tc.adminBypass {
				t.Fatalf("user_admin_bypass = %#v, want %t", row["user_admin_bypass"], tc.adminBypass)
			}
		})
	}

	row := map[string]any{"user_act_as_group_id": "spoofed-tenant", "user_admin_bypass": true}
	injectSessionContext(row, nil)
	if row["user_act_as_group_id"] != "" || row["user_admin_bypass"] != false {
		t.Fatalf("sessionless context retained caller values: %#v", row)
	}
	row[submittedFieldsKey] = ",title,"
	row["title"] = "changed"
	if got := submittedHookRow(row, nil); got["user_act_as_group_id"] != "" || got["user_admin_bypass"] != false {
		t.Fatalf("sessionless submitted hook context = %#v", got)
	}
}

// The before_update SQL path receives only submitted columns plus trusted
// session context. This checks the whole CRUD route, including the projection
// through submittedHookRow that field-injection unit tests do not cover.
func TestBeforeUpdateHookReceivesTrustedActAsAndBypass(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "stepin@example.com", "admin", "", "org-b")
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil || actor.ActingAsGroup != "org-b" || actor.IsAdminBypass() {
		t.Fatalf("test session did not resolve as stepped-in admin: %#v", actor)
	}
	if _, err := app.DB.Exec("INSERT INTO notes (id,user_id,title) VALUES (1,?,'before')", actor.UserID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `CREATE TABLE observed_hook_context (
		act_as TEXT, admin_bypass TEXT, group_id TEXT, email TEXT, user_id INTEGER
	)`)
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{
		When: "user_act_as_group_id = 'org-b' AND user_admin_bypass = 0 AND user_group_id = 'org-b'",
		SQL:  `INSERT INTO observed_hook_context VALUES ('{{user_act_as_group_id}}','{{user_admin_bypass}}','{{user_group_id}}','{{user_email}}',{{user_id}})`,
	}}}}
	tok := sid
	for _, body := range []map[string]any{
		{"title": "spoof attempt", "user_act_as_group_id": "foreign", "user_admin_bypass": true},
		{"title": "context omitted"},
	} {
		rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", tok, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("PATCH with body %#v: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM observed_hook_context").Scan(&count); err != nil || count != 2 {
		t.Fatalf("before_update hook executions = %d, err = %v", count, err)
	}
	rows, err := app.DB.Query("SELECT act_as,admin_bypass,group_id,email,user_id FROM observed_hook_context")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var actAs, bypass, groupID, email string
		var userID int64
		if err := rows.Scan(&actAs, &bypass, &groupID, &email, &userID); err != nil {
			t.Fatal(err)
		}
		if actAs != "org-b" || bypass != "0" || groupID != "org-b" || email != "stepin@example.com" || userID != actor.UserID {
			t.Errorf("hook context = (%q,%q,%q,%q,%d), want trusted step-in actor values", actAs, bypass, groupID, email, userID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
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
