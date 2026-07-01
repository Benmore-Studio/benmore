//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCrudScopeSQLGolden(t *testing.T) {
	groupApp := &App{
		Group:  &GroupConfig{Key: "org_id"},
		Tables: []Table{{Name: "records", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}}}},
	}
	ownerApp := &App{
		Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}}}},
	}
	memberApp := &App{
		Tables: []Table{
			{Name: "rooms", Columns: []Column{{Name: "id"}}},
			{Name: "room_members", Columns: []Column{{Name: "room_id"}, {Name: "member_id"}}},
		},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"rooms": {"all": "member-of:room_members(room_id, member_id)"},
		}},
	}

	groupUser := &Session{Role: "user", UserID: 10, Email: "g@example.com", GroupID: "org-a"}
	ownerUser := &Session{Role: "user", UserID: 20, Email: "o@example.com"}

	cases := []struct {
		name      string
		app       *App
		table     string
		session   *Session
		action    string
		predicate string
		args      []any
	}{
		{
			name:      "group edit",
			app:       groupApp,
			table:     "records",
			session:   groupUser,
			action:    "edit",
			predicate: "(org_id = ? OR id IN (SELECT resource_id FROM _benmore_permissions WHERE resource_type = ? AND grant_type = 'user' AND grantee_id = ? AND permission IN ('edit','admin') AND (expires_at IS NULL OR expires_at > datetime('now'))))",
			args:      []any{"org-a", "records", "g@example.com"},
		},
		{
			name:      "owner delete",
			app:       ownerApp,
			table:     "notes",
			session:   ownerUser,
			action:    "delete",
			predicate: "(user_id = ? OR id IN (SELECT resource_id FROM _benmore_permissions WHERE resource_type = ? AND grant_type = 'user' AND grantee_id = ? AND permission IN ('delete','admin') AND (expires_at IS NULL OR expires_at > datetime('now'))))",
			args:      []any{int64(20), "notes", "o@example.com"},
		},
		{
			name:      "member view",
			app:       memberApp,
			table:     "rooms",
			session:   groupUser,
			action:    "view",
			predicate: "(EXISTS (SELECT 1 FROM room_members WHERE room_members.room_id = rooms.id AND room_members.member_id = ?) OR id IN (SELECT resource_id FROM _benmore_permissions WHERE resource_type = ? AND grant_type = 'user' AND grantee_id = ? AND permission IN ('view','edit','delete','admin') AND (expires_at IS NULL OR expires_at > datetime('now'))))",
			args:      []any{int64(10), "rooms", "g@example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pred, args, bypass := rowScopeClause(tc.app, tc.table, tc.session, tc.action)
			if bypass {
				t.Fatal("did not expect bypass")
			}
			if pred != tc.predicate {
				t.Fatalf("predicate mismatch\n got: %s\nwant: %s", pred, tc.predicate)
			}
			if len(args) != len(tc.args) {
				t.Fatalf("args = %v, want %v", args, tc.args)
			}
			for i := range args {
				if args[i] != tc.args[i] {
					t.Fatalf("args = %v, want %v", args, tc.args)
				}
			}
		})
	}
}

func TestCrudScopeBehavior_CrossTenantIsolation(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	groupAToken := createCrudScopeSession(t, app, "group-a@example.com", "user", "org-a", "")
	adminActingBToken := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "org-b")

	assertListIDs(t, mux, groupAToken, "/api/records", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/records/2", groupAToken, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/records/2", groupAToken, map[string]any{"title": "leak"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/records/2", groupAToken, nil, http.StatusNotFound)

	assertListIDs(t, mux, adminActingBToken, "/api/records", []float64{2})
	assertStatus(t, mux, http.MethodGet, "/api/records/1", adminActingBToken, nil, http.StatusNotFound)

	batchUpdate := crudScopeRequest(t, mux, http.MethodPatch, "/api/records/batch", groupAToken, map[string]any{
		"ids":    []any{1, 2},
		"fields": map[string]any{"title": "group-a-only"},
	})
	if batchUpdate.Code != http.StatusOK {
		t.Fatalf("batch update status = %d body=%s", batchUpdate.Code, batchUpdate.Body.String())
	}
	var updated map[string]any
	mustDecodeBody(t, batchUpdate, &updated)
	if updated["updated"] != float64(1) {
		t.Fatalf("batch update affected %v rows, want 1", updated["updated"])
	}
	assertRecordTitle(t, app.DB, 1, "group-a-only")
	assertRecordTitle(t, app.DB, 2, "b")

	tx := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", groupAToken, map[string]any{
		"operations": []any{
			map[string]any{"table": "records", "action": "update", "id": 2, "data": map[string]any{"title": "tx-leak"}},
		},
	})
	if tx.Code != http.StatusBadRequest {
		t.Fatalf("transaction status = %d body=%s", tx.Code, tx.Body.String())
	}
	assertRecordTitle(t, app.DB, 2, "b")

	batchDelete := crudScopeRequest(t, mux, http.MethodDelete, "/api/records/batch", groupAToken, map[string]any{
		"ids": []any{1, 2},
	})
	if batchDelete.Code != http.StatusOK {
		t.Fatalf("batch delete status = %d body=%s", batchDelete.Code, batchDelete.Body.String())
	}
	var deleted map[string]any
	mustDecodeBody(t, batchDelete, &deleted)
	if deleted["deleted"] != float64(1) {
		t.Fatalf("batch delete affected %v rows, want 1", deleted["deleted"])
	}
	assertRowExists(t, app.DB, "records", 1, false)
	assertRowExists(t, app.DB, "records", 2, true)
}

func TestCrudScopeBehavior_OwnerAndAnonIsolation(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	ownerToken := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")

	assertListIDs(t, mux, ownerToken, "/api/notes", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/notes/2", ownerToken, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/notes/2", ownerToken, map[string]any{"title": "owner-leak"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/notes/2", ownerToken, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/records", "", nil, http.StatusUnauthorized)
}

func newCrudScopeTestApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	crudScopeMustExec(t, db, `CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)
	crudScopeMustExec(t, db, `INSERT INTO records (org_id, user_id, title) VALUES ('org-a', 1, 'a'), ('org-b', 2, 'b')`)
	crudScopeMustExec(t, db, `INSERT INTO notes (user_id, title) VALUES (1, 'owner-a'), (2, 'owner-b')`)

	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Key: "org_id"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"records": {"all": "group"},
		}},
		Tables: []Table{
			{Name: "records", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "title"}}},
			{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "title"}}},
		},
	}
	return app, buildAppMux(app, true, "http://localhost")
}

func createCrudScopeSession(t *testing.T, app *App, email, role, groupID, actingAsGroup string) string {
	t.Helper()
	if app == nil {
		t.Fatal("app is required")
	}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	result, err := app.DB.Exec(
		"INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)",
		email[:len(email)-len("@example.com")], email, role,
	)
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := result.LastInsertId()
	sessionID := CreateSession(app.DB, userID, email, groupID, time.Hour)
	if actingAsGroup != "" {
		if _, err := app.DB.Exec("UPDATE _benmore_sessions SET acting_as_group = ? WHERE id = ?", actingAsGroup, sessionID); err != nil {
			t.Fatal(err)
		}
	}
	return sessionID
}

func crudScopeRequest(t *testing.T, mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func assertListIDs(t *testing.T, mux *http.ServeMux, token, path string, want []float64) {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	mustDecodeBody(t, rec, &rows)
	if len(rows) != len(want) {
		t.Fatalf("list returned %d rows, want %d: %#v", len(rows), len(want), rows)
	}
	for i, id := range want {
		if rows[i]["id"] != id {
			t.Fatalf("row %d id = %v, want %v; rows=%#v", i, rows[i]["id"], id, rows)
		}
	}
}

func assertStatus(t *testing.T, mux *http.ServeMux, method, path, token string, body any, want int) {
	t.Helper()
	rec := crudScopeRequest(t, mux, method, path, token, body)
	if rec.Code != want {
		t.Fatalf("%s %s status = %d, want %d; body=%s", method, path, rec.Code, want, rec.Body.String())
	}
}

func assertRecordTitle(t *testing.T, db *sql.DB, id int, want string) {
	t.Helper()
	var got string
	if err := db.QueryRow("SELECT title FROM records WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("records/%d title = %q, want %q", id, got, want)
	}
}

func assertRowExists(t *testing.T, db *sql.DB, table string, id int, want bool) {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE id = ?", id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if (got > 0) != want {
		t.Fatalf("%s/%d exists = %v, want %v", table, id, got > 0, want)
	}
}

func crudScopeMustExec(t *testing.T, db *sql.DB, stmt string) {
	t.Helper()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatal(err)
	}
}

func mustDecodeBody(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}
