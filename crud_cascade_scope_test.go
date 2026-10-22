//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// newCascadeFixture: posts own comments (comments.post_id), and the grouped
// folders own files (files.folder_id). Every table soft-deletes.
func newCascadeFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	for _, stmt := range []string{
		`CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, deleted_at DATETIME)`,
		`CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER REFERENCES posts(id), user_id INTEGER, body TEXT, pinned INTEGER DEFAULT 0, deleted_at DATETIME)`,
		`CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, email TEXT)`,
		`CREATE TABLE folders (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, name TEXT, deleted_at DATETIME)`,
		`CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, folder_id INTEGER REFERENCES folders(id), org_id TEXT, name TEXT, deleted_at DATETIME)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Table: "members", Key: "org_id", UserField: "email"},
		// Posts are public to read, so anyone may hang a comment on one.
		Access: accessFromYAML(t, "access:\n  posts:\n    read: everyone\n"),
	}
	for _, name := range []string{"posts", "comments", "members", "folders", "files"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.JoinMap = BuildJoinMap(db)
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

func cascadeUser(t *testing.T, app *App, email, org string) (string, int64) {
	t.Helper()
	if org != "" {
		crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO members (org_id, email) VALUES ('%s', '%s')", org, email))
	}
	sid := createCrudScopeSession(t, app, email, "user", org, "")
	var uid int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	return sid, uid
}

func cascadeLive(t *testing.T, app *App, table string, id int) bool {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE id = ? AND deleted_at IS NULL", table), id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// Soft-deleting a parent used to soft-delete every child row pointing at it
// with one unscoped UPDATE: other owners' rows and other tenants' rows went
// with it, no audit row was written and no before-delete hook could object.
// The cascade now deletes exactly the children the caller could delete one by
// one, through the same pipeline.
func TestCascadeSoftDeleteStaysInDeleterScope(t *testing.T) {
	app, mux := newCascadeFixture(t)
	EnsureJobsTable(app.DB)
	aliceSID, alice := cascadeUser(t, app, "alice@example.com", "")
	_, bob := cascadeUser(t, app, "bob@example.com", "")
	for _, stmt := range []string{
		fmt.Sprintf("INSERT INTO posts (id, user_id, title) VALUES (1, %d, 'alice post')", alice),
		fmt.Sprintf("INSERT INTO comments (id, post_id, user_id, body) VALUES (1, 1, %d, 'mine')", alice),
		fmt.Sprintf("INSERT INTO comments (id, post_id, user_id, body) VALUES (2, 1, %d, 'bobs')", bob),
		fmt.Sprintf("INSERT INTO comments (id, post_id, user_id, body, pinned) VALUES (3, 1, %d, 'pinned', 1)", alice),
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	app.Hooks = &HookConfig{
		BeforeDelete: map[string][]Hook{"comments": {{SQL: "SELECT 'pinned comments stay' AS error", When: "pinned = 1"}}},
		OnDelete:     map[string][]Hook{"comments": {{SQL: "SELECT 1"}}},
	}

	assertStatus(t, mux, http.MethodDelete, "/api/posts/1", aliceSID, nil, http.StatusOK)
	if cascadeLive(t, app, "posts", 1) || cascadeLive(t, app, "comments", 1) {
		t.Fatal("the post and its owner's own comment should be soft-deleted")
	}
	if !cascadeLive(t, app, "comments", 2) {
		t.Fatal("the cascade soft-deleted another owner's row")
	}
	if !cascadeLive(t, app, "comments", 3) {
		t.Fatal("the cascade deleted a row its before-delete hook refuses")
	}
	var audits, hooks int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name = 'comments' AND action = 'delete' AND row_id = '1' AND user_id = ?", alice).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("cascaded child delete wrote %d audit rows, want 1", audits)
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'").Scan(&hooks); err != nil {
		t.Fatal(err)
	}
	if hooks != 1 {
		t.Fatalf("after-delete hooks queued for the cascaded child = %d, want 1", hooks)
	}
}

// A child row in another tenant that points at this tenant's parent is not
// the deleter's to remove; batch delete shares the cascade.
func TestCascadeSoftDeleteStaysInTenant(t *testing.T) {
	app, mux := newCascadeFixture(t)
	aSID, _ := cascadeUser(t, app, "a@example.com", "tenant-a")
	for _, stmt := range []string{
		"INSERT INTO folders (id, org_id, name) VALUES (1, 'tenant-a', 'a-folder'), (2, 'tenant-a', 'a-folder-2')",
		"INSERT INTO files (id, folder_id, org_id, name) VALUES (1, 1, 'tenant-a', 'a-file'), (2, 1, 'tenant-b', 'b-file'), (3, 2, 'tenant-a', 'a-file-2'), (4, 2, 'tenant-b', 'b-file-2')",
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	assertStatus(t, mux, http.MethodDelete, "/api/folders/1", aSID, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, "/api/folders/batch", aSID, map[string]any{"ids": []any{2}}, http.StatusOK)
	if cascadeLive(t, app, "files", 1) || cascadeLive(t, app, "files", 3) {
		t.Fatal("the tenant's own child rows should be soft-deleted with their parent")
	}
	if !cascadeLive(t, app, "files", 2) || !cascadeLive(t, app, "files", 4) {
		t.Fatal("the cascade soft-deleted another tenant's row")
	}

	// An admin's cascade still stops at the parent's tenant.
	rootSID := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	crudScopeMustExec(t, app.DB, "INSERT INTO folders (id, org_id, name) VALUES (3, 'tenant-a', 'a-folder-3')")
	crudScopeMustExec(t, app.DB, "INSERT INTO files (id, folder_id, org_id, name) VALUES (5, 3, 'tenant-a', 'a-file-3'), (6, 3, 'tenant-b', 'b-file-3')")
	assertStatus(t, mux, http.MethodDelete, "/api/folders/3", rootSID, nil, http.StatusOK)
	if cascadeLive(t, app, "files", 5) || !cascadeLive(t, app, "files", 6) {
		t.Fatal("an admin's cascade should cover the parent's tenant and nothing else")
	}
}
