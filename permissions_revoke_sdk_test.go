//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func permissionRevokeFixture(t *testing.T) (*App, *http.ServeMux, string, string) {
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
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT)`)
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	cols, err := GetTableColumns(db, "notes")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "notes", Columns: cols}}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	owner := createCrudScopeSession(t, app, "owner@example.test", "user", "", "")
	reader := createCrudScopeSession(t, app, "reader+files/test@example.test", "user", "", "")
	for _, title := range []string{"First private note", "Second private note"} {
		assertStatus(t, mux, http.MethodPost, "/api/notes", owner, map[string]any{"title": title}, http.StatusOK)
	}
	return app, mux, owner, reader
}

func TestPermissionsSDKRevokeIntegration(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping SDK integration")
	}
	_, mux, owner, reader := permissionRevokeFixture(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd := exec.Command(node, "embedded/bm_permissions_revoke_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_OWNER="+owner, "BM_TEST_READER="+reader)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real SDK permission revoke failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "permission SDK round trip passed") {
		t.Fatalf("missing success: %s", output)
	}
}

func TestSDUIShareDialogNativePermissions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app, mux, owner, _ := permissionRevokeFixture(t)
	// Authored role grants share the native list envelope. The same grantee
	// spelling must not let revocation select a different grant type.
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission) VALUES ('notes','1','role','reader+files/test@example.test','view')`)
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd := exec.Command(node, "embedded/sdui_permissions_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_OWNER="+owner)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real ShareDialog permission round trip failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ShareDialog native recipient and revoke passed") {
		t.Fatalf("missing success: %s", output)
	}
}

func TestPermissionsEmailRevokePreservesBoundaries(t *testing.T) {
	app, mux, owner, reader := permissionRevokeFixture(t)
	email := "reader+files/test@example.test"
	for _, id := range []string{"1", "2"} {
		assertStatus(t, mux, http.MethodPost, "/api/notes/"+id+"/share", owner, map[string]any{"email": email, "permission": "view"}, http.StatusOK)
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions (resource_type,resource_id,grant_type,grantee_id,permission) VALUES ('notes','1','role','reader+files/test@example.test','view')`)
	path := "/api/notes/1/permissions/" + url.PathEscape("  READER+FILES/TEST@EXAMPLE.TEST  ")
	assertStatus(t, mux, http.MethodDelete, path, reader, nil, http.StatusForbidden)
	assertStatus(t, mux, http.MethodGet, "/api/notes/1", reader, nil, http.StatusOK)
	// An ordinary cookie mutation still needs CSRF, including this compatibility route.
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.AddCookie(&http.Cookie{Name: "_benmore_session", Value: owner})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d %s", rec.Code, rec.Body.String())
	}
	assertStatus(t, mux, http.MethodDelete, path, owner, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/notes/1", reader, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/notes/2", reader, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, path, owner, nil, http.StatusNotFound)
	var retainedRoleGrants int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_permissions WHERE resource_type='notes' AND resource_id='1' AND grant_type='role'`).Scan(&retainedRoleGrants); err != nil || retainedRoleGrants != 1 {
		t.Fatalf("email revoke removed a role grant: count=%d err=%v", retainedRoleGrants, err)
	}
	var permissionID int
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_permissions WHERE resource_type='notes' AND resource_id='2' AND grantee_id=?`, email).Scan(&permissionID); err != nil {
		t.Fatal(err)
	}
	// Keep the original permission-ID endpoint working and bounded to its own row.
	assertStatus(t, mux, http.MethodDelete, "/api/notes/1/share/"+strconv.Itoa(permissionID), owner, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/notes/2", reader, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, "/api/notes/2/share/"+strconv.Itoa(permissionID), owner, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/notes/2", reader, nil, http.StatusNotFound)
}
