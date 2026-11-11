//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// On a tenant-keyed table, membership widens visibility within the caller's
// tenant and never beyond it. A caller with no tenant - removed from their
// company, or never in one - gains nothing there from membership rows (the
// documented missing_group rule); only an explicit share can authorize a row.
// The tenant clause used to be added only when the caller had a tenant, so a
// stale project membership kept reading and editing the old company's data.
func memberOfTenantApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, member_id INTEGER)`,
		`CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, name TEXT)`,
		`CREATE TABLE project_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, project_id INTEGER, member_id INTEGER)`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, project_id INTEGER, title TEXT)`,
	} {
		mustExec(t, db, stmt)
	}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	EnsureWebhooksTable(db)
	rule := "member-of:project_members(project_id, member_id)"
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Group: &GroupConfig{Table: "company_members", Key: "company_id", UserField: "member_id"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"projects": {"read": rule, "write": "group"},
			"tasks":    {"all": rule},
		}},
	}
	t.Cleanup(app.Shutdown)
	names, err := GetTableNames(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux
}

func TestMemberOfTenantlessCallerGainsNothingFromMembership(t *testing.T) {
	app, mux := memberOfTenantApp(t)
	member := createCrudScopeSession(t, app, "member@example.com", "user", "1", "")
	removed := createCrudScopeSession(t, app, "removed@example.com", "user", "", "")
	// User 1 is in company 1 and project 1. User 2 was removed from company 1
	// (no tenant now) but still has a project_members row for project 1.
	for _, stmt := range []string{
		`INSERT INTO company_members (company_id, member_id) VALUES (1, 1)`,
		`INSERT INTO projects (id, company_id, name) VALUES (1, 1, 'acme-secret-project')`,
		`INSERT INTO project_members (company_id, project_id, member_id) VALUES (1, 1, 1), (1, 1, 2)`,
		`INSERT INTO tasks (id, company_id, project_id, title) VALUES (1, 1, 1, 'acme-secret-task')`,
	} {
		mustExec(t, app.DB, stmt)
	}

	assertListIDs(t, mux, member, "/api/tasks", []float64{1})
	for _, path := range []string{"/api/projects", "/api/tasks", "/api/projects/1", "/api/tasks/1"} {
		rec := crudScopeRequest(t, mux, "GET", path, removed, nil)
		if strings.Contains(rec.Body.String(), "acme-secret") {
			t.Errorf("tenantless caller read %s through a stale membership: HTTP %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if rec := crudScopeRequest(t, mux, "PATCH", "/api/tasks/1", removed, map[string]any{"title": "changed"}); rec.Code == http.StatusOK {
		t.Errorf("tenantless caller updated a tenant task: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id = 1`).Scan(&title); err != nil || title != "acme-secret-task" {
		t.Fatalf("task changed to %q (%v)", title, err)
	}
	if rec := crudScopeRequest(t, mux, "POST", "/api/tasks", removed, map[string]any{"project_id": 1, "title": "planted"}); rec.Code == http.StatusOK {
		t.Errorf("tenantless caller created a task in a tenant project: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var planted int
	_ = app.DB.QueryRow(`SELECT COUNT(*) FROM tasks WHERE title = 'planted'`).Scan(&planted)
	if planted != 0 {
		t.Fatalf("planted %d task rows", planted)
	}
	// The member with a tenant keeps their access.
	if rec := crudScopeRequest(t, mux, "PATCH", "/api/tasks/1", member, map[string]any{"title": "acme-secret-task"}); rec.Code != http.StatusOK {
		t.Errorf("tenant member could not update: HTTP %d %s", rec.Code, rec.Body.String())
	}
}
