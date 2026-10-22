//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func scopingTestApp(t *testing.T) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db")+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE orgs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`,
		`CREATE TABLE org_members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER, email TEXT)`,
		`CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, org_id INTEGER, title TEXT)`,
		`CREATE TABLE project_members (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, member_id INTEGER)`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, org_id INTEGER, project_id INTEGER REFERENCES projects(id), title TEXT)`,
		// An author-declared index already leading with user_id: must be reused.
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, created_at TEXT)`,
		`CREATE INDEX idx_notes_user_id_created_at ON notes(user_id, created_at)`,
		// A partial index does not serve general lookups: still indexed.
		`CREATE TABLE drafts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, done INTEGER)`,
		`CREATE INDEX idx_drafts_open ON drafts(user_id) WHERE done = 0`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	cols := func(names ...string) []Column {
		out := []Column{{Name: "id", Type: "INTEGER", PK: true}}
		for _, n := range names {
			out = append(out, Column{Name: n})
		}
		return out
	}
	return &App{
		Dir: t.TempDir(), DB: db,
		Group: &GroupConfig{Table: "org_members", Key: "org_id", UserField: "email"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"projects": {"all": "member-of:project_members(project_id,member_id)"},
			"tasks":    {"read": "member-of:project_members(project_id,member_id)"},
		}},
		Tables: []Table{
			{Name: "orgs", Columns: cols("name")},
			{Name: "org_members", Columns: cols("org_id", "email")},
			{Name: "projects", Columns: cols("user_id", "org_id", "title")},
			{Name: "project_members", Columns: cols("project_id", "member_id")},
			{Name: "tasks", Columns: cols("user_id", "org_id", "project_id", "title")},
			{Name: "notes", Columns: cols("user_id", "created_at")},
			{Name: "drafts", Columns: cols("user_id", "done")},
		},
	}
}

func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, detail)
	}
	return strings.Join(lines, "\n")
}

func TestEnsureScopingIndexesCreatesScopingIndexes(t *testing.T) {
	app := scopingTestApp(t)
	created := EnsureScopingIndexes(app)
	for _, want := range []string{
		"idx_bm_project_members_project_id_member_id", // member-of composite
		"idx_bm_org_members_email",                    // group membership lookup
		"idx_bm_projects_user_id", "idx_bm_projects_org_id",
		"idx_bm_tasks_user_id", "idx_bm_tasks_org_id", "idx_bm_tasks_project_id", // owner, tenant, FK/child join
		"idx_bm_drafts_user_id", // only a partial index existed
	} {
		if !slices.Contains(created, want) {
			t.Errorf("missing %s; created %v", want, created)
		}
	}
	for _, unwanted := range []string{
		"idx_bm_notes_user_id",              // author index already leads with user_id
		"idx_bm_project_members_project_id", // composite already leads with project_id
		"idx_bm_orgs_id", "idx_bm_tasks_id",
	} {
		if slices.Contains(created, unwanted) {
			t.Errorf("created redundant %s", unwanted)
		}
	}

	// Idempotent and additive: a second pass creates nothing and the
	// author's index is untouched.
	if again := EnsureScopingIndexes(app); len(again) != 0 {
		t.Fatalf("second pass created %v", again)
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_notes_user_id_created_at'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("author index missing: %d %v", n, err)
	}
}

// The scoped list and the member-of EXISTS now SEARCH an index instead of
// scanning the table.
func TestScopingIndexesTurnScansIntoSearches(t *testing.T) {
	app := scopingTestApp(t)
	ownerList := `SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC LIMIT 50`
	tenantList := `SELECT * FROM projects WHERE org_id = ? ORDER BY id DESC LIMIT 50`
	session := &Session{UserID: 7}
	rule := memberOfFor(app, "projects", OpRead)
	if rule == nil {
		t.Fatal("member-of rule not resolved")
	}
	pred, args := memberOfPredicate(app, "projects", rule, session, "view")
	memberList := `SELECT * FROM main.projects WHERE ` + pred + ` LIMIT 50`

	before := queryPlan(t, app.DB, ownerList, 7)
	if !strings.Contains(before, "SCAN tasks") {
		t.Fatalf("precondition: expected a table scan before indexing, got:\n%s", before)
	}
	EnsureScopingIndexes(app)

	if plan := queryPlan(t, app.DB, ownerList, 7); !strings.Contains(plan, "SEARCH tasks USING INDEX idx_bm_tasks_user_id") {
		t.Errorf("owner list plan:\n%s", plan)
	}
	if plan := queryPlan(t, app.DB, tenantList, 1); !strings.Contains(plan, "SEARCH projects USING INDEX idx_bm_projects_org_id") {
		t.Errorf("tenant list plan:\n%s", plan)
	}
	plan := queryPlan(t, app.DB, memberList, args...)
	if !strings.Contains(plan, "USING COVERING INDEX idx_bm_project_members_project_id_member_id") &&
		!strings.Contains(plan, "USING INDEX idx_bm_project_members_project_id_member_id") {
		t.Errorf("member-of EXISTS plan:\n%s", plan)
	}
	if strings.Contains(plan, "SCAN project_members") {
		t.Errorf("member-of EXISTS still scans the membership table:\n%s", plan)
	}
}

// SQLite refuses to drop an indexed column; schema changes that drop a
// column must not fail on an index the framework added on its own.
func TestDropColumnClearsOnlyFrameworkIndexes(t *testing.T) {
	app := scopingTestApp(t)
	EnsureScopingIndexes(app)
	if _, err := app.DB.Exec(`ALTER TABLE projects DROP COLUMN user_id`); err == nil {
		t.Fatal("precondition: SQLite should refuse to drop an indexed column")
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt := `ALTER TABLE projects DROP COLUMN user_id;`
	if err := dropFrameworkIndexesForStatement(tx, stmt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(stmt); err != nil {
		t.Fatalf("drop column after clearing framework index: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Author indexes are never dropped: notes.user_id stays refused.
	if err := dropFrameworkIndexesForStatement(app.DB, `ALTER TABLE notes DROP COLUMN user_id`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`ALTER TABLE notes DROP COLUMN user_id`); err == nil {
		t.Fatal("author-declared index was removed")
	}
	// Non-DROP statements are untouched.
	if err := dropFrameworkIndexesForStatement(app.DB, `ALTER TABLE tasks ADD COLUMN x TEXT`); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='idx_bm_tasks_user_id'`).Scan(&n)
	if n != 1 {
		t.Fatal("unrelated framework index dropped")
	}
}

// Connector revision tracking digests a table's indexes; the framework's
// startup indexes must not change an enrolled table's identity.
func TestRevisionDigestIgnoresFrameworkIndexes(t *testing.T) {
	app := scopingTestApp(t)
	digest := func() string {
		tx, err := app.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		targets, err := appMCPRevisionTargets(tx, []string{"notes"})
		if err != nil {
			t.Fatal(err)
		}
		return targets[0].schemaDigest
	}
	crudScopeMustExec(t, app.DB, `CREATE INDEX idx_bm_notes_created_at ON notes(created_at)`)
	withFramework := digest()
	crudScopeMustExec(t, app.DB, `DROP INDEX idx_bm_notes_created_at`)
	if without := digest(); without != withFramework {
		t.Fatalf("framework index changed the revision digest")
	}
	crudScopeMustExec(t, app.DB, `CREATE INDEX idx_notes_created ON notes(created_at)`)
	if digest() == withFramework {
		t.Fatalf("author index no longer part of the digest")
	}
}
