//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// POST /api/_groups/create inserts the org row from the request body. It kept
// its own protected-column list, which lacked the rules every auto-CRUD create
// applies: a workflow's state column starts in its declared initial state,
// computed (computed.yaml) columns are never client-written, and the owner
// column is matched case-insensitively. A founder could create their
// organization directly in a role-guarded workflow state (an approval only an
// admin may grant) or with a derived column of their choosing.
func TestGroupBootstrapAppliesCreateWriteGates(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	EnsureSessionsTable(db)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, status TEXT DEFAULT 'pending', credit_limit INTEGER, User_Id INTEGER)")
	mustExec(t, db, "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, user_id INTEGER, member_role TEXT)")
	app.Group = &GroupConfig{
		Table: "company_members", Key: "company_id", UserField: "user_id", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "company_admin"},
	}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{
		"company_review": {Name: "company_review", Table: "companies", Field: "status", Initial: "pending",
			States:      []string{"pending", "approved"},
			Transitions: map[string]map[string]Transition{"pending": {"approved": {Role: "admin"}}}},
	}}
	app.Computed = &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"companies": {"credit_limit": {Table: "companies", Column: "credit_limit", SQL: "SELECT 0"}},
	}}
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('founder', 'founder@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(db, uid, "founder@example.com", "", time.Hour)

	w := bootstrapAs(app, sid, `{"name":"Acme","status":"approved","credit_limit":"1000000","User_Id":"999"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var status string
	var credit sql.NullInt64
	var owner sql.NullInt64
	if err := db.QueryRow("SELECT COALESCE(status, ''), credit_limit, User_Id FROM companies").Scan(&status, &credit, &owner); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Errorf("org created in workflow state %q; a new row starts in the initial state", status)
	}
	if credit.Valid {
		t.Errorf("computed column credit_limit took the client's value %d", credit.Int64)
	}
	if !owner.Valid || owner.Int64 != uid {
		t.Errorf("owner column = %v, want the founder %d", owner, uid)
	}

	// The initial state itself is still accepted, as on auto-CRUD create.
	mustExec(t, db, "DELETE FROM company_members")
	mustExec(t, db, "DELETE FROM companies")
	mustExec(t, db, "UPDATE _benmore_sessions SET group_id = NULL")
	if w := bootstrapAs(app, sid, `{"name":"Beta","status":"pending"}`); w.Code != http.StatusOK {
		t.Fatalf("bootstrap with the initial state: %d %s", w.Code, w.Body.String())
	}
}
