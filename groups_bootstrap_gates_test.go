//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// POST /api/_groups/create inserts the org row from the request body, so it
// must apply the gates every auto-CRUD create applies to that table: a
// workflow state column starts in its initial state, a foreign key must name
// a parent the founder can read, and constraint errors stay generic.
func TestGroupBootstrapOrgInsertUsesCreateGates(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  projects: role:company_admin\n")
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN showcase_project_id INTEGER REFERENCES projects(id)")
	crudScopeMustExec(t, app.DB, "CREATE UNIQUE INDEX companies_name ON companies(name)")
	for i := range app.Tables {
		if app.Tables[i].Name == "companies" {
			cols, err := GetTableColumns(app.DB, "companies")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	app.JoinMap = BuildJoinMap(app.DB)
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"company_review": {
		Name: "company_review", Table: "companies", Field: "status", Initial: "pending",
		States:      []string{"pending", "approved"},
		Transitions: map[string]map[string]Transition{"pending": {"approved": {Role: "admin"}}},
	}}}

	founder := createCrudScopeSession(t, app, "founder@example.com", "user", "", "")

	// Another tenant's project is not the founder's to point at.
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_groups/create", founder, map[string]any{"name": "Initech", "showcase_project_id": 2})
	if rec.Code == http.StatusOK {
		t.Fatalf("bootstrap accepted a foreign key to another tenant's project: %s", rec.Body.String())
	}
	if n := countOrgs(t, app, "Initech"); n != 0 {
		t.Fatalf("refused bootstrap left %d org rows", n)
	}

	// A UNIQUE clash answers the generic message, not the constraint text.
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/_groups/create", founder, map[string]any{"name": "acme"})
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "companies.name") {
		t.Fatalf("constraint error leaked or wrong status: %d %s", rec.Code, rec.Body.String())
	}

	// The workflow state column takes only its initial state.
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/_groups/create", founder, map[string]any{"name": "Initech", "status": "approved"})
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM companies WHERE name = 'Initech'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("founder skipped the workflow: new org status = %q", status)
	}
}

func countOrgs(t *testing.T, app *App, name string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM companies WHERE name = ?", name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
