//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A member-of create or re-point into a parent the caller is not a member of
// answered Go's text/plain "404 page not found", while every other refusal on
// the same table is JSON, so a client's res.json() threw on it. It now answers
// the JSON 404 a read of a missing row gets, and the body is the same whether
// the parent exists in the caller's tenant, does not exist, or belongs to
// another tenant: the refusal still tells nothing about the parent.
func TestMemberOfWriteRefusalIsJSONNotFound(t *testing.T) {
	app, mux := memberOfTenantApp(t)
	member := createCrudScopeSession(t, app, "member@example.com", "user", "1", "")
	for _, stmt := range []string{
		`INSERT INTO company_members (company_id, member_id) VALUES (1, 1)`,
		`INSERT INTO projects (id, company_id, name) VALUES (1, 1, 'mine'), (2, 1, 'not-mine'), (3, 2, 'other-tenant')`,
		`INSERT INTO project_members (company_id, project_id, member_id) VALUES (1, 1, 1), (2, 3, 99)`,
		`INSERT INTO tasks (id, company_id, project_id, title) VALUES (1, 1, 1, 'task')`,
	} {
		mustExec(t, app.DB, stmt)
	}

	missingRow := crudScopeRequest(t, mux, "GET", "/api/tasks/999", member, nil)
	if missingRow.Code != http.StatusNotFound {
		t.Fatalf("read of a missing row: %d %s", missingRow.Code, missingRow.Body.String())
	}
	want := strings.TrimSpace(missingRow.Body.String())

	for _, parent := range []int{2, 999, 3} {
		for name, rec := range map[string]*httptest.ResponseRecorder{
			"create": crudScopeRequest(t, mux, "POST", "/api/tasks", member, map[string]any{"project_id": parent, "title": "x"}),
			"batch":  crudScopeRequest(t, mux, "POST", "/api/tasks/batch", member, []map[string]any{{"project_id": parent, "title": "x"}}),
			"patch":  crudScopeRequest(t, mux, "PATCH", "/api/tasks/1", member, map[string]any{"project_id": parent}),
		} {
			got := strings.TrimSpace(rec.Body.String())
			if rec.Code != http.StatusNotFound || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || got != want {
				t.Errorf("%s into parent %d: %d %q %q, want 404 application/json %q", name, parent, rec.Code, rec.Header().Get("Content-Type"), got, want)
			}
		}
	}
	var planted int
	app.DB.QueryRow(`SELECT COUNT(*) FROM tasks WHERE title = 'x' OR project_id <> 1`).Scan(&planted)
	if planted != 0 {
		t.Fatalf("a refused write changed %d task rows", planted)
	}
	// Control: the member's own project still accepts the write.
	if rec := crudScopeRequest(t, mux, "POST", "/api/tasks", member, map[string]any{"project_id": 1, "title": "ok"}); rec.Code != http.StatusOK {
		t.Fatalf("create in the member's project: %d %s", rec.Code, rec.Body.String())
	}
}
