//go:build !cli && !windows

package main

import (
	"net/http"
	"testing"
)

// A column a command owns (`command.owns`) is refused by generic CRUD for
// every caller, so /api/_schema must not call it writable and the OpenAPI
// request schemas must not list it. This uses the loaded command app of
// crud_owned_fields_test.go: tasks.status and tasks.completed_by are owned.
func TestSchemaDescriptorAndOpenAPILeaveOutCommandOwnedColumns(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)

	// What the write paths do.
	rec := crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", f.user, map[string]any{"project_id": 7, "title": "new", "status": "done"})
	f.ownedBody(t, rec, "tasks.status")
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"completed_by": 5})
	f.ownedBody(t, rec, "tasks.completed_by")
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "renamed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH of a column nobody owns: %d %s", rec.Code, rec.Body.String())
	}

	// What the descriptor says to the same caller.
	rec = crudScopeRequest(t, f.mux, http.MethodGet, "/api/_schema", f.user, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/_schema: %d %s", rec.Code, rec.Body.String())
	}
	var desc struct {
		Tables map[string]struct {
			Fields []struct {
				Name     string `json:"name"`
				Writable bool   `json:"writable"`
			} `json:"fields"`
		} `json:"tables"`
	}
	mustDecodeBody(t, rec, &desc)
	writable := map[string]bool{}
	for _, field := range desc.Tables["tasks"].Fields {
		writable[field.Name] = field.Writable
	}
	for name, want := range map[string]bool{"title": true, "project_id": true, "status": false, "completed_by": false, "org_id": false} {
		if got, listed := writable[name]; !listed || got != want {
			t.Errorf("/api/_schema tasks.%s writable = %v (listed %v), want %v", name, got, listed, want)
		}
	}

	// And the request schemas.
	schemas := generateRuntimeOpenAPI(f.app)["components"].(map[string]any)["schemas"].(map[string]any)
	for _, schema := range []string{"CreateTask", "UpdateTask"} {
		props := schemas[schema].(map[string]any)["properties"].(map[string]any)
		if _, ok := props["title"]; !ok {
			t.Errorf("%s lost title", schema)
		}
		for _, owned := range []string{"status", "completed_by"} {
			if _, ok := props[owned]; ok {
				t.Errorf("%s lists the command-owned column %s", schema, owned)
			}
		}
	}
}
