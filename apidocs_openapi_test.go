//go:build !cli

package main

import "testing"

func TestGenerateRuntimeOpenAPIShape(t *testing.T) {
	app := &App{
		Design: &DesignConfig{SEO: map[string]string{"site_name": "Contracts"}},
		Tables: []Table{
			{
				Name: "notes",
				Columns: []Column{
					{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
					{Name: "title", Type: "TEXT", NotNull: true},
					{Name: "body", Type: "TEXT"},
					{Name: "user_id", Type: "INTEGER", NotNull: true},
					{Name: "updated_at", Type: "DATETIME"},
				},
			},
			{
				Name: "_benmore_users",
				Columns: []Column{
					{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
					{Name: "email", Type: "TEXT", NotNull: true},
					{Name: "password_hash", Type: "TEXT"},
					{Name: "totp_secret", Type: "TEXT"},
				},
			},
		},
	}

	spec := generateRuntimeOpenAPI(app)
	if got := spec["openapi"]; got != "3.1.0" {
		t.Fatalf("openapi = %v, want 3.1.0", got)
	}
	info := spec["info"].(map[string]any)
	if got := info["title"]; got != "Contracts API" {
		t.Fatalf("title = %v, want Contracts API", got)
	}
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{"/api/notes", "/api/notes/{id}"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("missing path %s", path)
		}
	}
	components := spec["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	if _, ok := schemas["Problem"]; !ok {
		t.Fatal("missing Problem schema")
	}
	if _, ok := schemas["BenmoreUser"]; ok {
		t.Fatal("internal _benmore_users table should not be exported as a runtime schema")
	}
	note := schemas["Note"].(map[string]any)
	props := note["properties"].(map[string]any)
	if props["id"].(map[string]any)["readOnly"] != true {
		t.Fatal("primary key should be readOnly")
	}
	if _, ok := props["password_hash"]; ok {
		t.Fatal("sensitive fields must not be exported")
	}
	createNote := schemas["CreateNote"].(map[string]any)
	createProps := createNote["properties"].(map[string]any)
	if _, ok := createProps["id"]; ok {
		t.Fatal("create schema must not accept primary key")
	}
	if _, ok := createProps["user_id"]; ok {
		t.Fatal("create schema must not accept managed user_id")
	}
	required := createNote["required"].([]string)
	if len(required) != 1 || required[0] != "title" {
		t.Fatalf("create required = %v, want [title]", required)
	}
	updateNote := schemas["UpdateNote"].(map[string]any)
	if _, ok := updateNote["required"]; ok {
		t.Fatal("update schema should not require create-only fields")
	}
}

func TestOpenAPIOperationIDsUnique(t *testing.T) {
	app := &App{Tables: []Table{
		{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}},
		{Name: "tasks", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}},
	}}
	spec := generateRuntimeOpenAPI(app)
	paths := spec["paths"].(map[string]any)
	seen := map[string]bool{}
	for path, rawOps := range paths {
		ops := rawOps.(map[string]any)
		for method, raw := range ops {
			op := raw.(map[string]any)
			id, _ := op["operationId"].(string)
			if id == "" {
				t.Fatalf("%s %s missing operationId", method, path)
			}
			if seen[id] {
				t.Fatalf("duplicate operationId %s", id)
			}
			seen[id] = true
			if _, ok := op["responses"]; !ok {
				t.Fatalf("%s %s missing responses", method, path)
			}
			if _, ok := op["tags"]; !ok {
				t.Fatalf("%s %s missing tags", method, path)
			}
		}
	}
}
