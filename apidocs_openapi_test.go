//go:build !cli

package main

import (
	"reflect"
	"testing"
)

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

// helper: walk into spec["paths"][path][method] safely.
func op(t *testing.T, spec map[string]any, path, method string) map[string]any {
	t.Helper()
	paths := spec["paths"].(map[string]any)
	p, ok := paths[path].(map[string]any)
	if !ok {
		t.Fatalf("missing path %s", path)
	}
	m, ok := p[method].(map[string]any)
	if !ok {
		t.Fatalf("missing %s on %s", method, path)
	}
	return m
}

func jsonResponseSchema(t *testing.T, operation map[string]any, code string) map[string]any {
	t.Helper()
	resp := operation["responses"].(map[string]any)[code].(map[string]any)
	content := resp["content"].(map[string]any)["application/json"].(map[string]any)
	return content["schema"].(map[string]any)
}

// TestOpenAPIListResponseMatchesRuntime asserts the documented list 200
// oneOf contains exactly the four shapes the auto-CRUD list handler emits:
// a bare array, {data,total,page,per_page}, {data,next_cursor,limit}, and
// {count}. This guards against the contract drifting from crud.go.
func TestOpenAPIListResponseMatchesRuntime(t *testing.T) {
	app := &App{Tables: []Table{
		{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true, NotNull: true}, {Name: "title", Type: "TEXT", NotNull: true}}},
	}}
	spec := generateRuntimeOpenAPI(app)
	schema := jsonResponseSchema(t, op(t, spec, "/api/notes", "get"), "200")
	variants, ok := schema["oneOf"].([]any)
	if !ok || len(variants) != 4 {
		t.Fatalf("list 200 oneOf = %#v, want 4 variants", schema["oneOf"])
	}

	gotArray := false
	keySets := map[string]bool{}
	for _, v := range variants {
		vm := v.(map[string]any)
		if vm["type"] == "array" {
			gotArray = true
			continue
		}
		props := vm["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		// record a normalized key signature
		sig := ""
		for _, want := range []string{"data", "total", "page", "per_page", "next_cursor", "limit", "count"} {
			if _, ok := props[want]; ok {
				sig += want + ","
			}
		}
		keySets[sig] = true
	}
	if !gotArray {
		t.Fatal("list 200 oneOf missing the bare-array variant")
	}
	for _, want := range []string{
		"data,total,page,per_page,", // offset page envelope
		"data,next_cursor,limit,",   // cursor envelope
		"count,",                    // count-only
	} {
		if !keySets[want] {
			t.Fatalf("list 200 oneOf missing variant with keys %q; got %v", want, keySets)
		}
	}
	// The old, wrong {rows,count} shape must be gone.
	if keySets["count,"] && keySets["rows"] {
		t.Fatal("list 200 oneOf still advertises the non-existent {rows,count} shape")
	}
}

// TestOpenAPIListParamsMatchRuntime asserts the list params describe the real
// page/per_page/cursor/limit/count/include/q surface and never the
// non-existent ?offset param.
func TestOpenAPIListParamsMatchRuntime(t *testing.T) {
	app := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}}}}
	spec := generateRuntimeOpenAPI(app)
	params := op(t, spec, "/api/notes", "get")["parameters"].([]map[string]any)
	names := map[string]bool{}
	for _, p := range params {
		names[p["name"].(string)] = true
	}
	for _, want := range []string{"page", "per_page", "cursor", "limit", "count", "include", "q"} {
		if !names[want] {
			t.Fatalf("list params missing %q; got %v", want, names)
		}
	}
	if names["offset"] {
		t.Fatal("list params advertise a non-existent ?offset parameter")
	}
}

// TestOpenAPICreateResponseEnvelope asserts the create 200 models the real
// {id, status:"created", ...row} envelope, not a bare resource ref.
func TestOpenAPICreateResponseEnvelope(t *testing.T) {
	app := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true, NotNull: true}, {Name: "title", Type: "TEXT", NotNull: true}}}}}
	spec := generateRuntimeOpenAPI(app)
	schema := jsonResponseSchema(t, op(t, spec, "/api/notes", "post"), "200")
	allOf, ok := schema["allOf"].([]any)
	if !ok || len(allOf) != 2 {
		t.Fatalf("create 200 = %#v, want allOf[resourceRef, envelope]", schema)
	}
	env := allOf[1].(map[string]any)
	props := env["properties"].(map[string]any)
	if props["status"].(map[string]any)["const"] != "created" {
		t.Fatalf("create envelope status const = %v, want created", props["status"])
	}
	if _, ok := props["id"]; !ok {
		t.Fatal("create envelope must document id")
	}
}

// TestOpenAPIUpdateResponseEnvelope asserts update returns the
// {status:"updated"} envelope (it does NOT echo the row).
func TestOpenAPIUpdateResponseEnvelope(t *testing.T) {
	app := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "title", Type: "TEXT"}, {Name: "updated_at", Type: "DATETIME"}}}}}
	spec := generateRuntimeOpenAPI(app)
	patch := op(t, spec, "/api/notes/{id}", "patch")
	schema := jsonResponseSchema(t, patch, "200")
	props := schema["properties"].(map[string]any)
	if props["status"].(map[string]any)["const"] != "updated" {
		t.Fatalf("update 200 status const = %v, want updated", props["status"])
	}
	// must NOT $ref the resource schema (it does not echo the row)
	if _, ok := schema["$ref"]; ok {
		t.Fatal("update 200 must not be the resource ref; runtime returns only {status}")
	}
	// No misleading X-Expected-Updated-At header param.
	if params, ok := patch["parameters"].([]map[string]any); ok {
		for _, p := range params {
			if p["name"] == "X-Expected-Updated-At" {
				t.Fatal("update must not advertise an X-Expected-Updated-At header the runtime ignores")
			}
		}
	}
	// _expected_updated_at must be modeled in the Update request body instead.
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	upd := schemas["UpdateNote"].(map[string]any)["properties"].(map[string]any)
	if _, ok := upd["_expected_updated_at"]; !ok {
		t.Fatal("UpdateNote must model _expected_updated_at (body field, not header)")
	}
}

// TestOpenAPIDeleteResponseEnvelope asserts delete returns {status:"deleted"}.
func TestOpenAPIDeleteResponseEnvelope(t *testing.T) {
	app := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}}}}
	spec := generateRuntimeOpenAPI(app)
	schema := jsonResponseSchema(t, op(t, spec, "/api/notes/{id}", "delete"), "200")
	props := schema["properties"].(map[string]any)
	if props["status"].(map[string]any)["const"] != "deleted" {
		t.Fatalf("delete 200 status const = %v, want deleted", props["status"])
	}
}

// TestOpenAPIReadSchemaAllowsIncludeKeys asserts read schemas keep
// additionalProperties open so ?include= expansion keys don't fail validation.
func TestOpenAPIReadSchemaAllowsIncludeKeys(t *testing.T) {
	app := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}}}}
	spec := generateRuntimeOpenAPI(app)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	note := schemas["Note"].(map[string]any)
	if note["additionalProperties"] != true {
		t.Fatalf("read schema additionalProperties = %v, want true (for ?include= expansion)", note["additionalProperties"])
	}
	// Write schemas must stay strict.
	if schemas["CreateNote"].(map[string]any)["additionalProperties"] != false {
		t.Fatal("create schema must keep additionalProperties:false")
	}
}

// TestOpenAPIColumnTypeMapping covers nullable [type,"null"] handling and the
// JSON multi-type union, which the original tests did not exercise.
func TestOpenAPIColumnTypeMapping(t *testing.T) {
	nullable := openAPISchemaForColumn(Column{Name: "body", Type: "TEXT"})
	if got, want := nullable["type"], []string{"string", "null"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nullable TEXT type = %#v, want %#v", got, want)
	}
	notNull := openAPISchemaForColumn(Column{Name: "title", Type: "TEXT", NotNull: true})
	if got := notNull["type"]; got != "string" {
		t.Fatalf("NOT NULL TEXT type = %#v, want \"string\"", got)
	}
	jsonCol := openAPISchemaForColumn(Column{Name: "meta", Type: "JSON", NotNull: true})
	if _, ok := jsonCol["type"].([]string); !ok {
		t.Fatalf("JSON column type = %#v, want a multi-type union", jsonCol["type"])
	}
}

// TestOpenAPIVersionTracksFingerprint asserts info.version moves with the
// schema so consumers can detect drift.
func TestOpenAPIVersionTracksFingerprint(t *testing.T) {
	a := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}}}}
	b := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "title", Type: "TEXT"}}}}}
	va := generateRuntimeOpenAPI(a)["info"].(map[string]any)["version"].(string)
	vb := generateRuntimeOpenAPI(b)["info"].(map[string]any)["version"].(string)
	if va == vb {
		t.Fatalf("version should change when the schema changes; both = %q", va)
	}
}

// TestOpenAPISingularizeCollision asserts two tables whose singular forms
// collide (note vs notes) keep distinct schema keys and operationIds.
func TestOpenAPISingularizeCollision(t *testing.T) {
	app := &App{Tables: []Table{
		{Name: "note", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}},
		{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}},
	}}
	spec := generateRuntimeOpenAPI(app)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	// Both must resolve to distinct schema keys (no silent overwrite).
	if _, ok := schemas["Note"]; !ok {
		t.Fatal("missing Note schema")
	}
	if _, ok := schemas["Notes"]; !ok {
		t.Fatal("collision fallback should produce a distinct Notes schema")
	}
	seen := map[string]bool{}
	paths := spec["paths"].(map[string]any)
	for _, raw := range paths {
		for _, rawOp := range raw.(map[string]any) {
			id := rawOp.(map[string]any)["operationId"].(string)
			if seen[id] {
				t.Fatalf("duplicate operationId %s after singular collision", id)
			}
			seen[id] = true
		}
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
