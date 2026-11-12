//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// schemaWritableFixture loads testdata/schema_descriptor_writable: an app
// with one column of every kind a generic create or PATCH treats differently
// (plain, same-row computed, aggregate computed, workflow state, encrypted
// with a blind-index sibling, owner, tenant key, membership identity and
// role, timestamps, soft delete), plus its routes.
func schemaWritableFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join("testdata", "schema_descriptor_writable")
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeTestFile(t, dir, name, string(b))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, false, "https://fixture.example")
}

// Round 2026-11-09 data F5: /api/_schema listed computed columns (and the
// tenant key, the workflow state column, ...) as writable and the OpenAPI
// Create<Model>/Update<Model> schemas listed them as request properties,
// while every write path drops them; custom fields were writable but missing
// from the request schemas.
//
// For every column of the fixture app this sends a real create and a real
// PATCH that set only that column and reads back what was stored, then
// compares the answer with the descriptor's `writable` for the same caller
// and with the OpenAPI request schemas.
func TestSchemaDescriptorWritableMatchesCreateAndPatch(t *testing.T) {
	app, mux := schemaWritableFixture(t)

	member := createCrudScopeSession(t, app, "member@example.com", "user", "1", "")
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	mustExec(t, app.DB, `INSERT INTO org_members (org_id, email, member_role) VALUES (1, 'member@example.com', 'member')`)

	// A custom field, added the way an app admin adds one.
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_schema/orders/fields", admin, map[string]any{"name": "cf_ref", "type": "TEXT"}); rec.Code != http.StatusCreated {
		t.Fatalf("add custom field: %d %s", rec.Code, rec.Body.String())
	}

	seq := 0
	create := func(token, table string, body map[string]any) (string, int, string) {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/"+table, token, body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		id := ""
		if out["id"] != nil {
			id = fmt.Sprint(out["id"])
		}
		return id, rec.Code, rec.Body.String()
	}
	mustCreate := func(token, table string, body map[string]any) string {
		t.Helper()
		id, code, text := create(token, table, body)
		if code != http.StatusOK || id == "" {
			t.Fatalf("create %s %v: %d %s", table, body, code, text)
		}
		return id
	}
	// base is the smallest body a create of table accepts from this caller.
	base := func(token, table string) map[string]any {
		t.Helper()
		seq++
		switch table {
		case "orders":
			return map[string]any{"title": fmt.Sprintf("base %d", seq)}
		case "order_items":
			return map[string]any{"order_id": mustCreate(token, "orders", map[string]any{"title": "parent"}), "label": "base"}
		case "projects":
			return map[string]any{"name": "base"}
		case "org_members":
			return map[string]any{"org_id": 1, "email": fmt.Sprintf("base-%d@example.com", seq)}
		}
		t.Fatalf("no base body for %s", table)
		return nil
	}
	// probeValue is a value no default, trigger or session would store.
	probeValue := func(token, table string, col Column) any {
		t.Helper()
		switch table + "." + col.Name {
		case "orders.status":
			return "approved" // a real state, just not the initial one
		case "order_items.order_id":
			return mustCreate(token, "orders", map[string]any{"title": "other parent"})
		case "org_members.email":
			seq++
			return fmt.Sprintf("probe-%d@example.com", seq)
		}
		typ := strings.ToUpper(col.Type)
		switch {
		case strings.Contains(typ, "INT"):
			return 4242
		case strings.Contains(typ, "REAL"), strings.Contains(typ, "FLOA"), strings.Contains(typ, "DOUB"):
			return 4242.5
		case strings.Contains(typ, "DATE"), strings.Contains(typ, "TIME"):
			return "2001-02-03T04:05:06Z"
		}
		return "probe"
	}
	// stored reports whether the row holds the probe value in col.
	stored := func(table, id, col string, probe any) bool {
		t.Helper()
		var v sql.NullString
		if err := app.DB.QueryRow("SELECT CAST("+quoteIdent(col)+" AS TEXT) FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatalf("read %s.%s of row %s: %v", table, col, id, err)
		}
		if !v.Valid {
			return false
		}
		if s, ok := probe.(string); ok && strings.HasPrefix(s, "2001-02-03") {
			return strings.HasPrefix(v.String, "2001-02-03")
		}
		if strings.HasPrefix(v.String, "enc:") {
			return true // an encrypted column holds the ciphertext of what was sent
		}
		return v.String == fmt.Sprint(probe)
	}
	createAccepts := func(token, table string, col Column) bool {
		t.Helper()
		body := base(token, table)
		probe := probeValue(token, table, col)
		body[col.Name] = probe
		id := mustCreate(token, table, body)
		return stored(table, id, col.Name, probe)
	}
	patchAccepts := func(token, table string, col Column) bool {
		t.Helper()
		id := mustCreate(token, table, base(token, table))
		probe := probeValue(token, table, col)
		rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/"+table+"/"+id, token, map[string]any{col.Name: probe})
		// 400 is a PATCH whose only field is one no update writes.
		if rec.Code != http.StatusOK && !(rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "No fields to update")) {
			t.Fatalf("PATCH %s.%s: %d %s", table, col.Name, rec.Code, rec.Body.String())
		}
		return stored(table, id, col.Name, probe)
	}

	type descriptor struct {
		Tables map[string]struct {
			Ops    map[string]bool `json:"ops"`
			Fields []struct {
				Name     string `json:"name"`
				Writable bool   `json:"writable"`
			} `json:"fields"`
		} `json:"tables"`
	}
	describe := func(token string) descriptor {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_schema", token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/_schema: %d %s", rec.Code, rec.Body.String())
		}
		var d descriptor
		mustDecodeBody(t, rec, &d)
		return d
	}

	callers := []struct {
		name, token string
		tables      []string
		// createOnly: columns this caller's create stores and no PATCH does.
		createOnly []string
	}{
		{name: "member", token: member, tables: []string{"orders", "order_items", "projects"}},
		// A platform admin's create keeps an explicit tenant key, and a new
		// membership row names its member; neither is an update's to change.
		{name: "admin", token: admin, tables: []string{"orders", "order_items", "projects", "org_members"},
			createOnly: []string{"org_members.email", "org_members.org_id", "projects.org_id"}},
	}
	anyCreate, anyPatch := map[string]bool{}, map[string]bool{}
	writable := map[string]bool{} // "<caller> <table>.<column>"
	for _, c := range callers {
		desc := describe(c.token)
		var createOnly []string
		for _, table := range c.tables {
			td, ok := desc.Tables[table]
			if !ok || !td.Ops["write"] || !td.Ops["update"] {
				t.Fatalf("%s: descriptor ops for %s = %v (listed %v), want create and update allowed", c.name, table, td.Ops, ok)
			}
			described := map[string]bool{}
			for _, f := range td.Fields {
				described[f.Name] = f.Writable
			}
			cols, err := GetTableColumns(app.DB, table)
			if err != nil {
				t.Fatal(err)
			}
			for _, col := range cols {
				key := table + "." + col.Name
				onCreate, onPatch := createAccepts(c.token, table, col), patchAccepts(c.token, table, col)
				writable[c.name+" "+key] = described[col.Name]
				anyCreate[key] = anyCreate[key] || onCreate
				anyPatch[key] = anyPatch[key] || onPatch
				if described[col.Name] != onCreate {
					t.Errorf("%s: /api/_schema says %s writable=%v, but a create that sends it stores it: %v", c.name, key, described[col.Name], onCreate)
				}
				if onPatch && !onCreate {
					t.Errorf("%s: PATCH writes %s but a create does not", c.name, key)
				}
				if onCreate && !onPatch {
					createOnly = append(createOnly, key)
				}
			}
		}
		sort.Strings(createOnly)
		if !reflect.DeepEqual(createOnly, c.createOnly) {
			t.Errorf("%s: columns a create stores and a PATCH drops = %v, want %v", c.name, createOnly, c.createOnly)
		}
	}

	// The comparison above is only worth something if both answers occur.
	for key, want := range map[string]bool{
		"member orders.title":           true,
		"member orders.qty":             true,
		"member orders.tax_id":          true,
		"member orders.cf_ref":          true, // custom field
		"member orders.line_total":      false,
		"member orders.item_count":      false,
		"member orders.status":          false,
		"member orders.user_id":         false,
		"member orders.created_at":      false,
		"member orders.deleted_at":      false,
		"member projects.org_id":        false,
		"member projects.name":          true,
		"admin projects.org_id":         true,
		"admin org_members.email":       true,
		"admin org_members.member_role": false,
	} {
		if got, ok := writable[key]; !ok || got != want {
			t.Errorf("descriptor writable for %s = %v (probed %v), want %v", key, got, ok, want)
		}
	}

	// The OpenAPI request schemas: Create<Model> lists what some caller's
	// create stores, Update<Model> what some caller's PATCH stores.
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_openapi", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/_openapi: %d %s", rec.Code, rec.Body.String())
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	mustDecodeBody(t, rec, &spec)
	for table, model := range map[string]string{"orders": "Order", "order_items": "OrderItem", "projects": "Project", "org_members": "OrgMember"} {
		createSchema, ok1 := spec.Components.Schemas["Create"+model]
		updateSchema, ok2 := spec.Components.Schemas["Update"+model]
		if !ok1 || !ok2 {
			t.Fatalf("OpenAPI lacks Create%s/Update%s", model, model)
		}
		cols, _ := GetTableColumns(app.DB, table)
		for _, col := range cols {
			key := table + "." + col.Name
			if _, listed := createSchema.Properties[col.Name]; listed != anyCreate[key] {
				t.Errorf("OpenAPI Create%s lists %s: %v, but a create stores it: %v", model, col.Name, listed, anyCreate[key])
			}
			if _, listed := updateSchema.Properties[col.Name]; listed != anyPatch[key] {
				t.Errorf("OpenAPI Update%s lists %s: %v, but a PATCH stores it: %v", model, col.Name, listed, anyPatch[key])
			}
		}
	}
	if _, ok := spec.Components.Schemas["UpdateOrder"].Properties["_expected_updated_at"]; !ok {
		t.Error("UpdateOrder lost the _expected_updated_at concurrency token")
	}
}

// The fixture's own tests/*.yaml (what `benmore test --app` runs) pass too.
func TestSchemaDescriptorWritableFixtureTests(t *testing.T) {
	app, _ := schemaWritableFixture(t)
	ran := 0
	for _, r := range RunAppTests(app) {
		if r.File == "SUMMARY" {
			continue
		}
		ran++
		if !r.Pass {
			t.Errorf("%s/%s: %s %+v", r.File, r.Test, r.Message, r.Steps)
		}
	}
	if ran == 0 {
		t.Fatal("the fixture ran no tests")
	}
}

// The request schemas are built without a database too (`benmore verify`
// and unit tests hand generateRuntimeOpenAPI a bare App).
func TestOpenAPIWriteSchemasWithoutDatabase(t *testing.T) {
	app := &App{
		Tables: []Table{{Name: "orders", Columns: []Column{
			{Name: "id", Type: "INTEGER", PK: true, NotNull: true},
			{Name: "user_id", Type: "INTEGER", NotNull: true},
			{Name: "org_id", Type: "INTEGER"},
			{Name: "title", Type: "TEXT", NotNull: true},
			{Name: "total", Type: "REAL", NotNull: true},
			{Name: "status", Type: "TEXT"},
			{Name: "deleted_at", Type: "DATETIME"},
		}}},
		Group:    &GroupConfig{Table: "members", Key: "org_id", UserField: "email"},
		Computed: &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{"orders": {"total": {Table: "orders", Column: "total", Expr: "1"}}}},
		Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"order": {
			Name: "order", Table: "orders", Field: "status", Initial: "draft", States: []string{"draft", "done"},
		}}},
	}
	schemas := generateRuntimeOpenAPI(app)["components"].(map[string]any)["schemas"].(map[string]any)
	names := func(schema string) []string {
		props := schemas[schema].(map[string]any)["properties"].(map[string]any)
		out := make([]string, 0, len(props))
		for name := range props {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	// The tenant key stays in Create: a platform admin's create keeps it.
	if got := names("CreateOrder"); !reflect.DeepEqual(got, []string{"org_id", "title"}) {
		t.Errorf("CreateOrder properties = %v, want [org_id title]", got)
	}
	if got := names("UpdateOrder"); !reflect.DeepEqual(got, []string{"title"}) {
		t.Errorf("UpdateOrder properties = %v, want [title]", got)
	}
	// A computed NOT NULL column is not something a create must send.
	if required := schemas["CreateOrder"].(map[string]any)["required"]; !reflect.DeepEqual(required, []string{"title"}) {
		t.Errorf("CreateOrder required = %v, want [title]", required)
	}
}
