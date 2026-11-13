//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// SQLite keeps tables of its own in every database: sqlite_sequence holds the
// next id of each AUTOINCREMENT table and sqlite_stat1 the planner's
// statistics. They are ordinary tables to the engine (PRAGMA table_list says
// "table"), so the admin panel's write route ran generic create on them: a
// row posted to sqlite_sequence moved a table's next id.
func TestAdminPanelWritesNoSQLiteTable(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: \"engine-tables\"\n")
	writeTestFile(t, dir, "schema.prisma", "model Doc {\n  id    Int     @id @default(autoincrement())\n  title String\n\n  @@map(\"docs\")\n}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "https://fixture.example")
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	create := func(title string) float64 {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/docs", admin, map[string]any{"title": title})
		if rec.Code != http.StatusOK {
			t.Fatalf("create a doc: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			ID float64 `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.ID == 0 {
			t.Fatalf("create a doc: %s", rec.Body.String())
		}
		return body.ID
	}
	first := create("one")
	mustExec(t, app.DB, `ANALYZE`)
	var tables []string
	rows, err := app.DB.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if !strings.Contains(strings.Join(tables, ","), "sqlite_sequence") || !strings.Contains(strings.Join(tables, ","), "sqlite_stat1") {
		t.Fatalf("fixture: the database's own tables are %v", tables)
	}
	form := url.Values{"name": {"docs"}, "seq": {"900"}, "tbl": {"docs"}, "idx": {"forged"}, "stat": {"1 1"}, "id": {"1"}}.Encode()
	for _, name := range append(tables, "sqlite_master", "sqlite_schema", "sqlite_temp_master") {
		before := ""
		if !strings.Contains(name, "temp") {
			before = adminTableDump(t, app.DB, name)
		}
		for _, spelled := range []string{name, strings.ToUpper(name)} {
			for _, action := range []string{"create", "update/1", "delete/1"} {
				rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/"+spelled+"/"+action, admin, "application/x-www-form-urlencoded", form)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"admin_table_read_only"`) {
					t.Errorf("POST /_admin/api/%s/%s: %d %s, want 403 admin_table_read_only", spelled, action, rec.Code, strings.TrimSpace(rec.Body.String()))
				}
			}
		}
		if before != "" && adminTableDump(t, app.DB, name) != before {
			t.Errorf("%s changed through the admin panel", name)
		}
	}
	// The next id of the app's table is the one after its last row.
	if second := create("two"); second != first+1 {
		t.Errorf("the next doc got id %v after id %v", second, first)
	}
}
