//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// GET /api/<table>/<id>?fields=a,b ignored the projection and answered every
// column, while the list honored it. The single-row read now resolves
// ?fields= through the list's helper, so for any projection it returns the
// same object the list returns for that row: unknown and hidden columns
// dropped, a projection of nothing falling back to every column, encrypted
// columns masked with the row's own tenant even when the tenant column is
// not projected.
func TestSingleRowReadHonorsFieldsLikeList(t *testing.T) {
	app := newTenantRoleApp(t, "access:\n  companies:\n    read: everyone\n  projects:\n    read: everyone\n")
	crudScopeMustExec(t, app.DB, "ALTER TABLE projects ADD COLUMN api_token TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE projects SET api_token='tok-hidden', name=CASE id WHEN 1 THEN 'own-tenant-value' ELSE 'other-tenant-value' END")
	cols, err := GetTableColumns(app.DB, "projects")
	if err != nil {
		t.Fatal(err)
	}
	for i := range app.Tables {
		if app.Tables[i].Name == "projects" {
			app.Tables[i].Columns = cols
		}
	}
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"projects": {{Column: "name", Roles: []string{"company_admin"}}},
	}}
	mux := buildAppMux(app, true, "http://localhost")
	sid, _ := tenantMember(t, app, "fields@example.test", "user", 1, "company_admin")

	get := func(path string) (map[string]any, string) {
		t.Helper()
		w := crudScopeRequest(t, mux, http.MethodGet, path, sid, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "tok-hidden") {
			t.Fatalf("GET %s exposed a hidden column: %s", path, w.Body.String())
		}
		var row map[string]any
		if strings.HasPrefix(strings.TrimSpace(w.Body.String()), "[") {
			var rows []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 {
				t.Fatalf("GET %s: %d rows, want 1", path, len(rows))
			}
			row = rows[0]
		} else if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		return row, w.Header().Get(ignoredParamsHeader)
	}

	for _, fields := range []string{"", "name", "id,name", "id, name", "id,api_token", "api_token", "nope", "id,nope", "company_id"} {
		for _, id := range []int{1, 2} {
			q := ""
			if fields != "" {
				q = "fields=" + url.QueryEscape(fields)
			}
			one, oneIgnored := get(fmt.Sprintf("/api/projects/%d?%s", id, q))
			listed, _ := get(fmt.Sprintf("/api/projects?id=%d&%s", id, q))
			if !reflect.DeepEqual(one, listed) {
				t.Errorf("fields=%q id=%d: read %v, list %v", fields, id, one, listed)
			}
			if oneIgnored != "" {
				t.Errorf("fields=%q id=%d: read reported X-Ignored-Params %q", fields, id, oneIgnored)
			}
		}
	}

	// The read answers exactly the projected columns, masked per row tenant.
	for path, want := range map[string]map[string]any{
		"/api/projects/1?fields=name":           {"name": "own-tenant-value"},
		"/api/projects/2?fields=name":           {"name": encryptedFieldMask},
		"/api/projects/1?fields=id,api_token":   {"id": float64(1)},
		"/api/projects/2?fields=id,company_id":  {"id": float64(2), "company_id": float64(2)},
		"/api/projects/1?fields=id,nope,status": {"id": float64(1)},
	} {
		if got, _ := get(path); !reflect.DeepEqual(got, want) {
			t.Errorf("GET %s = %v, want %v", path, got, want)
		}
	}
	// Nothing projectable falls back to every visible column, as the list does.
	if got, _ := get("/api/projects/1?fields=api_token"); got["id"] != float64(1) || got["name"] != "own-tenant-value" || got["company_id"] != float64(1) {
		t.Errorf("unprojectable fields did not fall back to the full row: %v", got)
	}
}
