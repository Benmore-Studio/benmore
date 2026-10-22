//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func editorPaginationFixture(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app, mux := newCrudScopeTestApp(t)
	token := createCrudScopeSession(t, app, "editor@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN deleted_at DATETIME")
	app.Tables[1].Columns = append(app.Tables[1].Columns, Column{Name: "deleted_at", Type: "DATETIME"})
	for i := 3; i <= 10; i++ {
		crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes(id,user_id,title) VALUES (%d,1,'article')", i))
	}
	crudScopeMustExec(t, app.DB, "UPDATE notes SET deleted_at='2026-01-01' WHERE id=5")
	cfg := &VersionedConfig{Tables: []string{"notes"}}
	if err := InstallVersioningTriggers(app.DB, cfg); err != nil {
		t.Fatal(err)
	}
	RegisterVersioningAPI(mux, app, cfg)
	return app, mux, token
}

func TestEditorPaginationAliases(t *testing.T) {
	_, mux, token := editorPaginationFixture(t)
	for _, tc := range []struct {
		query string
		ids   string
	}{
		{"limit=3&offset=0", "1,3,4"},
		{"limit=3&offset=3", "6,7,8"},
		{"limit=3&offset=6", "9,10"},
		{"limit=3&offset=1", "3,4,6"},
		{"limit=3&offset=100000", ""},
		{"limit=3&offset=-1", "1,3,4"},
		{"limit=3&offset=bad", "1,3,4"},
		{"limit=3&offset=0&title=article", "3,4,6"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?sort=id&order=asc&"+tc.query, token, nil)
			if r.Code != 200 {
				t.Fatalf("status %d: %s", r.Code, r.Body.String())
			}
			var rows []map[string]any
			if err := json.Unmarshal(r.Body.Bytes(), &rows); err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, row := range rows {
				ids = append(ids, fmt.Sprint(row["id"]))
			}
			if got := strings.Join(ids, ","); got != tc.ids {
				t.Fatalf("got ids %s, want %s", got, tc.ids)
			}
		})
	}
	for _, query := range []string{"limit=3&offset=100001", "limit=3&offset=999999999999999999999999999"} {
		r := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?"+query, token, nil)
		if r.Code != 400 || !strings.Contains(r.Body.String(), "cursor") {
			t.Errorf("deep offset: %d %s", r.Code, r.Body.String())
		}
	}
	// Legacy page/per_page wins over aliases; response metadata and rows agree.
	r := crudScopeRequest(t, mux, http.MethodGet, "/api/notes?sort=id&order=asc&page=2&per_page=2&limit=1&offset=100001", token, nil)
	var body struct {
		Data        []map[string]any
		Total, Page int
		PerPage     int `json:"per_page"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if r.Code != 200 || body.Total != 8 || body.Page != 2 || body.PerPage != 2 || len(body.Data) != 2 || body.Data[0]["id"] != float64(4) {
		t.Fatalf("legacy paging changed: %d %s", r.Code, r.Body.String())
	}
}

func TestEditorSDKAgainstRuntime(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	_, mux, token := editorPaginationFixture(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd := exec.Command(node, "embedded/bm_editor_contract_test.mjs")
	cmd.Env = append(os.Environ(), "BM_EDITOR_TEST_URL="+server.URL, "BM_EDITOR_TEST_TOKEN="+token)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("editor SDK journey: %v\n%s", err, out)
	}
}

func TestEditorGeneratedMutationAndHistoryTypes(t *testing.T) {
	output := GenerateBMTypes(&App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "deleted_at", Type: "DATETIME"}}}}})
	packageTypes, err := os.ReadFile("packages/bm/index.d.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, contract := range []string{
		"update(id: number | string, body: Partial<Row>): Promise<UpdateReceipt>;",
		"versions(id: number | string): Promise<VersionHistory>;",
		"revertTo(id: number | string, version: number): Promise<RevertReceipt>;",
		"_version: number;", "_valid_from: string;", "_valid_to: string | null;", "_changed_by: number | null;", "_change_type: string;",
		"versions: VersionMetadata[];", "reverted_to_version: string;", "owned_fields_kept: string[] | null;",
	} {
		if !strings.Contains(output, contract) {
			t.Errorf("generated declaration missing actual wire contract: %s", contract)
		}
		if !strings.Contains(string(packageTypes), contract) {
			t.Errorf("package declaration missing actual wire contract: %s", contract)
		}
	}
}
