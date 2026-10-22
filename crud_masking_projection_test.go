//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCRUDTenantMaskingPreservesProjectedReads(t *testing.T) {
	app, mux := newTenantRoleFixture(t, "access:\n  companies:\n    read: everyone\n  projects:\n    read: everyone\n")
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"companies": {{Column: "name", Roles: []string{"company_admin"}}},
		"projects":  {{Column: "name", Roles: []string{"company_admin"}}},
	}}
	sid, _ := tenantMember(t, app, "projection@example.test", "user", 1, "company_admin")
	for _, table := range []string{"companies", "projects"} {
		crudScopeMustExec(t, app.DB, "UPDATE "+table+" SET name=CASE id WHEN 1 THEN 'own-tenant-value' ELSE 'other-tenant-value' END")
		for _, page := range []string{"", "&page=1&per_page=2", "&cursor=0&limit=2"} {
			t.Run(table+page, func(t *testing.T) {
				w := crudScopeRequest(t, mux, http.MethodGet, "/api/"+table+"?fields=name"+page, sid, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("projected read: %d %s", w.Code, w.Body.String())
				}
				var rows []map[string]any
				if page == "" {
					if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
						t.Fatal(err)
					}
				} else {
					var result struct {
						Data       []map[string]any `json:"data"`
						NextCursor any              `json:"next_cursor"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					rows = result.Data
					if strings.Contains(page, "cursor") && result.NextCursor != float64(2) {
						t.Fatalf("cursor lost internal id: %s", w.Body.String())
					}
				}
				own, masked := 0, 0
				for _, row := range rows {
					if len(row) != 1 {
						t.Fatalf("internal identity columns escaped projection: %#v", row)
					}
					switch row["name"] {
					case "own-tenant-value":
						own++
					case maskValue("other-tenant-value"):
						masked++
					default:
						t.Errorf("unexpected projected value: %#v", row)
					}
				}
				if own != 1 || masked != 1 {
					t.Fatalf("own=%d masked=%d; response %s", own, masked, w.Body.String())
				}
			})
		}
	}
}
