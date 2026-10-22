//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func versionNumbers(t *testing.T, mux *http.ServeMux, token, path string) []float64 {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	var body struct {
		Versions []map[string]any `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var out []float64
	for _, v := range body.Versions {
		out = append(out, v["_version"].(float64))
	}
	return out
}

// Version history follows the row id. When a row moved to another owner or
// tenant, the new owner could read (and revert to) every snapshot taken
// while it belonged to someone else.
func TestVersionHistoryHidesPreTransferSnapshots(t *testing.T) {
	for _, tc := range []struct {
		mode, move, newOwner string
	}{
		{"self", "UPDATE records SET user_id = 2 WHERE id = 1", "bob@example.com"},
		{"group", "UPDATE records SET org_id = 'org-b', user_id = 2 WHERE id = 1", "bob@example.com"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			app, mux := newAccessScopeFixture(t,
				map[string]map[AccessOp]string{"records": {"all": tc.mode}},
				`INSERT INTO records (org_id, user_id, title) VALUES ('org-a', 1, 'alice-secret')`,
			)
			_ = createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
			bobGroup := "org-a"
			if tc.mode == "group" {
				bobGroup = "org-b"
			}
			bob := createCrudScopeSession(t, app, tc.newOwner, "user", bobGroup, "")
			admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
			cfg := &VersionedConfig{Tables: []string{"records"}}
			InstallVersioningTriggers(app.DB, cfg)
			RegisterVersioningAPI(mux, app, cfg)

			crudScopeMustExec(t, app.DB, `UPDATE records SET title = 'alice-later' WHERE id = 1`) // v1: alice-secret
			crudScopeMustExec(t, app.DB, tc.move)                                                 // v2: alice-later (pre-transfer)
			crudScopeMustExec(t, app.DB, `UPDATE records SET title = 'bob-edit' WHERE id = 1`)    // v3: bob's own

			if got := versionNumbers(t, mux, bob, "/api/records/1/versions"); len(got) != 1 || got[0] != 3 {
				t.Fatalf("new owner sees versions %v, want only [3]", got)
			}
			for _, v := range []string{"1", "2"} {
				rec := crudScopeRequest(t, mux, http.MethodGet, "/api/records/1/versions/"+v, bob, nil)
				if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "alice") {
					t.Fatalf("GET version %s = %d %s, want 404", v, rec.Code, rec.Body.String())
				}
				assertStatus(t, mux, http.MethodPost, "/api/records/1/revert/"+v, bob, nil, http.StatusNotFound)
			}
			assertRecordTitle(t, app.DB, 1, "bob-edit")
			assertStatus(t, mux, http.MethodGet, "/api/records/1/versions/3", bob, nil, http.StatusOK)

			// Admin bypass is unchanged.
			if got := versionNumbers(t, mux, admin, "/api/records/1/versions"); len(got) != 3 {
				t.Fatalf("admin sees versions %v, want all 3", got)
			}
		})
	}
}
