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

// A broad read rule (`everyone`, `anon`) opens the current rows; a row's
// history stays inside the row scope (owner, tenant, record grant, admin).
// Earlier values may have been removed from the row on purpose, so a caller
// who reads the row only through the broad rule gets 404 for its versions, a
// point-in-time read and a revert.
func TestVersionHistoryStaysRowScopedUnderReadEveryone(t *testing.T) {
	for _, mode := range []string{"everyone", "anon"} {
		t.Run(mode, func(t *testing.T) { versionHistoryUnderBroadRead(t, mode) })
	}
}

func versionHistoryUnderBroadRead(t *testing.T, mode string) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"read": mode}},
		`INSERT INTO records (org_id, user_id, title) VALUES ('org-a', 1, 'withdrawn-detail')`,
	)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-b", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	cfg := &VersionedConfig{Tables: []string{"records"}}
	InstallVersioningTriggers(app.DB, cfg)
	RegisterVersioningAPI(mux, app, cfg)
	crudScopeMustExec(t, app.DB, `UPDATE records SET title = 'public-title' WHERE id = 1`) // v1: withdrawn-detail

	// The broad rule: another tenant's user lists and reads the current row.
	for _, path := range []string{"/api/records", "/api/records/1"} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, bob, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "public-title") || strings.Contains(rec.Body.String(), "withdrawn-detail") {
			t.Fatalf("GET %s under read: %s = %d %s", path, mode, rec.Code, rec.Body.String())
		}
	}
	// Its history is not theirs.
	for _, path := range []string{"/api/records/1/versions", "/api/records/1/versions/1", "/api/records/1?as_of=2000-01-01T00:00:00Z"} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, bob, nil)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "withdrawn-detail") {
			t.Fatalf("GET %s for a caller outside the row scope = %d %s, want 404", path, rec.Code, rec.Body.String())
		}
	}
	assertStatus(t, mux, http.MethodPost, "/api/records/1/revert/1", bob, nil, http.StatusNotFound)
	assertRecordTitle(t, app.DB, 1, "public-title")

	// Inside the row scope, and for an admin, the history is served.
	for who, token := range map[string]string{"the owner": alice, "an admin": admin} {
		if got := versionNumbers(t, mux, token, "/api/records/1/versions"); len(got) != 1 || got[0] != 1 {
			t.Fatalf("%s sees versions %v, want [1]", who, got)
		}
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/records/1/versions/1", token, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "withdrawn-detail") {
			t.Fatalf("%s reads version 1: %d %s", who, rec.Code, rec.Body.String())
		}
	}
}
