//go:build !cli

package main

import (
	"net/http"
	"net/url"
	"testing"
)

// The document is created and shared through the same native routes an app's
// sharing panel uses. Existing tenant fixtures provide only synthetic identities.
func sharedDocumentFixture(t *testing.T, permission, expiry string) (*App, *http.ServeMux, string, string, string) {
	t.Helper()
	app, _ := newTenantRoleFixture(t, "access:\n  documents:\n    read: self\n    write: self\n    update: self\n    delete: self\n")
	mustExec(t, app.DB, `CREATE TABLE documents(id INTEGER PRIMARY KEY AUTOINCREMENT,company_id INTEGER,user_id INTEGER,title TEXT,deleted_at TEXT)`)
	refreshTableColumns(t, app, "documents")
	mux := buildAppMux(app, true, "http://localhost")
	owner, _ := tenantMember(t, app, "owner@example.test", "user", 1, "member")
	peer, _ := tenantMember(t, app, "peer@example.test", "user", 1, "member")
	foreign, _ := tenantMember(t, app, "foreign@example.test", "user", 2, "member")
	assertStatus(t, mux, http.MethodPost, "/api/documents", owner, map[string]any{"title": "Private evidence"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", owner, map[string]any{"email": "peer@example.test", "permission": permission, "expires_at": expiry}, http.StatusOK)
	return app, mux, owner, peer, foreign
}

func TestPermissionActionMatrix(t *testing.T) {
	for _, permission := range []string{"view", "edit", "delete", "admin"} {
		t.Run(permission, func(t *testing.T) {
			app, mux, owner, peer, foreign := sharedDocumentFixture(t, permission, "")
			assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusOK)
			assertListIDs(t, mux, peer, "/api/documents", []float64{1})
			wantUpdate, wantDelete, wantACL := http.StatusNotFound, http.StatusNotFound, http.StatusForbidden
			if permission == "edit" || permission == "admin" {
				wantUpdate = http.StatusOK
			}
			if permission == "delete" || permission == "admin" {
				wantDelete = http.StatusOK
			}
			if permission == "admin" {
				wantACL = http.StatusOK
			}
			assertStatus(t, mux, http.MethodPatch, "/api/documents/1", peer, map[string]any{"title": "Reviewed evidence"}, wantUpdate)
			assertStatus(t, mux, http.MethodGet, "/api/documents/1/permissions", peer, nil, wantACL)
			assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", peer, map[string]any{"email": "other@example.test", "permission": "view"}, wantACL)
			assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", owner, map[string]any{"email": "foreign@example.test", "permission": permission}, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/documents/1", foreign, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/documents/1", foreign, map[string]any{"title": "foreign overwrite"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/documents/1", foreign, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/documents/1", peer, nil, wantDelete)
			if wantDelete == http.StatusOK {
				assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
			} else {
				assertStatus(t, mux, http.MethodDelete, "/api/documents/1", owner, nil, http.StatusOK)
			}
			// Restore requires update authority. A delete-only grantee cannot restore.
			assertStatus(t, mux, http.MethodPost, "/api/documents/1/restore", peer, nil, wantUpdate)
			wantLive := "0"
			if wantUpdate == http.StatusOK {
				wantLive = "1"
			}
			if got := gateScalar(t, app, `SELECT deleted_at IS NULL FROM documents WHERE id=1`); got != wantLive {
				t.Fatalf("restore state=%s, want %s", got, wantLive)
			}
		})
	}
}

func TestPermissionListingNeedsSharingAuthority(t *testing.T) {
	for _, scopes := range []string{"documents:read", "documents:write", "projects:write"} {
		t.Run(scopes, func(t *testing.T) {
			app, mux, owner, _, _ := sharedDocumentFixture(t, "view", "")
			if _, err := app.DB.Exec(`UPDATE _benmore_sessions SET scopes=? WHERE id=?`, scopes, sessionStorageKey(owner)); err != nil {
				t.Fatal(err)
			}
			want := http.StatusForbidden
			if scopes == "documents:write" {
				want = http.StatusOK
			}
			assertStatus(t, mux, http.MethodGet, "/api/documents/1/permissions", owner, nil, want)
			assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", owner, map[string]any{"email": "other@example.test", "permission": "view"}, want)
		})
	}
}

func TestPermissionActionDenials(t *testing.T) {
	for _, condition := range []string{"expired", "revoked", "read scope", "table policy"} {
		t.Run(condition, func(t *testing.T) {
			expiry := ""
			if condition == "expired" {
				expiry = "2000-01-01T00:00:00Z"
			}
			app, mux, owner, peer, _ := sharedDocumentFixture(t, "edit", expiry)
			want := http.StatusNotFound
			switch condition {
			case "revoked":
				assertStatus(t, mux, http.MethodDelete, "/api/documents/1/permissions/"+url.PathEscape("peer@example.test"), owner, nil, http.StatusOK)
			case "read scope":
				if _, err := app.DB.Exec(`UPDATE _benmore_sessions SET scopes='documents:read' WHERE id=?`, sessionStorageKey(peer)); err != nil {
					t.Fatal(err)
				}
				want = http.StatusForbidden
			case "table policy":
				// Native creation queued a realtime policy read. Drain it before
				// this test changes policy; the grant must be created while edits
				// are still allowed by the ordinary sharing-authority gate.
				realtimeFlush()
				app.Access.rules["documents"][OpUpdate] = "off"
			}
			assertStatus(t, mux, http.MethodPatch, "/api/documents/1", peer, map[string]any{"title": "forbidden"}, want)
			if got := gateScalar(t, app, `SELECT title FROM documents WHERE id=1`); got != "Private evidence" {
				t.Fatalf("%s allowed edit: %s", condition, got)
			}
		})
	}
}
