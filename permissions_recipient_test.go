//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// A small document-sharing app, with native writes/reads and real synthetic
// account rows. The peer owns no documents and cannot read the encrypted note.
func shareRecipientFixture(t *testing.T, peerEmail string) (*App, *http.ServeMux, string, string) {
	t.Helper()
	app, _ := newTenantRoleFixture(t, "access:\n  documents:\n    read: self\n    write: self\n    update: self\n    delete: self\n")
	mustExec(t, app.DB, `CREATE TABLE documents(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, user_id INTEGER, title TEXT, private_note TEXT)`)
	path := filepath.Join(app.Dir, "data.db")
	RegisterDBEncryptionKey(path, testKeyBytes(0x46))
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"documents": {{Column: "private_note", Roles: []string{"company_admin"}}},
	}}
	InstallEncryptionTriggers(app.DB, app.Encrypted)
	refreshTableColumns(t, app, "documents")
	mux := buildAppMux(app, true, "http://localhost")
	owner, _ := tenantMember(t, app, "owner@example.test", "user", 1, "company_admin")
	peer, _ := tenantMember(t, app, peerEmail, "user", 1, "member")
	assertStatus(t, mux, http.MethodPost, "/api/documents", owner, map[string]any{"title": "Private evidence", "private_note": "synthetic secret"}, http.StatusOK)
	assertTenantEncryptedRead(t, mux, owner, "/api/documents/1", true, "synthetic secret")
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
	return app, mux, owner, peer
}

func shareRecipientPost(t *testing.T, mux *http.ServeMux, owner, email, permission string) *httptest.ResponseRecorder {
	t.Helper()
	return crudScopeRequest(t, mux, http.MethodPost, "/api/documents/1/share", owner, map[string]any{"email": email, "permission": permission})
}

func shareRecipientSnapshot(t *testing.T, app *App) string {
	t.Helper()
	rows, err := queryMetadataRows(app.DB, "SELECT * FROM _benmore_permissions ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := queryMetadataRows(app.DB, "SELECT * FROM _benmore_audit_log WHERE action='share' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal([]any{rows, audit})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestShareRecipientResolvesExistingAccountSpelling(t *testing.T) {
	for _, stored := range []string{"peer@example.test", "Peer@Example.Test"} {
		t.Run(stored, func(t *testing.T) {
			app, mux, owner, peer := shareRecipientFixture(t, stored)
			for _, input := range []string{stored, strings.ToUpper(stored), " \t" + stored + "\n"} {
				w := shareRecipientPost(t, mux, owner, input, "view")
				if w.Code != http.StatusOK {
					t.Fatalf("share %q: %d %s", input, w.Code, w.Body.String())
				}
				var response map[string]any
				mustDecodeBody(t, w, &response)
				if response["email"] != stored {
					t.Errorf("share response email=%q, want actual stored %q", response["email"], stored)
				}
				var recipient, auditRecipient string
				var grants int
				if err := app.DB.QueryRow("SELECT count(*), grantee_id FROM _benmore_permissions").Scan(&grants, &recipient); err != nil || grants != 1 || recipient != stored {
					t.Errorf("share must upsert one exact identity: grants=%d recipient=%q err=%v", grants, recipient, err)
				}
				if err := app.DB.QueryRow("SELECT json_extract(new_values, '$.shared_with') FROM _benmore_audit_log WHERE action='share' ORDER BY id DESC LIMIT 1").Scan(&auditRecipient); err != nil || auditRecipient != stored {
					t.Errorf("audited recipient=%q want=%q err=%v", auditRecipient, stored, err)
				}
				assertTenantEncryptedRead(t, mux, peer, "/api/documents/1", false, "synthetic secret")
			}
			assertListIDs(t, mux, peer, "/api/documents", []float64{1})
			assertStatus(t, mux, http.MethodDelete, "/api/documents/1/permissions/"+url.PathEscape(strings.ToUpper(stored)), owner, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
		})
	}
}

func TestShareRecipientRefusesAmbiguousAccountsWithoutEffects(t *testing.T) {
	for _, state := range []string{"verified", "unverified", "deactivated"} {
		t.Run(state, func(t *testing.T) {
			app, mux, owner, _ := shareRecipientFixture(t, "peer@example.test")
			if w := shareRecipientPost(t, mux, owner, "peer@example.test", "view"); w.Code != http.StatusOK {
				t.Fatalf("initial share: %d %s", w.Code, w.Body.String())
			}
			// Legacy DBs can lack this best-effort index. Every matching account
			// counts, even when it cannot currently exercise an email grant.
			mustExec(t, app.DB, "DROP INDEX idx_benmore_users_email_nocase")
			mustExec(t, app.DB, `INSERT INTO _benmore_users(username,email,verified) VALUES('duplicate','PEER@EXAMPLE.TEST',1)`)
			if state == "unverified" {
				mustExec(t, app.DB, "UPDATE _benmore_users SET verified=0, email_grandfathered=0 WHERE username='duplicate'")
			} else if state == "deactivated" {
				mustExec(t, app.DB, "UPDATE _benmore_users SET deactivated_at='2026-01-01' WHERE username='duplicate'")
			}
			before := shareRecipientSnapshot(t, app)
			for _, input := range []string{"peer@example.test", "PEER@EXAMPLE.TEST", " PeEr@Example.Test "} {
				w := shareRecipientPost(t, mux, owner, input, "admin")
				if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "ambiguous") {
					t.Errorf("ambiguous identity must refuse: %d %s", w.Code, w.Body.String())
				}
				if after := shareRecipientSnapshot(t, app); after != before {
					t.Errorf("ambiguous share changed grants or successful-share audit: before=%s after=%s", before, after)
				}
			}
		})
	}
}

func TestShareRecipientFutureSpellingRemainsExact(t *testing.T) {
	app, mux, owner, _ := shareRecipientFixture(t, "peer@example.test")
	for _, recipient := range []string{"Future@Example.Test", " FutureWhitespace@Example.Test "} {
		w := shareRecipientPost(t, mux, owner, recipient, "view")
		if w.Code != http.StatusOK {
			t.Fatalf("future recipient refused: %d %s", w.Code, w.Body.String())
		}
		var response map[string]any
		mustDecodeBody(t, w, &response)
		var stored string
		if err := app.DB.QueryRow("SELECT grantee_id FROM _benmore_permissions ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil || stored != recipient || response["email"] != recipient {
			t.Fatalf("future spelling changed: stored=%q response=%v want=%q err=%v", stored, response, recipient, err)
		}
	}
	// Case-preserving OAuth/provisioned identities may appear after the share.
	future, _ := tenantMember(t, app, "Future@Example.Test", "user", 1, "member")
	assertTenantEncryptedRead(t, mux, future, "/api/documents/1", false, "synthetic secret")
}

func TestShareRecipientDoesNotActivateHistoricalAdminGrant(t *testing.T) {
	app, mux, owner, peer := shareRecipientFixture(t, "peer@example.test")
	mustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission,granted_at,expires_at) VALUES('documents','1','user','PEER@EXAMPLE.TEST','admin','2001-01-01','2099-01-01')`)
	var before string
	if err := app.DB.QueryRow("SELECT json_object('id',id,'resource_type',resource_type,'resource_id',resource_id,'grant_type',grant_type,'grantee_id',grantee_id,'permission',permission,'granted_by',granted_by,'granted_at',granted_at,'expires_at',expires_at) FROM _benmore_permissions WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
	w := shareRecipientPost(t, mux, owner, " PEER@EXAMPLE.TEST ", "view")
	if w.Code != http.StatusOK {
		t.Fatalf("new view share: %d %s", w.Code, w.Body.String())
	}
	var after string
	if err := app.DB.QueryRow("SELECT json_object('id',id,'resource_type',resource_type,'resource_id',resource_id,'grant_type',grant_type,'grantee_id',grantee_id,'permission',permission,'granted_by',granted_by,'granted_at',granted_at,'expires_at',expires_at) FROM _benmore_permissions WHERE id=1").Scan(&after); err != nil || after != before {
		t.Fatalf("historical admin grant changed: before=%s after=%s err=%v", before, after, err)
	}
	assertTenantEncryptedRead(t, mux, peer, "/api/documents/1", false, "synthetic secret")
	assertStatus(t, mux, http.MethodPatch, "/api/documents/1", peer, map[string]any{"title": "forbidden"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/documents/1", peer, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodGet, "/api/documents/1/permissions", peer, nil, http.StatusForbidden)
	assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", peer, map[string]any{"email": "another@example.test", "permission": "admin"}, http.StatusForbidden)
	// Revoke just the new row; the old mismatched admin grant remains inert.
	assertStatus(t, mux, http.MethodDelete, "/api/documents/1/share/2", owner, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
}

func TestShareRecipientRetainsAuthorityAndProofGates(t *testing.T) {
	app, mux, owner, peer := shareRecipientFixture(t, "peer@example.test")
	foreign, _ := tenantMember(t, app, "foreign@example.test", "user", 2, "member")
	for _, recipient := range []string{" PEER@EXAMPLE.TEST ", " FOREIGN@EXAMPLE.TEST "} {
		if w := shareRecipientPost(t, mux, owner, recipient, "view"); w.Code != http.StatusOK {
			t.Fatalf("share: %d %s", w.Code, w.Body.String())
		}
	}
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", foreign, nil, http.StatusNotFound)
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified=0,email_grandfathered=0 WHERE email='peer@example.test'")
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified=1 WHERE email='peer@example.test'")
	assertTenantEncryptedRead(t, mux, peer, "/api/documents/1", false, "synthetic secret")
	assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", owner, map[string]any{"email": " PEER@EXAMPLE.TEST ", "permission": "view", "expires_at": "2000-01-01T00:00:00Z"}, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/documents/1", peer, nil, http.StatusNotFound)
	before := shareRecipientSnapshot(t, app)
	for _, empty := range []string{"", " \t\r\n", "\u2003"} {
		if w := shareRecipientPost(t, mux, owner, empty, "view"); w.Code != http.StatusBadRequest {
			t.Errorf("blank recipient accepted: %d %s", w.Code, w.Body.String())
		}
	}
	assertStatus(t, mux, http.MethodPost, "/api/documents/1/share", "", map[string]any{"email": "peer@example.test", "permission": "view"}, http.StatusUnauthorized)
	req := httptest.NewRequest(http.MethodPost, "/api/documents/1/share", strings.NewReader(`{"email":"peer@example.test","permission":"view"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: owner})
	csrf := httptest.NewRecorder()
	mux.ServeHTTP(csrf, req)
	if csrf.Code != http.StatusForbidden {
		t.Errorf("missing CSRF accepted: %d", csrf.Code)
	}
	if _, err := app.DB.Exec("UPDATE _benmore_sessions SET scopes='documents:read' WHERE id=?", sessionStorageKey(owner)); err != nil {
		t.Fatal(err)
	}
	if w := shareRecipientPost(t, mux, owner, " PEER@EXAMPLE.TEST ", "admin"); w.Code != http.StatusForbidden {
		t.Errorf("read-scoped owner share accepted: %d %s", w.Code, w.Body.String())
	}
	if after := shareRecipientSnapshot(t, app); after != before {
		t.Errorf("refused requests changed grants/audit: before=%s after=%s", before, after)
	}
}
