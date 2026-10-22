//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// The synthetic owner explicitly supplies a stored ciphertext. These tests do
// not demonstrate ciphertext discovery: the peer's source read stays masked.
func TestAccountMetadataKeepsCiphertextLookingTextLiteral(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Note {
 id Int @id @default(autoincrement())
 user_id Int
 secret String
 @@map("notes")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access:
 notes: {read: everyone, write: self, update: self, delete: self}
encrypted:
 notes:
  - {column: secret, roles: [owner]}
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://metadata.example.invalid")
	owner := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	peer := createCrudScopeSession(t, app, "peer@example.com", "user", "", "")
	request := func(t *testing.T, method, path, token string, body any) map[string]any {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		if r.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	protected := request(t, "POST", "/api/notes", owner, map[string]any{"secret": "owner-private"})
	if row := request(t, "GET", fmt.Sprint("/api/notes/", protected["id"]), peer, nil); row["secret"] == "owner-private" {
		t.Fatal("source plaintext readable by peer")
	}
	var cipher string
	if err := app.DB.QueryRow("SELECT secret FROM notes WHERE id=?", protected["id"]).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	var peerID, ownerID int64
	if err := app.DB.QueryRow("SELECT user_id FROM _benmore_sessions WHERE id=?", sessionStorageKey(peer)).Scan(&peerID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT user_id FROM _benmore_sessions WHERE id=?", sessionStorageKey(owner)).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"known_cipher": cipher, "prefix_literal": "enc:v2:ordinary-label"} {
		t.Run(name, func(t *testing.T) {
			assertOwnRows := func(t *testing.T, path, envelope, field string) {
				t.Helper()
				rows := request(t, "GET", path, peer, nil)[envelope].([]any)
				found := false
				for _, item := range rows {
					row := item.(map[string]any)
					if row[field] == "other-user-control" {
						t.Errorf("%s returned another user's metadata", path)
					}
					if row[field] == value {
						found = true
					}
				}
				if !found {
					t.Errorf("%s did not preserve literal %s metadata: %#v", path, field, rows)
				}
			}
			t.Run("session_browser", func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("User-Agent", value)
				AttachSessionContext(app.DB, peer, r)
				r.Header.Set("User-Agent", "other-user-control")
				AttachSessionContext(app.DB, owner, r)
				assertOwnRows(t, "/api/_auth/sessions", "sessions", "user_agent")
			})
			t.Run("token_name", func(t *testing.T) {
				request(t, "POST", "/api/_auth/api-tokens", owner, map[string]any{"name": "other-user-control", "scopes": "*"})
				request(t, "POST", "/api/_auth/api-tokens", peer, map[string]any{"name": value, "scopes": "*"})
				assertOwnRows(t, "/api/_auth/api-tokens", "tokens", "name")
			})
			t.Run("saved_view", func(t *testing.T) {
				for token, label := range map[string]string{owner: "other-user-control", peer: value} {
					request(t, "POST", "/api/_query/views", token, map[string]any{"name": label, "spec": map[string]any{"table": "notes"}})
				}
				assertOwnRows(t, "/api/_query/views", "views", "name")
			})
			t.Run("scheduled_reminder", func(t *testing.T) {
				for token, label := range map[string]string{owner: "other-user-control", peer: value} {
					request(t, "POST", "/api/_scheduled", token, map[string]any{"title": label, "message": label, "run_at": "24h"})
				}
				assertOwnRows(t, "/api/_scheduled", "tasks", "title")
				assertOwnRows(t, "/api/_scheduled", "tasks", "message")
				if _, err := app.DB.Exec("UPDATE _benmore_scheduled_tasks SET run_at='2000-01-01T00:00:00Z' WHERE user_id=? AND title=?", peerID, value); err != nil {
					t.Fatal(err)
				}
				sweepScheduledTasks(app)
				var title, body string
				if err := app.DB.QueryRow("SELECT title,body FROM _benmore_notifications WHERE user_id=? ORDER BY id DESC LIMIT 1", peerID).Scan(&title, &body); err != nil {
					t.Fatal(err)
				}
				if title != value || body != value {
					t.Errorf("reminder dispatch interpreted ordinary text: title=%q body=%q", title, body)
				}
			})
			t.Run("approval", func(t *testing.T) {
				for token, label := range map[string]string{owner: "other-user-control", peer: value} {
					request(t, "POST", "/api/_approvals", token, map[string]any{"table": "private-request", "row_id": name, "title": label})
				}
				assertOwnRows(t, "/api/_approvals", "approvals", "title")
			})
			t.Run("notification", func(t *testing.T) {
				for uid, label := range map[int64]string{ownerID: "other-user-control", peerID: value} {
					if _, err := CreateNotification(app.DB, uid, label, label, "info", ""); err != nil {
						t.Fatal(err)
					}
				}
				assertOwnRows(t, "/api/_notifications", "notifications", "title")
				assertOwnRows(t, "/api/_notifications", "notifications", "body")
			})
			t.Run("passkey_display_name", func(t *testing.T) {
				// This tests the stored metadata policy, not authenticator bypass.
				// Registration separately verifies WebAuthn and caps names at 64.
				for uid, label := range map[int64]string{ownerID: "other-user-control", peerID: value} {
					if _, err := app.DB.Exec("INSERT INTO _benmore_passkeys(user_id,credential_id,public_key,alg,name) VALUES (?,?,?,-7,?)", uid, fmt.Sprint(uid, name), []byte{1}, label); err != nil {
						t.Fatal(err)
					}
				}
				assertOwnRows(t, "/api/_auth/passkeys", "passkeys", "name")
			})
			t.Run("webhook_secret_decoded_once", func(t *testing.T) {
				// Store through the same explicit sealing helper as POST. No
				// endpoint is registered or contacted by this metadata test.
				sealed, err := fieldEncryptForDB(app.DB, value)
				if err != nil {
					t.Fatal(err)
				}
				result, err := app.DB.Exec("INSERT INTO _benmore_webhooks(user_id,url,secret,tables,events,active) VALUES (?,?,?,?,?,0)", peerID, "https://example.invalid/hook", sealed, value, "insert")
				if err != nil {
					t.Fatal(err)
				}
				id, _ := result.LastInsertId()
				rows := request(t, "GET", "/api/_webhooks", peer, nil)["webhooks"].([]any)
				found := false
				for _, entry := range rows {
					row := entry.(map[string]any)
					if row["id"] == float64(id) {
						found = true
						if row["tables"] != value || row["secret"] != webhookSecretHint(value) {
							t.Errorf("webhook literal metadata or sealed hint changed: %#v", row)
						}
					}
				}
				if !found {
					t.Fatal("missing own webhook")
				}
			})
			t.Run("oauth_metadata_and_sealed_token", func(t *testing.T) {
				StoreOAuthToken(app.DB, peerID, name, value, "refresh-control", value, 3600, value)
				r := crudScopeRequest(t, mux, "GET", "/api/_auth/oauth-tokens", peer, nil)
				var rows []map[string]any
				if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &rows) != nil {
					t.Fatalf("OAuth listing: %d %s", r.Code, r.Body.String())
				}
				found := false
				for _, row := range rows {
					if row["provider"] == name {
						found = true
						if row["token_type"] != value || row["scopes"] != value {
							t.Errorf("OAuth metadata interpreted: %#v", row)
						}
					}
					if _, exists := row["access_token"]; exists {
						t.Error("OAuth listing exposed token")
					}
				}
				if !found {
					t.Fatal("missing OAuth metadata")
				}
				if got := GetOAuthToken(app.DB, app.Dir, peerID, name); got != value {
					t.Errorf("sealed OAuth token changed: %q", got)
				}
			})
		})
	}
}
