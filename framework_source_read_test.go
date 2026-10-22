//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"html"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFrameworkAdminAndWorkspaceReadsKeepLiteralText(t *testing.T) {
	f := newCanonicalUpdateSourceFixture(t, "", "", "", false)
	var cipher string
	if err := f.app.DB.QueryRow("SELECT secret FROM notes WHERE id=1").Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"known_cipher": cipher, "prefix_literal": "enc:v2:ordinary-label"} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.app.DB.Exec("UPDATE notes SET title=? WHERE id=1", value); err != nil {
				t.Fatal(err)
			}
			for name, render := range map[string]func(*httptest.ResponseRecorder){
				"table": func(w *httptest.ResponseRecorder) {
					serveAdminTable(w, httptest.NewRequest("GET", "/_admin/notes", nil), f.app, "notes")
				},
				"detail": func(w *httptest.ResponseRecorder) {
					serveAdminDetail(w, httptest.NewRequest("GET", "/_admin/notes/1", nil), f.app, "notes", "1")
				},
			} {
				t.Run(name, func(t *testing.T) {
					w := httptest.NewRecorder()
					render(w)
					shown := value
					if name == "table" && len(shown) > 60 {
						shown = shown[:60] + "..."
					}
					if w.Code != 200 || !strings.Contains(w.Body.String(), html.EscapeString(shown)) {
						t.Errorf("admin %s did not retain ordinary literal text", name)
					}
				})
			}
			if _, err := f.app.DB.Exec("INSERT INTO public_notes(id,title) VALUES(17,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title", value); err != nil {
				t.Fatal(err)
			}
			f.app.Group.Label = &GroupLabelConfig{Table: "public_notes", Key: "id", Field: "title"}
			labels := appMCPOAuthWorkspaceLabels(context.Background(), f.app, []string{"17"})
			if labels["17"] != clampLabel(value) {
				t.Errorf("workspace display label interpreted ciphertext: %#v", labels)
			}
			session := GetSessionFromDB(f.app.DB, f.sid)
			if session == nil {
				t.Fatal("missing actor")
			}
			if _, err := f.app.DB.Exec("INSERT INTO members(org_id,email) VALUES(?,?)", value, session.Email); err != nil {
				t.Fatal(err)
			}
			ids, err := appMCPOAuthWorkspacesFor(context.Background(), f.app, session)
			found := false
			for _, id := range ids {
				if id == value {
					found = true
				}
			}
			if err != nil || !found {
				t.Errorf("workspace identity interpreted ciphertext: %v %v", ids, err)
			}
			for _, strict := range []bool{false, true} {
				actor, err := loadScheduledActorWith(f.app, f.app.DB, f.uid, &value, strict)
				if err != nil || actor == nil || actor.GroupID != value {
					t.Errorf("scheduled actor interpreted membership identity (strict=%v): %v %v", strict, actor, err)
				}
			}
			if _, err := f.app.DB.Exec("DELETE FROM members WHERE org_id=?", value); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Existing encrypted-label refusal and pool restoration are retained.
	f.app.Group.Label = &GroupLabelConfig{Table: "notes", Key: "id", Field: "secret"}
	if labels := appMCPOAuthWorkspaceLabels(context.Background(), f.app, []string{"1"}); len(labels) != 0 {
		t.Errorf("encrypted workspace label was admitted: %#v", labels)
	}
	if _, err := f.app.DB.Exec("UPDATE notes SET title=title WHERE id=1"); err != nil {
		t.Fatalf("read policy leaked into next pooled write: %v", err)
	}
}

func TestCommandHookSourceRowsKeepLiteralText(t *testing.T) {
	for _, name := range []string{"known_cipher", "prefix_literal"} {
		t.Run(name, func(t *testing.T) {
			hooks := `before_update:
  tasks:
    - when: "title = 'owner-private'"
      sql: SELECT 'ciphertext was interpreted as plaintext' AS error
on_update:
  tasks:
    - sql: INSERT INTO _benmore_notifications(user_id,title,body) VALUES({{user_id}},{{title}},{{old_title}})
`
			app, sid, uid := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
			value := "enc:v2:ordinary-label"
			if name == "known_cipher" {
				var err error
				// Supplied synthetic ciphertext, not discovered through an API.
				value, err = fieldEncryptCtx(cryptoKeyForQuerier(app.DB), "private_notes", "secret", "owner-private")
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := app.DB.Exec("UPDATE tasks SET title=? WHERE id=1", value); err != nil {
				t.Fatal(err)
			}
			EnsureNotificationsTable(app.DB)
			if _, err := runHookedCommand(t, app, sid); err != nil {
				t.Fatalf("literal title changed hook behavior: %v", err)
			}
			var title, body string
			if err := app.DB.QueryRow("SELECT title,body FROM _benmore_notifications WHERE user_id=? ORDER BY id DESC LIMIT 1", uid).Scan(&title, &body); err != nil {
				t.Fatal(err)
			}
			if title != value || body != value {
				t.Errorf("hook source rows changed: title=%q old_title=%q", title, body)
			}
		})
	}
}

// Hold the revision ledger constant only in this isolated fixture to verify
// that the row-image part of the digest distinguishes a literal envelope from
// its plaintext. This does not claim an ordinary API can bypass revisioning.
func TestTransferDigestLiteralIdentityAndOwningKey(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	var cipher string
	if err := f.app.DB.QueryRow("SELECT secret FROM notes WHERE id=1").Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("UPDATE notes SET title=? WHERE id=1", cipher); err != nil {
		t.Fatal(err)
	}
	digest := func() (string, error) {
		tx, err := f.app.DB.Begin()
		if err != nil {
			return "", err
		}
		defer tx.Rollback()
		return appMCPTransferRowDigest(context.Background(), tx, f.app, "notes", "1")
	}
	literal, err := digest()
	if err != nil {
		t.Fatal(err)
	}
	oldGlobal := appEncryptionKey
	appEncryptionKey = bytes.Repeat([]byte{0x9a}, 32)
	defer func() { appEncryptionKey = oldGlobal }()
	if got, err := digest(); err != nil || got != literal {
		t.Fatalf("ambient key changed owning-database digest: %q %v", got, err)
	}
	var revision int64
	if err := f.app.DB.QueryRow("SELECT revision FROM _benmore_mcp_row_revisions WHERE table_name='notes' AND row_key='1'").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("UPDATE notes SET title='old-secret' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("UPDATE _benmore_mcp_row_revisions SET revision=? WHERE table_name='notes' AND row_key='1'", revision); err != nil {
		t.Fatal(err)
	}
	plain, err := digest()
	if err != nil {
		t.Fatal(err)
	}
	if plain == literal {
		t.Error("row digest collapses ordinary ciphertext text into its protected plaintext")
	}
	path, err := mainDatabasePathForQuerier(f.app.DB)
	if err != nil {
		t.Fatal(err)
	}
	registered := cryptoKeysForDBPath(path)
	if registered == nil {
		t.Fatal("missing fixture database key")
	}
	dbCryptoRegistry.Delete(canonicalDBPath(path))
	defer dbCryptoRegistry.Store(canonicalDBPath(path), registered)
	if _, err := digest(); err == nil {
		t.Fatal("digest used ambient key after owning database key was removed")
	}
}
