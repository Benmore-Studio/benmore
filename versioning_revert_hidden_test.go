//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A revert leaves hidden credential columns (apiHiddenColumn: `*_token`,
// `*_secret`, ...) at their current value. No API response, version
// snapshots included, carries them, so the reverting caller cannot see what
// the version holds; restoring it let an editor who may never read the
// secret silently bring back a token the owner had rotated or revoked. Every
// other column still reverts, and the answer lists the hidden ones in
// `kept` with reason `hidden`. This holds for an app admin acting directly
// too: admins cannot read hidden columns either.
func TestRevertKeepsHiddenCredentialColumns(t *testing.T) {
	for _, reverter := range []string{"editor with an edit share", "app admin"} {
		t.Run(reverter, func(t *testing.T) {
			app, mux, ownerSID, _ := changedByFixture(t)
			mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN intake_token TEXT`)
			mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN portal_secret TEXT`)
			if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
				t.Fatal(err)
			}
			refreshTableColumns(t, app, "notes")
			for _, column := range []string{"intake_token", "portal_secret"} {
				if !apiHiddenColumn(app, "notes", column) {
					t.Fatalf("fixture: %s must be a hidden column", column)
				}
			}

			// The owner sets credentials, then rotates them after a leak.
			// Version 2 holds the leaked values.
			if w := canonicalPatch(app, ownerSID, "notes", "1", "application/json",
				`{"title":"with leaked token","intake_token":"tok-OLD-leaked","portal_secret":"sec-OLD-leaked"}`); w.Code != http.StatusOK {
				t.Fatalf("set credentials: %d %s", w.Code, w.Body.String())
			}
			if w := canonicalPatch(app, ownerSID, "notes", "1", "application/json",
				`{"title":"rotated","intake_token":"tok-NEW-after-rotation","portal_secret":"sec-NEW-after-rotation"}`); w.Code != http.StatusOK {
				t.Fatalf("rotate credentials: %d %s", w.Code, w.Body.String())
			}
			var leaked string
			if err := app.DB.QueryRow(`SELECT intake_token FROM notes_history WHERE id=1 AND _version=2`).Scan(&leaked); err != nil || leaked != "tok-OLD-leaked" {
				t.Fatalf("fixture: version 2 must hold the leaked token, got %q (%v)", leaked, err)
			}

			var sid string
			if reverter == "app admin" {
				sid = createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
			} else {
				sid = createCrudScopeSession(t, app, "editor@example.com", "user", "", "")
				mustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission) VALUES('notes','1','user','editor@example.com','edit')`)
			}

			// The reverting caller cannot see the credential in the snapshot.
			w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1/versions/2", sid, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("read version: %d %s", w.Code, w.Body.String())
			}
			var snapshot map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if _, ok := snapshot["intake_token"]; ok || snapshot["title"] != "with leaked token" {
				t.Fatalf("version snapshot must omit hidden columns and carry the rest: %s", w.Body.String())
			}

			w = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/2", sid, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("revert: %d %s", w.Code, w.Body.String())
			}
			var title, token, secret string
			if err := app.DB.QueryRow(`SELECT title, intake_token, portal_secret FROM notes WHERE id=1`).Scan(&title, &token, &secret); err != nil {
				t.Fatal(err)
			}
			if title != "with leaked token" {
				t.Fatalf("title = %q, want the version's value: a visible column still reverts", title)
			}
			if token != "tok-NEW-after-rotation" || secret != "sec-NEW-after-rotation" {
				t.Fatalf("revert restored rotated credentials: intake_token=%q portal_secret=%q", token, secret)
			}

			var body struct {
				Kept []revertKept `json:"kept"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			kept := map[string]string{}
			for _, k := range body.Kept {
				kept[k.Column] = k.Reason
			}
			for _, column := range []string{"intake_token", "portal_secret"} {
				if kept[column] != "hidden" {
					t.Errorf("kept[%s] = %q, want \"hidden\" (answer %s)", column, kept[column], w.Body.String())
				}
			}
			if _, ok := kept["title"]; ok {
				t.Errorf("title is restored, not kept: %s", w.Body.String())
			}
		})
	}
}
