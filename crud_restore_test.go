//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func restoreFixture(t *testing.T) (*App, *http.ServeMux, string, int64) {
	t.Helper()
	app, sid, uid := canonicalUpdateFixture(t)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN password_hash TEXT DEFAULT 'synthetic-hidden-value'`)
	refreshTableColumns(t, app, "notes")
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `UPDATE notes SET deleted_at='2026-10-14 10:00:00' WHERE id=1`)
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid, uid
}

func restoreRequest(mux *http.ServeMux, sid, body string, cookie bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/notes/1/restore", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	} else if sid != "" {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestRestoreReturnsSanitizedRowAndRetainsMutationPipeline(t *testing.T) {
	app, mux, sid, uid := restoreFixture(t)
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{SQL: `UPDATE notes SET title='restored by hook' WHERE id={{id}}`}}}}
	versionsBefore := gateScalar(t, app, "SELECT count(*) FROM notes_history")
	w := restoreRequest(mux, sid, `{"title":"body must not be applied","user_id":999,"deleted_at":"still deleted"}`, false)
	var row map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &row) != nil {
		t.Fatalf("restore returned %d %s", w.Code, w.Body.String())
	}
	if row["id"] != float64(1) || row["user_id"] != float64(uid) || row["title"] != "restored by hook" || row["deleted_at"] != nil {
		t.Fatalf("wrong restored row: %v", row)
	}
	if _, exposed := row["password_hash"]; exposed || strings.Contains(w.Body.String(), "synthetic-hidden-value") {
		t.Fatal("restore exposed a hidden field")
	}
	if got := gateScalar(t, app, "SELECT deleted_at IS NULL FROM notes WHERE id=1"); got != "1" {
		t.Fatalf("restore did not persist: %s", got)
	}
	if row["updated_at"] == "2026-10-03 12:00:00" || gateScalar(t, app, "SELECT count(*) FROM notes_history") == versionsBefore {
		t.Fatal("restore omitted timestamp/version history")
	}
	var oldJSON, newJSON string
	if err := app.DB.QueryRow(`SELECT old_values,new_values FROM _benmore_audit_log WHERE table_name='notes' AND row_id='1' AND action='update'`).Scan(&oldJSON, &newJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(oldJSON, `"deleted_at":"2026-10-14 10:00:00"`) || !strings.Contains(newJSON, `"deleted_at":null`) {
		t.Fatalf("restore audit omitted state change: old=%s new=%s", oldJSON, newJSON)
	}
	if got := restoreRequest(mux, sid, "", false); got.Code != http.StatusNotFound {
		t.Fatalf("already-live restore repeated mutation: %d %s", got.Code, got.Body.String())
	}
	if got := gateScalar(t, app, "SELECT count(*) FROM _benmore_audit_log WHERE table_name='notes'"); got != "1" {
		t.Fatalf("repeat restore wrote extra audit rows: %s", got)
	}
	if got := canonicalPatch(app, sid, "notes", "1", "application/json", `{"deleted_at":"2026-10-14"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("ordinary PATCH could write deleted_at: %d %s", got.Code, got.Body.String())
	}
}

func TestRestoreDenialsLeaveDeletedRowUnchanged(t *testing.T) {
	for _, scenario := range []string{"anonymous", "foreign", "csrf", "read denied", "update denied", "read-only token", "locked", "before hook", "after hook", "lost readback", "audit failure", "command owned"} {
		t.Run(scenario, func(t *testing.T) {
			app, mux, sid, _ := restoreFixture(t)
			want, cookie := http.StatusForbidden, false
			switch scenario {
			case "anonymous":
				sid, want = "", http.StatusUnauthorized
			case "foreign":
				sid = createCrudScopeSession(t, app, "outsider@example.com", "user", "tenant-a", "")
				want = http.StatusNotFound
			case "csrf":
				cookie = true
			case "read denied":
				app.Access.rules["notes"] = map[AccessOp]string{"read": "off", "update": "self"}
				want = http.StatusNotFound
			case "update denied":
				app.Access.rules["notes"] = map[AccessOp]string{"read": "self", "update": "off"}
				want = http.StatusNotFound
			case "locked":
				mustExec(t, app.DB, `INSERT INTO _benmore_locks(table_name,row_id,user_id,user_email,expires_at) VALUES ('notes','1',999,'synthetic@example.com',datetime('now','+1 hour'))`)
				want = http.StatusConflict
			case "read-only token":
				if _, err := app.DB.Exec(`UPDATE _benmore_sessions SET scopes='notes:read' WHERE id=?`, sessionStorageKey(sid)); err != nil {
					t.Fatal(err)
				}
				want = http.StatusForbidden
			case "command owned":
				app.Flows = []Flow{{Name: "restore_by_command", Command: &FlowCommand{Owns: []FlowCommandOwn{{Table: "notes", Column: "deleted_at"}}}}}
			case "after hook":
				app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{SQL: `INSERT INTO activities(note_id,status) VALUES ({{id}},'leak')`}, {SQL: `INSERT INTO missing_table VALUES(1)`}}}}
				want = http.StatusInternalServerError
			case "lost readback":
				app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"notes": {{SQL: `UPDATE notes SET user_id=999 WHERE id={{id}}`}}}}
				want = http.StatusForbidden
			case "before hook":
				app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{SQL: `SELECT RAISE(ABORT, 'restore refused')`}}}}
				want = http.StatusUnprocessableEntity
			case "audit failure":
				mustExec(t, app.DB, `CREATE TRIGGER reject_restore_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT,'reject audit'); END`)
				want = http.StatusInternalServerError
			}
			before := gateScalar(t, app, "SELECT updated_at FROM notes WHERE id=1")
			versions := gateScalar(t, app, "SELECT count(*) FROM notes_history")
			w := restoreRequest(mux, sid, "", cookie)
			if w.Code != want {
				t.Fatalf("%s: want %d got %d %s", scenario, want, w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM notes WHERE id=1 AND deleted_at IS NOT NULL AND title='before' AND updated_at=?", before); got != "1" {
				t.Fatal("denied restore changed row")
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM notes_history"); got != versions {
				t.Fatalf("denied restore leaked version: %s vs %s", got, versions)
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM _benmore_audit_log WHERE table_name='notes'"); got != "0" {
				t.Fatalf("denied restore leaked audit: %s", got)
			}
			if got := gateScalar(t, app, "SELECT count(*) FROM activities"); got != "0" {
				t.Fatalf("denied restore leaked hook write: %s", got)
			}
		})
	}
}

func TestRestoreMembershipCannotReactivateRemovedSelf(t *testing.T) {
	app, _ := newTenantRoleFixture(t, "access:\n  company_members:\n    read: self\n    update: self\n")
	mustExec(t, app.DB, `ALTER TABLE company_members ADD COLUMN user_id INTEGER`)
	mustExec(t, app.DB, `ALTER TABLE company_members ADD COLUMN deleted_at TEXT`)
	refreshTableColumns(t, app, "company_members")
	EnsureLocksTable(app.DB)
	sid, uid := tenantMember(t, app, "removed@example.test", "user", 1, "viewer")
	id := membershipRowID(t, app, "removed@example.test")
	if _, err := app.DB.Exec(`UPDATE company_members SET user_id=?,deleted_at='2026-10-14' WHERE id=?`, uid, id); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	w := crudScopeRequest(t, mux, http.MethodPost, fmt.Sprintf("/api/company_members/%d/restore", id), sid, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("removed member restore: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, `SELECT deleted_at IS NOT NULL FROM company_members WHERE id=?`, id); got != "1" {
		t.Fatal("removed member restored itself")
	}
}

func TestRestoreRechecksParentVisibilityAndMasksResult(t *testing.T) {
	for _, state := range []string{"visible", "foreign", "deleted", "read denied"} {
		t.Run(state, func(t *testing.T) {
			app, mux, sid, uid := restoreFixture(t)
			keyPath := filepath.Join(app.Dir, "data.db")
			RegisterDBEncryptionKey(keyPath, testKeyBytes(0x37))
			t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(keyPath)) })
			mustExec(t, app.DB, `CREATE TABLE restore_parents(id INTEGER PRIMARY KEY,user_id INTEGER,deleted_at TEXT)`)
			if _, err := app.DB.Exec(`INSERT INTO restore_parents(id,user_id) VALUES(7,?)`, uid); err != nil {
				t.Fatal(err)
			}
			mustExec(t, app.DB, `UPDATE notes SET room_id=7 WHERE id=1`)
			refreshTableColumns(t, app, "restore_parents")
			app.JoinMap = map[string]map[string]ForeignKey{"notes": {"room_id": {Table: "restore_parents", Column: "id"}}}
			app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "title", Roles: []string{"admin"}}}}}
			want := http.StatusUnprocessableEntity
			switch state {
			case "visible":
				want = http.StatusOK
			case "foreign":
				mustExec(t, app.DB, `UPDATE restore_parents SET user_id=999`)
			case "deleted":
				mustExec(t, app.DB, `UPDATE restore_parents SET deleted_at='2026-10-14'`)
			case "read denied":
				app.Access.rules["restore_parents"] = map[AccessOp]string{"read": "off"}
			}
			w := restoreRequest(mux, sid, "", false)
			if w.Code != want {
				t.Fatalf("%s parent: %d %s", state, w.Code, w.Body.String())
			}
			if state == "visible" {
				if strings.Contains(w.Body.String(), `"title":"before"`) {
					t.Fatal("restore bypassed encrypted field mask")
				}
			} else if gateScalar(t, app, `SELECT deleted_at IS NOT NULL FROM notes WHERE id=1`) != "1" {
				t.Fatal("restore with forbidden parent mutated row")
			}
		})
	}
}

func TestRestorePreservesAuthoredRoutes(t *testing.T) {
	for _, path := range []string{"/api/notes/:id/restore", "/api/notes/{item}/restore", "/api/notes/1/restore", "/api/{table}/{id}/restore", "/api/notes/", "/api/notes/{tail...}"} {
		t.Run(path, func(t *testing.T) {
			app, _, sid, _ := restoreFixture(t)
			flow := Flow{Name: "custom_restore", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: path}}
			app.Flows = []Flow{flow}
			if !restoreRouteOwnedByFlow(app, "notes") {
				t.Fatalf("did not recognize %s", path)
			}
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			registered := RegisterFlows(mux, app, app.Flows)
			if len(registered) != 1 {
				t.Fatalf("authored route lost: %v", registered)
			}
			w := restoreRequest(mux, sid, "", false)
			if gateScalar(t, app, `SELECT deleted_at IS NOT NULL FROM notes WHERE id=1`) != "1" {
				t.Fatalf("native restore stole custom route: %d %s", w.Code, w.Body.String())
			}
			app.Flows = []Flow{{Name: "private_restore", Command: &FlowCommand{Request: &FlowCommandRequest{Method: "POST", Path: path}}}}
			if !restoreRouteOwnedByFlow(app, "notes") {
				t.Fatal("private command restore was not reserved")
			}
		})
	}
	app, _, _, _ := restoreFixture(t)
	app.Flows = []Flow{{Name: "other", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/other/:id/restore"}}}
	if restoreRouteOwnedByFlow(app, "notes") {
		t.Fatal("unrelated route hid native restore")
	}
}

func TestRestoreDocumentationMatchesReadUpdateAndNativeOwnership(t *testing.T) {
	app, _, sid, _ := restoreFixture(t)
	path := "/api/notes/{id}/restore"
	viewer := docsViewerFor(GetSessionFromDB(app.DB, sid))
	for _, state := range []string{"native", "read denied", "update denied", "custom", "unsupported"} {
		t.Run(state, func(t *testing.T) {
			app.Access.rules["notes"] = map[AccessOp]string{"read": "self", "update": "self", "write": "off"}
			app.Flows = nil
			table := "notes"
			want := state == "native"
			switch state {
			case "read denied":
				app.Access.rules["notes"]["read"] = "off"
			case "update denied":
				app.Access.rules["notes"]["update"] = "off"
			case "custom":
				app.Flows = []Flow{{Trigger: FlowTrigger{Type: "http", Method: "POST", Path: path}}}
			case "unsupported":
				table = "activities"
			}
			found := false
			for _, rt := range viewer.routes(app, table) {
				if strings.HasSuffix(rt.path, "/restore") {
					found = true
				}
			}
			if found != want {
				t.Fatalf("docs advertised restore=%v want %v", found, want)
			}
			paths := generateRuntimeOpenAPIFor(app, viewer)["paths"].(map[string]any)
			_, found = paths["/api/"+table+"/{id}/restore"]
			if found != want {
				t.Fatalf("OpenAPI advertised restore=%v want %v", found, want)
			}
			if found {
				op := paths[path].(map[string]any)["post"].(map[string]any)
				raw, _ := json.Marshal(op)
				if !strings.Contains(string(raw), "#/components/schemas/Note") {
					t.Fatalf("restore response not Row: %s", raw)
				}
			}
		})
	}
}
