//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// changedByFixture versions the fixture's notes table (owner-scoped, a
// workflow on status) and signs in the owner of note 1.
func changedByFixture(t *testing.T) (*App, *http.ServeMux, string, int64) {
	t.Helper()
	app, _ := newCrudScopeTestApp(t)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN status TEXT DEFAULT 'draft'`)
	mustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'third')`)
	refreshTableColumns(t, app, "notes")
	app.Access.rules["notes"] = map[AccessOp]string{"all": "self"}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"note": {
		Name: "note", Table: "notes", Field: "status", Initial: "draft", States: []string{"draft", "done"},
		Transitions: map[string]map[string]Transition{"draft": {"done": {}}},
	}}}
	versioned := &VersionedConfig{Tables: []string{"notes"}}
	if err := InstallVersioningTriggers(app.DB, versioned); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterVersioningAPI(mux, app, versioned)
	sid := createCrudScopeSession(t, app, "author@example.com", "user", "", "")
	session := GetSessionFromDB(app.DB, sid)
	if session == nil || session.UserID != 1 {
		t.Fatalf("fixture session must own note 1: %+v", session)
	}
	return app, mux, sid, session.UserID
}

func changedByVersions(t *testing.T, mux *http.ServeMux, sid, id string) []map[string]any {
	t.Helper()
	w := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/"+id+"/versions", sid, nil)
	var body struct{ Versions []map[string]any }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("versions: %d %s", w.Code, w.Body.String())
	}
	return body.Versions
}

func changedByOf(t *testing.T, app *App, id string, version int) any {
	t.Helper()
	var changedBy any
	if err := app.DB.QueryRow(`SELECT _changed_by FROM notes_history WHERE id=? AND _version=?`, id, version).Scan(&changedBy); err != nil {
		t.Fatalf("version %s/%d: %v", id, version, err)
	}
	return changedBy
}

// Every framework write that knows its caller names it on the versions it
// records: the PATCH, the transition, a revert through the transaction
// pipeline and a delete. Authored SQL has no caller and leaves it null.
func TestVersioningRecordsChangedBy(t *testing.T) {
	app, mux, sid, uid := changedByFixture(t)
	want := fmt.Sprint(uid)

	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"edited"}`); w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	versions := changedByVersions(t, mux, sid, "1")
	if len(versions) != 1 || fmt.Sprint(versions[0]["_changed_by"]) != want {
		t.Fatalf("PATCH version: %v", versions)
	}

	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/notes/1/transition", strings.NewReader(`{"to":"done"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	r.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	handleTransition(w, r, app, app.Workflows.Workflows["note"])
	if w.Code != http.StatusOK {
		t.Fatalf("transition: %d %s", w.Code, w.Body.String())
	}
	if got := changedByOf(t, app, "1", 2); fmt.Sprint(got) != want {
		t.Fatalf("transition version changed_by=%v", got)
	}

	// Authored SQL (flows, hooks, migrations, the console) has no session.
	mustExec(t, app.DB, `UPDATE notes SET title='by sql' WHERE id=1`)
	if got := changedByOf(t, app, "1", 3); got != nil {
		t.Fatalf("raw SQL version names an author: %v", got)
	}

	w = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/1", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", w.Code, w.Body.String())
	}
	if got := changedByOf(t, app, "1", 4); fmt.Sprint(got) != want {
		t.Fatalf("revert version changed_by=%v", got)
	}

	w = crudScopeRequest(t, mux, http.MethodDelete, "/api/notes/3", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	var changeType string
	var changedBy any
	if err := app.DB.QueryRow(`SELECT _change_type, _changed_by FROM notes_history WHERE id=3 ORDER BY _version DESC LIMIT 1`).Scan(&changeType, &changedBy); err != nil {
		t.Fatal(err)
	}
	if changeType != "delete" || fmt.Sprint(changedBy) != want {
		t.Fatalf("delete version: %s by %v", changeType, changedBy)
	}
	// Earlier versions keep their own author.
	if got := changedByOf(t, app, "1", 3); got != nil {
		t.Fatalf("a later write re-attributed an earlier version: %v", got)
	}
}
