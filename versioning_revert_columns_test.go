//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Reverting to a version taken before a column existed leaves that column
// alone. It used to copy the history row's NULL into it, so a revert past a
// later NOT NULL column failed 422 (`attachment must be non-null`), and a
// column the history table lacks made every version "not found". The answer
// names every column that kept its current value and why, the workflow state
// column included (it moves only through its transitions).
func TestRevertKeepsColumnsTheVersionDidNotHave(t *testing.T) {
	app, mux, sid, _ := changedByFixture(t)

	// v1 is the state this PATCH replaces: title 'owner-a', before any of the
	// columns below existed.
	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"edited"}`); w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	// A required column and an optional one arrive later; history gains them
	// (NULL in v1) when its triggers are reinstalled.
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN attachment TEXT NOT NULL DEFAULT ''`)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN subtitle TEXT`)
	versioned := &VersionedConfig{Tables: []string{"notes"}}
	if err := InstallVersioningTriggers(app.DB, versioned); err != nil {
		t.Fatal(err)
	}
	// A column the history table does not have at all (added after the last
	// reinstall): no version holds a value for it.
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN label TEXT`)
	refreshTableColumns(t, app, "notes")
	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"latest","attachment":"report.pdf","subtitle":"sub","label":"blue"}`); w.Code != http.StatusOK {
		t.Fatalf("patch new columns: %d %s", w.Code, w.Body.String())
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

	w = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/1", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("revert to a version older than a NOT NULL column: %d %s", w.Code, w.Body.String())
	}
	var row struct {
		Title, Attachment, Status string
		Subtitle, Label           sql.NullString
	}
	if err := app.DB.QueryRow(`SELECT title, attachment, status, subtitle, label FROM notes WHERE id=1`).
		Scan(&row.Title, &row.Attachment, &row.Status, &row.Subtitle, &row.Label); err != nil {
		t.Fatal(err)
	}
	if row.Title != "owner-a" {
		t.Fatalf("title = %q, want the version's value", row.Title)
	}
	if row.Attachment != "report.pdf" || row.Label.String != "blue" || row.Status != "done" {
		t.Fatalf("columns the version did not have changed: %+v", row)
	}
	// A nullable column added later cannot be told apart from one that was
	// empty: it takes the version's NULL, its value before it existed.
	if row.Subtitle.Valid {
		t.Fatalf("subtitle = %q, want the version's NULL", row.Subtitle.String)
	}

	var body struct {
		Status string `json:"status"`
		Kept   []struct {
			Column string `json:"column"`
			Reason string `json:"reason"`
		} `json:"kept"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	kept := map[string]string{}
	for _, k := range body.Kept {
		kept[k.Column] = k.Reason
	}
	for column, reason := range map[string]string{
		"attachment": "not_in_version",
		"label":      "not_in_version",
		"status":     "workflow_state",
		"user_id":    "protected",
	} {
		if kept[column] != reason {
			t.Errorf("kept[%s] = %q, want %q (answer %s)", column, kept[column], reason, w.Body.String())
		}
	}
	for _, column := range []string{"title", "subtitle", "id", "updated_at"} {
		if _, ok := kept[column]; ok {
			t.Errorf("%s is restored or written by the revert, not kept: %s", column, w.Body.String())
		}
	}
}
