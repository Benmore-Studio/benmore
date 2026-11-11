//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// revertSubmittedFixture is changedByFixture's versioned notes table with a
// body, two server-set columns and the documented "set by the server" guard.
// Note 1 belongs to the returned session; status is its workflow state.
func revertSubmittedFixture(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app, mux, sid, _ := changedByFixture(t)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN body TEXT`)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN review_count INTEGER DEFAULT 0`)
	mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN reviewed_at DATETIME`)
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
		t.Fatal(err)
	}
	refreshTableColumns(t, app, "notes")
	mustExec(t, app.DB, `UPDATE notes SET body='frozen', review_count=2, reviewed_at='2026-03-01T09:00:00Z' WHERE id=1`)
	mustExec(t, app.DB, `DELETE FROM notes_history`)
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {
		// The refusal carries the list, so a test reads exactly what the
		// hook was told.
		{SQL: `SELECT 'set by the server; submitted=' || '{{_submitted}}' AS error`,
			When: `instr(_submitted, ',review_count,') > 0 OR instr(_submitted, ',reviewed_at,') > 0`},
		// A guard on a value the request sets, not on the stored one.
		{SQL: `SELECT CASE WHEN '{{body}}' = 'frozen' THEN RAISE(ABORT, 'a body is not set to frozen') END`},
	}}}
	return app, mux, sid
}

func revertSubmittedNote(t *testing.T, app *App) (title, body string, reviews int) {
	t.Helper()
	if err := app.DB.QueryRow(`SELECT title, COALESCE(body, ''), review_count FROM notes WHERE id=1`).Scan(&title, &body, &reviews); err != nil {
		t.Fatal(err)
	}
	return title, body, reviews
}

// A revert's before_update hooks are told the columns the revert changes, as
// `_submitted`, and their SQL placeholders hold those columns only. A revert
// used to report every column of the version, so a hook that refuses a
// caller-set column ("review_count is set by the server") refused every
// revert of the table, also one whose version holds the column's current
// value, and a guard on a submitted value fired off a value the row already
// had.
func TestRevertSubmitsOnlyTheColumnsItChanges(t *testing.T) {
	app, mux, sid := revertSubmittedFixture(t)
	patch := func(body string) {
		t.Helper()
		if w := canonicalPatch(app, sid, "notes", "1", "application/json", body); w.Code != http.StatusOK {
			t.Fatalf("PATCH %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	// The guards hold for ordinary updates.
	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"review_count":0}`); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "set by the server; submitted=,review_count,") {
		t.Fatalf("fixture: a PATCH of review_count must be refused: %d %s", w.Code, w.Body.String())
	}
	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"body":"frozen"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("fixture: a PATCH setting body to frozen must be refused: %d %s", w.Code, w.Body.String())
	}

	patch(`{"title":"second"}`) // version 1: owner-a / frozen / 2 reviews
	patch(`{"title":"fourth"}`) // version 2: second / frozen / 2 reviews

	// Version 1 differs from the row in title alone: neither guard applies.
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/1", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("a revert that changes only title was refused: %d %s", w.Code, w.Body.String())
	}
	if title, body, reviews := revertSubmittedNote(t, app); title != "owner-a" || body != "frozen" || reviews != 2 {
		t.Fatalf("after the revert: title=%q body=%q review_count=%d, want owner-a / frozen / 2", title, body, reviews)
	}

	// The server reviews the note again (version 4 holds 2 reviews); a later
	// revert to an older version would put review_count back.
	mustExec(t, app.DB, `UPDATE notes SET review_count=3, reviewed_at='2026-03-05T09:00:00Z' WHERE id=1`)
	patch(`{"title":"fifth"}`)
	w = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/2", sid, nil)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a revert that changes review_count must be refused by the guard: %d %s", w.Code, w.Body.String())
	}
	// Exactly the changed columns: not body (unchanged), status (the
	// workflow state, kept) or user_id (protected).
	if want := "submitted=,review_count,reviewed_at,title,"; !strings.Contains(w.Body.String(), want+`"`) {
		t.Fatalf("the hook was told %s, want %s", w.Body.String(), want)
	}
	if title, _, reviews := revertSubmittedNote(t, app); title != "fifth" || reviews != 3 {
		t.Fatalf("a refused revert wrote: title=%q review_count=%d", title, reviews)
	}

	// A revert that sets a guarded value is still refused: version 5 holds
	// body 'frozen', the row no longer does.
	mustExec(t, app.DB, `UPDATE notes SET body='thawed' WHERE id=1`)
	patch(`{"title":"sixth"}`)
	w = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/5", sid, nil)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "a body is not set to frozen") {
		t.Fatalf("a revert that sets body to frozen must be refused: %d %s", w.Code, w.Body.String())
	}
}

// A revert whose version holds what the row already has (in every column a
// revert writes) still succeeds, as before: an update that names no column
// is refused, so the version's columns are written as they are. The same
// holds when the only difference is a column the revert keeps.
func TestRevertToAVersionTheRowAlreadyMatches(t *testing.T) {
	app, mux, sid := revertSubmittedFixture(t)
	app.Hooks = nil
	if w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"second"}`); w.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body.String())
	}
	// Put the content back by hand, then move the workflow state: version 1
	// now differs from the row in status alone, which a revert keeps.
	mustExec(t, app.DB, `UPDATE notes SET title='owner-a', status='done' WHERE id=1`)
	var before int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes_history WHERE id=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/revert/1", sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("revert to a version the row matches: %d %s", w.Code, w.Body.String())
	}
	var title, status string
	var after int
	if err := app.DB.QueryRow(`SELECT title, status, (SELECT COUNT(*) FROM notes_history WHERE id=1) FROM notes WHERE id=1`).Scan(&title, &status, &after); err != nil {
		t.Fatal(err)
	}
	if title != "owner-a" || status != "done" {
		t.Fatalf("row after the revert: title=%q status=%q, want owner-a / done", title, status)
	}
	if after != before+1 {
		t.Fatalf("the revert's write recorded %d versions, want 1", after-before)
	}
}

// revertChanges hands the update only what it will write with another value:
// not a column that already holds the version's value, not one the update
// drops (protected columns, the workflow state, an encrypted column's
// decrypt-failure placeholder). When that leaves nothing, the whole version
// is written, as a revert always was.
func TestRevertChangesLeavesOutWhatTheUpdateDrops(t *testing.T) {
	app, _, sid := revertSubmittedFixture(t)
	session := GetSessionFromDB(app.DB, sid)
	version := map[string]any{
		"title": "older", "body": "frozen", "review_count": int64(2),
		"reviewed_at": nil, "status": "done", "user_id": int64(99),
	}
	got := revertChanges(app, session, "notes", "1", version)
	if len(got) != 2 || got["title"] != "older" || got["reviewed_at"] != nil {
		t.Fatalf("changes = %#v, want title and reviewed_at (set in the row, NULL in the version)", got)
	}
	if _, ok := got["reviewed_at"]; !ok {
		t.Fatalf("a column the version clears is a change: %#v", got)
	}

	// The same version once body is encrypted and its snapshot unreadable:
	// the placeholder is never written, so it is not a change either.
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "body"}}}}
	unreadable := map[string]any{"title": "owner-a", "body": decryptFailMask, "review_count": int64(2), "status": "done"}
	got = revertChanges(app, session, "notes", "1", unreadable)
	if len(got) != len(unreadable) {
		t.Fatalf("nothing the update writes differs, so the version is written whole; got %#v", got)
	}
	unreadable["title"] = "older"
	got = revertChanges(app, session, "notes", "1", unreadable)
	if len(got) != 1 || got["title"] != "older" {
		t.Fatalf("changes = %#v, want title alone", got)
	}

	// A row that cannot be read leaves the version as it is for the update
	// to refuse.
	if got = revertChanges(app, session, "notes", "9999", version); len(got) != len(version) {
		t.Fatalf("missing row: %#v", got)
	}
}

func TestRevertSameValue(t *testing.T) {
	for _, c := range []struct {
		name             string
		current, version any
		same             bool
	}{
		{"both NULL", nil, nil, true},
		{"NULL now", nil, "x", false},
		{"NULL in the version", int64(0), nil, false},
		{"empty text is not NULL", "", nil, false},
		{"equal text", "a", "a", true},
		{"equal integer", int64(2), int64(2), true},
		{"different integer", int64(2), int64(3), false},
		{"text is not a number", "2", int64(2), false},
		{"integer is not a real", int64(2), float64(2), false},
		{"equal boolean", true, true, true},
	} {
		if got := revertSameValue(c.current, c.version); got != c.same {
			t.Errorf("%s: revertSameValue(%#v, %#v) = %v, want %v", c.name, c.current, c.version, got, c.same)
		}
	}
}
