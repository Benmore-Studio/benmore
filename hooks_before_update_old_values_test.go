//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A before_update hook reads the stored row as old_<column>, in its `when:`
// and in its SQL placeholders, on every update path: PATCH, batch,
// /api/_transaction and an approved command, as it always did on a workflow
// transition. On the generic paths every old_<column> used to be NULL (and
// `{{old_x}}` its literal text), so a guard such as "a done note stays done"
// written as `old_status = 'done' AND status != 'done'` never fired.

func beforeUpdateOldValuesApp(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app, mux := auditApp(t)
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN status TEXT")
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN weight INTEGER")
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN old_title TEXT")
	for i := range app.Tables {
		if app.Tables[i].Name == "notes" {
			cols, err := GetTableColumns(app.DB, "notes")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	sid := createCrudScopeSession(t, app, "writer@example.com", "user", "", "")
	tok := auditToken(t, app, sid, "*")
	for _, title := range []string{"first", "second", "third", "fourth"} {
		rec := crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": title, "status": "done", "weight": 5, "old_title": "kept"})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	}
	return app, mux, tok
}

func TestBeforeUpdateHookSeesThePreviousValues(t *testing.T) {
	app, mux, tok := beforeUpdateOldValuesApp(t)
	column := func(id int, col string) string {
		var s string
		if err := app.DB.QueryRow("SELECT CAST("+col+" AS TEXT) FROM notes WHERE id = ?", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {
		// The previous value in `when:`.
		{When: "old_status = 'done' AND status != 'done'", SQL: `SELECT 'a done note stays done' AS error`},
		// The previous value as an SQL placeholder, for a column the request
		// did not send as well as for one it did.
		{When: "instr(_submitted, ',weight,') > 0", SQL: `SELECT 'weight only goes up from ' || {{old_weight}} || ' (' || {{old_status}} || ')' AS error WHERE CAST({{weight}} AS INTEGER) < CAST({{old_weight}} AS INTEGER)`},
	}}}

	patch := func(id int, fields map[string]any) (int, string) {
		rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/"+valueText(id), tok, fields)
		return rec.Code, rec.Body.String()
	}
	batch := func(id int, fields map[string]any) (int, string) {
		rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/batch", tok, map[string]any{"ids": []any{id}, "fields": fields})
		return rec.Code, rec.Body.String()
	}
	transaction := func(id int, fields map[string]any) (int, string) {
		rec := crudScopeRequest(t, mux, "POST", "/api/_transaction", tok, map[string]any{"operations": []any{
			map[string]any{"table": "notes", "action": "update", "id": id, "data": fields},
		}})
		return rec.Code, rec.Body.String()
	}
	paths := []struct {
		name   string
		id     int
		update func(int, map[string]any) (int, string)
	}{{"PATCH", 1, patch}, {"batch", 2, batch}, {"transaction", 3, transaction}}
	for _, p := range paths {
		if code, body := p.update(p.id, map[string]any{"status": "reopened"}); !strings.Contains(body, "a done note stays done") {
			t.Errorf("%s: the hook did not see old_status in when: (%d %s)", p.name, code, body)
		}
		if got := column(p.id, "status"); got != "done" {
			t.Errorf("%s: status is %q after the refused update, want done", p.name, got)
		}
		if code, body := p.update(p.id, map[string]any{"weight": 3}); !strings.Contains(body, "weight only goes up from 5 (done)") {
			t.Errorf("%s: the hook SQL did not get {{old_weight}} and {{old_status}} (%d %s)", p.name, code, body)
		}
		if got := column(p.id, "weight"); got != "5" {
			t.Errorf("%s: weight is %q after the refused update, want 5", p.name, got)
		}
		// An update neither guard is about still lands.
		if code, body := p.update(p.id, map[string]any{"weight": 8, "title": "renamed"}); column(p.id, "weight") != "8" {
			t.Errorf("%s: an allowed update was refused (%d %s)", p.name, code, body)
		}
	}

	// A column of the table that is itself named old_<x> keeps its own value:
	// old_title is the column, not the previous title.
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {
		{When: "old_title = 'kept' AND old_status = 'done'", SQL: `SELECT 'own column ' || '{{old_title}}' AS error WHERE instr('{{_submitted}}', ',old_title,') > 0`},
		// Not sent, it is no placeholder value, like any unsubmitted column.
		{SQL: `SELECT 'old_title resolved without being sent' AS error WHERE instr('{{_submitted}}', ',old_title,') = 0 AND '{{old_title}}' != ('{' || '{old_title}}')`},
	}}}
	if code, body := patch(4, map[string]any{"title": "retitled"}); code != http.StatusOK {
		t.Fatalf("an update that does not send old_title: %d %s", code, body)
	}
	if code, body := patch(4, map[string]any{"old_title": "kept", "weight": 6}); code != http.StatusUnprocessableEntity || !strings.Contains(body, "own column kept") {
		t.Fatalf("a column named old_title was replaced by the previous title: %d %s", code, body)
	}
}

// An approved command's update gives its before_update hooks the same keys.
func TestAppMCPCommandBeforeHookSeesThePreviousValues(t *testing.T) {
	hooks := `before_update:
  tasks:
    - when: "old_status = 'open' AND status = 'done'"
      sql: SELECT 'left ' || {{old_status}} AS error
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	_, err := runHookedCommand(t, app, sessionID)
	if err == nil || !strings.Contains(err.Error(), "left open") {
		t.Fatalf("the command's before_update hook did not see the previous status: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}
