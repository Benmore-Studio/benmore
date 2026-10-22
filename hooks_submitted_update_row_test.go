//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A before_update hook's SQL placeholders are the values the request sent;
// an unsubmitted column stays its literal placeholder text. When single-row
// and batch updates moved onto the shared update helper (2.7.251) the hook
// row became the stored row merged with the change, so `{{weight}}` rendered
// the stored weight for a request that only set status. Guards written as
// "the request may change status and nothing else" then refused every such
// request, and a guard on a value (`'{{status}}' = 'approved'`) fired for
// requests that never named the column. `when:` still judges the merged row.
func TestBeforeUpdateHookSQLSeesOnlySubmittedFields(t *testing.T) {
	app, mux := auditApp(t)
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN status TEXT")
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN weight INTEGER")
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
	for _, title := range []string{"first", "second"} {
		rec := crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": title, "status": "done", "weight": 5})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
	}
	status := func(id int) string {
		var s string
		if err := app.DB.QueryRow("SELECT status FROM notes WHERE id = ?", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// The portal's guard: a caller may submit status and nothing else. The
	// placeholder comparison is the fallback for runtimes without
	// {{_submitted}}; it must stay false for a column the request did not send.
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {
		{SQL: `SELECT CASE WHEN (instr('{{_submitted}}', ',weight,') > 0 OR '{{weight}}' != ('{' || '{weight}}'))
			OR (instr('{{_submitted}}', ',title,') > 0 OR '{{title}}' != ('{' || '{title}}'))
			THEN RAISE(ABORT, 'only status may change') END`},
		// A guard on a submitted value must not fire off the stored one.
		{SQL: `SELECT CASE WHEN '{{weight}}' = '5' THEN RAISE(ABORT, 'weight 5 is reserved') END`},
		// It reads the stored row with a subquery.
		{SQL: `SELECT CASE WHEN (SELECT weight FROM notes WHERE id = {{id}}) IS NULL THEN RAISE(ABORT, 'no stored row') END`},
	}}}

	if rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"status": "accepted"}); rec.Code != http.StatusOK {
		t.Fatalf("PATCH of status alone refused: %d %s", rec.Code, rec.Body.String())
	}
	if got := status(1); got != "accepted" {
		t.Fatalf("status = %q after the PATCH", got)
	}
	rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/batch", tok, map[string]any{"ids": []any{2}, "fields": map[string]any{"status": "accepted"}})
	if got := status(2); got != "accepted" {
		t.Fatalf("batch update of status alone refused (%d %s); status = %q", rec.Code, rec.Body.String(), got)
	}
	rec = crudScopeRequest(t, mux, "POST", "/api/_transaction", tok, map[string]any{"operations": []any{
		map[string]any{"table": "notes", "action": "update", "id": 1, "data": map[string]any{"status": "reopened"}},
	}})
	if got := status(1); got != "reopened" {
		t.Fatalf("transaction update of status alone refused (%d %s); status = %q", rec.Code, rec.Body.String(), got)
	}

	// A submitted field is still caught, by name and by value.
	rec = crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"status": "x", "weight": 9})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "only status may change") {
		t.Fatalf("submitted weight not refused: %d %s", rec.Code, rec.Body.String())
	}
	app.Hooks.BeforeUpdate["notes"] = app.Hooks.BeforeUpdate["notes"][1:]
	rec = crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"weight": 5})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "weight 5 is reserved") {
		t.Fatalf("submitted weight 5 not refused: %d %s", rec.Code, rec.Body.String())
	}

	// `when:` is judged over the row as it will be: a stored column the
	// request did not send still decides whether the hook applies.
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {
		{When: "weight = 5", SQL: `SELECT 'weight-5 rows are frozen' AS error`},
	}}}
	rec = crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"status": "later"})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "frozen") {
		t.Fatalf("when: no longer sees the stored column: %d %s", rec.Code, rec.Body.String())
	}
}
