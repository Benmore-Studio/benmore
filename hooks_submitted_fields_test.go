//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// Before-hooks can tell which fields a request submitted: {{_submitted}}
// lists them. Comparing a field against its literal placeholder text was
// the only signal before, and a caller could submit that literal text as
// the value.
func TestBeforeHooksSeeSubmittedFields(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "writer@example.com", "user", "", "")
	tok := auditToken(t, app, sid, "*")
	create := crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": "first"})
	if create.Code != http.StatusOK && create.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Code, create.Body.String())
	}
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{
		SQL: "SELECT CASE WHEN instr('{{_submitted}}', ',title,') > 0 THEN RAISE(ABORT, 'title is locked') END",
	}}}}
	for _, value := range []string{"renamed", "{{title}}"} {
		rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"title": value})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "title is locked") {
			t.Fatalf("submitted title %q not detected: %d %s", value, rec.Code, rec.Body.String())
		}
	}
	rec := crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"user_id": 1})
	if strings.Contains(rec.Body.String(), "title is locked") {
		t.Fatalf("an update without title was treated as submitting it: %s", rec.Body.String())
	}
	row := map[string]any{}
	markSubmittedFields(row, []string{"b", "a", "id", "a"})
	if row[submittedFieldsKey] != ",a,b," {
		t.Fatalf("submitted list = %q", row[submittedFieldsKey])
	}
}
