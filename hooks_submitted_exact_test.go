//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// {{_submitted}} must list exactly the columns the request is writing. It
// listed every key the request carried instead - form fields such as _csrf,
// query parameters, unknown or protected names the write drops, and names
// with a comma in them - plus user_id and the tenant key the framework fills
// in on create. A key named "x,title" then made an unsubmitted title look
// submitted to a hook that requires it.
func TestSubmittedFieldsListOnlyWrittenColumns(t *testing.T) {
	app, mux := auditApp(t)
	mustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN body TEXT")
	sid := createCrudScopeSession(t, app, "writer@example.com", "user", "", "")
	tok := auditToken(t, app, sid, "*")
	if rec := crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": "first"}); rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("seed create: %d %s", rec.Code, rec.Body.String())
	}
	echo := []Hook{{SQL: "SELECT 'submitted=' || '{{_submitted}}' AS error"}}
	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"notes": echo}, BeforeUpdate: map[string][]Hook{"notes": echo}}
	submitted := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		body := rec.Body.String()
		i := strings.Index(body, "submitted=")
		if i < 0 {
			t.Fatalf("hook did not run: %d %s", rec.Code, body)
		}
		rest := body[i+len("submitted="):]
		if j := strings.IndexAny(rest, "\"\n"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}

	cases := []struct {
		name string
		rec  *httptest.ResponseRecorder
	}{
		{"update json", crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"title": "x", "user_id": 5, "nosuch": 1, "bogus,title": 1})},
		{"create json", crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": "x", "user_id": 5})},
		{"batch update", crudScopeRequest(t, mux, "PATCH", "/api/notes/batch", tok, map[string]any{"ids": []any{1}, "fields": map[string]string{"title": "x", "user_id": "5", "bogus,title": "1"}})},
		{"batch create", crudScopeRequest(t, mux, "POST", "/api/notes/batch", tok, []map[string]any{{"title": "x", "user_id": 5}})},
		{"transaction create", crudScopeRequest(t, mux, "POST", "/api/_transaction", tok, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "insert", "data": map[string]any{"title": "x", "user_id": 5}}}})},
		{"transaction update", crudScopeRequest(t, mux, "POST", "/api/_transaction", tok, map[string]any{"operations": []map[string]any{{"table": "notes", "action": "update", "id": 1, "data": map[string]any{"title": "x", "user_id": 5, "bogus,title": 1}}}})},
	}
	form := url.Values{"_csrf": {"anything"}, "title": {"y"}}
	req := httptest.NewRequest("PATCH", "/api/notes/1?nosuch=1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	cases = append(cases, struct {
		name string
		rec  *httptest.ResponseRecorder
	}{"update form", rec})

	for _, c := range cases {
		if got := submitted(c.rec); got != ",title," {
			t.Errorf("%s: {{_submitted}} = %q, want \",title,\"", c.name, got)
		}
	}

	// A hook that requires title is not satisfied by a key that only
	// mentions it.
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{"notes": {{
		SQL: "SELECT 'title required' AS error WHERE instr('{{_submitted}}', ',title,') = 0",
	}}}}
	forged := crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"body": "b", "x,title": "1"})
	if !strings.Contains(forged.Body.String(), "title required") {
		t.Fatalf("a key naming title passed the title-required hook: %d %s", forged.Code, forged.Body.String())
	}
	if ok := crudScopeRequest(t, mux, "PATCH", "/api/notes/1", tok, map[string]any{"body": "b", "title": "t"}); ok.Code != http.StatusOK {
		t.Fatalf("control: a real title update was refused: %d %s", ok.Code, ok.Body.String())
	}
}
