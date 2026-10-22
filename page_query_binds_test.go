//go:build !cli

package main

import (
	"strings"
	"testing"
)

func rawQueryPage(sql string) *Page {
	return &Page{Route: "/r", RawHTML: `<query sql="` + sql + `" as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>none</p>{{/rows}}</query>`}
}

// Every occurrence of a template value in raw <query sql> is bound, whether
// it sits inside a string literal or not, and however often it appears.
func TestRawQueryBindsEveryTemplateValue(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'row-one'), (2, 'row-two')`)
	cases := []struct {
		name, sql string
		data      map[string]any
		want      string
		dontWant  []string
	}{
		{"quoted then unquoted", `SELECT title FROM notes WHERE title LIKE '%{{param_q}}%' OR id = {{param_q}}`,
			map[string]any{"param_q": "0 OR 1=1"}, "none", []string{"row-one", "row-two"}},
		{"unquoted then quoted", `SELECT title FROM notes WHERE id = {{param_q}} OR title = '{{param_q}}'`,
			map[string]any{"param_q": "2"}, "row-two", []string{"row-one"}},
		{"backslash before a quote", `SELECT title FROM notes WHERE title <> 'C:\' AND id = {{param_id}}`,
			map[string]any{"param_id": "0 OR 1=1"}, "none", []string{"row-one", "row-two"}},
		{"quote in a comment", "SELECT title FROM notes -- it's here\n WHERE id = {{param_id}}",
			map[string]any{"param_id": "0 OR 1=1"}, "none", []string{"row-one", "row-two"}},
	}
	for _, tc := range cases {
		out := ssrRender(t, app, rawQueryPage(tc.sql), nil, tc.data)
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s: want %q in %s", tc.name, tc.want, out)
		}
		for _, w := range tc.dontWant {
			if strings.Contains(out, w) {
				t.Errorf("%s: unexpected %q in %s", tc.name, w, out)
			}
		}
	}
}

// :current_user and {{vars}} bind in statement order: a value placed after
// :current_user can't land in the user_id comparison.
func TestRawQueryCurrentUserBindsInOrder(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (id, user_id, title) VALUES (1, 1, 'alice-1'), (2, 2, 'bob-2')`)
	page := rawQueryPage(`SELECT title FROM notes WHERE user_id = :current_user AND id >= {{param_min}}`)
	out := ssrRender(t, app, page, &Session{UserID: 1}, map[string]any{"param_min": "2"})
	if !strings.Contains(out, "none") || strings.Contains(out, "bob-2") {
		t.Fatalf("arguments bound out of order: %s", out)
	}
	out = ssrRender(t, app, page, &Session{UserID: 1}, map[string]any{"param_min": "1"})
	if !strings.Contains(out, "alice-1") || strings.Contains(out, "bob-2") {
		t.Fatalf("own row missing or other user's row present: %s", out)
	}
}
