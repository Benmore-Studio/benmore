//go:build !cli

package main

import (
	"strings"
	"testing"
)

const shorthandListTmpl = `{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>none</p>{{/rows}}`

func shorthandPage(attrs string) *Page {
	return &Page{Route: "/s", RawHTML: `<query from="notes" pick="title" ` + attrs + ` as="rows">` + shorthandListTmpl + `</query>`}
}

// Template values in a shorthand where= are bound as ? arguments: they select
// rows as data and never change the query's predicate.
func TestShorthandWhereBindsTemplateValues(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'row-one'), (2, 'row-two')`)
	cases := []struct {
		name, attrs string
		data        map[string]any
		want        []string
		dontWant    []string
	}{
		{"equality", `where="id = {{param_id}}"`, map[string]any{"param_id": "2"}, []string{"row-two"}, []string{"row-one"}},
		{"expression text is data", `where="id = {{param_id}}"`, map[string]any{"param_id": "0 OR 1=1"}, []string{"none"}, []string{"row-one", "row-two"}},
		{"inside a literal", `where="title LIKE '%{{param_q}}%'"`, map[string]any{"param_q": "-on"}, []string{"row-one"}, []string{"row-two"}},
		{"quote inside a literal", `where="title LIKE '%{{param_q}}%'"`, map[string]any{"param_q": "x' OR '1'='1"}, []string{"none"}, []string{"row-one", "row-two", "benmore-error"}},
		{"same var in and out of quotes", `where="title LIKE '%{{param_q}}%' OR id = {{param_q}}"`, map[string]any{"param_q": "0 OR 1=1"}, []string{"none"}, []string{"row-one", "row-two"}},
	}
	for _, tc := range cases {
		out := ssrRender(t, app, shorthandPage(tc.attrs), nil, tc.data)
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in %s", tc.name, w, out)
			}
		}
		for _, w := range tc.dontWant {
			if strings.Contains(out, w) {
				t.Errorf("%s: unexpected %q in %s", tc.name, w, out)
			}
		}
	}
}

// :current_user in where= binds the session user in statement order.
func TestShorthandWhereCurrentUser(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'row-one'), (2, 'row-two')`)
	page := shorthandPage(`where="user_id = :current_user AND id >= {{param_min}}"`)
	out := ssrRender(t, app, page, &Session{UserID: 2}, map[string]any{"param_min": "1"})
	if !strings.Contains(out, "row-two") || strings.Contains(out, "row-one") {
		t.Fatalf(":current_user bound out of order: %s", out)
	}
	if out := ssrRender(t, app, page, nil, map[string]any{"param_min": "1"}); !strings.Contains(out, "none") {
		t.Fatalf("anonymous :current_user must match nothing: %s", out)
	}
}

// Identifiers the builder writes into SQL must be real columns.
func TestShorthandRejectsUnknownIdentifiers(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'row-one')`)
	for name, page := range map[string]*Page{
		"pick":  {Route: "/p", RawHTML: `<query from="notes" pick="{{param_cols}}" as="rows">` + shorthandListTmpl + `</query>`},
		"owned": {Route: "/o", RawHTML: `<query from="notes" pick="title" owned="{{param_col}}" as="rows">` + shorthandListTmpl + `</query>`},
		"from":  {Route: "/f", RawHTML: `<query from="no_such_table" as="rows">` + shorthandListTmpl + `</query>`},
	} {
		out := ssrRender(t, app, page, &Session{UserID: 1}, map[string]any{"param_cols": "title, 1 AS x", "param_col": "user_id OR 1"})
		if !strings.Contains(out, "benmore-error") || strings.Contains(out, "row-one") {
			t.Errorf("%s: want an error block, got %s", name, out)
		}
	}
}

func TestBindTemplateSQLShapes(t *testing.T) {
	data := map[string]any{"a": "x", "empty": ""}
	cases := []struct {
		in, want string
		args     int
	}{
		{`SELECT 1 WHERE c = {{a}}`, `SELECT 1 WHERE c = ?`, 1},
		{`SELECT 1 WHERE c = {{empty}}`, `SELECT 1 WHERE c = NULL`, 0},
		{`SELECT 1 WHERE c LIKE '%{{a}}%'`, `SELECT 1 WHERE c LIKE ('%' || ? || '%')`, 1},
		{`SELECT 1 WHERE c = 'it''s {{a}}'`, `SELECT 1 WHERE c = ('it''s ' || ? || '')`, 1},
		{`SELECT 1 -- {{a}}` + "\n", `SELECT 1 -- ` + "\n", 0},
		{`SELECT 1 WHERE c = ':current_user'`, `SELECT 1 WHERE c = ':current_user'`, 0},
	}
	for _, tc := range cases {
		got, args, err := bindTemplateSQL(tc.in, data, nil)
		if err != nil || got != tc.want || len(args) != tc.args {
			t.Errorf("bindTemplateSQL(%q) = %q, %d args, %v; want %q, %d args", tc.in, got, len(args), err, tc.want, tc.args)
		}
	}
	if _, _, err := bindTemplateSQL(`SELECT "{{a}}" FROM t`, data, nil); err == nil {
		t.Errorf("a template value inside a quoted identifier must be refused")
	}
}
