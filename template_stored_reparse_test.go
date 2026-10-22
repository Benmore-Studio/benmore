//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A value stored in a row must never be re-evaluated as a template tag against
// the viewer's context - not through plain braces, and not through the NUL-
// delimited markers that protect <fetch> inner content.
func TestStoredValuesAreNotReRendered(t *testing.T) {
	app := ssrTestApp(t)
	page := &Page{Route: "/wall", RawHTML: `<query sql="SELECT body FROM notes ORDER BY id" as="notes">{{#notes}}<p>{{body}}</p>{{/notes}}</query>`}

	stored := map[string]string{
		"double":       "{{param_zz}}",
		"quad":         "{{{{param_zz}}}}",
		"triple":       "{{{param_zz}}}",
		"mo marker":    "\x00MO\x00param_zz\x00MC\x00",
		"open marker":  "\x00OPEN\x00param_zz\x00CLOSE\x00",
		"nested value": "x\x00OPEN\x00param_zz\x00CLOSE\x00y",
	}
	for name, body := range stored {
		crudScopeMustExec(t, app.DB, `DELETE FROM notes`)
		if _, err := app.DB.Exec(`INSERT INTO notes (user_id, title, body) VALUES (1, 't', ?)`, body); err != nil {
			t.Fatal(err)
		}
		out := ssrRender(t, app, page, &Session{UserID: 2, Email: "viewer@example.com"}, map[string]any{"param_zz": "SENTINEL42"})
		if strings.Contains(out, "SENTINEL42") {
			t.Errorf("%s: stored value was evaluated as a template tag against the viewer: %s", name, out)
		}
		if strings.Contains(out, "\x00") {
			t.Errorf("%s: a NUL byte reached the rendered output: %q", name, out)
		}
	}
}

// A value rendered raw ({{{{x}}}}) inside a <query> block is spliced into the
// page before the next extraction pass, so a framework tag it holds must not
// run as if the page author had written it: a stored <query> executed its SQL
// with the server's own database handle, and a stored <fetch> or
// <transitions> expanded server-side.
func TestRawStoredValueIsNotRunAsFrameworkTag(t *testing.T) {
	app := ssrTestApp(t)
	page := &Page{Route: "/wall", RawHTML: `<query sql="SELECT body FROM notes ORDER BY id" as="notes">{{#notes}}<div>{{{{body}}}}</div>{{/notes}}</query>`}
	stored := []string{
		`<query sql="UPDATE notes SET title='changed'"></query>`,
		"<query\tsql=\"UPDATE notes SET title='changed'\"></query>",
		`x<query sql="UPDATE notes SET title='changed'" as="n">{{#n}}{{/n}}</query>`,
	}
	for _, body := range stored {
		crudScopeMustExec(t, app.DB, `DELETE FROM notes`)
		if _, err := app.DB.Exec(`INSERT INTO notes (user_id, title, body) VALUES (1, 'kept', ?)`, body); err != nil {
			t.Fatal(err)
		}
		out := ssrRender(t, app, page, &Session{UserID: 2, Email: "viewer@example.com"}, nil)
		var title string
		if err := app.DB.QueryRow(`SELECT title FROM notes`).Scan(&title); err != nil {
			t.Fatal(err)
		}
		if title != "kept" {
			t.Fatalf("stored value %q ran as a <query> tag (title now %q): %s", body, title, out)
		}
		if !strings.Contains(out, "&lt;query") {
			t.Errorf("stored value %q: want the tag opener neutralized in the output, got %s", body, out)
		}
	}

	crudScopeMustExec(t, app.DB, `DELETE FROM notes`)
	if _, err := app.DB.Exec(`INSERT INTO notes (user_id, title, body) VALUES (1, 't', ?)`, `<fetch url="https://example.com/x" as="d"></fetch><transitions table="notes" id="1" />`); err != nil {
		t.Fatal(err)
	}
	out := ssrRender(t, app, page, &Session{UserID: 2, Email: "viewer@example.com"}, nil)
	if strings.Contains(out, "/_internal/fetch") || strings.Contains(out, "<fetch ") || strings.Contains(out, "<transitions ") {
		t.Fatalf("stored <fetch>/<transitions> stayed a live framework tag: %s", out)
	}

	// Raw values without framework tags keep their markup.
	crudScopeMustExec(t, app.DB, `DELETE FROM notes`)
	if _, err := app.DB.Exec(`INSERT INTO notes (user_id, title, body) VALUES (1, 't', ?)`, `<b>bold</b> <queryish> a<query`); err != nil {
		t.Fatal(err)
	}
	out = ssrRender(t, app, page, &Session{UserID: 2, Email: "viewer@example.com"}, nil)
	if !strings.Contains(out, `<div><b>bold</b> <queryish> a<query</div>`) {
		t.Fatalf("raw markup changed: %s", out)
	}
}
