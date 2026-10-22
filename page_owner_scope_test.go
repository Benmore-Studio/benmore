//go:build !cli

package main

import (
	"strings"
	"testing"
)

func ownerScopeRows(t *testing.T, app *App, page *Page, session *Session) string {
	t.Helper()
	return ssrRender(t, app, page, session, nil)
}

// An OR in the page's WHERE must not widen scope="owner" past the owner.
func TestScopeOwnerHoldsAcrossOr(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title, body) VALUES (1, 'a', 'alice-a'), (2, 'a', 'bob-a'), (2, 'b', 'bob-b')`)
	alice := &Session{UserID: 1, Email: "alice@example.com", Role: "user"}
	for name, sql := range map[string]string{
		"or":             `SELECT body FROM notes WHERE title = 'a' OR title = 'b'`,
		"or+order":       `SELECT body FROM notes WHERE title = 'a' OR title = 'b' ORDER BY id`,
		"keyword in str": `SELECT body FROM notes WHERE title <> 'x LIMIT 5' OR title = 'b' ORDER BY id`,
		"newline where":  "SELECT body FROM notes n WHERE\n n.title = 'a' OR n.title = 'b'\nORDER\nBY n.id",
		"alias as":       `SELECT n.body FROM notes AS n WHERE n.title = 'a' OR n.title = 'b'`,
		"trailing semi":  `SELECT body FROM notes WHERE title = 'a' OR title = 'b';`,
		"line comment":   "SELECT body FROM notes -- every note\n",
	} {
		page := &Page{Route: "/o", Scope: "owner", RawHTML: `<query sql="` + sql + `" as="rows">{{#rows}}<li>{{body}}</li>{{/rows}}</query>`}
		out := ownerScopeRows(t, app, page, alice)
		if !strings.Contains(out, "alice-a") {
			t.Errorf("%s: owner's own row missing: %s", name, out)
		}
		if strings.Contains(out, "bob-") || strings.Contains(out, "benmore-error") {
			t.Errorf("%s: got another user's row or an error: %s", name, out)
		}
	}
}

// Shapes the rewrite can't scope with certainty are refused, not guessed at.
func TestScopeOwnerRefusesCompoundQueries(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title, body) VALUES (2, 'b', 'bob-b')`)
	page := &Page{Route: "/u", Scope: "owner", RawHTML: `<query sql="SELECT body FROM notes WHERE user_id = 1 UNION SELECT body FROM notes" as="rows">{{#rows}}<li>{{body}}</li>{{/rows}}</query>`}
	out := ownerScopeRows(t, app, page, &Session{UserID: 1})
	if strings.Contains(out, "bob-b") || !strings.Contains(out, "benmore-error") {
		t.Fatalf("compound query under scope=owner must render an error, got: %s", out)
	}
}

// With no session, owner scoping matches nothing instead of everything.
func TestOwnerScopeWithoutSessionMatchesNothing(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (2, 'bob-private')`)
	for name, page := range map[string]*Page{
		"scope=owner": {Route: "/p1", Scope: "owner", RawHTML: `<query sql="SELECT title FROM notes" as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>none</p>{{/rows}}</query>`},
		"owned=true":  {Route: "/p2", RawHTML: `<query from="notes" pick="title" owned="true" as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>none</p>{{/rows}}</query>`},
	} {
		out := ssrRender(t, app, page, nil, nil)
		if strings.Contains(out, "bob-private") || !strings.Contains(out, "none") {
			t.Errorf("%s: anonymous render = %s; want the empty state", name, out)
		}
	}
}

// owned= is ANDed onto a parenthesized where=.
func TestShorthandOwnedHoldsAcrossOr(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title, body) VALUES (1, 'a', 'alice-a'), (2, 'a', 'bob-a')`)
	page := &Page{Route: "/s", RawHTML: `<query from="notes" pick="body" where="title = 'a' OR title = 'b'" owned="true" as="rows">{{#rows}}<li>{{body}}</li>{{/rows}}</query>`}
	out := ssrRender(t, app, page, &Session{UserID: 1}, nil)
	if !strings.Contains(out, "alice-a") || strings.Contains(out, "bob-a") {
		t.Fatalf("owned=true with an OR in where=: %s", out)
	}
}
