//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A template key in <query> SQL that names no page value used to bind NULL,
// so the page answered 200 with its empty state ("Invoice not found") as if
// no row matched. It now stops the page like any failed query tag: 500 with
// the request id, the detail in dev mode.
func TestQueryTagUnknownKeyStopsThePage(t *testing.T) {
	const marker = "rest-of-page-marker"
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (id, user_id, title, body) VALUES (1, 1, 'inv-one', 'line-a'), (2, 1, 'inv-two', 'line-b')`)
	list := func(attrs string) string {
		return `<h1>` + marker + `</h1><query ` + attrs + ` as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>empty-state</p>{{/rows}}</query>`
	}
	ssrLoadPages(t, app, map[string]string{
		// ?id=1 is {{param_id}}; a bare {{id}} names nothing.
		"code.html":    list(`sql="SELECT title FROM notes WHERE id = {{id}}"`),
		"literal.html": list(`sql="SELECT title FROM notes WHERE title LIKE '%{{q}}%'"`),
		"where.html":   list(`from="notes" pick="title" where="id = {{id}}"`),
		// The logic-round repro: the nested tag runs first, so the outer
		// row's {{id}} does not exist yet.
		"nested.html": `<h1>` + marker + `</h1><query sql="SELECT id, title FROM notes WHERE id = {{param_id}}" as="inv">{{#inv}}<h2>{{title}}</h2>` +
			`<query sql="SELECT body FROM notes WHERE id = {{id}}" as="lines">{{#lines}}<li>{{body}}</li>{{/lines}}{{^lines}}<p>no-lines</p>{{/lines}}</query>{{/inv}}{{^inv}}<p>Invoice not found.</p>{{/inv}}</query>`,
		"typo.html": list(`sql="SELECT title FROM notes WHERE user_id = {{user.idd}}"`),
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	viewer := createCrudScopeSession(t, app, "viewer@example.com", "user", "", "")
	for _, tc := range []struct{ route, token string }{
		{"/code?id=1", ""},
		{"/literal?q=inv", ""},
		{"/where?id=1", ""},
		{"/nested?id=1", ""},
		{"/typo", viewer},
	} {
		w := ssrGet(mux, tc.route, tc.token)
		body := w.Body.String()
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500; body %s", tc.route, w.Code, body)
			continue
		}
		for _, leak := range []string{marker, "empty-state", "Invoice not found", "no-lines", "inv-one"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: the page rendered (%q) instead of stopping: %s", tc.route, leak, body)
			}
		}
		if id := w.Header().Get(requestIDHeader); id == "" || !strings.Contains(body, id) {
			t.Errorf("%s: no request id in the answer: header %q body %s", tc.route, id, body)
		}
		if strings.Contains(body, "nothing binds") || strings.Contains(body, "SELECT") {
			t.Errorf("%s: production answer disclosed the detail: %s", tc.route, body)
		}
	}

	// Dev mode names the key and where page values come from.
	app.DevMode = true
	dev := buildAppMux(app, true, "http://localhost")
	w := ssrGet(dev, "/code?id=1", "")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "nothing binds {{id}}") || !strings.Contains(w.Body.String(), "param_id") {
		t.Fatalf("dev answer lost its detail: %d %s", w.Code, w.Body.String())
	}
}

// Keys an ordinary request may lack still bind NULL (or ” inside a quoted
// literal): a URL value the request leaves out, the identity of an anonymous
// viewer, and their user.<column> values. The page renders its empty state.
func TestQueryTagOptionalKeysBindNull(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (id, user_id, title) VALUES (1, 1, 'row-one'), (2, NULL, 'row-null')`)
	list := func(sql string) string {
		return `<query sql="` + sql + `" as="rows">{{#rows}}<li>{{title}}</li>{{/rows}}{{^rows}}<p>none</p>{{/rows}}</query>`
	}
	for name, tc := range map[string]struct {
		sql      string
		data     map[string]any
		session  *Session
		want     string
		dontWant string
	}{
		"absent filter":        {`SELECT title FROM notes WHERE ({{param_status}} IS NULL OR title = {{param_status}}) ORDER BY id`, nil, nil, "row-one", ""},
		"absent in a literal":  {`SELECT title FROM notes WHERE title LIKE '%{{param_q}}%' ORDER BY id`, nil, nil, "row-null", ""},
		"present filter":       {`SELECT title FROM notes WHERE ({{param_status}} IS NULL OR title = {{param_status}})`, map[string]any{"param_status": "row-one"}, nil, "row-one", "row-null"},
		"anonymous user_id":    {`SELECT title FROM notes WHERE user_id = {{user_id}}`, nil, nil, "none", "row-"},
		"anonymous user.email": {`SELECT title FROM notes WHERE title = {{user.email}}`, nil, nil, "none", "row-"},
		"anonymous group":      {`SELECT title FROM notes WHERE user_id = {{user_group_id}}`, nil, nil, "none", "row-"},
		"signed-in user.id":    {`SELECT title FROM notes WHERE user_id = {{user.id}}`, map[string]any{"user": map[string]any{"id": int64(1)}}, &Session{UserID: 1}, "row-one", "row-null"},
		"row index":            {`SELECT title FROM notes WHERE id = {{prior.0.id}}`, map[string]any{"prior": []map[string]any{{"id": int64(2)}}}, nil, "row-null", "row-one"},
	} {
		page := &Page{Route: "/r", RawHTML: list(tc.sql)}
		out := ssrRender(t, app, page, tc.session, tc.data)
		if !strings.Contains(out, tc.want) || (tc.dontWant != "" && strings.Contains(out, tc.dontWant)) {
			t.Errorf("%s: got %s, want %q without %q", name, out, tc.want, tc.dontWant)
		}
	}
}
