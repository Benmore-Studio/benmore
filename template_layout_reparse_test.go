//go:build !cli

package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// layoutReparseApp serves a public events listing twice, as a gotmpl page and
// as a mustache page, both wrapped in a mustache layout that renders its own
// variables before and after the {{content}} slot.
func layoutReparseApp(t *testing.T) *App {
	t.Helper()
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, summary TEXT)`)
	app.Access.rules["events"] = map[AccessOp]string{OpRead: "everyone"}
	app.Tables = append(app.Tables, Table{Name: "events", Columns: []Column{
		{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}, {Name: "summary"},
	}})
	// Stored by an ordinary user on their own events: template syntax in
	// both fields and markup in the summary.
	crudScopeMustExec(t, app.DB, `INSERT INTO events(user_id,title,summary) VALUES
		(2,'Mallory party {{#events}}{{{{summary}}}}{{/events}}','<img src=x onerror="stored()">'),
		(2,'Mallory {{user_email}} {{{{param_x}}}}','plain')`)
	if err := os.Mkdir(filepath.Join(app.Dir, "layouts"), 0o755); err != nil {
		t.Fatal(err)
	}
	layout := `<header data-layout-title>{{page_title}}</header>` +
		`<nav data-layout-user>{{#logged_in}}{{user_email}}{{/logged_in}}{{^logged_in}}guest{{/logged_in}}</nav>` +
		`<main>{{content}}</main>` +
		`<footer data-layout-city>{{param_city}}</footer>`
	if err := os.WriteFile(filepath.Join(app.Dir, "layouts", "public.html"), []byte(layout), 0o644); err != nil {
		t.Fatal(err)
	}
	ssrLoadPages(t, app, map[string]string{
		"events.html": "---\nengine: gotmpl\ntitle: Upcoming events\nlayout: public\nqueries:\n  events: SELECT id, title, summary FROM events ORDER BY id\n---\n" +
			`<p>showing <span data-testid="city-filter">{{.param_city}}</span></p>` +
			`{{range .events}}<h2>{{.title}}</h2><p>{{.summary}}</p>{{end}}`,
		"listing.html": `<page layout="public" title="Upcoming events">` +
			`<p>showing <span data-testid="city-filter">{{param_city}}</span></p>` +
			`<query sql="SELECT id, title, summary FROM events ORDER BY id" as="events">{{#events}}<h2>{{title}}</h2><p>{{summary}}</p>{{/events}}</query>` +
			`</page>`,
	})
	return app
}

func layoutMain(t *testing.T, body string) string {
	t.Helper()
	start, end := strings.Index(body, "<main>"), strings.LastIndex(body, "</main>")
	if start < 0 || end < start {
		t.Fatalf("layout <main> slot missing: %s", body)
	}
	return body[start : end+len("</main>")]
}

// A page wrapped in a layout is rendered once: the layout's own tags render,
// and the page's already-rendered output (request parameters, query rows) is
// placed in the slot without another mustache pass, for either engine and
// for anonymous and signed-in viewers.
func TestLayoutDoesNotReparsePageOutput(t *testing.T) {
	app := layoutReparseApp(t)
	mux := buildAppMux(app, false, "https://fixture.example.com")
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	query := "?" + url.Values{
		"city": {"{{{{param_x}}}}"},
		"x":    {`<script>reflected()</script>`},
	}.Encode()

	for _, route := range []string{"/events", "/listing"} {
		for _, viewer := range []struct{ name, token string }{{"anonymous", ""}, {"signed-in", alice}} {
			t.Run(route+"/"+viewer.name, func(t *testing.T) {
				rec := ssrGet(mux, route+query, viewer.token)
				if rec.Code != 200 {
					t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
				body := rec.Body.String()
				for _, live := range []string{"<script>reflected()", `<img src=x onerror="stored()">`, "<img src=x"} {
					if strings.Contains(body, live) {
						t.Fatalf("page value rendered as live markup %q:\n%s", live, body)
					}
				}
				main := layoutMain(t, body)
				if strings.Contains(main, "alice@example.com") {
					t.Fatalf("stored {{user_email}} expanded to the viewer's email inside the page:\n%s", main)
				}
				if strings.Count(main, "<h2>") != 2 || !strings.Contains(main, "<p>plain</p>") {
					t.Fatalf("page rows did not render once each:\n%s", main)
				}
				// The values are shown as text: gotmpl leaves braces as is,
				// mustache entity-encodes them; neither is a template tag.
				wantTitle, wantCity, wantImg := "Mallory {{user_email}} {{{{param_x}}}}", `data-testid="city-filter">{{{{param_x}}}}<`, "&lt;img src=x onerror=&#34;stored()&#34;&gt;"
				if route == "/listing" {
					wantTitle = "Mallory {&#123;user_email&#125;} {&#123;{&#123;param_x&#125;}&#125;}"
					wantCity = `data-testid="city-filter">{&#123;{&#123;param_x&#125;}&#125;}<`
				}
				for _, want := range []string{wantTitle, wantCity, wantImg} {
					if !strings.Contains(main, want) {
						t.Fatalf("page value not shown literally, want %q in:\n%s", want, main)
					}
				}

				// The layout's own variables still render, before and after
				// the slot.
				if !strings.Contains(body, "<header data-layout-title>Upcoming events</header>") {
					t.Fatalf("layout title did not render:\n%s", body)
				}
				wantUser := "guest"
				if viewer.token != "" {
					wantUser = "alice@example.com"
				}
				if !strings.Contains(body, "<nav data-layout-user>"+wantUser+"</nav>") {
					t.Fatalf("layout user section did not render %q:\n%s", wantUser, body)
				}
				if !strings.Contains(body, "<footer data-layout-city>{&#123;{&#123;param_x&#125;}&#125;}</footer>") {
					t.Fatalf("layout variable after the slot did not render escaped:\n%s", body)
				}
			})
		}
	}
}

// renderLayout writes the page verbatim wherever the layout puts its slot,
// keeps the layout's own sections intact around it, and escapes the layout's
// later values for the HTML context the page leaves open.
func TestRenderLayoutWritesPageVerbatim(t *testing.T) {
	data := map[string]any{"logged_in": true, "user_email": "alice@example.com", "v": `"a"; alert(1)`}
	page := `<p>{{user_email}} {{/logged_in}} {{{{v}}}}</p>`
	cases := []struct{ name, layout, want string }{
		{"slot inside a section", `{{#logged_in}}<main>{{content}}</main><i>{{user_email}}</i>{{/logged_in}}`,
			`<main>` + page + `</main><i>alice@example.com</i>`},
		{"sanitized-raw spelling", `<main>{{{content}}}</main>`, `<main>` + page + `</main>`},
		{"raw spelling", `<main>{{{{content}}}}</main>`, `<main>` + page + `</main>`},
		{"no slot", `<main>layout only</main>`, `<main>layout only</main>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderLayout(tc.layout, page, data); got != tc.want {
				t.Fatalf("renderLayout = %q, want %q", got, tc.want)
			}
		})
	}

	// The page leaves a script open: the layout's value after the slot is
	// JavaScript-encoded, as it was when the page was part of the layout.
	got := renderLayout(`{{content}}{{v}};</script>`, `<script>var x = `, data)
	if want := `<script>var x = "\"a\"; alert(1)";</script>`; got != want {
		t.Fatalf("value after the slot lost the page's script context: %q, want %q", got, want)
	}
}

// engine: raw pages keep their documented "no template pass" inside a layout.
func TestRawPageBodyIsNotRenderedByLayout(t *testing.T) {
	app := ssrTestApp(t)
	if err := os.Mkdir(filepath.Join(app.Dir, "layouts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "layouts", "frame.html"), []byte(`<nav>{{user_email}}</nav><main>{{content}}</main>`), 0o644); err != nil {
		t.Fatal(err)
	}
	page := &Page{Route: "/spa", File: "spa.html", RawHTML: "---\nengine: raw\nlayout: frame\n---\n<div id=app>{{ message }} {{user_email}}</div>"}
	out := ssrRender(t, app, page, &Session{UserID: 1, Email: "alice@example.com"}, map[string]any{"user_email": "alice@example.com"})
	if !strings.Contains(out, "<nav>alice@example.com</nav><main><div id=app>{{ message }} {{user_email}}</div></main>") {
		t.Fatalf("raw body was rendered by the layout pass: %s", out)
	}
}
