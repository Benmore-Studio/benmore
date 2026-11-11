//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Page render data holds values made for templates. Anything else placed
// there by framework code (the session, the app, a request) reads as empty
// in both engines, whatever name it is under.
func TestPageDataNeverHoldsFrameworkObjects(t *testing.T) {
	app := ssrTestApp(t)
	session := &Session{ID: "sha256:feedface", UserID: 7, Email: "held@example.com", Role: "admin", Roles: []string{"admin"}}
	objects := func() map[string]any {
		return map[string]any{
			"session": session, "nilsession": (*Session)(nil), "app": app, "value": *session,
			"sessions": []*Session{session}, "byname": map[string]*Session{"a": session},
			"fn": func() string { return "sha256:fromfunc" },
		}
	}
	mustache := &Page{Route: "/m", File: "m.html", Layout: "none", RawHTML: `<page layout="none">` +
		`[{{session}}|{{{session}}}|{{{{session}}}}|{{session | json}}|{{nilsession}}|{{app}}|{{value}}|{{sessions}}|{{byname}}|{{fn}}]` +
		`[{{#session}}S{{/session}}{{#nilsession}}N{{/nilsession}}{{#app}}A{{/app}}{{#if value}}V{{/if}}{{^session}}EMPTY{{/session}}]` +
		`[{{rows.0.title}}|{{#rows}}{{title}}{{/rows}}|{{count}}|{{flag}}|{{names}}]</page>`}
	data := objects()
	// Values made for templates are untouched.
	data["rows"] = []map[string]any{{"title": "kept"}}
	data["count"] = int64(3)
	data["flag"] = true
	data["names"] = []string{"a", "b"}
	out := ssrRender(t, app, mustache, session, data)
	if want := "[|||||||||][EMPTY][kept|kept|3|true|[a b]]"; !strings.Contains(out, want) {
		t.Errorf("mustache render = %q, want it to contain %q", out, want)
	}
	for _, leak := range []string{"sha256:", "held@example.com", "feedface", "fromfunc", "main.", "0x"} {
		if strings.Contains(out, leak) {
			t.Errorf("mustache render contains %q: %s", leak, out)
		}
	}

	gotmpl := &Page{Route: "/g", File: "g.html", Layout: "none", RawHTML: "---\nengine: gotmpl\nlayout: none\n---\n" +
		`[{{.session}}|{{printf "%+v" .session}}|{{.nilsession}}|{{printf "%v" .app}}|{{.value}}|{{.sessions}}|{{.byname}}|{{toJson .session}}]` +
		`[{{if .session}}S{{end}}{{if .app}}A{{end}}{{with .value}}V{{end}}{{if .sessions}}L{{end}}]` +
		`[{{range .rows}}{{.title}}{{end}}|{{.count}}|{{.flag}}|{{join "," .names}}]`}
	out = ssrRender(t, app, gotmpl, session, withPageData(objects(), map[string]any{
		"rows": []map[string]any{{"title": "kept"}}, "count": int64(3), "flag": true, "names": []string{"a", "b"},
	}))
	if want := `[|||||||&#34;&#34;][][kept|3|true|a,b]`; !strings.Contains(out, want) {
		t.Errorf("gotmpl render = %q, want it to contain %q", out, want)
	}
	for _, leak := range []string{"sha256:", "held@example.com", "feedface", "main.", "0x"} {
		if strings.Contains(out, leak) {
			t.Errorf("gotmpl render contains %q: %s", leak, out)
		}
	}
	// A field of a held object is not reachable either: the page stops.
	field := &Page{Route: "/f", File: "f.html", Layout: "none", RawHTML: "---\nengine: gotmpl\nlayout: none\n---\n[{{.session.ID}}]"}
	ctx := &RenderContext{Data: objects(), User: session, App: app, Page: field}
	if rendered, err := RenderTemplate(app, field, ctx); err == nil {
		t.Errorf("gotmpl read a field of a held session: %q", rendered)
	}
}

func withPageData(base, more map[string]any) map[string]any {
	for k, v := range more {
		base[k] = v
	}
	return base
}

// What the page handler itself puts in render data passes the same check, for
// a signed-in and an anonymous viewer: a framework value that is not made for
// templates is replaced and logged, and a real request logs nothing.
func TestServedPageDataIsTemplateValuesOnly(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"m.html": `<page layout="none"><p id="m">[{{current_user}}]</p></page>`,
		"g.html": "---\nengine: gotmpl\nlayout: none\n---\n<p id=\"g\">[{{.current_user}}]</p>",
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	token := createCrudScopeSession(t, app, "viewer@example.com", "user", "", "")
	logged := captureLog(t, func() {
		for _, path := range []string{"/m", "/g"} {
			for _, tok := range []string{token, ""} {
				if out := ssrGet(mux, path, tok); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), ">[]</p>") {
					t.Errorf("GET %s: %d %s", path, out.Code, pageAuthored(out.Body.String()))
				}
			}
		}
	})
	if strings.Contains(logged, "page data") {
		t.Errorf("a served page's own render data was replaced:\n%s", logged)
	}

	session := &Session{ID: "sha256:feedface", UserID: 7, Email: "held@example.com", Role: "user", Roles: []string{"user"}}
	page := &Page{Route: "/x", File: "x.html", Layout: "none", RawHTML: `<page layout="none">[{{held}}]</page>`}
	logged = captureLog(t, func() {
		if out := ssrRender(t, app, page, session, map[string]any{"held": session}); !strings.Contains(out, "[]") {
			t.Errorf("held session rendered as %q", out)
		}
	})
	if !strings.Contains(logged, `page data "held"`) || strings.Contains(logged, "feedface") || strings.Contains(logged, "held@example.com") {
		t.Errorf("replacing a held session logged %q, want the key named and no session content", logged)
	}

	for _, v := range []any{nil, "", "x", true, 3, int64(3), 1.5, []byte("x"), time.Now(), map[string]any{}, []map[string]any{}, []any{}, []string{},
		map[string][]map[string]any{}, map[string]string{}, layoutPageHTML("x"), pageCurrentUser(session), pageCurrentUser(nil)} {
		if !templateValue(v) {
			t.Errorf("%T is refused as a template value", v)
		}
	}
	type recursive []recursive
	for _, v := range []any{session, *session, (*Session)(nil), app, []*Session{}, map[string]Session{}, func() {}, make(chan int), recursive{}} {
		if templateValue(v) {
			t.Errorf("%T is accepted as a template value", v)
		}
	}
}
