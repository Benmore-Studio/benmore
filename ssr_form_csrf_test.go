//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var injectedCSRFValueRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

// Only forms that send a request body get the CSRF token. A GET form (an
// explicit method="get", no method at all, hx-get) puts its fields in the
// URL, so a token there would reach browser history, logs and Referer
// headers; InjectCSRF used to add it to every <form>.
func TestCSRFInjectionOnlyInBodyForms(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{`<form method="get" action="/events">`, false},
		{`<form method=GET action="/events">`, false},
		{`<form action="/search">`, false},
		{`<form>`, false},
		{`<form hx-get="/partials/results" hx-target="#r">`, false},
		{`<form method="dialog">`, false},
		{`<form data-method="post">`, false},
		{`<form method="POST" action="/api/rsvp">`, true},
		{`<form method = 'post' action="/x">`, true},
		{`<form method=post>`, true},
		{`<form hx-post="/api/notes">`, true},
		{`<form data-hx-patch="/api/notes/1">`, true},
		{`<form hx-delete="/api/notes/1">`, true},
		{`<form method="get" hx-put="/api/notes/1">`, true},
		{`<form :create="notes">`, true},
	}
	probe := httptest.NewRequest(http.MethodPost, "/x", nil)
	for _, tc := range cases {
		html := tc.tag + `<input name="q"><button>Go</button></form>`
		for name, out := range map[string]string{
			"InjectCSRF":           InjectCSRF(html),
			"injectCSRFFormFields": string(injectCSRFFormFields([]byte(html), "")),
		} {
			m := injectedCSRFValueRe.FindStringSubmatch(out)
			if got := m != nil; got != tc.want {
				t.Errorf("%s(%s): token injected = %v, want %v: %s", name, tc.tag, got, tc.want, out)
				continue
			}
			if m != nil && !validateCSRFToken(probe, m[1]) {
				t.Errorf("%s(%s): injected token does not validate", name, tc.tag)
			}
		}
	}
	// A page with both: only the POST form carries the token.
	out := InjectCSRF(`<form method="get" action="/events"><input name="city"></form><form method="post" action="/api/rsvp"><button>RSVP</button></form>`)
	get, post, _ := strings.Cut(out, `<form method="post"`)
	if strings.Contains(get, "_csrf") || !strings.Contains(post, `name="_csrf"`) {
		t.Fatalf("token placement wrong: %s", out)
	}
}

// The round-1105 events page: a gotmpl GET filter form beside a POST form.
// The filter form is served without a token, so submitting it lands on a
// clean /events?city=... (200) instead of a URL carrying _csrf that the page
// handler strips with a 303 and an AUTH WARNING log line.
func TestServedGetFilterFormCarriesNoToken(t *testing.T) {
	app := ssrTestApp(t)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'Austin'), (1, 'Boston')`)
	ssrLoadPages(t, app, map[string]string{
		"events.html": "---\nengine: gotmpl\ntitle: Upcoming events\nqueries:\n  events: \"SELECT title FROM notes WHERE (:param_city IS NULL OR title = :param_city) ORDER BY id\"\n---\n" +
			`<form method="get" action="/events" id="filter"><input name="city"><button type="submit">Filter</button></form>` +
			`<form method="post" action="/api/notes" id="add"><input name="title"><button>Add</button></form>` +
			`{{range .events}}<h2>{{.title}}</h2>{{end}}`,
		"about.html": `<form method="get" action="/about" id="m-filter"><input name="q"></form><p>about-page</p>`,
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")

	w := ssrGet(mux, "/events", "")
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("/events: %d %s", w.Code, body)
	}
	filterStart := strings.Index(body, `id="filter"`)
	addStart := strings.Index(body, `id="add"`)
	if filterStart < 0 || addStart < filterStart {
		t.Fatalf("forms missing: %s", body)
	}
	if strings.Contains(body[filterStart:addStart], "_csrf") {
		t.Fatalf("GET filter form carries the CSRF token: %s", body[filterStart:addStart])
	}
	m := injectedCSRFValueRe.FindStringSubmatch(body[addStart:])
	if m == nil || !validateCSRFToken(httptest.NewRequest(http.MethodPost, "/api/notes", nil), m[1]) {
		t.Fatalf("POST form lost its valid token: %s", body[addStart:])
	}
	about := ssrGet(mux, "/about", "").Body.String()
	start := strings.Index(about, `id="m-filter"`)
	end := strings.Index(about, "about-page")
	if start < 0 || end < start || strings.Contains(about[start:end], "_csrf") {
		t.Fatalf("mustache GET form carries the CSRF token: %s", about)
	}

	// Submitting the filter form: the browser sends exactly its fields.
	w = ssrGet(mux, "/events?city=Austin", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<h2>Austin</h2>") || strings.Contains(w.Body.String(), "<h2>Boston</h2>") {
		t.Fatalf("filtered page: %d %s", w.Code, w.Body.String())
	}
}
