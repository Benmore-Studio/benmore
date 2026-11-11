//go:build !cli

package main

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// pathParamTestApp is an app with two public SSR pages that take a path
// parameter (a gotmpl record page and a mustache page), a public flat page,
// and seo.url set so canonical links are emitted.
func pathParamTestApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app := ssrTestApp(t)
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"read": "anon"}}}
	app.Design = &DesignConfig{
		SEO:    map[string]string{"url": "https://site.example", "site_name": "Site"},
		Colors: map[string]string{},
		PWA:    map[string]string{"name": "Site", "offline": "true"},
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (id, user_id, title, body) VALUES (1, 1, 'first-note', 'a'), (2, 1, 'second-note', 'b')`)
	ssrLoadPages(t, app, map[string]string{
		"note-:id.html": "---\nengine: gotmpl\nqueries:\n  note: \"SELECT id, title FROM notes WHERE id = :id LIMIT 1\"\n---\n" +
			`<h1 id="t">{{.note.title}}</h1><p id="p">param={{.param_id}}</p>`,
		"speaker-:name.html":    `<page><p id="s">speaker={{param_name}}</p></page>`,
		"note-:id-history.html": "---\nengine: gotmpl\ntitle: Note history\n---\n<p id=\"h\">history={{.param_id}}</p>",
		"card-:id.html":         `<page title="Card"><query sql="SELECT title FROM notes WHERE id = {{param_id}}" as="card"><p id="c">card={{title}}</p></query></page>`,
		"about.html":            `<page title="About us"><p>about</p></page>`,
		"index.html":            `<page title="Home"><p>home</p></page>`,
	})
	return app, buildAppMux(app, false, "https://site.example")
}

// A root page named `name-:param.html` serves /name/:param and binds the
// path value: `:param` and `:param_<param>` in queries, {{.param_<param>}} /
// {{param_<param>}} in the template. It used to serve only the literal
// /name-:param (a 500 for a gotmpl query, an empty value for mustache).
func TestSSRPathParamPageServesAndBinds(t *testing.T) {
	_, mux := pathParamTestApp(t)

	for _, tc := range []struct{ path, want string }{
		{"/note/1", `<h1 id="t">first-note</h1><p id="p">param=1</p>`},
		{"/note/2", `<h1 id="t">second-note</h1><p id="p">param=2</p>`},
		// The path value wins over a query value of the same name.
		{"/note/2?id=1", `<h1 id="t">second-note</h1><p id="p">param=2</p>`},
		// No such record: the page renders its empty state, not a 500.
		{"/note/99", `<h1 id="t"></h1><p id="p">param=99</p>`},
		{"/speaker/ada", `<p id="s">speaker=ada</p>`},
		// A mustache <query> binds the path value as an argument.
		{"/card/2", `<p id="c">card=second-note</p>`},
		{"/note/1/history", `<p id="h">history=1</p>`},
	} {
		w := ssrGet(mux, tc.path, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("GET %s: %d, want %q in:\n%s", tc.path, w.Code, tc.want, w.Body.String())
		}
	}

	// The <query> binds the value as an argument, never as SQL text: no row
	// matches the text "2 OR 1=1", so the block renders once without a row.
	if w := ssrGet(mux, "/card/2%20OR%201=1", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<p id="c">card=</p>`) {
		t.Fatalf("path value reached the SQL text: %d %s", w.Code, w.Body.String())
	}

	// Path values are escaped like any other request value.
	w := ssrGet(mux, "/speaker/%3Cscript%3Ex%3C%2Fscript%3E", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<script>x</script>") ||
		!strings.Contains(w.Body.String(), "speaker=&lt;script&gt;x&lt;/script&gt;") {
		t.Fatalf("mustache path value not escaped: %d %s", w.Code, w.Body.String())
	}
	w = ssrGet(mux, "/note/%3Cb%3E", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "param=<b>") ||
		!strings.Contains(w.Body.String(), "param=&lt;b&gt;") {
		t.Fatalf("gotmpl path value not escaped: %d %s", w.Code, w.Body.String())
	}

	// The filename itself is no longer a route, and no request reaches the
	// page without its parameter; none of these may answer 500.
	for _, path := range []string{"/note-:id", "/note-1", "/note/", "/speaker", "/speaker/"} {
		w := ssrGet(mux, path, "")
		if w.Code == http.StatusInternalServerError || w.Code == http.StatusOK {
			t.Fatalf("GET %s: %d, want no page:\n%s", path, w.Code, w.Body.String())
		}
	}
}

// Pages with path parameters have no single URL to list: sitemap.xml,
// llms.txt, feed.xml and the service worker's precache leave them out.
func TestPathParamPagesAreNotListed(t *testing.T) {
	app, mux := pathParamTestApp(t)
	for _, path := range []string{"/sitemap.xml", "/llms.txt", "/feed.xml"} {
		w := ssrGet(mux, path, "")
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "https://site.example/about") {
			t.Fatalf("%s: %d, public page missing:\n%s", path, w.Code, body)
		}
		for _, leaked := range []string{"note", "speaker", ":id", ":name"} {
			if strings.Contains(body, leaked) {
				t.Fatalf("%s lists a path-parameter page (%q):\n%s", path, leaked, body)
			}
		}
	}
	// The service worker precaches no page routes (only its offline page),
	// so a parameter route can never appear there either.
	sw := GenerateServiceWorker(app)
	if strings.Contains(sw, ":id") || strings.Contains(sw, ":name") {
		t.Fatalf("service worker precaches a path-parameter route:\n%s", sw)
	}
}

var canonicalLinkRe = regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)
var ogURLRe = regexp.MustCompile(`<meta property="og:url" content="([^"]*)">`)
var titleTagRe = regexp.MustCompile(`<title>([^<]*)</title>`)

func pageHead(t *testing.T, mux *http.ServeMux, path string) (canonical, ogURL, title string) {
	t.Helper()
	w := ssrGet(mux, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	body := w.Body.String()
	if m := canonicalLinkRe.FindStringSubmatch(body); m != nil {
		canonical = m[1]
	}
	if m := ogURLRe.FindStringSubmatch(body); m != nil {
		ogURL = m[1]
	}
	if m := titleTagRe.FindStringSubmatch(body); m != nil {
		title = m[1]
	}
	return
}

// A path-parameter page's canonical link and og:url are the requested
// record's own URL (path values re-escaped, no query string), so records do
// not collapse into one canonical. Other pages keep their route.
func TestPathParamPageCanonicalIsPerRecord(t *testing.T) {
	_, mux := pathParamTestApp(t)
	for _, tc := range []struct{ path, want string }{
		{"/note/1", "https://site.example/note/1"},
		{"/note/2?id=1&utm_source=x", "https://site.example/note/2"},
		{"/note/2/history", "https://site.example/note/2/history"},
		{"/speaker/ada%20lovelace", "https://site.example/speaker/ada%20lovelace"},
		{`/speaker/%22%3E%3Cscript%3E`, "https://site.example/speaker/%22%3E%3Cscript%3E"},
		{"/about?x=1", "https://site.example/about"},
		{"/", "https://site.example/"},
	} {
		canonical, ogURL, _ := pageHead(t, mux, tc.path)
		if canonical != tc.want || ogURL != tc.want {
			t.Fatalf("GET %s: canonical %q og:url %q, want %q", tc.path, canonical, ogURL, tc.want)
		}
	}
}

// title: is fixed text: a path-parameter page shows it for every record. A
// page with no title gets one from its literal route segments, never the
// parameter placeholder.
func TestPathParamPageTitle(t *testing.T) {
	_, mux := pathParamTestApp(t)
	for _, tc := range []struct{ path, want string }{
		{"/note/1", "Note"},
		{"/note/2", "Note"},
		{"/note/1/history", "Note history"},
		{"/speaker/ada", "Speaker"},
		{"/about", "About us"},
	} {
		if _, _, title := pageHead(t, mux, tc.path); title != tc.want {
			t.Fatalf("GET %s: title %q, want %q", tc.path, title, tc.want)
		}
	}
}

// The filename-to-route mapping: `-:name` parts are path parameters and the
// hyphens beside them separate segments. A `:` that is not a well-formed
// parameter keeps the literal route it always had (the write gate refuses it).
func TestPageRouteForFile(t *testing.T) {
	for _, tc := range []struct{ file, route string }{
		{"index.html", "/"},
		{"about.html", "/about"},
		{"about-us.html", "/about-us"},
		{"event-:id.html", "/event/:id"},
		{"my-events-:id.html", "/my-events/:id"},
		{"event-:id-rsvps.html", "/event/:id/rsvps"},
		{"org-:org-team-:member_id.html", "/org/:org/team/:member_id"},
		{"a-:x-:y.html", "/a/:x/:y"},
		// Malformed: literal, as before.
		{":id.html", "/:id"},
		{"a:b.html", "/a:b"},
		{"event-:1d.html", "/event-:1d"},
		{"event-:id-:id.html", "/event-:id-:id"},
		{"event--:id.html", "/event--:id"},
		{"event-:id-.html", "/event-:id-"},
		{"event-:x.y.html", "/event-:x.y"},
	} {
		if got := pageRouteForFile(tc.file); got != tc.route {
			t.Errorf("%s: route %q, want %q", tc.file, got, tc.route)
		}
	}
	for route, want := range map[string]string{
		"/about": "About", "/about-us": "About-Us", "/event/:id": "Event",
		"/event/:id/rsvps": "Event Rsvps", "/org/:org/team/:id": "Org Team",
	} {
		if got := pageDefaultTitle(route); got != want {
			t.Errorf("default title of %s: %q, want %q", route, got, want)
		}
	}
}

// The write gate (and `benmore check`, which runs the same per-file
// validator) refuses a root page filename whose `:` is not a path parameter,
// and a parameter page whose route another page or a flow already answers,
// since registration would skip it and it would never be served.
func TestPageRouteFilenameWriteGate(t *testing.T) {
	dir := routeFixtureDir(t)
	const body = "<page><p>x</p></page>\n"
	writeTestFile(t, dir, "note-:id.html", body)
	writeTestFile(t, dir, "flows/report.yaml", routeFixtureFlow("GET", "/report/:id"))

	for _, tc := range []struct{ file, want string }{
		{":id.html", "must start with a fixed part"},
		{"a:b.html", "`:` may only start a path parameter"},
		{"event-:1d.html", "must be a name of letters, digits and _"},
		{"event-:id-:id.html", `":id" appears twice`},
		{"event--:id.html", "must separate two parts"},
		{"note-:slug.html", "collides with the page note-:id.html (GET /note/{id})"},
		{"report-:key.html", `collides with flow "report" (GET /report/{id})`},
	} {
		msg := ValidateOnWriteIn(dir, tc.file, body)
		if !strings.Contains(msg, "page route: "+tc.file) || !strings.Contains(msg, tc.want) {
			t.Fatalf("%s: refusal lacks %q:\n%s", tc.file, tc.want, msg)
		}
	}
	// Well-formed, unclaimed routes pass, and so does rewriting the page that
	// already holds a route. Files outside the app root are not pages.
	for _, file := range []string{"event-:id.html", "event-:id-rsvps.html", "note-:id.html", "note-view-:slug.html", "about.html", "static/x-:id.html", "partials/a:b.html"} {
		if msg := ValidateOnWriteIn(dir, file, body); strings.Contains(msg, "page route") {
			t.Fatalf("%s refused:\n%s", file, msg)
		}
	}
	report := RunCompleteCheck(dir, "")
	for _, f := range report.Findings {
		if strings.Contains(f.Message, "page route") {
			t.Fatalf("check flags a valid page: %+v", f)
		}
	}
	writeTestFile(t, dir, "note-:slug.html", body)
	report = RunCompleteCheck(dir, "")
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, "page route: note-:slug.html") {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check missed the colliding page: %+v", report.Findings)
	}
}
