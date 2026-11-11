//go:build !cli

package main

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// Every form a mustache page can read `current_user` in. The last element
// prints the viewer's address through a documented page value.
const currentUserMustachePage = `<page title="Viewer" layout="none">
<p id="plain">[{{current_user}}]</p>
<p id="triple">[{{{current_user}}}]</p>
<p id="quad">[{{{{current_user}}}}]</p>
<p id="json">[{{current_user | json}}]</p>
<p id="upper">[{{current_user | upper}}]</p>
<p id="dot">[{{current_user.Email}}|{{current_user.email}}|{{current_user.ID}}]</p>
<p id="attr" title="{{current_user}}" data-x={{current_user}}>attr</p>
<a id="href" href="/x?u={{current_user}}">link</a>
<script>var cu = {{current_user}}; var cuj = {{current_user | json}}; var cus = "{{current_user}}";</script>
<p id="section">[{{#current_user}}SIGNED-IN{{/current_user}}]</p>
<p id="inverted">[{{^current_user}}SIGNED-OUT{{/current_user}}]</p>
<p id="if">[{{#if current_user}}IF-IN{{else}}IF-OUT{{/if}}]</p>
<p id="user">[{{#user}}USER-IN {{email}}{{/user}}]</p>
<p id="documented">[{{user_id}}|{{user_email}}|{{user_role}}|{{user.email}}]</p>
<query sql="SELECT COUNT(*) AS n FROM notes WHERE title = {{current_user}}" as="q"><p id="sql">[{{n}}]</p></query>
</page>`

// The same for a gotmpl page, where a template reaches every exported field
// and method of what it is handed.
const currentUserGotmplPage = "---\nengine: gotmpl\nlayout: none\ntitle: Viewer\n---\n" +
	`<p id="plain">[{{.current_user}}]</p>
<p id="v">[{{printf "%v" .current_user}}]</p>
<p id="plusv">[{{printf "%+v" .current_user}}]</p>
<p id="sharpv">[{{printf "%#v" .current_user}}]</p>
<p id="s">[{{printf "%s" .current_user}}]</p>
<p id="d">[{{printf "%d" .current_user}}]</p>
<p id="tojson">[{{toJson .current_user}}]</p>
<p id="tostring">[{{toString .current_user}}]</p>
<p id="attr" title="{{.current_user}}">attr</p>
<script>var cu = {{.current_user}};</script>
<p id="if">[{{if .current_user}}IF-IN{{else}}IF-OUT{{end}}]</p>
<p id="with">[{{with .current_user}}WITH-IN{{else}}WITH-OUT{{end}}]</p>
<p id="documented">[{{.user_id}}|{{.user_email}}|{{.user_role}}]</p>
`

var pageElementRe = regexp.MustCompile(`(?s)<p id="([a-z]+)"[^>]*>(.*?)</p>`)

// pageElements maps each <p id="x"> of a rendered page to its content.
func pageElements(body string) map[string]string {
	out := map[string]string{}
	for _, m := range pageElementRe.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// sessionDumpMarkers are strings a printed session carries: the stored
// session key hash, Go's struct syntax and the session's field names.
var sessionDumpMarkers = []string{"sha256:", "&amp;{", "&{", "map[]", "main.", "CredentialScopes", "ImpersonatorEmail", "GlobalAdmin", "<nil>", "&lt;nil&gt;", "no value"}

func assertNoSessionDump(t *testing.T, label, body string) {
	t.Helper()
	for _, marker := range sessionDumpMarkers {
		if strings.Contains(body, marker) {
			t.Errorf("%s: page contains %q:\n%s", label, marker, pageAuthored(body))
		}
	}
}

// pageAuthored is the part of a rendered page the test page wrote (from its
// first element on), for failure messages.
func pageAuthored(body string) string {
	if i := strings.Index(body, `<p id="`); i >= 0 {
		body = body[i:]
	}
	if len(body) > 3000 {
		body = body[:3000] + " ..."
	}
	return body
}

// `current_user` in a mustache page is a signed-in test and nothing else: no
// form of it prints the session (the stored session key hash, the user id,
// address and roles were written into the page), and its sections follow the
// viewer's sign-in state.
func TestCurrentUserPrintsNothingInMustachePages(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{"viewer.html": currentUserMustachePage})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	const email = "viewer@example.com"
	token := createCrudScopeSession(t, app, email, "user", "", "")

	signedIn := ssrGet(mux, "/viewer", token)
	if signedIn.Code != http.StatusOK {
		t.Fatalf("signed-in GET /viewer: %d\n%s", signedIn.Code, signedIn.Body.String())
	}
	body := signedIn.Body.String()
	assertNoSessionDump(t, "signed in", body)
	got := pageElements(body)
	for id, want := range map[string]string{
		"plain": "[]", "triple": "[]", "quad": "[]", "dot": "[||]", "attr": "attr",
		"section": "[SIGNED-IN]", "inverted": "[]", "if": "[IF-IN]",
		"user":       "[USER-IN " + email + "]",
		"documented": "[1|" + email + "|user|" + email + "]",
		"sql":        "[0]",
	} {
		if got[id] != want {
			t.Errorf("signed in, %s = %q, want %q", id, got[id], want)
		}
	}
	// The address is on the page only where a documented value printed it.
	if n := strings.Count(body, email); n != 3 {
		t.Errorf("signed in: the viewer's address appears %d times, want 3 (user.email twice, user_email once):\n%s", n, pageAuthored(body))
	}
	for _, want := range []string{`title=""`, `href="/x?u="`, `var cus = "";`} {
		if !strings.Contains(body, want) {
			t.Errorf("signed in: page lacks %s:\n%s", want, pageAuthored(body))
		}
	}

	anonymous := ssrGet(mux, "/viewer", "")
	if anonymous.Code != http.StatusOK {
		t.Fatalf("anonymous GET /viewer: %d\n%s", anonymous.Code, anonymous.Body.String())
	}
	body = anonymous.Body.String()
	assertNoSessionDump(t, "anonymous", body)
	got = pageElements(body)
	for id, want := range map[string]string{
		"plain": "[]", "triple": "[]", "quad": "[]", "upper": "[]", "dot": "[||]",
		"section": "[]", "inverted": "[SIGNED-OUT]", "if": "[IF-OUT]",
		"user": "[]", "documented": "[|||]", "sql": "[0]",
	} {
		if got[id] != want {
			t.Errorf("anonymous, %s = %q, want %q", id, got[id], want)
		}
	}
}

// A gotmpl page reads `.current_user` the same way: it prints nothing through
// any verb or helper, and `if` / `with` follow the viewer's sign-in state.
func TestCurrentUserPrintsNothingInGotmplPages(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"viewer.html": currentUserGotmplPage,
		"fields.html": "---\nengine: gotmpl\nlayout: none\n---\n" +
			`<p id="fields">[{{with .current_user}}{{.UserID}}|{{.Email}}|{{.Role}}{{end}}]</p>`,
		"key.html":     "---\nengine: gotmpl\nlayout: none\n---\n<p id=\"key\">[{{.current_user.ID}}]</p>",
		"method.html":  "---\nengine: gotmpl\nlayout: none\n---\n<p id=\"method\">[{{.current_user.IsAdmin}}]</p>",
		"scopes.html":  "---\nengine: gotmpl\nlayout: none\n---\n<p id=\"scopes\">[{{.current_user.CredentialScopes}}]</p>",
		"partial.html": "---\nengine: gotmpl\nlayout: none\n---\n{{define \"who\"}}<p id=\"partial\">[{{.current_user}}]</p>{{end}}{{template \"who\" .}}",
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	const email = "viewer@example.com"
	token := createCrudScopeSession(t, app, email, "user", "", "")

	signedIn := ssrGet(mux, "/viewer", token)
	if signedIn.Code != http.StatusOK {
		t.Fatalf("signed-in GET /viewer: %d\n%s", signedIn.Code, signedIn.Body.String())
	}
	body := signedIn.Body.String()
	assertNoSessionDump(t, "signed in", body)
	got := pageElements(body)
	for id, want := range map[string]string{
		"plain": "[]", "v": "[]", "plusv": "[]", "sharpv": "[]", "s": "[]", "d": "[]",
		"tojson": "[true]", "tostring": "[]", "attr": "attr",
		"if": "[IF-IN]", "with": "[WITH-IN]",
		"documented": "[1|" + email + "|user]",
	} {
		if got[id] != want {
			t.Errorf("signed in, %s = %q, want %q", id, got[id], want)
		}
	}
	if n := strings.Count(body, email); n != 1 {
		t.Errorf("signed in: the viewer's address appears %d times, want 1 (user_email):\n%s", n, pageAuthored(body))
	}
	if !strings.Contains(body, `title=""`) || !strings.Contains(body, "var cu =  true ;") {
		t.Errorf("signed in: attribute or script form is not the empty value / true:\n%s", pageAuthored(body))
	}

	anonymous := ssrGet(mux, "/viewer", "")
	if anonymous.Code != http.StatusOK {
		t.Fatalf("anonymous GET /viewer: %d\n%s", anonymous.Code, anonymous.Body.String())
	}
	body = anonymous.Body.String()
	assertNoSessionDump(t, "anonymous", body)
	got = pageElements(body)
	for id, want := range map[string]string{
		"plain": "[]", "v": "[]", "plusv": "[]", "s": "[]", "tostring": "[]",
		"if": "[IF-OUT]", "with": "[WITH-OUT]",
	} {
		if got[id] != want {
			t.Errorf("anonymous, %s = %q, want %q", id, got[id], want)
		}
	}

	// The three values a page already has by name (user_id, user_email,
	// user_role) stay readable as fields, so a page that read them this way
	// keeps rendering.
	fields := ssrGet(mux, "/fields", token)
	if fields.Code != http.StatusOK || pageElements(fields.Body.String())["fields"] != "[1|"+email+"|user]" {
		t.Errorf("signed in, fields = %d %q", fields.Code, pageAuthored(fields.Body.String()))
	}
	if out := ssrGet(mux, "/fields", ""); out.Code != http.StatusOK || pageElements(out.Body.String())["fields"] != "[]" {
		t.Errorf("anonymous, fields = %d %q", out.Code, pageAuthored(out.Body.String()))
	}
	// A partial reads the same data.
	if out := ssrGet(mux, "/partial", token); out.Code != http.StatusOK || pageElements(out.Body.String())["partial"] != "[]" {
		t.Errorf("signed in, partial = %d %q", out.Code, pageAuthored(out.Body.String()))
	}
	// Nothing else of the session is there: its stored key, its other
	// fields and its methods stop the page instead of printing.
	for _, path := range []string{"/key", "/method", "/scopes"} {
		out := ssrGet(mux, path, token)
		if out.Code == http.StatusOK {
			t.Errorf("GET %s rendered a session field or method: %s", path, pageAuthored(out.Body.String()))
		}
		assertNoSessionDump(t, path, out.Body.String())
	}
}
