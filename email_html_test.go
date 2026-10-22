//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const emailInjectedMarkup = `<a href="https://phish.fixturemail.net/login">Your account is locked - sign in</a>`

// A hook email body is HTML, and the row values substituted into it were
// written verbatim. A visitor filling in a contact form could put markup in
// their name or message, and the owner (or another user) received it as part
// of an email from the app's own sender: a link, an image, a whole fake
// notice. A substituted value is text.
func TestHookEmailBodyKeepsAuthorMarkup(t *testing.T) {
	dir := t.TempDir()
	SetAppEnv(dir, "FOOTER_HTML", `<p class="footer">Fixture Co</p>`)
	if err := os.MkdirAll(filepath.Join(dir, "emails"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "emails", "lead.html"),
		[]byte(`<h1>New lead</h1><p>{{name}} wrote:</p><blockquote>{{message}}</blockquote>{{env.FOOTER_HTML}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{
		"name":    emailInjectedMarkup,
		"message": "Fish & chips <b>now</b>\nline two",
		"link":    "https://app.fixturemail.net/leads?id=7&tab=notes",
		"html":    "<table><tr><td>built by the app</td></tr></table>",
	}
	for name, hook := range map[string]*EmailHook{
		"template file":            {Template: "lead"},
		"inline body":              {Body: `<h1>New lead</h1><p>{{name}} wrote:</p><blockquote>{{message}}</blockquote>{{env.FOOTER_HTML}}`},
		"literal template as body": {Template: `<p>{{name}} wrote: {{message}}</p>{{env.FOOTER_HTML}}`},
	} {
		body := hookEmailBody(hook, row, dir)
		if strings.Contains(body, "<a href") || strings.Contains(body, "<b>now</b>") {
			t.Errorf("%s: a row value's markup reached the email body: %s", name, body)
		}
		for _, want := range []string{
			"&lt;a href=&#34;https://phish.fixturemail.net/login&#34;&gt;", "Fish &amp; chips &lt;b&gt;now&lt;/b&gt;",
			`<p class="footer">Fixture Co</p>`, // env is the author's own markup
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: body lacks %q: %s", name, want, body)
			}
		}
	}

	// A value in an attribute stays in the attribute and still works there.
	if got := hookEmailBody(&EmailHook{Body: `<a href="{{link}}">Open</a>`}, row, dir); got != `<a href="https://app.fixturemail.net/leads?id=7&amp;tab=notes">Open</a>` {
		t.Errorf("link attribute: %s", got)
	}
	// The author can still hand over markup: a body that IS one value, or a
	// value written with three braces.
	if got := hookEmailBody(&EmailHook{Body: "{{html}}"}, row, dir); got != row["html"] {
		t.Errorf("a body that is exactly one value changed: %s", got)
	}
	if got := hookEmailBody(&EmailHook{Body: "<div>{{{{html}}}}</div><p>{{name}}</p>"}, row, dir); !strings.HasPrefix(got, "<div><table><tr><td>built by the app</td></tr></table></div><p>&lt;a href") {
		t.Errorf("four-brace value: %s", got)
	}
	// Three braces keep formatting and drop what can run.
	row["rich"] = `<p>Hello <b>there</b></p><script>steal()</script><img src="x" onerror="steal()">`
	got := hookEmailBody(&EmailHook{Body: "<div>{{{rich}}}</div>"}, row, dir)
	if !strings.Contains(got, "<p>Hello <b>there</b></p>") || strings.Contains(got, "script") || strings.Contains(got, "onerror") {
		t.Errorf("three-brace value: %s", got)
	}
}

func TestFlowEmailHTMLBodyKeepsAuthorMarkup(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "FOOTER_HTML", `<p class="footer">Fixture Co</p>`)
	render := func(email *FlowEmail, data map[string]any, params map[string]string) (string, string) {
		t.Helper()
		if params == nil {
			params = map[string]string{}
		}
		ctx := &FlowContext{App: app, Data: data, Params: params}
		html, text, err := resolveEmailBody(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		return html, text
	}
	data := map[string]any{
		"name":    emailInjectedMarkup,
		"message": "Fish & chips <b>now</b>\nline two",
		"doc":     "<table><tr><td>built by a step</td></tr></table>",
		"notes":   "**bold** note",
	}

	html, _ := render(&FlowEmail{Html: `<p>{{name}} wrote:</p><blockquote>{{ message }}</blockquote>{{env.FOOTER_HTML}}`}, data, nil)
	if strings.Contains(html, "<a href") || strings.Contains(html, "<b>now</b>") {
		t.Errorf("a value's markup reached the email body: %s", html)
	}
	for _, want := range []string{"&lt;a href=", "Fish &amp; chips &lt;b&gt;now&lt;/b&gt;", `<p class="footer">Fixture Co</p>`} {
		if !strings.Contains(html, want) {
			t.Errorf("body lacks %q: %s", want, html)
		}
	}

	// A `:param` in the body is a value too.
	if html, _ := render(&FlowEmail{Html: `<p>Hello :who</p>`}, map[string]any{}, map[string]string{"who": "<i>x</i>"}); html != "<p>Hello &lt;i&gt;x&lt;/i&gt;</p>" {
		t.Errorf("colon parameter: %s", html)
	}

	for name, tc := range map[string]struct{ tmpl, want string }{
		// The author's ways to pass markup through.
		"body is one value":   {"{{doc}}", "<table><tr><td>built by a step</td></tr></table>"},
		"raw pipe":            {"<div>{{ doc | raw }}</div>", "<div><table><tr><td>built by a step</td></tr></table></div>"},
		"markdown pipe":       {"<div>{{ notes | markdown_inline }}</div>", "<div><strong>bold</strong> note</div>"},
		"line breaks kept":    {"<p>{{ message | nl2br }}</p>", "<p>Fish &amp; chips &lt;b&gt;now&lt;/b&gt;<br>line two</p>"},
		"fallback then break": {"<p>{{ missing || message | nl2br }}</p>", "<p>Fish &amp; chips &lt;b&gt;now&lt;/b&gt;<br>line two</p>"},
		// Ordinary values render as they always did.
		"plain text":   {"<p>Hi {{who}}</p>", "<p>Hi Ada</p>"},
		"numbers":      {"<p>{{count}} new</p>", "<p>3 new</p>"},
		"missing nil":  {"<p>[{{nothing}}]</p>", "<p>[]</p>"},
		"pipe applied": {"<p>{{ who | upper }}</p>", "<p>ADA</p>"},
	} {
		d := map[string]any{"who": "Ada", "count": 3, "nothing": nil}
		for k, v := range data {
			d[k] = v
		}
		if got, _ := render(&FlowEmail{Html: tc.tmpl}, d, nil); got != tc.want {
			t.Errorf("%s: %q rendered %q, want %q", name, tc.tmpl, got, tc.want)
		}
	}

	// The plain-text part has no markup to protect: unchanged.
	if _, text := render(&FlowEmail{Text: "{{name}} & {{message}}"}, data, nil); text != emailInjectedMarkup+" & Fish & chips <b>now</b>\nline two" {
		t.Errorf("text part changed: %q", text)
	}
}
