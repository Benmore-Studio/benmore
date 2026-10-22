//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hook email's body is HTML, but row values were substituted into it
// verbatim: a submitted name of `<a href="https://evil.example">Reset your
// password</a>` became a real link in the mail the app sends to its admin.
// Values are escaped for where they land; `{{{x}}}` (sanitized HTML) and
// `{{{{x}}}}` (raw) are the explicit ways to send markup.
func TestHookEmailBodyEscapesRowValues(t *testing.T) {
	dir := t.TempDir()
	storeAppEnv(dir, map[string]string{"APP_URL": "https://app.example.com/?a=1&b=2"})
	t.Cleanup(func() { storeAppEnv(dir, nil) })
	row := map[string]any{
		"name":  `<a href="https://evil.example">Reset your password</a><img src=x onerror=alert(1)>`,
		"site":  "javascript:alert(document.domain)",
		"note":  "Tom & Jerry <3",
		"plain": "Ada Lovelace",
		"count": 3,
		"html":  `<b>bold</b><script>alert(1)</script>`,
	}
	body := hookEmailBody(&EmailHook{Body: `<p>From {{name}} ({{plain}}, {{count}})</p><p>{{note}}</p><a href="{{site}}">site</a><a href="{{env.APP_URL}}">app</a> {{missing}}`}, row, dir)
	for _, bad := range []string{`<a href="https://evil.example">`, "<img src=x", "onerror=alert(1)>", `href="javascript:`} {
		if strings.Contains(body, bad) {
			t.Errorf("row value reached the email as markup (%q): %s", bad, body)
		}
	}
	for _, want := range []string{"&lt;a href=", "Tom &amp; Jerry &lt;3", "(Ada Lovelace, 3)", `<a href="https://app.example.com/?a=1&b=2">app</a>`, "{{missing}}"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in: %s", want, body)
		}
	}

	// The emails/<name>.html template goes through the same rendering.
	if err := os.MkdirAll(filepath.Join(dir, "emails"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "emails", "contact.html"), []byte(`<h1>{{name}}</h1><div>{{{html}}}</div><div>{{{{html}}}}</div>`), 0o644); err != nil {
		t.Fatal(err)
	}
	body = hookEmailBody(&EmailHook{Template: "contact"}, row, dir)
	if strings.Contains(body, "<h1><a href") {
		t.Errorf("template file substituted a row value as markup: %s", body)
	}
	// {{{x}}} keeps safe HTML and drops script; {{{{x}}}} is the raw opt-in.
	if !strings.Contains(body, "<div><b>bold</b></div>") {
		t.Errorf("{{{html}}} should be sanitized HTML: %s", body)
	}
	if !strings.Contains(body, `<div><b>bold</b><script>alert(1)</script></div>`) {
		t.Errorf("{{{{html}}}} should be the raw value: %s", body)
	}
}

// The same holds for a flow email's inline `html:`; `text:` is plain text
// and stays verbatim, and a template file was already escaped.
func TestFlowEmailInlineHTMLEscapesValues(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{"note": `<script>alert(1)</script>`}}
	ctx.Data["name"] = `<a href="https://evil.example">Reset</a>`
	ctx.Data["link"] = "javascript:alert(1)"
	ctx.Data["rich"] = `<b>bold</b><script>x()</script>`
	ctx.Data["user"] = map[string]any{"name": "Ada & Co"}

	html, text, err := resolveEmailBody(ctx, &FlowEmail{
		Html: `<p>Hi {{name}} / {{user.name}}</p><p>:note</p><a href="{{link}}">go</a><div>{{{rich}}}</div><div>{{{{rich}}}}</div>`,
		Text: `Hi {{name}} :note`,
	})
	if err != nil {
		t.Fatalf("resolveEmailBody: %v", err)
	}
	for _, bad := range []string{`<a href="https://evil.example">`, "<p><script>alert(1)</script></p>", `href="javascript:`} {
		if strings.Contains(html, bad) {
			t.Errorf("value reached the email HTML as markup (%q): %s", bad, html)
		}
	}
	for _, want := range []string{"&lt;a href=", "Ada &amp; Co", "&lt;script&gt;alert(1)&lt;/script&gt;", "<div><b>bold</b></div>", "<div><b>bold</b><script>x()</script></div>"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q in: %s", want, html)
		}
	}
	if text != `Hi <a href="https://evil.example">Reset</a> <script>alert(1)</script>` {
		t.Errorf("text body must stay verbatim plain text, got %q", text)
	}
	if len(ctx.MissingRefs) != 0 {
		t.Errorf("raw/sanitized placeholders must resolve, missing refs: %v", ctx.MissingRefs)
	}
}

// An attachment's filename is written inside a quoted MIME parameter; a
// quote in it closed the parameter and added others.
func TestEmailAttachmentFilenameCannotInjectParameters(t *testing.T) {
	raw, err := buildRawMIMEMessage("from@example.com", "to@example.com", "", "s", "", "", false, "", "<p>x</p>", "",
		[]EmailAttachment{{Filename: "report.pdf\"; filename=\"evil.exe\r\nX-Injected: 1", Content: "aGVsbG8="}})
	if err != nil {
		t.Fatal(err)
	}
	msg := string(raw)
	if strings.Contains(msg, `filename="evil.exe"`) || strings.Contains(msg, "\nX-Injected:") {
		t.Fatalf("attachment filename injected a MIME parameter or header:\n%s", msg)
	}
	if !strings.Contains(msg, `Content-Disposition: attachment; filename="report.pdf`) {
		t.Fatalf("attachment part missing:\n%s", msg)
	}
}

// A notification's link is a URL the client puts in an href; a hook fills it
// from row values. A script-capable scheme is never stored.
func TestNotificationLinkDropsScriptSchemes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureNotificationsTable(app.DB)
	hook := &NotifyHook{UserID: "{{owner}}", Title: "New {{name}}", Body: "b", Link: "{{url}}"}
	for url, want := range map[string]string{
		"javascript:alert(document.cookie)": "",
		" JavaScript:alert(1)":              "",
		"data:text/html,<script>1</script>": "",
		"/orders/7":                         "/orders/7",
		"https://example.com/x?a=1":         "https://example.com/x?a=1",
		"mailto:help@example.com":           "mailto:help@example.com",
	} {
		mustExec(t, app.DB, "DELETE FROM _benmore_notifications")
		if err := executeNotifyHook(app.DB, hook, map[string]any{"owner": 7, "name": "x", "url": url}, app.Dir); err != nil {
			t.Fatalf("%q: %v", url, err)
		}
		var link string
		if err := app.DB.QueryRow("SELECT COALESCE(link, '') FROM _benmore_notifications").Scan(&link); err != nil {
			t.Fatalf("%q: notification not stored: %v", url, err)
		}
		if link != want {
			t.Errorf("link for %q stored as %q, want %q", url, link, want)
		}
	}
}

// The `${{ }}` spelling keeps its brace count through the flow loader, so
// `${{{ }}}` and `${{{{ }}}}` reach the email renderer as the sanitized and
// raw forms with their refs translated like any other.
func TestFlowEmailHTMLBraceFormsSurviveNormalization(t *testing.T) {
	got := normalizeGHARefs(`<p>${{ steps.u.outputs.name }}</p>${{{ steps.build.outputs.html }}}${{{{ steps.build.outputs.html | default:'' }}}}`)
	want := `<p>{{u.name}}</p>{{{build.html}}}{{{{build.html | default:''}}}}`
	if got != want {
		t.Fatalf("normalizeGHARefs = %q, want %q", got, want)
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	ctx.Data["u"] = map[string]any{"name": "A<b>"}
	ctx.Data["build"] = map[string]any{"html": `<i>x</i><script>1</script>`}
	html, _, err := resolveEmailBody(ctx, &FlowEmail{Html: got})
	if err != nil || html != `<p>A&lt;b&gt;</p><i>x</i><i>x</i><script>1</script>` {
		t.Fatalf("html = %q err = %v", html, err)
	}
}
