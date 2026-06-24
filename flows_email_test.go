package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the v2.7.165 email-step fix: pre-fix, the flow
// `run: email` step dropped every body-carrying key (html/text/body),
// ignored `data:`, and resolved `template:` only as a literal app-root
// path - so the provider request carried no html/text at all and Resend
// rejected it with 422 "Missing 'html' or 'text' field".

func TestResolveEmailBody_InlineHTML(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	ctx.Data["user"] = map[string]any{"name": "Ada"}

	html, text, err := resolveEmailBody(ctx, &FlowEmail{Html: "<p>Hi {{user.name}}</p>"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if html != "<p>Hi Ada</p>" {
		t.Errorf("html = %q, want interpolated inline html", html)
	}
	if text != "" {
		t.Errorf("text = %q, want empty", text)
	}
}

func TestResolveEmailBody_InlineTextOnly(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	html, text, err := resolveEmailBody(ctx, &FlowEmail{Text: "plain words"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if html != "" || text != "plain words" {
		t.Errorf("got html=%q text=%q, want text-only", html, text)
	}
}

func TestResolveEmailBody_TemplateBareNameResolvesEmailsDir(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.MkdirAll(filepath.Join(app.Dir, "emails"), 0755); err != nil {
		t.Fatal(err)
	}
	tmpl := "<h1>Invite from {{org_name}} for {{user.email}}</h1>"
	if err := os.WriteFile(filepath.Join(app.Dir, "emails", "external-invite.html"), []byte(tmpl), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	ctx.Data["user"] = map[string]any{"email": "a@b.co"}

	// The exact shape from the field report: bare template name + data:.
	html, _, err := resolveEmailBody(ctx, &FlowEmail{
		Template: "external-invite",
		Data:     map[string]string{"org_name": "Acme"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if html != "<h1>Invite from Acme for a@b.co</h1>" {
		t.Errorf("html = %q - template render with data: overlay broken", html)
	}

	// With-extension form must reach the same file.
	html2, _, err := resolveEmailBody(ctx, &FlowEmail{
		Template: "external-invite.html",
		Data:     map[string]string{"org_name": "Acme"},
	})
	if err != nil {
		t.Fatalf("with-extension form: %v", err)
	}
	if html2 != html {
		t.Errorf("extension form rendered %q, bare form %q", html2, html)
	}
}

func TestResolveEmailBody_TemplateLiteralPathStillWorks(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := os.WriteFile(filepath.Join(app.Dir, "notice.html"), []byte("<p>root-level</p>"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	html, _, err := resolveEmailBody(ctx, &FlowEmail{Template: "notice.html"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if html != "<p>root-level</p>" {
		t.Errorf("html = %q, want app-root literal path render", html)
	}
}

func TestResolveEmailBody_MissingTemplateFailsLoud(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	_, _, err := resolveEmailBody(ctx, &FlowEmail{Template: "nope"})
	if err == nil {
		t.Fatal("expected loud error for missing template, got nil (pre-fix this silently sent an empty body)")
	}
	if !strings.Contains(err.Error(), "emails/nope.html") {
		t.Errorf("error should list tried paths, got: %v", err)
	}
}

func TestResolveEmailBody_NoBodyFailsLoud(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	_, _, err := resolveEmailBody(ctx, &FlowEmail{})
	if err == nil {
		t.Fatal("expected error for body-less email step, got nil")
	}
}

func TestWithToEmail_BodyKeysSurvive(t *testing.T) {
	e := withToEmail(map[string]any{
		"to":      "x@y.z",
		"subject": "s",
		"html":    "<p>inline ${{ steps.row.outputs.name }}</p>",
		"text":    "alt",
		"vars":    map[string]any{"org": "${{ inputs.org }}"},
	})
	if e.Html == "" || !strings.Contains(e.Html, "{{") || strings.Contains(e.Html, "${{") {
		t.Errorf("html not carried/normalized: %q", e.Html)
	}
	if e.Text != "alt" {
		t.Errorf("text = %q", e.Text)
	}
	if e.Data["org"] == "" || strings.Contains(e.Data["org"], "${{") {
		t.Errorf("vars: alias not carried/normalized: %v", e.Data)
	}

	// `body:` alias maps onto Html.
	e2 := withToEmail(map[string]any{"body": "<p>b</p>"})
	if e2.Html != "<p>b</p>" {
		t.Errorf("body: alias not mapped to Html, got %q", e2.Html)
	}
}

func TestEmailTemplateCandidates(t *testing.T) {
	got := emailTemplateCandidates("external-invite")
	want := []string{
		"external-invite", "external-invite.html",
		filepath.Join("emails", "external-invite"), filepath.Join("emails", "external-invite.html"),
		filepath.Join("templates", "external-invite"), filepath.Join("templates", "external-invite.html"),
	}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidates[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// A path-qualified template doesn't get the dir variants.
	got2 := emailTemplateCandidates("emails/x.html")
	if len(got2) != 1 || got2[0] != "emails/x.html" {
		t.Errorf("path-qualified candidates = %v", got2)
	}
}
