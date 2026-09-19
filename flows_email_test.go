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

// --- per-send sender ("send as") ---------------------------------------
//
// Pre-fix, FlowEmail carried no From/ReplyTo at all, so a flow declaring
// `from:` was parsed, discarded, and the send went out as EMAIL_FROM -
// silently. These lock the whole path: parse (both step shapes), exec-time
// interpolation, and the refusal of an unverified from-domain.

func TestBuildEmailOpts_FromAndReplyToInterpolateIntoTheSend(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	ctx.Data["rep"] = map[string]any{"email": "sender@example.com"}

	opts, appDir, err := buildEmailOpts(ctx, &FlowStep{Email: &FlowEmail{
		To:      "customer@example.net",
		Subject: "Statement",
		Html:    "<p>hi</p>",
		From:    "{{rep.email}}",
		ReplyTo: " {{rep.email}} ",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if appDir != app.Dir {
		t.Errorf("appDir = %q, want %q", appDir, app.Dir)
	}
	if opts.From != "sender@example.com" {
		t.Errorf("From = %q - per-send sender did not reach the send (this is the bug)", opts.From)
	}
	if opts.ReplyTo != "sender@example.com" {
		t.Errorf("ReplyTo = %q, want interpolated + trimmed", opts.ReplyTo)
	}
}

func TestBuildEmailOpts_NoFromLeavesItToEmailFrom(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	opts, _, err := buildEmailOpts(ctx, &FlowStep{Email: &FlowEmail{
		To: "customer@example.net", Subject: "s", Text: "t",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.From != "" || opts.ReplyTo != "" {
		t.Errorf("From=%q ReplyTo=%q, want both empty so EMAIL_FROM applies", opts.From, opts.ReplyTo)
	}
}

func TestApplyStepProperty_FromAndReplyTo(t *testing.T) {
	step := &FlowStep{Type: "email", Email: &FlowEmail{}}
	applyStepProperty(step, "from", "sender@example.com")
	applyStepProperty(step, "reply_to", "ar@example.com")
	if step.Email.From != "sender@example.com" || step.Email.ReplyTo != "ar@example.com" {
		t.Errorf("from/reply_to not parsed: %+v", step.Email)
	}

	// `from:` on a respond step keeps its pre-existing JSON fallthrough.
	r := &FlowStep{Type: "respond", Respond: &FlowRespond{}}
	applyStepProperty(r, "from", "x")
	if r.Respond.JSON["from"] != "x" {
		t.Errorf("respond from: fallthrough broken: %+v", r.Respond.JSON)
	}
}

func TestWithToEmail_FromAndReplyTo(t *testing.T) {
	e := withToEmail(map[string]any{
		"to":       "x@y.z",
		"subject":  "s",
		"text":     "t",
		"from":     "${{ inputs.sender }}",
		"reply_to": "ar@example.com",
	})
	if e.From == "" || strings.Contains(e.From, "${{") {
		t.Errorf("from: not carried/normalized: %q", e.From)
	}
	if e.ReplyTo != "ar@example.com" {
		t.Errorf("reply_to: not carried: %q", e.ReplyTo)
	}
}

func TestResolveEmailFrom_PerSendWinsOtherwiseEmailFrom(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "EMAIL_FROM", "no-reply@example.com")

	if got := resolveEmailFrom(app.Dir, ""); got != "no-reply@example.com" {
		t.Errorf("no per-send from: got %q, want EMAIL_FROM", got)
	}
	if got := resolveEmailFrom(app.Dir, "sender@example.com"); got != "sender@example.com" {
		t.Errorf("per-send from: got %q, want the override", got)
	}
}

func TestSendEmailOpts_RefusesUnverifiedFromDomain(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "EMAIL_FROM", "no-reply@example.com")
	SetAppEnv(app.Dir, "SMTP_HOST", "127.0.0.1")
	SetAppEnv(app.Dir, "SMTP_PORT", "1")

	err := SendEmailOpts(app.Dir, EmailOpts{
		To: "customer@example.net", Subject: "s", BodyText: "t",
		From: "ceo@some-other-domain.test",
	})
	if err == nil {
		t.Fatal("expected a loud refusal for an unverified from-domain, got nil")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("want an authorization refusal before any send, got: %v", err)
	}

	// Same-domain From passes the guard: the only thing left to fail is
	// the (deliberately dead) SMTP dial, never authorization.
	err = SendEmailOpts(app.Dir, EmailOpts{
		To: "customer@example.net", Subject: "s", BodyText: "t",
		From: "sender@example.com",
	})
	if err != nil && strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("same-domain From was refused: %v", err)
	}
}

func TestSameEmailDomain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"a@x.com", "b@x.com", true},
		{"A@X.com", "b@x.COM", true},
		{"Example Sender <a@x.com>", "b@x.com", true},
		{"a@x.com", "b@y.com", false},
		{"a@x.com", "", false}, // nothing configured authorizes nothing
		{"", "b@x.com", false},
		{"not-an-address", "b@x.com", false},
	}
	for _, c := range cases {
		if got := sameEmailDomain(c.a, c.b); got != c.want {
			t.Errorf("sameEmailDomain(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
