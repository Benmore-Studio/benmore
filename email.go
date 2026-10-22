//go:build !cli

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// stripEmailFrontmatter removes a leading YAML page-frontmatter block
// from an email template body. Agents trained on Benmore's page DSL
// frequently prepend `---\nengine: raw\nlayout: none\n---` to email
// templates by reflex; without this strip the literal block lands in
// the email body and customers see "--- engine: raw layout: none ---"
// at the top of every welcome message. Idempotent - leaves templates
// without frontmatter untouched.
func stripEmailFrontmatter(body string) string {
	trimmed := strings.TrimLeft(body, " \t\r\n")
	if !strings.HasPrefix(trimmed, "---") {
		return body
	}
	rest := trimmed[3:]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return body
	}
	rest = rest[nl+1:]
	endIdx := strings.Index(rest, "\n---")
	if endIdx < 0 {
		return body
	}
	rest = rest[endIdx+4:]
	return strings.TrimLeft(rest, " \t\r\n")
}

// SendEmail sends an email via SMTP configured in env.yaml.
// On draft branches, the send is intercepted and stored in the per-app
// _benmore_draft_capture table - drafts never deliver real email so
// they can't be used as free transactional infrastructure.
func SendEmail(appDir, to, subject, body string) error {
	return SendEmailOpts(appDir, EmailOpts{To: to, Subject: subject, BodyHTML: body})
}

// EmailAttachment is one file attached to a send. Content is the raw file
// bytes encoded as standard base64 (the wire-friendly shape carried over the
// gateway socket and provider JSON). ContentType defaults to
// application/octet-stream when empty.
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	Content     string `json:"content"` // base64-encoded file bytes
}

// EmailOpts is the full sending shape. Use SendEmail for the common
// transactional path; use SendEmailOpts when you need List-Unsubscribe
// headers (marketing) or a specific SES configuration set.
type EmailOpts struct {
	To             string // single recipient or comma-list
	CC             string
	BCC            string
	Subject        string
	BodyHTML       string
	BodyText       string // optional plain-text alt; if set, sends multipart/alternative
	UnsubscribeURL string // when set: adds List-Unsubscribe
	// UnsubscribeOneClick also sends the RFC 8058 `List-Unsubscribe-Post:
	// List-Unsubscribe=One-Click` header, which makes mail clients POST to
	// UnsubscribeURL with no session. Set it only for a URL built for that
	// (the platform's marketing drips: a per-subscriber token and a POST
	// handler). Flow mail opts in with `unsubscribe_one_click: true`.
	UnsubscribeOneClick bool
	ConfigurationSet    string // optional SES config set (e.g., "my-config-set")
	From                string // override SMTP_FROM
	ReplyTo             string
	Attachments         []EmailAttachment // when set: multipart/mixed with base64 file parts
}

func SendEmailOpts(appDir string, opts EmailOpts) error {
	if err := validateEmailHeaders(opts.From, opts.To, opts.CC, opts.BCC, opts.ReplyTo, opts.Subject, opts.UnsubscribeURL, opts.ConfigurationSet); err != nil {
		return err
	}
	if opts.UnsubscribeOneClick && emailOneClickURLProblem(opts.UnsubscribeURL) != "" {
		return fmt.Errorf("one-click unsubscribe requires a valid https unsubscribe_url")
	}
	to, err := parseEmailAddressList(opts.To)
	if err != nil {
		return err
	}
	cc, err := parseEmailAddressList(opts.CC)
	if err != nil {
		return err
	}
	bcc, err := parseEmailAddressList(opts.BCC)
	if err != nil {
		return err
	}
	if len(to) == 0 || len(to)+len(cc)+len(bcc) > 50 {
		return fmt.Errorf("1-50 recipients per send across to, cc and bcc")
	}
	if opts.UnsubscribeOneClick && len(to)+len(cc)+len(bcc) != 1 {
		return fmt.Errorf("one-click unsubscribe requires exactly one recipient")
	}
	recipients := append(append(append([]string{}, to...), cc...), bcc...)
	for i, recipient := range recipients {
		a, _ := mail.ParseAddress(recipient)
		recipients[i] = a.Address
	}
	opts.To = strings.Join(to, ", ")
	opts.CC = strings.Join(cc, ", ")

	// Provider priority: platform SES gateway (hosted platform - ALWAYS
	// wins when reachable) > SMTP (AWS SES SMTP creds or generic).
	// On the hosted platform every send routes through the router's
	// SES broker regardless of per-app provider env vars, so delivery,
	// suppression, quotas and reputation are managed in ONE place.
	// Off-platform the gateway socket doesn't exist and SMTP applies.
	from := resolveEmailFrom(appDir, opts.From)

	if emailGatewayReachable() {
		resp, gerr := requestGatewayEmailSend(emailGatewayReq{
			From: from,
			To:   to,
			CC:   cc, BCC: bcc,
			ReplyTo:        opts.ReplyTo,
			Subject:        opts.Subject,
			HTML:           stripEmailFrontmatter(opts.BodyHTML),
			Text:           opts.BodyText,
			UnsubscribeURL: opts.UnsubscribeURL,
			OneClick:       opts.UnsubscribeOneClick,
			Attachments:    opts.Attachments,
			App:            os.Getenv("BENMORE_APP_NAME"),
		})
		if gerr != nil {
			// The broker's errors are precise + actionable (unauthorized
			// from-domain, quota, suppression, pause) - surface verbatim.
			log.Printf("EMAIL [platform gateway failed] to=%s subject=%s: %s", logRecipientsRef(opts.To), opts.Subject, logSendErrorRecipients(gerr, strings.Join(recipients, ", ")))
			return gerr
		}
		log.Printf("EMAIL [sent via platform] to=%s from=%s subject=%s id=%s", logRecipientsRef(opts.To), resp.From, opts.Subject, resp.MessageID)
		return nil
	}

	// On the hosted platform the SES broker is the only sender. Falling back
	// to the app's own SMTP_HOST when the broker socket is unreachable would
	// let an app point the tenant process at the host's loopback services.
	if hostedTenantProcess() {
		log.Printf("EMAIL [not sent - platform email service unreachable] to=%s subject=%s", logRecipientsRef(opts.To), opts.Subject)
		return fmt.Errorf("email not delivered: the platform email service is unreachable; retry shortly (SMTP_HOST is not used on the hosted platform)")
	}
	host := GetEnv(appDir, "SMTP_HOST")
	port := GetEnv(appDir, "SMTP_PORT")
	user := GetEnv(appDir, "SMTP_USER")
	pass := GetEnv(appDir, "SMTP_PASS")

	if host == "" {
		// Return an explicit error rather than logging + nil. Pre-fix
		// behavior made `hooks.yaml` welcome-email steps look like they
		// succeeded - operators kept seeing "EMAIL [not sent]" in the
		// global log without realising the hook had effectively no-op'd.
		// Hook engine surfaces the error to the audit log + can be read
		// via the get_recent_activity MCP tool.
		log.Printf("EMAIL [not sent - no provider configured] to=%s subject=%s", logRecipientsRef(opts.To), opts.Subject)
		return fmt.Errorf("email not delivered: no provider configured. " +
			"On the hosted platform sends route through the platform SES service automatically (zero config). " +
			"Off-platform, set SMTP_HOST+SMTP_PORT+SMTP_USER+SMTP_PASS (AWS SES SMTP credentials work directly) " +
			"in env.yaml or your environment. For production-quality from-addresses verify your sending " +
			"domain (DKIM) with SES first - without one, mailbox providers treat the sender as untrusted, " +
			"lowering inbox-placement rates. The hook step that called this is marked failed.")
	}
	if port == "" {
		port = "587"
	}
	// A caller-supplied From is a sender identity, so it needs the same
	// kind of proof EMAIL_FROM has. On the hosted platform the broker
	// checks platform_email_domains (and returns its own precise error);
	// that table is platform-side only, so off-platform the strongest
	// evidence available is the sender the operator configured. Refuse
	// anything on a different domain - loudly. Falling back to the
	// configured sender here would reproduce exactly the bug this
	// feature exists to fix: a send that looks fine and isn't.
	if opts.From != "" {
		configured := firstNonEmptyStr(GetEnv(appDir, "EMAIL_FROM"), GetEnv(appDir, "SMTP_FROM"), user)
		if !sameEmailDomain(opts.From, configured) {
			return fmt.Errorf("from address %q is not authorized: its domain is not the app's configured sending domain (%s). "+
				"Verify the domain for this app and set EMAIL_FROM to an address on it, or send from an address on the configured domain",
				opts.From, firstNonEmptyStr(configured, "none configured"))
		}
	}
	if from == "" {
		from = user
	}

	envelopeFrom, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("invalid sender address")
	}

	// Build headers
	headers := []string{
		"From: " + from,
		"To: " + opts.To,
		"Subject: " + opts.Subject,
		"MIME-Version: 1.0",
	}
	if opts.CC != "" {
		headers = append(headers, "Cc: "+opts.CC)
	}
	if opts.ReplyTo != "" {
		headers = append(headers, "Reply-To: "+opts.ReplyTo)
	}
	// SES uses X-SES-CONFIGURATION-SET to route events to the right
	// configuration set (bounce/complaint pipelines + reputation
	// metrics). For marketing sends this MUST be set so suppression
	// fires correctly.
	if opts.ConfigurationSet != "" {
		headers = append(headers, "X-SES-CONFIGURATION-SET: "+opts.ConfigurationSet)
	}
	// RFC 2369 + RFC 8058: List-Unsubscribe lets the mail client
	// surface a native unsubscribe button. The Post header enables
	// one-click unsubscribe - Gmail and Apple Mail call the URL as
	// POST with body "List-Unsubscribe=One-Click", no human nav.
	if opts.UnsubscribeURL != "" {
		headers = append(headers, "List-Unsubscribe: <"+opts.UnsubscribeURL+">")
		if opts.UnsubscribeOneClick {
			headers = append(headers, "List-Unsubscribe-Post: List-Unsubscribe=One-Click")
		}
	}

	// Attachments require a multipart/mixed envelope, which the shared raw-MIME
	// builder assembles (headers included) — bypass the simple-body branches.
	if len(opts.Attachments) > 0 {
		raw, berr := buildRawMIMEMessage(from, opts.To, opts.CC, opts.Subject, opts.ReplyTo,
			opts.UnsubscribeURL, opts.UnsubscribeOneClick, opts.ConfigurationSet, opts.BodyHTML, opts.BodyText, opts.Attachments)
		if berr != nil {
			return fmt.Errorf("build attachment message: %w", berr)
		}
		addr := host + ":" + port
		auth := smtp.PlainAuth("", user, pass, host)
		if err := smtp.SendMail(addr, auth, envelopeFrom.Address, recipients, raw); err != nil {
			return fmt.Errorf("send email to %s: %w", opts.To, err)
		}
		log.Printf("EMAIL sent (smtp) to=%s subject=%s attachments=%d", logRecipientsRef(opts.To), opts.Subject, len(opts.Attachments))
		return nil
	}

	var body string
	if opts.BodyText != "" && opts.BodyHTML == "" {
		// Text-only send: plain text/plain, no empty HTML part.
		headers = append(headers, "Content-Type: text/plain; charset=UTF-8")
		body = "\r\n" + opts.BodyText
	} else if opts.BodyText != "" {
		// Multipart alternative: text + HTML
		boundary := "_b_" + fmt.Sprintf("%d", time.Now().UnixNano())
		headers = append(headers, "Content-Type: multipart/alternative; boundary=\""+boundary+"\"")
		body = strings.Join([]string{
			"",
			"--" + boundary,
			"Content-Type: text/plain; charset=UTF-8",
			"",
			opts.BodyText,
			"",
			"--" + boundary,
			"Content-Type: text/html; charset=UTF-8",
			"",
			opts.BodyHTML,
			"",
			"--" + boundary + "--",
			"",
		}, "\r\n")
	} else {
		headers = append(headers, "Content-Type: text/html; charset=UTF-8")
		body = "\r\n" + opts.BodyHTML
	}
	msg := strings.Join(headers, "\r\n") + "\r\n" + body

	addr := host + ":" + port
	auth := smtp.PlainAuth("", user, pass, host)

	if err := smtp.SendMail(addr, auth, envelopeFrom.Address, recipients, []byte(msg)); err != nil {
		return fmt.Errorf("send email to %s: %w", opts.To, err)
	}

	log.Printf("EMAIL sent (smtp) to=%s subject=%s configset=%s",
		logRecipientsRef(opts.To), opts.Subject, opts.ConfigurationSet)
	return nil
}

// emailAttachmentType returns the attachment's declared content type,
// inferring from the filename extension and finally defaulting to
// application/octet-stream.
func emailAttachmentType(a EmailAttachment) string {
	if a.ContentType != "" {
		return a.ContentType
	}
	if ct := mime.TypeByExtension(filepath.Ext(a.Filename)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// buildRawMIMEMessage assembles a complete RFC 5322 message with a
// multipart/mixed envelope: an (optional) text+html multipart/alternative
// sub-part, then one base64 part per attachment. This is the only shape that
// can carry binary files — used by the SMTP path directly and, base64-wrapped,
// by the SESv2 raw-content path (Simple/JSON content can't attach files).
func buildRawMIMEMessage(from, to, cc, subject, replyTo, unsubscribeURL string, oneClick bool, configSet, html, text string, attachments []EmailAttachment) ([]byte, error) {
	clean := strings.NewReplacer("\r", "", "\n", "").Replace

	// Build the body first so the mixed boundary is known for the header.
	var bodyBuf bytes.Buffer
	mixed := multipart.NewWriter(&bodyBuf)

	if text != "" && html != "" {
		var altBuf bytes.Buffer
		alt := multipart.NewWriter(&altBuf)
		if pw, err := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}}); err == nil {
			io.WriteString(pw, text)
		}
		if pw, err := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=UTF-8"}}); err == nil {
			io.WriteString(pw, html)
		}
		alt.Close()
		pw, err := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"multipart/alternative; boundary=\"" + alt.Boundary() + "\""},
		})
		if err != nil {
			return nil, err
		}
		pw.Write(altBuf.Bytes())
	} else {
		ctype, content := "text/html; charset=UTF-8", html
		if html == "" {
			ctype, content = "text/plain; charset=UTF-8", text
		}
		pw, err := mixed.CreatePart(textproto.MIMEHeader{"Content-Type": {ctype}})
		if err != nil {
			return nil, err
		}
		io.WriteString(pw, content)
	}

	for _, a := range attachments {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a.Content))
		if err != nil {
			return nil, fmt.Errorf("attachment %q: invalid base64 content: %w", a.Filename, err)
		}
		// The name is written inside a quoted MIME parameter: a quote or
		// backslash in it would end the parameter and add others.
		fn := strings.NewReplacer(`"`, "'", `\`, "_").Replace(clean(a.Filename))
		if fn == "" {
			fn = "attachment"
		}
		pw, err := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {emailAttachmentType(a) + "; name=\"" + fn + "\""},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {"attachment; filename=\"" + fn + "\""},
		})
		if err != nil {
			return nil, err
		}
		writeBase64Wrapped(pw, raw)
	}
	mixed.Close()

	var msg bytes.Buffer
	wh := func(k, v string) { msg.WriteString(k + ": " + v + "\r\n") }
	wh("From", clean(from))
	wh("To", clean(to))
	if cc != "" {
		wh("Cc", clean(cc))
	}
	wh("Subject", mime.QEncoding.Encode("UTF-8", subject))
	if replyTo != "" {
		wh("Reply-To", clean(replyTo))
	}
	wh("MIME-Version", "1.0")
	if configSet != "" {
		wh("X-SES-CONFIGURATION-SET", clean(configSet))
	}
	if unsubscribeURL != "" {
		wh("List-Unsubscribe", "<"+clean(unsubscribeURL)+">")
		if oneClick {
			wh("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
		}
	}
	msg.WriteString("Content-Type: multipart/mixed; boundary=\"" + mixed.Boundary() + "\"\r\n\r\n")
	msg.Write(bodyBuf.Bytes())
	return msg.Bytes(), nil
}

// writeBase64Wrapped writes raw as standard base64, wrapped at 76 columns
// (RFC 2045).
func writeBase64Wrapped(w io.Writer, raw []byte) {
	enc := base64.StdEncoding.EncodeToString(raw)
	for len(enc) > 76 {
		io.WriteString(w, enc[:76]+"\r\n")
		enc = enc[76:]
	}
	if len(enc) > 0 {
		io.WriteString(w, enc+"\r\n")
	}
}

// resolveEmailFrom picks the sender for one send: the caller's per-send
// From when set (flow `from:`, "send as"), otherwise the app's
// instance-wide configured sender. Authorization of the result is a
// separate step - see the platform broker and SendEmailOpts's SMTP guard.
func resolveEmailFrom(appDir, optsFrom string) string {
	if optsFrom != "" {
		return optsFrom
	}
	return firstNonEmptyStr(GetEnv(appDir, "EMAIL_FROM"), GetEnv(appDir, "SMTP_FROM"))
}

// sameEmailDomain reports whether two addresses share a domain. Both
// sides accept the bare and the "Display Name <addr>" forms; an
// unparseable or empty side is never a match, so an unset configured
// sender refuses every override rather than waving it through.
func sameEmailDomain(a, b string) bool {
	da, db := emailDomainOf(a), emailDomainOf(b)
	return da != "" && da == db
}

func emailDomainOf(addr string) string {
	parsed, err := mail.ParseAddress(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	at := strings.LastIndexByte(parsed.Address, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(parsed.Address[at+1:])
}

// firstNonEmptyStr is local to email.go because validators_cross.go
// already has a firstNonEmpty with a different signature. Same
// semantics, different name.
func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// EmailBrand describes the per-app branding pulled into RenderBrandedEmail.
// Callers populate this from app.Design (site_name, brand color, base
// URL) so each app's transactional emails match its own brand - not
// the framework's.
type EmailBrand struct {
	SiteName   string // app.Design.SEO["site_name"] (or sensible default)
	BrandColor string // app.Design.Colors["_brand"] (e.g., "#3a6cf0"); falls back to a neutral if empty
	SiteURL    string // canonical https URL for this app
	LogoURL    string // absolute URL to a logo image (favicon / brand mark). Rendered at 22px in the email header. Falls back to a colored square when empty.
	Footer     string // optional footer line - e.g., the company / legal entity owning the app
}

// RenderBrandedEmail wraps body content in a clean HTML email shell
// using the app's own brand. Pure inline CSS for cross-client
// compatibility (Gmail / Outlook / Apple Mail / iOS).
//
// Framework: callers MUST pass a brand sourced from the calling
// app's app.Design, NEVER hardcoded values, so customer apps get
// their own branding on auth emails.
func RenderBrandedEmail(brand EmailBrand, headline, intro, ctaText, ctaURL, outro string) string {
	const (
		brandDark = "#1c1c20"
		bgPage    = "#fafafa"
		bgCard    = "#ffffff"
		fgText    = "#1c1c20"
		fgMuted   = "#4b4b54"
		fgSubtle  = "#7a7a85"
		border    = "rgba(0,0,0,0.08)"
	)

	siteName := brand.SiteName
	if siteName == "" {
		siteName = "App"
	}
	brandColor := brand.BrandColor
	if brandColor == "" {
		brandColor = "#3a6cf0"
	}
	siteURL := brand.SiteURL
	if siteURL == "" {
		siteURL = "#"
	}

	cta := ""
	if ctaText != "" && ctaURL != "" {
		cta = fmt.Sprintf(`<table cellpadding="0" cellspacing="0" border="0" style="margin:24px 0;"><tr><td style="background:%s;border-radius:9999px;">
  <a href="%s" style="display:inline-block;padding:12px 28px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:9999px;">%s</a>
</td></tr></table>
<p style="margin:0 0 18px;font-size:12px;color:%s;line-height:1.5;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">Or paste this URL into your browser:<br><a href="%s" style="color:%s;word-break:break-all;">%s</a></p>`,
			brandColor, ctaURL, ctaText, fgSubtle, ctaURL, brandColor, ctaURL)
	}

	outroBlock := ""
	if outro != "" {
		outroBlock = fmt.Sprintf(`<p style="margin:0;font-size:14px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</p>`, fgMuted, outro)
	}

	footer := brand.Footer
	if footer == "" {
		footer = siteName
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:%s;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;color:%s;-webkit-font-smoothing:antialiased;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:%s;padding:32px 16px;">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%%;">

      <tr><td style="padding:0 0 24px;">
        <a href="%s" style="display:inline-flex;align-items:center;gap:8px;text-decoration:none;color:%s;font-weight:600;font-size:17px;letter-spacing:-0.015em;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">
          %s
          <span style="vertical-align:middle;">%s</span>
        </a>
      </td></tr>

      <tr><td style="background:%s;border:1px solid %s;border-radius:14px;padding:32px;">
        <h1 style="margin:0 0 12px;font-size:22px;font-weight:600;letter-spacing:-0.02em;color:%s;line-height:1.25;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</h1>
        <p style="margin:0 0 18px;font-size:15px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</p>
        %s
        %s
      </td></tr>

      <tr><td style="padding:24px 4px 0;font-size:12px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">
        %s · <a href="%s" style="color:%s;text-decoration:none;">%s</a>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`,
		bgPage, fgText,
		bgPage,
		siteURL, brandDark, brandMark(brand, brandColor), siteName, // wordmark (logo + sitename)
		bgCard, border, fgText, headline,
		fgMuted, intro,
		cta,
		outroBlock,
		fgSubtle,
		footer, siteURL, brandColor, strings.TrimPrefix(strings.TrimPrefix(siteURL, "https://"), "http://"),
	)
}

// brandMark renders the brand image at the top of every email - either
// the app's actual logo (when EmailBrand.LogoURL is set) or a colored
// square placeholder. The image is sized to match the wordmark's
// 22px line height and rounded 5px so it sits flush with the brand-
// colored fallback. Outlook is fussy about `display:inline-flex` on
// `<img>`, so we keep this as a plain inline element.
func brandMark(brand EmailBrand, brandColor string) string {
	if brand.LogoURL != "" {
		return fmt.Sprintf(
			`<img src="%s" alt="" width="22" height="22" style="display:inline-block;width:22px;height:22px;border-radius:5px;vertical-align:middle;border:0;">`,
			brand.LogoURL,
		)
	}
	return fmt.Sprintf(
		`<span style="display:inline-block;width:22px;height:22px;background:%s;border-radius:5px;vertical-align:middle;"></span>`,
		brandColor,
	)
}

// RenderBrandedCodeEmail is the OTP / verification-code variant of
// RenderBrandedEmail - same shell, header, logo, and footer, but the
// body shows a monospaced code block instead of a CTA button. Use this
// for any email whose primary action is "read this 6-digit code".
//
// `code` is rendered verbatim - caller is responsible for formatting
// (e.g. inserting a space between groups for readability).
func RenderBrandedCodeEmail(brand EmailBrand, headline, intro, code, outro string) string {
	const (
		brandDark  = "#1c1c20"
		bgPage     = "#fafafa"
		bgCard     = "#ffffff"
		fgText     = "#1c1c20"
		fgMuted    = "#4b4b54"
		fgSubtle   = "#7a7a85"
		border     = "rgba(0,0,0,0.08)"
		codeBg     = "#f4f4f6"
		codeBorder = "rgba(0,0,0,0.12)"
	)

	siteName := brand.SiteName
	if siteName == "" {
		siteName = "App"
	}
	brandColor := brand.BrandColor
	if brandColor == "" {
		brandColor = "#3a6cf0"
	}
	siteURL := brand.SiteURL
	if siteURL == "" {
		siteURL = "#"
	}

	codeBlock := fmt.Sprintf(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="margin:18px 0 22px;"><tr><td align="center" style="background:%s;border:1px solid %s;border-radius:12px;padding:22px;">
  <div style="font-family:'SF Mono','Menlo','Consolas',monospace;font-size:30px;font-weight:700;letter-spacing:0.18em;color:%s;">%s</div>
</td></tr></table>`,
		codeBg, codeBorder, fgText, code)

	outroBlock := ""
	if outro != "" {
		outroBlock = fmt.Sprintf(`<p style="margin:0;font-size:14px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</p>`, fgMuted, outro)
	}

	footer := brand.Footer
	if footer == "" {
		footer = siteName
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:%s;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;color:%s;-webkit-font-smoothing:antialiased;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:%s;padding:32px 16px;">
  <tr><td align="center">
    <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%%;">

      <tr><td style="padding:0 0 24px;">
        <a href="%s" style="display:inline-flex;align-items:center;gap:8px;text-decoration:none;color:%s;font-weight:600;font-size:17px;letter-spacing:-0.015em;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">
          %s
          <span style="vertical-align:middle;">%s</span>
        </a>
      </td></tr>

      <tr><td style="background:%s;border:1px solid %s;border-radius:14px;padding:32px;">
        <h1 style="margin:0 0 12px;font-size:22px;font-weight:600;letter-spacing:-0.02em;color:%s;line-height:1.25;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</h1>
        <p style="margin:0 0 18px;font-size:15px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">%s</p>
        %s
        %s
      </td></tr>

      <tr><td style="padding:24px 4px 0;font-size:12px;color:%s;line-height:1.6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,sans-serif;">
        %s · <a href="%s" style="color:%s;text-decoration:none;">%s</a>
      </td></tr>

    </table>
  </td></tr>
</table>
</body></html>`,
		bgPage, fgText,
		bgPage,
		siteURL, brandDark, brandMark(brand, brandColor), siteName,
		bgCard, border, fgText, headline,
		fgMuted, intro,
		codeBlock,
		outroBlock,
		fgSubtle,
		footer, siteURL, brandColor, strings.TrimPrefix(strings.TrimPrefix(siteURL, "https://"), "http://"),
	)
}

// AppEmailBrand derives an EmailBrand from an App's design.
// Centralized so every caller in auth.go gets the same shape and any
// future tweak (e.g., theme-derived color) lands in one place.
func AppEmailBrand(app *App, r *http.Request) EmailBrand {
	b := EmailBrand{SiteURL: baseURL(app, r)}
	if app != nil && app.Design != nil {
		if v, ok := app.Design.SEO["site_name"]; ok && v != "" {
			b.SiteName = v
		}
		if v, ok := app.Design.Colors["_brand"]; ok && v != "" {
			b.BrandColor = v
		}
		if v, ok := app.Design.SEO["footer"]; ok && v != "" {
			b.Footer = v
		}
		// LogoURL: derive from seo.favicon (or seo.logo if present).
		// Emails are rendered out-of-band, so the URL must be absolute -
		// relative paths get resolved against the recipient's mail client,
		// not the app. Prepend b.SiteURL when the configured value starts
		// with `/`.
		logoPath := ""
		if v, ok := app.Design.SEO["logo"]; ok && v != "" {
			logoPath = v
		} else if v, ok := app.Design.SEO["favicon"]; ok && v != "" {
			logoPath = v
		}
		if logoPath != "" {
			if strings.HasPrefix(logoPath, "http://") || strings.HasPrefix(logoPath, "https://") {
				b.LogoURL = logoPath
			} else if strings.HasPrefix(logoPath, "/") && b.SiteURL != "" {
				b.LogoURL = strings.TrimRight(b.SiteURL, "/") + logoPath
			}
		}
	}
	if b.SiteName == "" {
		b.SiteName = "App"
	}
	return b
}

func validateEmailHeaders(values ...string) error {
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("email headers must not contain control characters")
		}
	}
	return nil
}

func parseEmailAddressList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	addresses, err := mail.ParseAddressList(value)
	if err != nil {
		return nil, fmt.Errorf("invalid email recipient list")
	}
	result := make([]string, len(addresses))
	for i, a := range addresses {
		if len(a.Address) > 254 {
			return nil, fmt.Errorf("email address exceeds 254 bytes")
		}
		if a.Name == "" {
			result[i] = a.Address
		} else {
			result[i] = a.String()
		}
		if len(result[i]) > 512 {
			return nil, fmt.Errorf("email recipient exceeds 512 bytes")
		}
	}
	return result, nil
}
