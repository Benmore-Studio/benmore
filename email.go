//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
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

// EmailOpts is the full sending shape. Use SendEmail for the common
// transactional path; use SendEmailOpts when you need List-Unsubscribe
// headers (marketing) or a specific SES configuration set.
type EmailOpts struct {
	To               string // single recipient or comma-list
	Subject          string
	BodyHTML         string
	BodyText         string // optional plain-text alt; if set, sends multipart/alternative
	UnsubscribeURL   string // when set: adds List-Unsubscribe + RFC 8058 one-click
	ConfigurationSet string // optional SES config set (e.g., "my-config-set")
	From             string // override SMTP_FROM
	ReplyTo          string
}

func SendEmailOpts(appDir string, opts EmailOpts) error {
	// Prevent email header injection by stripping newlines from inputs.
	clean := strings.NewReplacer("\r", "", "\n", "").Replace
	opts.To = clean(opts.To)
	opts.Subject = clean(opts.Subject)
	opts.UnsubscribeURL = clean(opts.UnsubscribeURL)
	opts.ConfigurationSet = clean(opts.ConfigurationSet)
	opts.ReplyTo = clean(opts.ReplyTo)

	// Provider priority: Resend > Postmark > AWS SES (via SMTP creds)
	// > generic SMTP. Each is detected by env var presence so apps can
	// switch providers by changing env without code edits.
	from := opts.From
	if from == "" {
		from = firstNonEmptyStr(GetEnv(appDir, "EMAIL_FROM"), GetEnv(appDir, "SMTP_FROM"))
	}

	if key := GetEnv(appDir, "RESEND_API_KEY"); key != "" {
		return sendViaResend(key, from, opts)
	}
	if key := GetEnv(appDir, "POSTMARK_SERVER_TOKEN"); key != "" {
		return sendViaPostmark(key, from, opts)
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
		log.Printf("EMAIL [not sent - no provider configured] to=%s subject=%s", opts.To, opts.Subject)
		return fmt.Errorf("email not delivered: no provider configured. " +
			"Set RESEND_API_KEY (preferred - free tier 3k/month at https://resend.com, no card required) " +
			"or POSTMARK_SERVER_TOKEN or SMTP_HOST+SMTP_USER+SMTP_PASS in env.yaml or your " +
			"environment. For production-quality " +
			"from-addresses you'll also need a custom domain verified with the provider - without one, " +
			"emails go from a generic sender (e.g. onboarding@resend.dev) that Gmail and Outlook treat " +
			"as untrusted, lowering inbox-placement rates. The hook step that called this is marked failed.")
	}
	if port == "" {
		port = "587"
	}
	if from == "" {
		from = user
	}

	// Build headers
	headers := []string{
		"From: " + from,
		"To: " + opts.To,
		"Subject: " + opts.Subject,
		"MIME-Version: 1.0",
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
		headers = append(headers, "List-Unsubscribe-Post: List-Unsubscribe=One-Click")
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

	recipients := strings.Split(opts.To, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	if err := smtp.SendMail(addr, auth, from, recipients, []byte(msg)); err != nil {
		return fmt.Errorf("send email to %s: %w", opts.To, err)
	}

	log.Printf("EMAIL sent (smtp) to=%s subject=%s configset=%s",
		opts.To, opts.Subject, opts.ConfigurationSet)
	return nil
}

// sendViaResend POSTs to api.resend.com/emails. Resend's free tier
// gives 100/day with no SMTP setup - the right default for "I just
// want email to work."
func sendViaResend(apiKey, from string, opts EmailOpts) error {
	if from == "" {
		return fmt.Errorf("resend: EMAIL_FROM env var is required")
	}
	body := map[string]any{
		"from":    from,
		"to":      []string{opts.To},
		"subject": opts.Subject,
	}
	// Only send the fields that exist - Resend 422s on an empty/missing
	// html when no text is present, so a text-only send must omit html
	// entirely rather than ship "".
	if opts.BodyHTML != "" {
		body["html"] = opts.BodyHTML
	}
	if opts.BodyText != "" {
		body["text"] = opts.BodyText
	}
	if opts.ReplyTo != "" {
		body["reply_to"] = opts.ReplyTo
	}
	return postProviderJSON("https://api.resend.com/emails", apiKey, "Bearer", body, opts)
}

// sendViaPostmark POSTs to api.postmarkapp.com. Same shape as
// Resend, different auth header. Postmark's selling point is
// transactional reliability + analytics; same code path either way.
func sendViaPostmark(token, from string, opts EmailOpts) error {
	if from == "" {
		return fmt.Errorf("postmark: EMAIL_FROM env var is required")
	}
	body := map[string]any{
		"From":    from,
		"To":      opts.To,
		"Subject": opts.Subject,
	}
	if opts.BodyHTML != "" {
		body["HtmlBody"] = opts.BodyHTML
	}
	if opts.BodyText != "" {
		body["TextBody"] = opts.BodyText
	}
	if opts.ReplyTo != "" {
		body["ReplyTo"] = opts.ReplyTo
	}
	return postProviderJSON("https://api.postmarkapp.com/email", token, "X-Postmark-Server-Token", body, opts)
}

func postProviderJSON(url, key, scheme string, body map[string]any, opts EmailOpts) error {
	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if scheme == "Bearer" {
		req.Header.Set("Authorization", "Bearer "+key)
	} else {
		req.Header.Set(scheme, key)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("email provider request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("email provider returned %d: %s", resp.StatusCode, string(buf))
	}
	log.Printf("EMAIL sent (%s) to=%s subject=%s",
		hostOf(url), opts.To, opts.Subject)
	return nil
}

func hostOf(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if j := strings.Index(url, "/"); j >= 0 {
		return url[:j]
	}
	return url
}

// firstNonEmptyStr is local to email.go because mcp_validators_cross.go
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

// AddResendContact best-effort-adds a new signup to a Resend audience
// (contacts list) for marketing blasts. Reads from app env:
//
//	RESEND_API_KEY      - required (already used by SendEmail)
//	RESEND_AUDIENCE_ID  - required (the audience to add to)
//	RESEND_CONTACT_TAG  - optional. When set, the value is appended
//	                      to last_name as " [<tag>]" so contacts can
//	                      be filtered by source in the Resend dashboard.
//	                      Useful when multiple sites populate the same
//	                      audience: Resend's contacts API has no custom
//	                      fields, so embedding the source in last_name
//	                      is the only Resend-native way to differentiate.
//
// Silently no-ops if RESEND_API_KEY or RESEND_AUDIENCE_ID is missing.
// Runs synchronously so callers can fire-and-forget with `go`.
func AddResendContact(appDir, email, firstName, lastName string) {
	apiKey := GetEnv(appDir, "RESEND_API_KEY")
	audienceID := GetEnv(appDir, "RESEND_AUDIENCE_ID")
	if apiKey == "" || audienceID == "" {
		return
	}
	if tag := strings.TrimSpace(GetEnv(appDir, "RESEND_CONTACT_TAG")); tag != "" {
		suffix := " [" + tag + "]"
		if lastName == "" {
			lastName = "[" + tag + "]"
		} else if !strings.Contains(lastName, suffix) {
			lastName += suffix
		}
	}
	body := map[string]any{
		"email":        email,
		"unsubscribed": false,
	}
	if firstName != "" {
		body["first_name"] = firstName
	}
	if lastName != "" {
		body["last_name"] = lastName
	}
	url := "https://api.resend.com/audiences/" + audienceID + "/contacts"
	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		log.Printf("resend-contact: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("resend-contact: POST failed (email=%s): %v", email, err)
		return
	}
	defer resp.Body.Close()
	// 201 created / 409 already exists - both fine
	if resp.StatusCode >= 400 && resp.StatusCode != 409 {
		buf, _ := io.ReadAll(resp.Body)
		log.Printf("resend-contact: %d for %s - %s", resp.StatusCode, email, string(buf))
		return
	}
	log.Printf("resend-contact: added %s to audience %s", email, audienceID[:8])
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
