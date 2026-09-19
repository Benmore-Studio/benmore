//go:build !cli

package main

// Queue, real-time messaging, and email delivery steps.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// execStepEnqueue inserts a job into _benmore_jobs. The named flow
// is invoked later by the background worker - out-of-band from the
// request lifecycle, so it can run for minutes/hours without
// blocking. Payload is interpolated from the current flow context.
func execStepEnqueue(ctx *FlowContext, step *FlowStep) error {
	if step.Enqueue == nil || step.Enqueue.Flow == "" {
		return fmt.Errorf("enqueue step requires flow:")
	}
	flowName := interpolateCtx(step.Enqueue.Flow, ctx)
	payload := map[string]any{}
	for k, v := range step.Enqueue.With {
		payload[k] = interpolateCtx(v, ctx)
	}
	var runAt *time.Time
	if step.Enqueue.RunAt != "" {
		v := interpolateCtx(step.Enqueue.RunAt, ctx)
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			runAt = &t
		}
	}
	uniqueKey := ""
	if step.Enqueue.UniqueKey != "" {
		uniqueKey = interpolateCtx(step.Enqueue.UniqueKey, ctx)
	}
	var (
		id       int64
		jobToken string
		err      error
	)
	if ctx.Tx != nil {
		// Serialize Tx access: a `parallel:` block inside a transactional
		// flow may enqueue concurrently, and *sql.Tx is not safe for
		// concurrent use. See FlowContext.TxMu.
		ctx.TxMu.Lock()
		id, jobToken, err = EnqueueJobTxUnique(ctx.Tx, uniqueKey, flowName, payload, runAt)
		ctx.TxMu.Unlock()
	} else {
		id, jobToken, err = EnqueueJobUnique(ctx.App.DB, uniqueKey, flowName, payload, runAt)
	}
	if err != nil {
		return fmt.Errorf("enqueue %s: %w", flowName, err)
	}
	if ctx.Data == nil {
		ctx.Data = map[string]any{}
	}
	if step.Name != "" {
		// Expose status_token so a respond step can build a pollable
		// status_url: /api/_jobs/${{steps.x.outputs.job_id}}/status?token=${{steps.x.outputs.status_token}}
		ctx.Data[step.Name] = map[string]any{"job_id": id, "flow": flowName, "status_token": jobToken}
	}
	return nil
}

// execStepWS broadcasts a payload to every WebSocket client joined
// to the named room. Room IDs interpolate flow context variables and
// are scope-namespaced server-side, so a flow firing
// room="order-{{order_id}}" reaches every authenticated client in
// the matching group/user scope. Payload defaults to the full
// JSON-serialized context when not supplied, matching the webhook
// step's convention.
func execStepWS(ctx *FlowContext, step *FlowStep) error {
	if step.WS == nil || step.WS.Room == "" {
		return fmt.Errorf("ws step requires room")
	}
	room := interpolateCtx(step.WS.Room, ctx)
	if room == "" {
		return fmt.Errorf("ws step room interpolated to empty string")
	}
	payload := interpolateCtx(step.WS.Payload, ctx)
	if payload == "" {
		data, _ := json.Marshal(ctx.Data)
		payload = string(data)
	}
	groupID := ""
	if ctx.Session != nil {
		groupID = ctx.Session.EffectiveGroupID()
	}
	return BroadcastWSToRoom(ctx.App, groupID, room, payload)
}

func execStepEmail(ctx *FlowContext, step *FlowStep) error {
	opts, appDir, err := buildEmailOpts(ctx, step)
	if err != nil {
		return err
	}
	return SendEmailOpts(appDir, opts)
}

// buildEmailOpts turns an email step + flow context into the send shape.
// Split out of execStepEmail so the interpolation of every field - From
// and ReplyTo included - is testable without a mail provider.
func buildEmailOpts(ctx *FlowContext, step *FlowStep) (EmailOpts, string, error) {
	if step.Email == nil {
		return EmailOpts{}, "", fmt.Errorf("email step has no config")
	}
	to := interpolateCtx(step.Email.To, ctx)
	subject := interpolateCtx(step.Email.Subject, ctx)

	html, text, err := resolveEmailBody(ctx, step.Email)
	if err != nil {
		return EmailOpts{}, "", err
	}

	appDir := ""
	if ctx.App != nil {
		appDir = ctx.App.Dir
	}

	var atts []EmailAttachment
	for _, a := range step.Email.Attachments {
		content := strings.TrimSpace(interpolateCtx(a.Content, ctx))
		if content == "" {
			continue
		}
		atts = append(atts, EmailAttachment{
			Filename:    interpolateCtx(a.Filename, ctx),
			ContentType: a.ContentType,
			Content:     content,
		})
	}

	return EmailOpts{
		To:          to,
		Subject:     subject,
		BodyHTML:    html,
		BodyText:    text,
		From:        strings.TrimSpace(interpolateCtx(step.Email.From, ctx)),
		ReplyTo:     strings.TrimSpace(interpolateCtx(step.Email.ReplyTo, ctx)),
		Attachments: atts,
	}, appDir, nil
}

// emailTemplateCandidates returns the relative paths tried for an email
// step's `template:` value, in order. A bare name resolves like hook
// emails do (emails/<name>.html), so `template: external-invite`,
// `template: external-invite.html`, and `template: emails/external-invite.html`
// all reach the same file; templates/ is the other carve-out dir for
// full-HTML email bodies.
func emailTemplateCandidates(tmpl string) []string {
	candidates := []string{tmpl}
	if !strings.HasSuffix(tmpl, ".html") {
		candidates = append(candidates, tmpl+".html")
	}
	if !strings.Contains(tmpl, "/") {
		for _, dir := range []string{"emails", "templates"} {
			candidates = append(candidates, filepath.Join(dir, tmpl))
			if !strings.HasSuffix(tmpl, ".html") {
				candidates = append(candidates, filepath.Join(dir, tmpl+".html"))
			}
		}
	}
	return candidates
}

// resolveEmailBody produces the HTML + plain-text bodies for an email
// step. Pre-v2.7.165 this logic only honored `template:` as a literal
// app-root path and passed everything else through as an empty body -
// the provider request then carried no html/text at all and Resend
// 422'd the flow ("Missing 'html' or 'text' field").
func resolveEmailBody(ctx *FlowContext, email *FlowEmail) (html, text string, err error) {
	if email.Html != "" {
		html = interpolateCtx(email.Html, ctx)
	}
	if email.Text != "" {
		text = interpolateCtx(email.Text, ctx)
	}

	if tmpl := email.Template; tmpl != "" && ctx.App != nil {
		// Render context: the flow's flattened data (+ env overlay) with
		// the step's `data:` map interpolated and overlaid on top.
		renderData := flatDataForCtx(ctx)
		for k, v := range email.Data {
			renderData[k] = interpolateCtx(v, ctx)
		}
		found := false
		candidates := emailTemplateCandidates(tmpl)
		appRoot, _ := filepath.Abs(ctx.App.Dir)
		for _, c := range candidates {
			// Contain the candidate to the app dir (mirrors
			// execStepServeFile's uploads/ guard): `template:` is
			// developer-controlled, but a `..`-shaped value must not read
			// outside the app tree (2026-06-11 audit).
			full, absErr := filepath.Abs(filepath.Join(ctx.App.Dir, c))
			if absErr != nil || (full != appRoot && !strings.HasPrefix(full, appRoot+string(os.PathSeparator))) {
				continue
			}
			raw, readErr := os.ReadFile(full)
			if readErr != nil {
				continue
			}
			html = RenderMustache(stripEmailFrontmatter(string(raw)), renderData)
			found = true
			break
		}
		if !found {
			return "", "", fmt.Errorf("email step: template %q not found (tried %s)", tmpl, strings.Join(candidates, ", "))
		}
	}

	if html == "" && text == "" {
		return "", "", fmt.Errorf("email step has no body: set `template: <name>` (rendered from emails/<name>.html) or an inline `html:` / `text:` on the step - the provider rejects body-less messages")
	}
	return html, text, nil
}
