//go:build !cli

package main

// Queue, real-time messaging, and email delivery steps.

import (
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"sort"
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
	// A request-controlled flow name would run any app flow through the
	// worker, skipping the target flow's auth/role gate.
	if key := ctx.taintedRef(step.Enqueue.Flow); key != "" {
		return fmt.Errorf("enqueue: step %q builds the target flow name from request-sourced value %q; the flow name must be a fixed literal (branch with `if:` steps to enqueue one of several known flows)", step.Name, key)
	}
	flowName := interpolateCtx(step.Enqueue.Flow, ctx)
	payload := map[string]any{}
	var tainted, secret []string
	for k, v := range step.Enqueue.With {
		payload[k] = interpolateCtx(v, ctx)
		if ctx.taintedRef(v) != "" {
			tainted = append(tainted, k)
		}
		if ctx.readsSecret(v) {
			secret = append(secret, k)
		}
	}
	// Explicit enqueue jobs are sessionless. Only the async HTTP entry point
	// may attach an actor snapshot; a with: value can contain request input.
	delete(payload, flowJobActorPayloadField)
	// A payload value computed from request input is still request input in
	// the job flow. Carry the taint across the queue the same way an async
	// HTTP flow does (executeFlowJob → takeFlowRequestKeys), written after
	// the copy so no `with:` key can forge or clear it.
	if len(tainted) > 0 {
		sort.Strings(tainted)
		payload[flowRequestKeysPayloadField] = tainted
	} else {
		delete(payload, flowRequestKeysPayloadField)
	}
	// An env-derived payload value stays secret-derived in the job flow
	// (flows_taint.go), carried the same way.
	if len(secret) > 0 {
		sort.Strings(secret)
		payload[flowSecretKeysPayloadField] = secret
	} else {
		delete(payload, flowSecretKeysPayloadField)
	}
	var runAt *time.Time
	if step.Enqueue.RunAt != "" {
		v := interpolateCtx(step.Enqueue.RunAt, ctx)
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fmt.Errorf("enqueue: run_at must resolve to an RFC3339 timestamp")
		}
		runAt = &t
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
		ctx.transactionMutex().Lock()
		id, jobToken, err = EnqueueJobTxUnique(ctx.Tx, uniqueKey, flowName, payload, runAt)
		ctx.transactionMutex().Unlock()
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
// the matching group/user scope. A step with no payload (or one that
// renders empty) sends the minimal event `{}`: room members are clients,
// and an undeclared room is open to any signed-in user of the app or
// tenant, so the flow context (request fields, the caller's user row, step
// outputs, enqueue status tokens) is never sent by default. Declare the
// payload the client reads.
func execStepWS(ctx *FlowContext, step *FlowStep) error {
	if step.WS == nil || step.WS.Room == "" {
		return fmt.Errorf("ws step requires room")
	}
	room := interpolateCtx(step.WS.Room, ctx)
	if room == "" {
		return fmt.Errorf("ws step room interpolated to empty string")
	}
	payload := interpolateCtxJSON(step.WS.Payload, ctx)
	if payload == "" {
		payload = "{}"
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
	// Part by part: a substituted value is one recipient (email_recipients.go).
	to, err := emailRecipients(step.Email.To, func(part string) string { return interpolateCtx(part, ctx) })
	if err != nil {
		return EmailOpts{}, "", err
	}
	cc, err := emailRecipients(step.Email.CC, func(part string) string { return interpolateCtx(part, ctx) })
	if err != nil {
		return EmailOpts{}, "", fmt.Errorf("cc: %w", err)
	}
	bcc, err := emailRecipients(step.Email.BCC, func(part string) string { return interpolateCtx(part, ctx) })
	if err != nil {
		return EmailOpts{}, "", fmt.Errorf("bcc: %w", err)
	}
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

	unsubscribe := flowEmailUnsubscribeURL(ctx, step.Email.UnsubscribeURL)
	oneClick := false
	if step.Email.UnsubscribeOneClick != "" {
		switch strings.TrimSpace(interpolateCtx(step.Email.UnsubscribeOneClick, ctx)) {
		case "true":
			oneClick = true
		case "false":
		default:
			return EmailOpts{}, "", fmt.Errorf("unsubscribe_one_click must resolve to true or false")
		}
	}
	if oneClick && emailOneClickURLProblem(unsubscribe) != "" {
		return EmailOpts{}, "", fmt.Errorf("one-click unsubscribe requires a valid https unsubscribe_url")
	}

	return EmailOpts{
		To: to,
		CC: cc, BCC: bcc, UnsubscribeOneClick: oneClick,
		Subject:        subject,
		BodyHTML:       html,
		BodyText:       text,
		From:           strings.TrimSpace(interpolateCtx(step.Email.From, ctx)),
		ReplyTo:        strings.TrimSpace(interpolateCtx(step.Email.ReplyTo, ctx)),
		Attachments:    atts,
		UnsubscribeURL: unsubscribe,
	}, appDir, nil
}

// flowEmailUnsubscribeURL renders an email step's `unsubscribe_url` into the
// List-Unsubscribe target. The header is optional and the message is not: a
// value that renders empty, holds a reference with no value, or is not a plain
// https URL sends the message WITHOUT the header and logs a WARNING naming the
// step. A security alert must not be lost because its unsubscribe link was
// bad (an app that builds the link from an unset base URL). A literal
// non-https value is refused at write time (flowStepValueProblems).
//
// One-click is an explicit opt-in handled by buildEmailOpts; it fails closed
// if this optional header resolver cannot produce a valid URL.
func flowEmailUnsubscribeURL(ctx *FlowContext, template string) string {
	if template == "" {
		return ""
	}
	// The URL's own unresolved references only drop the header; those of the
	// step's other fields are left for the dispatcher, as before.
	earlier := ctx.takeMissingRefs()
	rendered := strings.TrimSpace(interpolateCtx(template, ctx))
	own := ctx.takeMissingRefs()
	for _, ref := range earlier {
		ctx.noteMissingRef(ref)
	}
	where := "a job"
	if ctx.Request != nil && ctx.Request.URL != nil {
		where = ctx.Request.Method + " " + ctx.Request.URL.Path
	}
	if len(own) > 0 {
		log.Printf("WARNING: %s: email sent without List-Unsubscribe: unsubscribe_url references %s, which had no value in scope (write `| default:''` for an optional URL)", where, strings.Join(own, ", "))
		return ""
	}
	if rendered == "" {
		return ""
	}
	if problem := emailUnsubscribeURLProblem(rendered); problem != "" {
		log.Printf("WARNING: %s: email sent without List-Unsubscribe: unsubscribe_url %s", where, problem)
		return ""
	}
	return rendered
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
		// HTML: values are escaped for where they land (html_template.go).
		html = interpolateCtxHTML(email.Html, ctx)
	}
	if email.Text != "" {
		text = interpolateCtx(email.Text, ctx)
	}

	if tmpl := email.Template; tmpl != "" && ctx.App != nil {
		// Render context: the flow's flattened data (+ env overlay) with
		// the step's `data:` map interpolated and overlaid on top.
		// Cloned: flatDataForCtx returns the run's shared cached table.
		renderData := maps.Clone(flatDataForCtx(ctx))
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
			// A reviewed app reads the bytes its digest captured, so a template
			// the runtime-source digest does not bind (docs/x.html) is not found.
			raw, readErr := ctx.App.readSourceFile(c)
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
