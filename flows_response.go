//go:build !cli

package main

// HTTP response, redirect, and private-upload delivery steps.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func execStepRedirect(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	target, err := flowRedirectTarget(ctx, step)
	if err != nil {
		return err
	}
	http.Redirect(ctx.Writer, ctx.Request, target, http.StatusSeeOther)
	ctx.Stopped = true
	return nil
}

// flowRedirectTarget resolves a `run: redirect` target and refuses an open
// redirect. A rendered target is allowed when it is same-origin (a relative
// reference, or an http(s) URL on the request's own host). An off-origin
// target is allowed only when `to:` is a literal the author wrote (nothing
// was substituted into it) or, for http(s), when its host is listed in the
// step's `allow_hosts:`. Anything else fails the step, so a templated
// `to: ${{ params.next }}` can no longer bounce a visitor to an attacker's
// site.
func flowRedirectTarget(ctx *FlowContext, step *FlowStep) (string, error) {
	raw := step.Redirect
	target := strings.TrimSpace(interpolateCtx(raw, ctx))
	label := step.Name
	if label == "" {
		label = "redirect"
	}
	if target == "" {
		return "", fmt.Errorf("redirect: step %q rendered an empty `to:`", label)
	}
	for i := 0; i < len(target); i++ {
		// Browsers delete tab/CR/LF before parsing a Location, so
		// "/\t/evil.com" would be followed as "//evil.com".
		if target[i] < 0x20 || target[i] == 0x7f {
			return "", fmt.Errorf("redirect: step %q target contains a control character", label)
		}
	}
	if flowRedirectSameOrigin(target, ctx.Request) {
		return target, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("redirect: step %q target is not a valid URL", label)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "javascript", "vbscript", "data", "file":
		return "", fmt.Errorf("redirect: step %q refuses a %s: target", label, scheme)
	}
	literal := !strings.Contains(raw, "{{") && strings.TrimSpace(raw) == target
	if literal {
		return target, nil
	}
	if (scheme == "http" || scheme == "https") && u.Host != "" {
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		for _, allowed := range step.RedirectAllowHosts {
			if host == allowed {
				return target, nil
			}
		}
		return "", fmt.Errorf("redirect: step %q refused off-origin target host %q: a templated `to:` may only redirect within this app; list trusted hosts under `with: { allow_hosts: [%s] }`", label, host, host)
	}
	return "", fmt.Errorf("redirect: step %q refused off-origin target: a templated `to:` must render a same-origin path or an http(s) URL whose host is listed in `allow_hosts:`", label)
}

// flowRedirectSameOrigin reports whether target stays on the request's own
// origin: a relative reference that cannot be read as protocol-relative
// ("//host", "\\host", "/\\host"), or an http(s) URL whose host is the
// request's host.
func flowRedirectSameOrigin(target string, r *http.Request) bool {
	if strings.HasPrefix(target, "//") || strings.HasPrefix(target, `\`) || strings.HasPrefix(target, `/\`) {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	if u.Scheme == "" && u.Host == "" && u.Opaque == "" {
		return true
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || r == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), flowRequestHostname(r))
}

// flowRequestHostname is the request Host without its port.
func flowRequestHostname(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.Trim(host, "[]"), ".")
}

// flowRedirectAllowHosts normalizes a redirect step's `allow_hosts:` value
// (a YAML list or a comma-separated string, like auth's `allow_emails`) to
// lowercase bare hostnames. A pasted URL contributes its hostname.
func flowRedirectAllowHosts(v any) []string {
	var items []string
	switch t := v.(type) {
	case string:
		items = strings.Split(t, ",")
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				items = append(items, s)
			}
		}
	case []string:
		items = t
	}
	var out []string
	for _, item := range items {
		h := strings.ToLower(strings.TrimSpace(item))
		if strings.Contains(h, "://") {
			if u, err := url.Parse(h); err == nil {
				h = u.Hostname()
			}
		}
		h = strings.TrimSuffix(h, ".")
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// execStepServeFile streams a file from the app's uploads/ directory as
// the terminal response. The flow itself is the authorization gate - it
// reads the bytes off disk directly, bypassing the /uploads/ HTTP route
// - so a flow that has already validated (e.g.) a data-room share token
// can serve a PRIVATE file (uploads/private/...) to an anonymous caller
// WITHOUT minting a signed URL. No signed URL escapes to be reshared;
// the gate is the only path to the bytes.
func execStepServeFile(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	if step.ServeFile == nil || step.ServeFile.Path == "" {
		return fmt.Errorf("serve_file step missing `path:` - point at an uploaded file, e.g. path: ${{ steps.item.outputs.file_url }}")
	}
	raw := strings.TrimSpace(interpolateCtx(step.ServeFile.Path, ctx))
	// Connector artifacts are served only by GET /api/_mcp/artifacts/{id}.
	if raw == "" || appMCPArtifactStorageReference(raw) {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	cfg := getPlatformMedia()

	// Compute the local-disk candidate once (traversal-guarded to uploads/).
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimPrefix(raw, "/"), "uploads/"))
	uploadsRoot := filepath.Join(ctx.App.Dir, "uploads")
	fullPath := filepath.Join(uploadsRoot, rel)
	inUploads := fullPath == uploadsRoot || strings.HasPrefix(fullPath, uploadsRoot+string(os.PathSeparator))
	localExists := false
	var localFile *servableFile
	if inUploads {
		// Resolve symlinks: a link under uploads/ must not serve bytes from
		// outside it (another tenant's tree, env.yaml). Same rule as static.
		if file, ok := openServableFile(uploadsRoot, fullPath); ok {
			localExists = true
			localFile = file
			defer file.Close()
		}
	}
	isCDNURL := cfg != nil && strings.HasPrefix(raw, "https://"+cfg.CDNDomain+"/")

	// CDN backend: serve via a CloudFront redirect - SIGNED + short-TTL for
	// private files (the flow has already authorized this request), plain
	// for public. Bytes never transit the app; the URL is on the cookieless
	// origin. Prefer a still-present LOCAL file over a maybe-missing S3
	// object (pre-migration window): only go to CDN for an actual CDN URL,
	// or a logical path whose local file is absent (migrated / new upload).
	if cfg != nil && (isCDNURL || !localExists) {
		if url, isPrivate, ok := cdnURLForServe(ctx.App, raw, cfg); ok {
			target := url
			if isPrivate {
				signed, err := signPrivateMediaURL(ctx.App, cfg, url, 120*time.Second)
				if err != nil {
					serverError(ctx.Writer, ctx.Request, ctx.App, "serve_file", err, "media signing unavailable")
					ctx.Stopped = true
					return nil
				}
				target = signed
			}
			http.Redirect(ctx.Writer, ctx.Request, target, http.StatusFound)
			ctx.Stopped = true
			return nil
		}
	}

	// Local-disk serve (file present on disk, or CDN not configured).
	if !inUploads || !localExists {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	// XSS-safe content-type/disposition defaults (forces attachment for
	// active content like .html/.svg even when inline is requested).
	applyUploadFileDispositionHeaders(ctx.Writer, fullPath, localFile)
	// Explicit attachment override (the "Download" affordance) wins. The
	// disposition may be a template (`${{ params.dl == '1' && 'attachment'
	// || 'inline' }}`); anything but "attachment" serves inline.
	disposition := strings.TrimSpace(flowValueTemplate(step.ServeFile.Disposition, ctx))
	if strings.EqualFold(disposition, "attachment") {
		name := step.ServeFile.Filename
		if name == "" {
			name = filepath.Base(fullPath)
		}
		ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	} else if step.ServeFile.Filename != "" {
		// Inline with a suggested filename (only set if the safety helper
		// left it inline - i.e. it didn't force an attachment).
		if ctx.Writer.Header().Get("Content-Disposition") == "" {
			ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename=%q`, step.ServeFile.Filename))
		}
	}
	// Serve from the validated handle, retaining Range and cache support.
	localFile.serveHTTP(ctx.Writer, ctx.Request)
	ctx.Stopped = true
	return nil
}

func execStepDeleteUpload(ctx *FlowContext, step *FlowStep) error {
	if step.DeleteUpload == "" {
		return fmt.Errorf("delete_upload step missing `path:`")
	}
	target := interpolateCtx(step.DeleteUpload, ctx)
	// Connector artifacts are immutable, hash-verified exports; a flow deleting
	// their bytes would leave the owner's download failing its integrity check.
	if appMCPArtifactStorageReference(target) {
		return fmt.Errorf("delete_upload cannot remove connector artifact storage")
	}
	return deletePrivateUpload(ctx.App, target)
}

func execStepRespond(ctx *FlowContext, step *FlowStep) error {
	if ctx != nil && ctx.command != nil {
		return ctx.command.respond(ctx, step)
	}
	if ctx.Writer == nil {
		return nil
	}
	r := step.Respond
	if r == nil {
		return nil
	}
	// Public flows may also read a signed-in caller's identity. Cookie
	// authentication does not keep max-age/Expires responses out of shared
	// caches. Protect both success and error responses, regardless of the
	// authored cache directives (including qualified `private="field"`).
	privateResponse := ctx.Session != nil || ctx.privateResponse
	if privateResponse {
		ctx.Writer.Header().Set("Cache-Control", "private, no-store")
	}
	// The status and the headers are rendered first: a status that is not an
	// HTTP status, or a header value that could not be sent, fails the step
	// before anything is written (a templated status used to go out as 200).
	status, missing, err := respondStatus(ctx, r)
	if err != nil {
		return err
	}
	headers, headerErr := renderRespondHeaders(ctx, r)
	if more := ctx.takeMissingRefs(); len(missing)+len(more) > 0 {
		writeRespondUnresolved(ctx, append(missing, more...))
		ctx.Stopped = true
		return nil
	}
	if headerErr != nil {
		return headerErr
	}
	// write sends the response with the step's own headers. They are set
	// only here, so an error envelope never carries them (a JSON error
	// offered as a download).
	write := func(contentType string, body []byte) {
		h := ctx.Writer.Header()
		applyRespondHeaders(h, headers)
		if privateResponse {
			h.Set("Cache-Control", "private, no-store")
		}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write(body)
		ctx.Stopped = true
	}
	// A map or list body is JSON; the loader keeps a declared type on it
	// only when that type is JSON.
	jsonType := "application/json"
	if r.ContentType != "" {
		jsonType = r.ContentType
	}
	// Bare-template body shortcut. When body is a single `{{var}}` or
	// `{{var.path}}` reference, resolve it from context - including
	// dotted/indexed paths through flattenData - and marshal the
	// resolved value as JSON directly. Closes the gap where every
	// agent's "respond with the rows from my SQL query" intent had to
	// be wrapped as `json: { rows: "{{rows}}" }`. Under a declared
	// content type the value is sent as the text it is (respondTextValue).
	if r.Body != "" {
		trimmed := strings.TrimSpace(r.Body)
		if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") && strings.Count(trimmed, "{{") == 1 {
			key := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			// Try the flattened path map first so dotted/indexed
			// accesses like `stories.0`, `user.email` resolve.
			flat := flattenData(ctx.Data)
			ctxVal, ok := flowLookup(flat, key)
			if !ok {
				ctxVal, ok = flowDataValue(ctx, key)
			}
			if ok {
				if r.ContentType == "" {
					body, err := marshalRespondJSON(ctxVal)
					if err != nil {
						return err
					}
					write("application/json", body)
					return nil
				}
				body, err := respondTextValue(ctxVal, r.ContentType)
				if err != nil {
					return err
				}
				write(r.ContentType, body)
				return nil
			}
			// Bare template that didn't resolve. Fail loudly with a
			// diagnostic that names the missing key + what's actually
			// in ctx.Data. Pre-v2.3.2 we fell through and wrote the
			// literal `{{key}}` to the response - the storyforge
			// debugging session was filled with this footgun.
			envelope := map[string]any{
				"error":          "template_unresolved",
				"unresolved_key": key,
				"hint":           "the body template referenced {{" + key + "}} but no step produced that key. Check (a) the step that should produce it has `id: <name>` set, (b) the path matches (steps.<id>.outputs / steps.<id>.outputs.rows / steps.<id>.outputs[0]), (c) the step actually ran (no prior step errored). Run describe_flows to see the resolved step list.",
				"request_id":     recordRespondUnresolved(ctx, []string{key}),
			}
			if keys := flowDiagnosticKeys(ctx); keys != nil {
				envelope["available_keys"] = keys
			}
			ctx.Writer.Header().Set("Content-Type", "application/json")
			ctx.Writer.WriteHeader(500)
			json.NewEncoder(ctx.Writer).Encode(envelope)
			ctx.Stopped = true
			return nil
		}
	}
	// Render into a buffer first, then check ctx.MissingRefs, THEN write
	// the response. Pre-v2.7.5 we wrote headers + status before
	// interpolation finished - by the time the dispatcher noticed the
	// unresolved `${{ ... }}` references, a 200 + half-broken body was
	// already on the wire. Now: if any reference failed to resolve, we
	// emit a 500 with a structured `template_unresolved` envelope
	// instead of the half-broken success response.
	if r.JSONArray != nil {
		resolved := resolveJSONValue(r.JSONArray, ctx)
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(resolved); err != nil {
			return err
		}
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx, missing)
			ctx.Stopped = true
			return nil
		}
		write(jsonType, buf.Bytes())
	} else if r.JSON != nil {
		// Interpolate {{var}} placeholders in JSON values before encoding
		resolved := interpolateJSONValues(r.JSON, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx, missing)
			ctx.Stopped = true
			return nil
		}
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(resolved); err != nil {
			return err
		}
		write(jsonType, buf.Bytes())
	} else if r.Body != "" {
		rendered := interpolateCtx(r.Body, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx, missing)
			ctx.Stopped = true
			return nil
		}
		// A declared type is sent as declared, the body as written.
		contentType := r.ContentType
		if contentType == "" && ctx.Writer.Header().Get("Content-Type") == "" {
			contentType = respondBodyContentType(r.Body, rendered)
		}
		write(contentType, []byte(rendered))
	}
	// If we got here without writing, fall through to the global
	// default-response path in executeFlow (which now emits a 500
	// + flow_no_response diagnostic instead of "status: ok").
	return nil
}

// respondBodyContentType types a `respond:` text body from the author's
// template with every `{{ }}` ref removed. Leaving it to net/http's sniffing
// typed the RENDERED body, so a request value at the start of a plain-text
// response (`${{ params.q }} not found`) could make it an HTML page. A body
// that is only refs (a stored file, an upstream response) is typed from the
// rendered bytes, except that it is never served as HTML or XML.
func respondBodyContentType(template, rendered string) string {
	literal := respondTemplateLiteral(template)
	if strings.TrimSpace(literal) != "" {
		return http.DetectContentType([]byte(literal))
	}
	ct := http.DetectContentType([]byte(rendered))
	if strings.HasPrefix(ct, "text/html") || strings.HasPrefix(ct, "text/xml") {
		return "text/plain; charset=utf-8"
	}
	return ct
}

// respondTemplateLiteral is template with every `{{ }}` ref removed.
func respondTemplateLiteral(template string) string {
	var b strings.Builder
	for {
		i := strings.Index(template, "{{")
		if i < 0 {
			b.WriteString(template)
			break
		}
		b.WriteString(template[:i])
		end := strings.Index(template[i+2:], "}}")
		if end < 0 {
			break
		}
		template = template[i+2+end+2:]
	}
	return b.String()
}

// writeRespondUnresolved emits the 500 envelope the dispatcher uses for
// respond steps whose template body referenced unresolved `${{ ... }}`
// expressions. Lists the missing refs + a sorted snapshot of what was
// in ctx.Data, so the agent can see whether the missing key is a typo,
// a step that didn't run, or a name they expected the framework to
// provide automatically (e.g. an unresolved `${{ user.first_name }}`
// when auth wasn't required on the route). The keys are listed only for a
// development app (flowDiagnosticKeys); the field is omitted otherwise.
func writeRespondUnresolved(ctx *FlowContext, missing []string) {
	envelope := map[string]any{
		"error":           "template_unresolved",
		"unresolved_refs": missing,
		"hint":            "the respond step's body referenced template variables that didn't resolve. Most common: (a) the step you reference has no `id:` set, (b) you used `${{ steps.<id>.outputs.<col> }}` but the upstream SQL was INSERT/UPDATE without RETURNING - add RETURNING <col> so the value is captured, (c) you referenced `${{ user.<field> }}` on a route without `auth: required`. Pre-v2.7.5 the literal placeholder text would have been baked into the response - now it's surfaced explicitly here.",
		"request_id":      recordRespondUnresolved(ctx, missing),
	}
	if keys := flowDiagnosticKeys(ctx); keys != nil {
		envelope["available_keys"] = keys
	}
	w := ctx.Writer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(envelope)
}

// recordRespondUnresolved keeps a template_unresolved halt server-side (the
// respond step answers 500 without a step error, so the flow's own failure
// record never sees it), sets the answer's X-Request-Id and returns the id.
func recordRespondUnresolved(ctx *FlowContext, missing []string) string {
	id := noteServerError(ctx.Request, "flow respond", errors.New("template_unresolved: "+strings.Join(missing, ", ")))
	ctx.Writer.Header().Set(requestIDHeader, id)
	return id
}

// flowDiagnosticKeys lists the run's top-level data keys for a
// template_unresolved response, sorted - but only for a development app
// (`serve --dev`, or a hosted `<sub>-dev` instance). The names include
// request fields and internal step ids, which a production caller has no
// need to see; there the server log and describe_flows remain.
func flowDiagnosticKeys(ctx *FlowContext) []string {
	if ctx == nil || ctx.App == nil {
		return nil
	}
	if !ctx.App.DevMode && !IsDevSubdomain(filepath.Base(ctx.App.Dir)) {
		return nil
	}
	keys := make([]string, 0, len(ctx.Data))
	for k := range ctx.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
