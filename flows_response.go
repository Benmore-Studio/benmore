//go:build !cli

package main

// HTTP response, redirect, and private-upload delivery steps.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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
	// A target built from step values leaves out the app's declared
	// blind-index columns (flows_respond_blind_index.go). A target the
	// author wrote out is sent as written.
	targetBuilt := beginFlowResponse(ctx)
	target := strings.TrimSpace(interpolateCtx(raw, ctx))
	if target != strings.TrimSpace(raw) {
		target = flowResponseURL(ctx, target)
	}
	targetBuilt()
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
		// http.Redirect joins a relative target onto the request path and
		// runs path.Clean, which treats `\` as text: "/./\evil.com" or
		// "../\evil.com" cleaned to "/\evil.com", which browsers follow as
		// "//evil.com". No backslash in the path, and Clean cannot make a
		// protocol-relative prefix (it folds repeated slashes).
		return !strings.Contains(u.Path, `\`) && !strings.Contains(target[:pathEnd(target)], `\`)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || r == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), flowRequestHostname(r))
}

// pathEnd is the length of target's path part: up to the first ? or #.
func pathEnd(target string) int {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		return i
	}
	return len(target)
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
	// The untrimmed value is what a private reference must match: a stored
	// reference never carries surrounding space.
	untrimmed := interpolateCtx(step.ServeFile.Path, ctx)
	raw := strings.TrimSpace(untrimmed)
	// Connector artifacts are served only by GET /api/_mcp/artifacts/{id}.
	if raw == "" || appMCPArtifactStorageReference(raw) {
		httpError(ctx.Writer, "Not found", http.StatusNotFound)
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
		if file, ok := openStoredUpload(uploadsRoot, fullPath); ok {
			localExists = true
			localFile = file
			defer file.Close()
		}
	}
	isCDNURL := cfg != nil && strings.HasPrefix(raw, "https://"+cfg.CDNDomain+"/")
	// The disposition may be a template (`${{ params.dl == '1' &&
	// 'attachment' || 'inline' }}`); anything but "attachment" serves inline.
	// The filename may be one too (`${{ steps.doc.outputs.name }}`).
	attachment := strings.EqualFold(strings.TrimSpace(flowValueTemplate(step.ServeFile.Disposition, ctx)), "attachment")
	filename := strings.TrimSpace(flowValueTemplate(step.ServeFile.Filename, ctx))
	recordID := ""
	if step.UploadRecord != nil {
		recordID = strings.TrimSpace(interpolateCtx(step.UploadRecord.ID, ctx))
	}
	if ctx.hasMissingRefs() {
		// Write nothing: the step dispatcher answers the unresolved
		// reference (template_unresolved) once the step returns.
		return nil
	}

	// A private upload is served only from the reference its upload stored
	// (the delete_upload rule: a query, fragment, space or other spelling
	// names no stored file, and on the CDN would sign a URL the CDN
	// refuses), and only when the caller or the step's `record:` vouches
	// for the uploader, as /api/_signed_url requires (flows_upload_owner.go).
	vouchedLogical := ""
	if serveFileNamesPrivateUpload(ctx.App, raw, cfg) {
		backend := serveFileStorage(ctx.App, cfg)
		logical, err := privateUploadReadPath(ctx.App, backend, untrimmed)
		if err != nil {
			log.Printf("serve_file [%s]: refused a private upload reference that is not in its stored form: %v", filepath.Base(ctx.App.Dir), err)
			httpError(ctx.Writer, "Not found", http.StatusNotFound)
			ctx.Stopped = true
			return nil
		}
		// On local disk a reference that opens no stored file (missing, or
		// another spelling of a stored name: openStoredUpload) is not found
		// before the uploader rule is asked, which would read the respelled
		// reference as a file with no uploader record.
		if _, local := backend.(*LocalStorage); local && !localExists {
			httpError(ctx.Writer, "Not found", http.StatusNotFound)
			ctx.Stopped = true
			return nil
		}
		if why := flowPrivateUploadOwnerRefusal(ctx, step.UploadRecord, recordID, backend, logical); why != "" {
			log.Printf("serve_file [%s]: refused %s: %s", filepath.Base(ctx.App.Dir), logical, why)
			httpError(ctx.Writer, "serve_file: "+why, http.StatusForbidden)
			ctx.Stopped = true
			return nil
		}
		vouchedLogical = logical
	}

	// CDN backend: serve via a CloudFront redirect - SIGNED + short-TTL for
	// private files (the flow has already authorized this request), plain
	// for public. Bytes never transit the app; the URL is on the cookieless
	// origin. Prefer a still-present LOCAL file over a maybe-missing S3
	// object (pre-migration window): only go to CDN for an actual CDN URL,
	// or a logical path whose local file is absent (migrated / new upload).
	if cfg != nil && (isCDNURL || !localExists) {
		if url, isPrivate, ok := cdnURLForServe(ctx.App, raw, cfg); ok {
			// A redirect cannot name the download: the CDN answers with the
			// headers stored on the object, and a signed CloudFront URL
			// carries response-content-disposition to the bucket only if the
			// distribution forwards that query string, which the framework
			// cannot check. A download is streamed through the app instead,
			// from a short-lived signed URL that never leaves this process.
			if attachment {
				streamCDNDownload(ctx, cfg, url, isPrivate, filename)
				ctx.Stopped = true
				return nil
			}
			target := url
			if isPrivate {
				// Short by default; audio/video lasts long enough to play to
				// the end, because the player keeps range-requesting the URL it
				// was redirected to (signedLinkTTL).
				ttl := signedLinkTTL(url, step.ServeFile.ExpiresIn, serveFileSignTTL)
				signed, err := signPrivateMediaURL(ctx.App, cfg, url, ttl)
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
		httpError(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	// The bytes come from the symlink-resolved file. One that resolves into
	// a private folder must be the private reference vouched for above, not
	// an alias reaching it from a public path (the /uploads/ route re-checks
	// the resolved path the same way).
	if resolved := "uploads/" + filepath.ToSlash(localFile.relative); isPrivateUploadPath(strings.ToLower(resolved)) && resolved != vouchedLogical {
		httpError(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	// XSS-safe content-type/disposition defaults (forces attachment for
	// active content like .html/.svg even when inline is requested).
	applyUploadFileDispositionHeaders(ctx.Writer, fullPath, localFile)
	// Explicit attachment override (the "Download" affordance) wins. The
	// name's extension follows the stored file's (serveFileDownloadName).
	if attachment {
		ctx.Writer.Header().Set("Content-Disposition", serveFileContentDisposition("attachment", serveFileDownloadName(filename, filepath.Base(fullPath))))
	} else if filename != "" {
		// Inline with a suggested filename (only set if the safety helper
		// left it inline - i.e. it didn't force an attachment).
		if ctx.Writer.Header().Get("Content-Disposition") == "" {
			ctx.Writer.Header().Set("Content-Disposition", serveFileContentDisposition("inline", serveFileDownloadName(filename, filepath.Base(fullPath))))
		}
	}
	// Serve from the validated handle, retaining Range and cache support.
	localFile.serveHTTP(ctx.Writer, ctx.Request)
	ctx.Stopped = true
	return nil
}

// serveFileDownloadName is the download name a serve_file response offers:
// the step's `filename:` (else the stored name) cut to a safe name whose
// extension is one of the stored file's type, run: proxy's rule
// (proxyDownloadName). A name a user wrote into a row cannot present a CSV
// as `page.html` or carry its own Content-Disposition parameters. "" sends
// no name.
func serveFileDownloadName(name, storedName string) string {
	ext := strings.ToLower(filepath.Ext(storedName))
	if !proxyExtensionRe.MatchString(ext) {
		return ""
	}
	exts := []string{ext}
	if mediaType, _, err := mime.ParseMediaType(mime.TypeByExtension(ext)); err == nil {
		if known := proxyTypeExtensions[mediaType]; slices.Contains(known, ext) {
			exts = known
		}
	}
	if out := downloadNameWithExtension(proxySafeFilename(name), exts); out != "" {
		return out
	}
	return downloadNameWithExtension(proxySafeFilename(storedName), exts)
}

// serveFileContentDisposition formats a Content-Disposition (RFC 6266, as
// run: proxy sends it) with an optional download name.
func serveFileContentDisposition(disposition, name string) string {
	if name == "" {
		return disposition
	}
	if v := mime.FormatMediaType(disposition, map[string]string{"filename": name}); v != "" {
		return v
	}
	return disposition
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
	recordID := ""
	if step.UploadRecord != nil {
		recordID = strings.TrimSpace(interpolateCtx(step.UploadRecord.ID, ctx))
	}
	if ctx.hasMissingRefs() {
		// Delete nothing: the step dispatcher reports the unresolved
		// reference once the step returns.
		return nil
	}
	// The reference must also be the caller's (or the record's) to delete,
	// as for serve_file (flows_upload_owner.go). A public file is deleted
	// only on that proof: `record:` is required for it.
	return deleteUploadAuthorized(ctx.App, target, func(backend StorageBackend, logical string, public bool) error {
		why := ""
		if public {
			why = flowPublicUploadOwnerRefusal(ctx, step.UploadRecord, recordID, backend, logical)
		} else {
			why = flowPrivateUploadOwnerRefusal(ctx, step.UploadRecord, recordID, backend, logical)
		}
		if why != "" {
			return fmt.Errorf("delete_upload refused: %s", why)
		}
		return nil
	})
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
	// The response leaves out the app's declared blind-index columns; the
	// step outputs it is built from keep them (flows_respond_blind_index.go).
	defer beginFlowResponse(ctx)()
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
		writeRespondUnresolved(ctx, step, append(missing, more...))
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
			overlayRequestOnlyParams(flat, ctx)
			ctxVal, ok := flowLookup(flat, key)
			if !ok {
				ctxVal, ok = flowDataValue(ctx, key)
			}
			if ok {
				ctxVal = flowResponseValue(ctx, ctxVal)
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
				"docs":           refusalDocsAt("template_unresolved", ""),
			}
			if keys := flowDiagnosticKeys(ctx); keys != nil {
				envelope["available_keys"] = keys
			}
			ctx.Writer.Header().Set("Content-Type", "application/json")
			ctx.Writer.WriteHeader(500)
			json.NewEncoder(ctx.Writer).Encode(envelope)
			ctx.noteRespondFailure(step, []string{key})
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
		resolved := flowResponseValue(ctx, resolveJSONValue(r.JSONArray, ctx))
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(resolved); err != nil {
			return err
		}
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx, step, missing)
			ctx.Stopped = true
			return nil
		}
		write(jsonType, buf.Bytes())
	} else if r.JSON != nil {
		// Interpolate {{var}} placeholders in JSON values before encoding
		resolved := flowResponseValue(ctx, interpolateJSONValues(r.JSON, ctx))
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx, step, missing)
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
			writeRespondUnresolved(ctx, step, missing)
			ctx.Stopped = true
			return nil
		}
		// A declared type is sent as declared, the body as written.
		contentType := r.ContentType
		if contentType == "" && ctx.Writer.Header().Get("Content-Type") == "" {
			contentType = respondBodyContentType(r.Body, rendered)
		}
		write(contentType, []byte(rendered))
	} else {
		// No body: the status (with any headers) is the answer. This step
		// used to write nothing and leave the run going, so a 403 guard
		// written without a body let the steps after it run, and a flow
		// that ended on `status: 204` committed and answered 500
		// flow_no_response.
		write(r.ContentType, nil)
	}
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
func writeRespondUnresolved(ctx *FlowContext, step *FlowStep, missing []string) {
	ctx.noteRespondFailure(step, missing)
	envelope := map[string]any{
		"error":           "template_unresolved",
		"unresolved_refs": missing,
		"hint":            "the respond step's body referenced template variables that didn't resolve. Most common: (a) the step you reference has no `id:` set, (b) you used `${{ steps.<id>.outputs.<col> }}` but the upstream SQL was INSERT/UPDATE without RETURNING - add RETURNING <col> so the value is captured, (c) you referenced `${{ user.<field> }}` on a route without `auth: required`. Pre-v2.7.5 the literal placeholder text would have been baked into the response - now it's surfaced explicitly here.",
		"request_id":      recordRespondUnresolved(ctx, missing),
		"docs":            refusalDocsAt("template_unresolved", ""),
	}
	if keys := flowDiagnosticKeys(ctx); keys != nil {
		envelope["available_keys"] = keys
	}
	w := ctx.Writer
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(envelope)
}

// noteRespondFailure records that a respond step answered template_unresolved
// in place of its own answer. The step returns no error (the envelope is the
// answer, and an on_error handler does not run for it), so without this
// record the run looked successful: a `transaction: true` request flow
// committed its order, stock and queued jobs behind a 500, and the caller's
// retry wrote them again. executeFlowHTTP reads it to roll back.
func (ctx *FlowContext) noteRespondFailure(step *FlowStep, missing []string) {
	ctx.respondFailure = errors.New("template_unresolved: " + strings.Join(missing, ", "))
	ctx.respondFailureStep = "respond"
	if step != nil && step.Name != "" {
		ctx.respondFailureStep = flowStepDisplayName(step.Name)
	}
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
// (a hosted `<sub>-dev` instance, or App.DevMode in tests). The names include
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
