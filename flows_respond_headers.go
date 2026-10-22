//go:build !cli

package main

// Response headers and the content type a `run: respond` step may set.
//
// `with.headers` and `with.content_type` used to be accepted and dropped, so
// a CSV export answered as application/json holding a JSON string. They are
// read now, through an allowlist: a flow may describe its response (type,
// download name, caching, language, validators, links) and add its own X-
// headers, and nothing else. Cookies, CSP, CORS, HSTS, framing, redirects,
// message framing and every header the framework, the router or a proxy in
// front of them sets or acts on stay the framework's. The write gate refuses
// any other header (flowStepValueProblems); the loader drops it from a
// deployed file and logs the same line.
//
// Content-Type and Cache-Control must be literal text: a request value must
// not be able to turn a response into an HTML page, or mark it storable by a
// shared cache. Other values may be templates; a rendered value holding a
// line break or another control character (header injection) or longer than
// respondHeaderValueMax fails the step.
//
// A declared content type changes how a text body is sent (execStepRespond):
//   - no declared type: as before. A body that is one `${{ }}` reference is
//     JSON-encoded; other text is typed from its template.
//   - a JSON type (application/json, */*+json): a map or list body is
//     JSON-encoded as before; a text body is sent as written, and a body
//     that is one reference sends a text value as written and any other
//     value JSON-encoded.
//   - any other type: a text body is sent as written. A body that is one
//     reference sends a text value as written and a number or boolean as its
//     text; a list or object fails the step. A map or list body cannot take
//     such a type (refused at write time; a deployed file keeps sending
//     application/json).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// respondHeaderValueMax caps one rendered response header value.
const respondHeaderValueMax = 4096

// respondHeaderNames are the headers without an X- prefix a respond step may
// set, in canonical form (http.CanonicalHeaderKey writes ETag as Etag).
var respondHeaderNames = map[string]bool{
	"Content-Type": true, "Content-Disposition": true, "Cache-Control": true,
	"Content-Language": true, "Etag": true, "Last-Modified": true,
	"Expires": true, "Vary": true, "Link": true,
}

// respondHeadersAllowedText lists the allowlist for messages and docs.
const respondHeadersAllowedText = "Content-Type (or `content_type:`), Content-Disposition, Cache-Control, Content-Language, ETag, Last-Modified, Expires, Vary, Link, and X- headers the framework does not use"

// respondReservedXHeaders are X- headers the framework or the router sets or
// reads, the legacy names of security headers, and the ones a proxy or web
// server in front of an app acts on.
var respondReservedXHeaders = map[string]bool{
	"X-Frame-Options": true, "X-Content-Type-Options": true, "X-Xss-Protection": true,
	"X-Content-Security-Policy": true, "X-Webkit-Csp": true,
	"X-Permitted-Cross-Domain-Policies": true, "X-Dns-Prefetch-Control": true,
	"X-Download-Options": true, "X-Ua-Compatible": true,
	"X-Real-Ip": true, "X-Request-Id": true, "X-Csrf-Token": true, "X-Mfa-Setup-Token": true,
	"X-Idempotency-Key": true, "X-Expected-Updated-At": true, "X-Member-Of-Autojoin": true,
	"X-Stripped-Fields": true, "X-Internal-Probe": true,
	"X-Http-Method-Override": true, "X-Http-Method": true, "X-Method-Override": true,
	"X-Original-Url": true, "X-Rewrite-Url": true,
	"X-Sendfile": true, "X-Lighttpd-Send-File": true,
}

// respondReservedXPrefixes are reserved X- header families: the framework's
// and the router's own, forwarding headers, and nginx's internal redirect
// and buffering controls.
var respondReservedXPrefixes = []string{"X-Benmore-", "X-Forwarded-", "X-Accel-"}

// respondHeaderRefusal returns why a respond step may not set the header
// with this canonical name, or "" when it may.
func respondHeaderRefusal(name string) string {
	if name == "" || len(name) > 64 || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return "is not a header name (letters, digits and hyphens)"
	}
	lower := strings.ToLower(name)
	switch {
	case lower == "set-cookie" || lower == "set-cookie2":
		return "is refused: a flow response may not set cookies (sessions and sign-in cookies are the framework's)"
	case strings.HasPrefix(lower, "content-security-policy"), lower == "x-content-security-policy", lower == "x-webkit-csp":
		return "is refused: the Content-Security-Policy is the framework's (app.yaml `csp:`)"
	case strings.HasPrefix(lower, "access-control-"):
		return "is refused: CORS is configured for the whole app (the CORS_ORIGIN env var), not per response"
	case lower == "location" || lower == "refresh":
		return "is refused: redirect with a `run: redirect` step, which checks the target"
	case lower == "strict-transport-security":
		return "is refused: HSTS is set by the platform"
	case lower == "content-length", lower == "transfer-encoding", lower == "connection", lower == "keep-alive",
		lower == "upgrade", lower == "trailer", lower == "te", lower == "content-encoding":
		return "is refused: the server writes the message framing itself"
	}
	if respondHeaderNames[name] {
		return ""
	}
	if strings.HasPrefix(name, "X-") && len(name) > 2 {
		if respondReservedXHeaders[name] {
			return "is refused: the framework or the router sets or reads it"
		}
		for _, prefix := range respondReservedXPrefixes {
			if strings.HasPrefix(name, prefix) {
				return "is refused: " + prefix + "* headers are the framework's, the router's or a proxy's"
			}
		}
		return ""
	}
	return "is not a header a respond step may set. Allowed: " + respondHeadersAllowedText
}

// respondHeaderValueProblem checks one header value as it will be sent (a
// literal, or a rendered template); "" when it may be sent.
func respondHeaderValueProblem(name, value string) string {
	if len(value) > respondHeaderValueMax {
		return fmt.Sprintf("is %d bytes, over the %d-byte limit", len(value), respondHeaderValueMax)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return "holds a line break or another control character"
		}
	}
	switch name {
	case "Content-Type":
		return respondContentTypeProblem(value)
	case "Content-Disposition":
		return respondContentDispositionProblem(value)
	}
	return ""
}

// respondContentTypeProblem checks a declared content type; "" when it is a
// media type a respond step may send.
func respondContentTypeProblem(ct string) string {
	if strings.Contains(ct, "{{") {
		return "must be literal text, not a template: a request value could otherwise choose the type (an HTML page)"
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || !strings.Contains(mediaType, "/") {
		return "is not a media type (type/subtype, e.g. `text/csv; charset=utf-8`)"
	}
	if mediaType == "text/event-stream" {
		return "is refused: the router holds event streams open; a flow response is one finished body"
	}
	return ""
}

// respondContentTypeIsJSON reports a JSON media type: application/json or a
// structured `+json` type.
func respondContentTypeIsJSON(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

// respondContentDispositionProblem accepts `attachment` or `inline`,
// optionally followed by one `filename="..."` whose name holds no quote,
// backslash or control character.
func respondContentDispositionProblem(v string) string {
	const want = "must be `attachment` or `inline`, optionally with `; filename=\"name.ext\"`"
	kind, rest, hasParam := strings.Cut(strings.TrimSpace(v), ";")
	if k := strings.ToLower(strings.TrimSpace(kind)); k != "attachment" && k != "inline" {
		return want
	}
	if !hasParam {
		return ""
	}
	param, quoted, ok := strings.Cut(strings.TrimSpace(rest), "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(param), "filename") {
		return want
	}
	quoted = strings.TrimSpace(quoted)
	if len(quoted) < 3 || quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
		return want + " (the name quoted, and not empty)"
	}
	if strings.ContainsAny(quoted[1:len(quoted)-1], "\"\\") {
		return want + " (no quote or backslash in the name)"
	}
	return ""
}

// respondCacheControlShared reports a Cache-Control value that lets a shared
// cache (a CDN, a proxy) store the response. Cookie authentication does not
// restrict shared caching: max-age needs an unqualified private/no-store.
func respondCacheControlShared(v string) bool {
	private, freshness := false, false
	for _, directive := range strings.Split(v, ",") {
		name, _, qualified := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "public", "s-maxage":
			return true
		case "max-age":
			freshness = true
		case "private", "no-store":
			private = private || !qualified
		}
	}
	return freshness && !private
}

// respondHeaderScalar is a `with.headers` value as text; ok is false for a
// value that is not one scalar (a map, a list, null).
func respondHeaderScalar(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case int, int64, uint64, float64, bool:
		return fmt.Sprint(t), true
	}
	return "", false
}

// respondHeadersFromWith reads a respond step's declared content type and
// response headers. A header the allowlist refuses, a templated Content-Type
// or Cache-Control, and a literal value that could not be sent are dropped:
// the write gate refuses each and the loader logs it (flowStepValueProblems).
// `content_type:` wins over a Content-Type entry under `headers:`.
func respondHeadersFromWith(with map[string]any) (contentType string, headers []FlowRespondHeader) {
	if v, ok := with["content_type"].(string); ok && respondContentTypeProblem(strings.TrimSpace(v)) == "" {
		contentType = strings.TrimSpace(v)
	}
	raw, _ := with["headers"].(map[string]any)
	seen := map[string]bool{}
	for _, written := range slices.Sorted(maps.Keys(raw)) {
		name := http.CanonicalHeaderKey(strings.TrimSpace(written))
		value, ok := respondHeaderScalar(raw[written])
		if !ok || seen[name] || respondHeaderRefusal(name) != "" {
			continue
		}
		seen[name] = true
		value = strings.TrimSpace(normalizeGHARefs(value))
		literal := !strings.Contains(value, "{{")
		switch name {
		case "Content-Type":
			if contentType == "" && respondContentTypeProblem(value) == "" {
				contentType = value
			}
			continue
		case "Cache-Control":
			if !literal {
				continue
			}
		}
		if literal && respondHeaderValueProblem(name, value) != "" {
			continue
		}
		headers = append(headers, FlowRespondHeader{Name: name, Value: value})
	}
	return contentType, headers
}

// respondStatusFromWith reads `with.status`. An integer 200-599 (written as a
// number or quoted) is the status; anything else is kept as a template the
// step renders when it runs, and fails on unless it renders such an integer.
// Neither is set when the key is absent or null (the status is then 200).
func respondStatusFromWith(v any) (status int, template string) {
	switch t := v.(type) {
	case nil:
		return 0, ""
	case int:
		if t >= 200 && t <= 599 {
			return t, ""
		}
		return 0, strconv.Itoa(t)
	case float64:
		if t == math.Trunc(t) && t >= 200 && t <= 599 {
			return int(t), ""
		}
	case string:
		text := strings.TrimSpace(normalizeGHARefs(t))
		if n, err := strconv.Atoi(text); err == nil && n >= 200 && n <= 599 {
			return n, ""
		}
		if text == "" {
			return 0, "" // `status: ""` reads as no status, as before
		}
		return 0, text
	}
	return 0, fmt.Sprint(v)
}

// respondStatus is the status a respond step sends. A template renders here;
// unresolved is set when it referenced a value that is not in scope (the
// caller answers template_unresolved).
func respondStatus(ctx *FlowContext, r *FlowRespond) (status int, unresolved []string, err error) {
	if r.StatusTemplate == "" {
		if r.Status == 0 {
			return http.StatusOK, nil, nil
		}
		if r.Status < 200 || r.Status > 599 {
			return 0, nil, fmt.Errorf("respond status is %d, want 200-599", r.Status)
		}
		return r.Status, nil, nil
	}
	rendered := strings.TrimSpace(interpolateCtx(r.StatusTemplate, ctx))
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		return 0, missing, nil
	}
	n, convErr := strconv.Atoi(rendered)
	if convErr != nil || n < 200 || n > 599 {
		if len(rendered) > 64 {
			rendered = rendered[:64] + "..."
		}
		return 0, nil, fmt.Errorf("respond status rendered to %q, want 200-599", rendered)
	}
	return n, nil, nil
}

// renderRespondHeaders renders a respond step's headers. A value that renders
// empty is not sent; one that could not be sent fails the step, before
// anything is written.
func renderRespondHeaders(ctx *FlowContext, r *FlowRespond) ([]FlowRespondHeader, error) {
	out := make([]FlowRespondHeader, 0, len(r.Headers))
	for _, h := range r.Headers {
		value := h.Value
		if strings.Contains(value, "{{") {
			value = strings.TrimSpace(interpolateCtx(value, ctx))
		}
		if value == "" {
			continue
		}
		if problem := respondHeaderValueProblem(h.Name, value); problem != "" {
			return nil, fmt.Errorf("respond header %s %s", h.Name, problem)
		}
		out = append(out, FlowRespondHeader{Name: h.Name, Value: value})
	}
	return out, nil
}

// applyRespondHeaders sets rendered headers on a response. Vary and Link add
// to what the framework set (CORS adds `Vary: Origin`); the others replace.
func applyRespondHeaders(h http.Header, headers []FlowRespondHeader) {
	for _, hd := range headers {
		switch hd.Name {
		case "Vary", "Link":
			h.Add(hd.Name, hd.Value)
		default:
			h.Set(hd.Name, hd.Value)
		}
	}
}

// respondTextValue is the body for a respond step whose text body is one
// reference, under a declared content type: a text value as written, a
// number or boolean as its text, nothing for null; a list or object is
// JSON-encoded under a JSON type and refused under any other.
func respondTextValue(v any, contentType string) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		if respondContentTypeIsJSON(contentType) {
			return []byte("null"), nil
		}
		return nil, nil
	case string:
		return []byte(t), nil
	case []byte:
		return t, nil
	case bool, int, int64, int32, uint64, float64, float32:
		return []byte(fmt.Sprint(t)), nil
	}
	if respondContentTypeIsJSON(contentType) {
		return marshalRespondJSON(v)
	}
	return nil, fmt.Errorf("respond body resolved to a %T, which is not text; with content type %q the body must render to text (or use a JSON content type)", v, contentType)
}

// marshalRespondJSON encodes a respond body the way the JSON paths always
// have (json.Encoder: HTML-safe escaping and a trailing newline).
func marshalRespondJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dropSharedCacheControl removes a Cache-Control that lets a shared cache
// store the response from the respond steps of a flow
// only signed-in callers reach: one caller's data must not be served to the
// next. The write gate refuses it (flowStepValueProblems); a deployed file
// loads without it.
func dropSharedCacheControl(steps []FlowStep) {
	for i := range steps {
		if r := steps[i].Respond; r != nil {
			r.Headers = slices.DeleteFunc(r.Headers, func(h FlowRespondHeader) bool {
				return h.Name == "Cache-Control" && respondCacheControlShared(h.Value)
			})
		}
		dropSharedCacheControl(steps[i].Steps)
		dropSharedCacheControl(steps[i].ElseSteps)
		dropSharedCacheControl(steps[i].OnError)
	}
}
