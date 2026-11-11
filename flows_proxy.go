//go:build !cli

package main

// `run: proxy`: stream an outside service's answer to the caller.
//
// `run: api` reads at most 1 MiB of an answer, as text, into the flow, and
// `run: serve_file` serves only the app's own uploads, so an app could not
// hand a caller the bytes an outside service produces: text-to-speech audio,
// a generated PDF or CSV, an image fetched for CORS or mixed-content reasons,
// a download kept behind the app's own permission checks. A proxy step is a
// terminal step like respond and serve_file: it makes one outbound request
// and streams the answer as the flow's response. It is deliberately narrow:
//
//   - The upstream scheme and host are the author's: literal text or an env
//     value (interpolateAuthoredHostURL). Request input and step outputs may
//     fill path segments and query values only, encoded for where they land.
//     The write gate refuses any other reference before the path
//     (proxyURLAuthorityProblem) and the step refuses it again when it runs.
//     A value the author did not write (request input, a stored row, a step
//     output, a set value) placed in the path may not hold `/` or `\`, also
//     percent-encoded, and may not be a dot segment (proxyPathValueUnsafe):
//     an upstream that decodes %2F and normalizes the path would otherwise
//     serve another of its endpoints with the author's credentials. A value
//     a user wrote through auto-CRUD and a step read back is as much theirs
//     as request input. `path_slashes: true` lets a value that is not
//     request text (a stored file key) span segments, each one checked.
//   - SSRF: a literal private host, in any spelling a resolver reads
//     (`127.1`, `0x7f000001`), is refused at write and load time without a
//     DNS lookup; outboundURLCheck runs before the call and the strict
//     client's dial-time check on every connection. Redirects are followed
//     for GET only, at most 10, and only on the URL's own origin.
//   - An upstream POST needs a POST, PUT, PATCH or DELETE flow: a GET flow
//     skips the CSRF check, so a cross-site link could make a signed-in
//     victim's browser trigger the (often billable) call. A flow anonymous
//     callers can run must declare `on.request.rate_limit`, or it is an open
//     bandwidth relay to the author's upstream.
//   - Only allow-listed media types (proxyContentTypes) are served, and only
//     those the step lists in `content_types:`. The upstream Content-Type is
//     checked before any byte is written; the response carries the
//     normalized type, nosniff and `Content-Security-Policy: default-src
//     'none'; sandbox`, so a mislabeled body cannot run script. PDF, CSV and
//     ZIP are always attachments, and a download name's extension is the
//     served type's (proxyDownloadName), so request input cannot name a
//     `.bat` or `.html` file.
//   - Only the upstream's ETag, Last-Modified and Content-Length are passed
//     on; never Cache-Control, Expires, Set-Cookie or any other header. The
//     answer is `Cache-Control: private, no-store` unless the step declares
//     a literal `cache_control:` (proxyCacheControl); a value a shared cache
//     may store (Cloudflare in front of the platform) is accepted only on an
//     `auth: none` flow. The caller's cookies and Authorization are never
//     sent upstream: the request carries only the author's `headers:` and
//     `auth:`.
//   - The first chunk of the body is read before the status is written. A
//     failure until then (an upstream that sends its headers and stalls or
//     dies, the time running out, a first chunk over `max_bytes`) fails the
//     step with nothing sent, so the flow answers its normal error. Writing
//     nothing and closing the connection instead let the router's keep-alive
//     transport replay a GET on another connection, running the whole flow
//     (its writes and the billable upstream call) again.
//   - The body is capped at `max_bytes` (default 10 MiB, at most 100 MiB): a
//     declared length over the cap is refused before anything is written.
//     Once the status and the first chunk are flushed to the caller, a
//     stream that passes the cap, an upstream read error or the time running
//     out aborts the connection, so the caller never takes a truncated body
//     for a complete one (FlowContext.responseAborted), and a proxy in front
//     passes the abort on instead of retrying.
//   - The call and the copy end at the step's timeout, at the flow's own
//     time limit (flows_time_limit.go) and when the caller goes away, and
//     use the run: api circuit breaker; only the step's timeout, a transport
//     failure or a 5xx counts against the host (flows_outbound_call.go).
//   - It answers a live caller only: never in an async, scheduled, data-event
//     or connector run, a parallel branch, an on_error handler or a
//     `transaction: true` flow (its answer is held until commit).
//
// One log line per upstream answer names the host, status, type and bytes
// (never the URL's path or query, never headers), so operators can see the
// volume. Result caching and per-plan bandwidth metering are not part of
// this step; `on.request.rate_limit` bounds how often a caller can run it.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	neturl "net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// proxyDefaultMaxBytes is the body cap of a step without `max_bytes:`.
	proxyDefaultMaxBytes int64 = 10 << 20
	// proxyMaxBytesCeiling is the largest `max_bytes:` a step may declare.
	proxyMaxBytesCeiling int64 = 100 << 20
	// proxyDefaultTimeout bounds a step without `timeout:`, like run: api.
	proxyDefaultTimeout = 30 * time.Second
	// proxyMinTimeout is the shortest `timeout:` the write gate accepts.
	proxyMinTimeout = time.Second
	// proxyMaxRedirects is the redirect limit run: api's client has.
	proxyMaxRedirects = 10
)

// proxyContentTypes is the framework-wide allow-list of media types a proxy
// step may serve. The value says the type is always served as an attachment.
// Never HTML, JavaScript, SVG, XML or JSON: a page under the app's origin
// that a third party wrote.
var proxyContentTypes = map[string]bool{
	"image/png": false, "image/jpeg": false, "image/gif": false, "image/webp": false, "image/avif": false,
	"audio/mpeg": false, "audio/mp4": false, "audio/aac": false, "audio/ogg": false, "audio/wav": false,
	"audio/webm": false, "audio/flac": false,
	"video/mp4": false, "video/webm": false, "video/ogg": false,
	"application/pdf": true, "text/csv": true, "application/zip": true,
}

// proxyContentTypeAliases maps other labels upstreams send for the same
// formats onto their allow-listed name.
var proxyContentTypeAliases = map[string]string{
	"image/jpg":                    "image/jpeg",
	"audio/mp3":                    "audio/mpeg",
	"audio/x-wav":                  "audio/wav",
	"audio/wave":                   "audio/wav",
	"audio/vnd.wave":               "audio/wav",
	"audio/x-flac":                 "audio/flac",
	"audio/x-m4a":                  "audio/mp4",
	"audio/x-aac":                  "audio/aac",
	"application/x-zip-compressed": "application/zip",
}

// proxyTypeExtensions are the file extensions a download name may end in for
// each allow-listed type; the first is the one a name gets when its own
// extension is not in the list (proxyDownloadName).
var proxyTypeExtensions = map[string][]string{
	"image/png": {".png"}, "image/jpeg": {".jpg", ".jpeg"}, "image/gif": {".gif"},
	"image/webp": {".webp"}, "image/avif": {".avif"},
	"audio/mpeg": {".mp3"}, "audio/mp4": {".m4a", ".mp4"}, "audio/aac": {".aac"},
	"audio/ogg": {".ogg", ".oga", ".opus"}, "audio/wav": {".wav"}, "audio/webm": {".weba", ".webm"},
	"audio/flac": {".flac"},
	"video/mp4":  {".mp4", ".m4v"}, "video/webm": {".webm"}, "video/ogg": {".ogv", ".ogg"},
	"application/pdf": {".pdf"}, "text/csv": {".csv"}, "application/zip": {".zip"},
}

// proxyCSVCharsets are the charsets a text/csv answer keeps. Any other
// parameter of the upstream type is dropped.
var proxyCSVCharsets = map[string]bool{"utf-8": true, "us-ascii": true, "iso-8859-1": true, "windows-1252": true}

// proxyRefusedRequestHeaders are headers a step may not set: transport and
// framing headers the client owns, and Accept-Encoding/Range, which would
// make the upstream answer encoded or partial bytes the step would pass on
// as the whole file.
var proxyRefusedRequestHeaders = map[string]bool{
	"Accept-Encoding": true, "Range": true, "If-Range": true, "Host": true, "Content-Length": true,
	"Connection": true, "Keep-Alive": true, "Proxy-Authorization": true, "Proxy-Connection": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Expect": true,
}

// proxyCanonicalType returns the allow-listed name of a media type written
// without parameters (an alias maps to its name), or false.
func proxyCanonicalType(name string) (string, bool) {
	mt := strings.ToLower(strings.TrimSpace(name))
	if alias, ok := proxyContentTypeAliases[mt]; ok {
		mt = alias
	}
	_, ok := proxyContentTypes[mt]
	return mt, ok
}

// proxyContentTypeNames lists the allow-list for messages.
func proxyContentTypeNames() string {
	names := make([]string, 0, len(proxyContentTypes))
	for name := range proxyContentTypes {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// proxyUpstreamType reads an upstream Content-Type: the allow-listed media
// type it names and the value the response sends (the type alone, or
// text/csv with an allowed charset). Both are "" for any other value,
// including a missing or unparsable one: the body is never sniffed.
func proxyUpstreamType(header string) (mediaType, sent string) {
	mt, params, err := mime.ParseMediaType(header)
	if err != nil {
		return "", ""
	}
	mt, ok := proxyCanonicalType(mt)
	if !ok {
		return "", ""
	}
	sent = mt
	if mt == "text/csv" {
		if cs := strings.ToLower(strings.TrimSpace(params["charset"])); proxyCSVCharsets[cs] {
			sent += "; charset=" + cs
		}
	}
	return mt, sent
}

// proxyContentTypeList reads `with.content_types`: a list, or one string of
// comma-separated types. A non-text list item is kept as its text, so the
// write gate and the step refuse it by name.
func proxyContentTypeList(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		for _, part := range strings.Split(t, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	case []any:
		for _, item := range t {
			out = append(out, strings.TrimSpace(fmt.Sprint(item)))
		}
	}
	return out
}

// proxyAcceptedTypes resolves a step's content_types to allow-listed names.
func proxyAcceptedTypes(written []string) (map[string]bool, error) {
	if len(written) == 0 {
		return nil, fmt.Errorf("`content_types:` is required: list the media types the step may serve (from: %s)", proxyContentTypeNames())
	}
	accepted := make(map[string]bool, len(written))
	for _, name := range written {
		mt, ok := proxyCanonicalType(name)
		if !ok || strings.Contains(name, ";") {
			return nil, fmt.Errorf("content type %q is not one a proxy step may serve; write the media type alone, one of: %s", name, proxyContentTypeNames())
		}
		accepted[mt] = true
	}
	return accepted, nil
}

var proxyByteSizeRe = regexp.MustCompile(`^(\d+)\s*([A-Za-z]*)$`)

// parseProxyMaxBytes reads `max_bytes`: a whole number of bytes, or a number
// with a unit B, KB/KiB or MB/MiB (both binary: 1 KB = 1024 bytes), between
// 1 byte and proxyMaxBytesCeiling.
func parseProxyMaxBytes(v any) (int64, error) {
	var n int64
	switch t := v.(type) {
	case int:
		n = int64(t)
	case int64:
		n = t
	case uint64:
		if t > uint64(proxyMaxBytesCeiling) {
			n = proxyMaxBytesCeiling + 1
		} else {
			n = int64(t)
		}
	case string:
		m := proxyByteSizeRe.FindStringSubmatch(strings.TrimSpace(t))
		if m == nil {
			return 0, fmt.Errorf("`max_bytes: %s` is not a size; write bytes (`10485760`) or a size with a unit (`10MB`, `512KB`)", t)
		}
		value, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || value > proxyMaxBytesCeiling {
			value = proxyMaxBytesCeiling + 1
		}
		switch strings.ToLower(m[2]) {
		case "", "b":
		case "k", "kb", "kib":
			value *= 1 << 10
		case "m", "mb", "mib":
			value *= 1 << 20
		default:
			return 0, fmt.Errorf("`max_bytes: %s` has an unknown unit; use B, KB or MB", t)
		}
		n = value
	default:
		return 0, fmt.Errorf("`max_bytes` must be a size such as `10MB` or a number of bytes")
	}
	if n < 1 || n > proxyMaxBytesCeiling {
		return 0, fmt.Errorf("`max_bytes` must be between 1 byte and %d MiB", proxyMaxBytesCeiling>>20)
	}
	return n, nil
}

// withToProxy maps a `with:` block onto FlowProxy. Only the keys a proxy
// step takes are read (flowStepKeyTable); GHA refs are normalized.
func withToProxy(with map[string]any) *FlowProxy {
	req := &FlowAPICall{}
	if v, ok := with["method"].(string); ok {
		req.Method = strings.ToUpper(strings.TrimSpace(v))
	}
	if v, ok := with["url"].(string); ok {
		req.URL = normalizeGHARefs(v)
	}
	if v, ok := with["auth"].(string); ok {
		req.Auth = normalizeGHARefs(v)
	}
	if v, ok := with["body"].(string); ok {
		req.Body = normalizeGHARefs(v)
	}
	if h, ok := with["headers"].(map[string]any); ok {
		req.Headers = stringMap(h)
	}
	req.JSON, req.JSONArray = jsonBodyTree(with["json"])
	if v, ok := with["json"].(string); ok {
		if ref := normalizeGHARefs(v); ref != "" {
			if _, sole := soleFlowExpr(ref); sole {
				req.JSONRef = ref
			}
		}
	}
	p := &FlowProxy{Request: req, ContentTypes: proxyContentTypeList(with["content_types"])}
	if raw, ok := with["max_bytes"]; ok {
		if n, err := parseProxyMaxBytes(raw); err == nil {
			p.MaxBytes = n
		} else {
			p.MaxBytes = -1
		}
	}
	if v, ok := with["disposition"].(string); ok {
		p.Disposition = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := with["filename"].(string); ok {
		p.Filename = normalizeGHARefs(v)
	}
	if v, ok := with["cache_control"].(string); ok {
		p.CacheControl = strings.TrimSpace(normalizeGHARefs(v))
	}
	// Only a literal boolean opts in; the write gate refuses anything else.
	p.PathSlashes, _ = with["path_slashes"].(bool)
	return p
}

// proxyFilenameMax caps a download name, extension included.
const proxyFilenameMax = 128

// proxySafeFilename keeps a download name to letters, digits, space, dot,
// dash and underscore (anything else becomes `_`), drops any directory part
// and caps it at proxyFilenameMax bytes. "" means no name is sent.
func proxySafeFilename(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), " .")
	if len(out) > proxyFilenameMax {
		out = strings.TrimRight(out[:proxyFilenameMax], " .")
	}
	return out
}

var proxyExtensionRe = regexp.MustCompile(`^\.[A-Za-z0-9]{1,8}$`)

// proxyDownloadName is the download name sent for a served media type: the
// safe name (proxySafeFilename) ending in one of the type's extensions
// (proxyTypeExtensions). An extension outside the type's list is replaced by
// the type's first one (`report.bat` served as text/csv is `report.csv`), and
// a name with none gets it appended, so the name never says another file
// type than the bytes are. "" when the written name keeps nothing.
func proxyDownloadName(name, mediaType string) string {
	return downloadNameWithExtension(proxySafeFilename(name), proxyTypeExtensions[mediaType])
}

// downloadNameWithExtension ends a safe download name (proxySafeFilename)
// in one of exts, the first when its own extension is not among them. ""
// when the name keeps nothing or there is no extension to give it. Shared by
// run: proxy and run: serve_file (serveFileDownloadName).
func downloadNameWithExtension(safe string, exts []string) string {
	if safe == "" || len(exts) == 0 {
		return ""
	}
	base := safe
	if ext := filepath.Ext(safe); proxyExtensionRe.MatchString(ext) {
		if slices.Contains(exts, strings.ToLower(ext)) {
			return safe
		}
		base = strings.TrimRight(strings.TrimSuffix(safe, ext), " .")
	}
	want := exts[0]
	if len(base) > proxyFilenameMax-len(want) {
		base = strings.TrimRight(base[:proxyFilenameMax-len(want)], " .")
	}
	if base == "" {
		base = "download"
	}
	return base + want
}

// proxyCacheDirectives are the Cache-Control directives a step's
// `cache_control:` may name, and whether each takes a number (`max-age=N`).
var proxyCacheDirectives = map[string]bool{
	"public": false, "private": false, "no-cache": false, "no-store": false, "max-age": true, "s-maxage": true,
	"must-revalidate": false, "proxy-revalidate": false, "immutable": false, "no-transform": false,
	"stale-while-revalidate": true, "stale-if-error": true,
}

// parseProxyCacheControl reads a step's `cache_control:`: literal text of
// known directives (a number where the directive takes one, none
// elsewhere, so no `private="field"` forms), returned lowercased and
// comma-joined. shared reports a value that lets a shared cache (Cloudflare
// in front of the platform, any proxy) store the answer: one with neither
// `private` nor `no-store`. `public` or `s-maxage` with either of those is
// refused as contradictory.
func parseProxyCacheControl(text string) (value string, shared bool, err error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return "", false, fmt.Errorf("`cache_control:` is empty; leave it out for `private, no-store`")
	case strings.Contains(text, "{{"):
		return "", false, fmt.Errorf("`cache_control:` must be literal text, not a template: a request value must not decide how long a shared cache keeps the answer")
	case len(text) > 256:
		return "", false, fmt.Errorf("`cache_control:` is longer than 256 characters")
	}
	seen := map[string]bool{}
	var parts []string
	for _, part := range strings.Split(text, ",") {
		name, arg, hasArg := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		numeric, known := proxyCacheDirectives[name]
		switch {
		case !known:
			return "", false, fmt.Errorf("`cache_control:` directive %q is not one a proxy step sends; use public, private, no-cache, no-store, max-age=N, s-maxage=N, must-revalidate, proxy-revalidate, immutable, no-transform, stale-while-revalidate=N or stale-if-error=N", truncate(name, 40))
		case seen[name]:
			return "", false, fmt.Errorf("`cache_control:` names %s twice", name)
		case numeric && (!hasArg || strings.TrimSpace(arg) == "" || strings.Trim(strings.TrimSpace(arg), "0123456789") != ""):
			return "", false, fmt.Errorf("`cache_control:` %s needs a number of seconds (`%s=300`)", name, name)
		case !numeric && hasArg:
			return "", false, fmt.Errorf("`cache_control:` %s takes no value", name)
		}
		seen[name] = true
		if hasArg {
			name += "=" + strings.TrimSpace(arg)
		}
		parts = append(parts, name)
	}
	if len(parts) == 0 {
		return "", false, fmt.Errorf("`cache_control:` names no directive")
	}
	private := seen["private"] || seen["no-store"]
	if private && (seen["public"] || seen["s-maxage"]) {
		return "", false, fmt.Errorf("`cache_control:` says both private (private or no-store) and shared (public or s-maxage); keep one")
	}
	return strings.Join(parts, ", "), !private, nil
}

// proxyCacheControl is the Cache-Control a proxied answer carries: the
// step's `cache_control:` (authored), else `private, no-store`. A private
// answer (a caller with a session, or identity injected into a public flow)
// never takes a shared value, as respond answers do: the flow authorized
// that caller, so no shared cache may keep the bytes. The upstream's own
// Cache-Control and Expires are never passed on: an upstream lifetime (a
// year, `immutable`) would let a CDN keep serving a revoked share link, or
// serve an answer gated by a header or cookie to anyone with the URL.
func proxyCacheControl(authored string, private bool) string {
	if authored == "" {
		return "private, no-store"
	}
	value, shared, err := parseProxyCacheControl(authored)
	if err != nil || private && shared {
		return "private, no-store"
	}
	return value
}

// proxyPathValueUnsafe reports a request value a proxy step may not place in
// a path segment: one holding `/` or `\`, also percent-encoded (once or more:
// an upstream that decodes %2F and then normalizes the path would turn
// `..%2Fadmin` into another endpoint, called with the author's credentials),
// or a dot segment (`.`, `..`, also encoded).
func proxyPathValueUnsafe(v string) bool {
	for range 4 {
		lower := strings.ToLower(v)
		if strings.ContainsAny(v, `/\`) || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") ||
			v != "" && strings.Trim(v, ".") == "" {
			return true
		}
		decoded, err := neturl.PathUnescape(v)
		if err != nil || decoded == v {
			return false
		}
		v = decoded
	}
	return true // still decoding after four rounds
}

var proxyETagRe = regexp.MustCompile(`^(W/)?"[\x21\x23-\x7e]{0,200}"$`)

// proxyHTTPDate re-formats a valid HTTP date, or returns "".
func proxyHTTPDate(v string) string {
	t, err := http.ParseTime(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return t.UTC().Format(http.TimeFormat)
}

// proxyHTTPClient is the client a proxy step fetches with: the strict
// outbound client (dial-time address check, no environment proxy), or a
// test run's client, whose redirects stay on the URL's own origin, at most
// proxyMaxRedirects, and are refused for a POST.
func proxyHTTPClient(base *http.Client) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	} else {
		c = *safeHTTPClientStrict(0)
	}
	inner := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if via[0].Method != http.MethodGet {
			return fmt.Errorf("the upstream redirected a %s request; a proxy step follows redirects only for GET", via[0].Method)
		}
		if len(via) >= proxyMaxRedirects {
			return fmt.Errorf("the upstream redirected more than %d times", proxyMaxRedirects)
		}
		if !sameRedirectOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("%s; a proxy step follows redirects only on the URL's own origin", proxyRedirectChange(via[0].URL, req.URL))
		}
		if inner != nil {
			return inner(req, via)
		}
		return nil
	}
	c.Timeout = 0 // the request context bounds the call and the copy
	return &c
}

// proxyRedirectChange says how a redirect left the URL's origin: another
// host, another scheme on the same host (https to http), or another port.
func proxyRedirectChange(from, next *neturl.URL) string {
	switch {
	case !strings.EqualFold(from.Hostname(), next.Hostname()):
		return fmt.Sprintf("the upstream redirected to another host (%s)", next.Host)
	case !strings.EqualFold(from.Scheme, next.Scheme):
		return fmt.Sprintf("the upstream redirected from %s to %s on the same host (%s)", strings.ToLower(from.Scheme), strings.ToLower(next.Scheme), next.Host)
	}
	return fmt.Sprintf("the upstream redirected to another port (%s)", next.Host)
}

// proxyTransportError is a client error without the URL net/http quotes in
// it (its query may hold an env key).
func proxyTransportError(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// logProxyAnswer writes the one line per upstream answer: app, step, host,
// status, media type, bytes sent and outcome. Never the URL's path or query
// and never a header.
func logProxyAnswer(ctx *FlowContext, step *FlowStep, host string, status int, mediaType string, bytes int64, started time.Time, outcome string) {
	app := ""
	if ctx.App != nil {
		app = filepath.Base(ctx.App.Dir)
	}
	if mediaType == "" {
		mediaType = "-"
	}
	log.Printf("FLOW PROXY [%s] step=%s host=%s status=%d type=%s bytes=%d duration=%s outcome=%s",
		app, quoteForHint(step.Name), host, status, mediaType, bytes, time.Since(started).Round(time.Millisecond), outcome)
}

// execStepProxy makes the step's request and streams the answer as the
// flow's response (see the file comment for the rules). Every refusal before
// the status is written fails the step with nothing sent, so the flow's
// error handling answers; a failure while streaming aborts the response.
func execStepProxy(ctx *FlowContext, step *FlowStep) error {
	p := step.Proxy
	if p == nil || p.Request == nil || strings.TrimSpace(p.Request.URL) == "" {
		return fmt.Errorf("proxy step missing `url:`")
	}
	if !ctx.liveResponse || ctx.Writer == nil || ctx.Request == nil {
		return fmt.Errorf("proxy: the step answers the HTTP caller and runs only in a synchronous request flow; it cannot run in an async, scheduled, data-event or connector run, a parallel branch or an on_error handler")
	}
	if ctx.Tx != nil {
		return fmt.Errorf("proxy: the step streams its answer and cannot run in a `transaction: true` flow, whose response is held until commit")
	}
	method := p.Request.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("proxy: `method: %s` is not supported; a proxy step sends GET or POST", method)
	}
	if method == http.MethodPost && !proxyFlowMethodChecksCSRF(ctx.Request.Method) {
		return fmt.Errorf("proxy: an upstream POST runs only in a POST, PUT, PATCH or DELETE flow; a %s flow skips the CSRF check, so a link on another site could make a signed-in caller's browser send it", ctx.Request.Method)
	}
	accepted, err := proxyAcceptedTypes(p.ContentTypes)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	maxBytes := p.MaxBytes
	if maxBytes == 0 {
		maxBytes = proxyDefaultMaxBytes
	}
	if maxBytes < 0 || maxBytes > proxyMaxBytesCeiling {
		return fmt.Errorf("proxy: `max_bytes` must be between 1 byte and %d MiB", proxyMaxBytesCeiling>>20)
	}
	if p.Disposition != "" && p.Disposition != "inline" && p.Disposition != "attachment" {
		return fmt.Errorf("proxy: `disposition: %s` is not inline or attachment", p.Disposition)
	}
	allowance := step.Timeout
	if allowance <= 0 {
		allowance = proxyDefaultTimeout
	}
	// A synchronous run's call ends at the run's time limit too.
	if ctx.boundStepTimeout(allowance) <= 0 {
		return ctx.timeLimitError(quoteForHint(step.Name))
	}

	target, err := interpolateAuthoredHostURL(p.Request.URL, ctx, p.PathSlashes)
	if err != nil {
		return err
	}
	u, err := neturl.Parse(strings.TrimSpace(target))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("proxy: `url:` must render an absolute http(s) URL")
	}
	target, host := u.String(), u.Host
	if err := outboundURLCheck(target); err != nil {
		// Both refuse the call; only the message differs. A host with no
		// address was reported as a private one.
		if errors.Is(err, errOutboundUnresolved) {
			return fmt.Errorf("proxy: could not resolve the upstream host %s; nothing was sent", host)
		}
		return fmt.Errorf("SECURITY: proxy refused a private or internal address (%s)", host)
	}

	bodyBytes, hasBody, contentType, err := apiRequestBody(ctx, p.Request)
	if err != nil {
		return fmt.Errorf("proxy %s: %w", host, err)
	}
	if hasBody && method == http.MethodGet {
		return fmt.Errorf("proxy: a GET sends no body; set `method: POST` to send `body:` or `json:`")
	}
	auth := ""
	if p.Request.Auth != "" {
		auth = interpolateCtx(p.Request.Auth, ctx)
	}
	headers := make(map[string]string, len(p.Request.Headers))
	for name, value := range p.Request.Headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if proxyRefusedRequestHeaders[canonical] {
			return fmt.Errorf("proxy: header %s may not be set on a proxy step", canonical)
		}
		if apiMethodOverrideHeader(canonical) {
			if key := ctx.taintedRef(value); key != "" {
				return fmt.Errorf("proxy %s: header %s would let request input %q pick the upstream method; a method-override header must be a literal or env value", host, canonical, key)
			}
		}
		headers[canonical] = interpolateCtx(value, ctx)
	}
	filename := ""
	if p.Filename != "" {
		// Cut to a safe name now; its extension follows the served type
		// once the upstream named it (proxyDownloadName).
		filename = proxySafeFilename(interpolateCtx(p.Filename, ctx))
	}
	// Nothing is sent with a value missing.
	if err := flowOutboundMissingRefs(ctx, "proxy"); err != nil {
		return err
	}

	breaker := circuitKey(ctx.App, target)
	if err := CheckCircuit(breaker); err != nil {
		return fmt.Errorf("proxy %s: %w", host, err)
	}
	// The call ends at the step's allowance, at the run's time limit, or
	// when the caller goes away (the flow deadline does not follow the
	// request's cancellation). Only the first counts against the host
	// (flows_outbound_call.go).
	call, cancel := ctx.startOutboundCall(allowance, true)
	defer cancel()
	requestContext := call.ctx
	var reqBody io.Reader
	if hasBody {
		reqBody = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(requestContext, method, target, reqBody)
	if err != nil {
		return fmt.Errorf("proxy %s: %w", host, proxyTransportError(err))
	}
	if hasBody {
		req.Header.Set("Content-Type", contentType)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	started := time.Now()
	resp, err := proxyHTTPClient(ctx.apiClient).Do(req)
	if err != nil {
		call.recordFailure(breaker)
		return fmt.Errorf("proxy %s: %w", host, proxyTransportError(err))
	}
	defer resp.Body.Close()
	// As for run: api, only a transport failure or a 5xx counts against
	// the host; a 4xx is the endpoint answering.
	if resp.StatusCode >= 500 {
		RecordFailure(breaker)
	} else {
		RecordSuccess(breaker)
	}
	refuse := func(outcome, mediaType string, err error) error {
		logProxyAnswer(ctx, step, host, resp.StatusCode, mediaType, 0, started, outcome)
		return err
	}
	switch {
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return refuse("refused_status", "", fmt.Errorf("proxy upstream answered %d (%s); nothing was sent", resp.StatusCode, host))
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusResetContent || resp.StatusCode == http.StatusPartialContent:
		return refuse("refused_status", "", fmt.Errorf("proxy upstream answered %d (%s), which is not a whole body to serve; nothing was sent", resp.StatusCode, host))
	}
	// The client asks for gzip itself and decodes it (the header is then
	// gone, and max_bytes counts the decoded bytes); any other encoding is
	// one the step would pass on undecoded under a type that says otherwise.
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		return refuse("refused_encoding", "", fmt.Errorf("proxy upstream %s answered with Content-Encoding %s, which a proxy step does not decode (it asks for gzip and decodes that); nothing was sent", host, strconv.Quote(truncate(ce, 40))))
	}
	mediaType, sentType := proxyUpstreamType(resp.Header.Get("Content-Type"))
	if mediaType == "" || !accepted[mediaType] {
		return refuse("refused_type", mediaType, fmt.Errorf("proxy upstream %s answered Content-Type %s, which the step does not serve (content_types: %s); nothing was sent", host, strconv.Quote(truncate(resp.Header.Get("Content-Type"), 100)), strings.Join(p.ContentTypes, ", ")))
	}
	if resp.ContentLength > maxBytes {
		return refuse("refused_size", mediaType, fmt.Errorf("proxy upstream %s declared %d bytes, over max_bytes (%d); nothing was sent", host, resp.ContentLength, maxBytes))
	}

	// writeHeader sends the status and the answer's headers. Until it runs,
	// any failure fails the step with nothing sent.
	writeHeader := func() {
		h := ctx.Writer.Header()
		h.Set("Content-Type", sentType)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
		disposition := "inline"
		if p.Disposition == "attachment" || proxyContentTypes[mediaType] {
			disposition = "attachment"
		}
		params := map[string]string{}
		if name := proxyDownloadName(filename, mediaType); name != "" {
			params["filename"] = name
		}
		h.Set("Content-Disposition", mime.FormatMediaType(disposition, params))
		h.Set("Cache-Control", proxyCacheControl(p.CacheControl, ctx.Session != nil || ctx.privateResponse))
		if v := resp.Header.Get("ETag"); proxyETagRe.MatchString(v) {
			h.Set("ETag", v)
		}
		if v := proxyHTTPDate(resp.Header.Get("Last-Modified")); v != "" {
			h.Set("Last-Modified", v)
		}
		if resp.ContentLength >= 0 {
			h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}
		ctx.Stopped = true
		ctx.Writer.WriteHeader(http.StatusOK)
	}
	if ctx.Request.Method == http.MethodHead {
		writeHeader()
		logProxyAnswer(ctx, step, host, resp.StatusCode, mediaType, 0, started, "head")
		return nil
	}

	// The first chunk is read before anything is written. An upstream that
	// sends its headers and then stalls or fails, the time running out, or a
	// first chunk over the cap fails the step here, with nothing sent, so the
	// flow answers its normal error. Writing the status first and closing
	// the connection with no byte on it let the router's keep-alive
	// transport replay the GET on another connection, running the flow (its
	// writes and the upstream call) again.
	buf := make([]byte, 32<<10)
	n, readErr := 0, error(nil)
	for n == 0 && readErr == nil {
		n, readErr = resp.Body.Read(buf)
	}
	if int64(n) > maxBytes {
		return refuse("refused_size", mediaType, fmt.Errorf("proxy upstream %s sent a body over max_bytes (%d); nothing was sent", host, maxBytes))
	}
	if n == 0 && readErr != io.EOF {
		switch {
		case ctx.Request.Context().Err() != nil:
			return refuse("failed_before_body", mediaType, fmt.Errorf("proxy upstream %s: the caller went away before the first byte of the body; nothing was sent", host))
		case requestContext.Err() != nil:
			return refuse("failed_before_body", mediaType, fmt.Errorf("proxy upstream %s: the step's time ran out before the first byte of the body (%s); nothing was sent", host, requestContext.Err()))
		}
		return refuse("failed_before_body", mediaType, fmt.Errorf("proxy upstream %s: reading the body failed before its first byte (%s); nothing was sent", host, proxyTransportError(readErr)))
	}

	// From here the status and the first chunk are flushed to the caller, so
	// any later failure is a body cut short, which aborts the connection and
	// which a proxy in front passes on rather than retries.
	writeHeader()
	var written int64
	abort := func(cause string) error {
		ctx.responseAborted = true
		logProxyAnswer(ctx, step, host, resp.StatusCode, mediaType, written, started, "aborted")
		return fmt.Errorf("proxy upstream %s: %s after %d bytes; the response was aborted", host, cause, written)
	}
	rc := http.NewResponseController(ctx.Writer)
	for {
		if n > 0 {
			if written+int64(n) > maxBytes {
				return abort(fmt.Sprintf("the body passed max_bytes (%d)", maxBytes))
			}
			if _, err := ctx.Writer.Write(buf[:n]); err != nil {
				return abort("the caller stopped reading: " + err.Error())
			}
			written += int64(n)
			if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return abort("the caller stopped reading: " + err.Error())
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			if timeErr := requestContext.Err(); timeErr != nil {
				return abort("the step's time ran out (" + timeErr.Error() + ")")
			}
			return abort("reading the body failed: " + proxyTransportError(readErr).Error())
		}
		n, readErr = resp.Body.Read(buf)
	}
	logProxyAnswer(ctx, step, host, resp.StatusCode, mediaType, written, started, "sent")
	return nil
}

// proxyFlowMethodChecksCSRF reports a request method the flow gate checks
// CSRF on (flows.go): the methods a flow whose proxy step POSTs upstream
// must answer.
func proxyFlowMethodChecksCSRF(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
