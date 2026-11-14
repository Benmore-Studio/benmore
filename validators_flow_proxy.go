//go:build !cli

package main

// Write-time and load-time checks of `run: proxy` steps (flows_proxy.go).
//
// validateGHAFlowsContents calls ghaProxyViolation, so the write gate,
// `benmore check` (which runs the same dispatcher per file) and the loader
// all refuse a proxy step that could not run as written: in a flow with no
// live caller (async, scheduled, data event), in an on_error handler or
// inside for_each (it answers once, so the loop would stop after one item);
// in a flow anonymous callers can run without `on.request.rate_limit` (an
// open bandwidth relay to the author's upstream); an upstream POST from a GET
// flow (no CSRF check, so a cross-site link could trigger it); a URL whose
// scheme or host is not the author's literal text or an env value, or whose
// literal host is private (in any spelling a resolver reads: `127.1`,
// `0x7f000001`); a media type outside the framework list; a size, time,
// method, header, body, disposition, cache_control or path_slashes the step
// does not take. The step type is new (2.7.324), so few deployed files can
// carry one of these shapes. The step re-checks the run-time rules when it
// runs.

import (
	"fmt"
	"maps"
	"net/http"
	neturl "net/url"
	"slices"
	"strings"
)

const proxyStepExample = "\n\nExample:\n" +
	"  - run: proxy\n" +
	"    with:\n" +
	"      url: https://api.elevenlabs.io/v1/text-to-speech/${{ params.voice_id }}\n" +
	"      method: POST\n" +
	"      headers: { xi-api-key: \"${{ env.ELEVENLABS_KEY }}\" }\n" +
	"      json: { text: \"${{ params.text }}\" }\n" +
	"      content_types: [audio/mpeg]\n" +
	"      max_bytes: 20MB"

// ghaProxyViolation returns the first problem of a proxy step in the file,
// jobs in name order and steps in file order at every nesting depth.
func ghaProxyViolation(file FlowFileGHA) string {
	background := ""
	switch {
	case file.On.Request == nil:
		background = "a scheduled or data-event flow has no HTTP caller to answer"
	case strings.EqualFold(strings.TrimSpace(file.On.Request.Mode), "async"):
		background = "under `mode: async` the caller already got its 202 and job id before the step runs"
	}
	var walk func(job, path string, steps []FlowStepGHA, inHandler, inLoop bool) string
	walk = func(job, path string, steps []FlowStepGHA, inHandler, inLoop bool) string {
		for i, s := range steps {
			here := fmt.Sprintf("%s[%d]", path, i)
			if ghaStepRunType(s) == "proxy" {
				where := fmt.Sprintf("flows.yaml: job %q step %s", job, here)
				if s.ID != "" {
					where += fmt.Sprintf(" (%q)", s.ID)
				}
				switch {
				case background != "":
					return where + ": `run: proxy` streams the answer to the HTTP caller, and " + background + ". Use it in a synchronous `on: request` flow."
				case inHandler:
					return where + ": `run: proxy` can't run in an `on_error:` handler. It streams a live answer; a handler runs after another step failed. Answer the failure with `run: respond`, or put the proxy step in the main steps."
				case inLoop:
					return where + ": `run: proxy` can't run inside `for_each:`. It answers the caller once and ends the flow, so the loop would stop after its first item and the other items would never run. Pick the one item before the step (a SQL step with `LIMIT 1`), or answer the list with `run: respond`."
				case flowRequestAnonymous(file.On.Request) && strings.TrimSpace(file.On.Request.RateLimit) == "":
					return where + ": `run: proxy` in a flow anonymous callers can run (`auth: none`, `optional` or unset, with no role or permissions) needs `on.request.rate_limit`: every proxied byte is outbound bandwidth on the app's upstream account, so without a limit the route is an open relay to it. Add e.g. `rate_limit: \"30/minute per ip\"` under `on: request:`, or `auth: required`."
				}
				if problem := proxyStepProblem(s, file.On.Request); problem != "" {
					return where + ": " + problem
				}
			}
			// A loop's body runs once per item; its on_error handler runs
			// after the loop failed.
			loop := inLoop || ghaStepRunType(s) == "for_each"
			for _, nested := range []struct {
				name      string
				steps     []FlowStepGHA
				inHandler bool
				inLoop    bool
			}{{".steps", s.Steps, inHandler, loop}, {".else", s.Else, inHandler, loop}, {".on_error", s.OnError, true, inLoop}} {
				if msg := walk(job, here+nested.name, nested.steps, nested.inHandler, nested.inLoop); msg != "" {
					return msg
				}
			}
		}
		return ""
	}
	for _, job := range slices.Sorted(maps.Keys(file.Jobs)) {
		if msg := walk(job, "steps", file.Jobs[job].Steps, false, false); msg != "" {
			return msg
		}
	}
	return ""
}

// flowRequestAnonymous reports a request flow a caller with no session can
// run: `auth:` none, unset or optional, with no role or permissions gate.
func flowRequestAnonymous(req *FlowRequestTrigger) bool {
	if req == nil {
		return false
	}
	return normalizeFlowAuth(req.Auth, "", nil) != "required" && strings.TrimSpace(string(req.Role)) == "" && len(req.Permissions) == 0
}

// proxyStepProblem checks one proxy step's values in its request flow; ""
// when it can run.
func proxyStepProblem(s FlowStepGHA, req *FlowRequestTrigger) string {
	with := s.With
	rawURL, isText := with["url"].(string)
	if !isText || strings.TrimSpace(rawURL) == "" {
		return "`with.url` is required: the upstream URL, with a literal (or env) scheme and host." + proxyStepExample
	}
	if problem := proxyURLAuthorityProblem(rawURL); problem != "" {
		return problem
	}

	method := "GET"
	if raw, set := with["method"]; set {
		text, ok := raw.(string)
		method = strings.ToUpper(strings.TrimSpace(text))
		if !ok || (method != "GET" && method != "POST") {
			return fmt.Sprintf("`with.method: %v` is not supported: a proxy step sends GET (the default) or POST, written literally.", raw)
		}
	}
	if flowMethod := strings.ToUpper(strings.TrimSpace(req.Method)); method == "POST" && flowMethod != "" && !proxyFlowMethodChecksCSRF(flowMethod) {
		return fmt.Sprintf("`with.method: POST` sends the upstream a POST from a %s flow. A %s request skips the CSRF check, so a link or image on another site could make a signed-in caller's browser trigger the call (often billable, with the app's credentials). Make the flow `method: POST` (or PUT, PATCH, DELETE), or send a GET upstream.", flowMethod, flowMethod)
	}

	if raw, set := with["headers"]; set {
		headers, isMap := raw.(map[string]any)
		if !isMap {
			return "`with.headers` must be a map of header names to values."
		}
		for _, name := range slices.Sorted(maps.Keys(headers)) {
			canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
			if proxyRefusedRequestHeaders[canonical] {
				return fmt.Sprintf("`with.headers` sets %s, which a proxy step may not set: the client owns transport headers, and Accept-Encoding or Range would make the upstream answer encoded or partial bytes the step would pass on as the whole file.", canonical)
			}
			value, scalar := respondHeaderScalar(headers[name])
			if !scalar {
				return fmt.Sprintf("`with.headers` %q must have one text value.", name)
			}
			if apiMethodOverrideHeader(canonical) {
				for _, expr := range flowTemplateExprs(normalizeGHARefs(value)) {
					if !flowExprIsEnvOnly(strings.TrimSpace(expr)) {
						return fmt.Sprintf("`with.headers` %s would let a value choose the upstream method; a method-override header must be literal text or an env value.", canonical)
					}
				}
			}
		}
	}
	if raw, set := with["auth"]; set {
		if _, ok := raw.(string); !ok {
			return "`with.auth` must be text (the Authorization value, e.g. `Bearer ${{ env.API_KEY }}`)."
		}
	}

	rawBody, hasBody := with["body"]
	rawJSON, hasJSON := with["json"]
	if hasBody {
		if _, ok := rawBody.(string); !ok {
			return "`with.body` must be text; for a JSON body write `with.json` (a map, a list or one `${{ }}` reference)."
		}
	}
	if hasJSON && !isJSONBodyShape(rawJSON) {
		text, ok := rawJSON.(string)
		if _, sole := soleFlowExpr(normalizeGHARefs(text)); !ok || !sole {
			return "`with.json` must be a map, a list, or one `${{ }}` reference to the value to send."
		}
	}
	if hasBody && hasJSON {
		return "`with.body` and `with.json` are both set, and the step sends one body. Keep one."
	}
	if (hasBody || hasJSON) && method == "GET" {
		return "a GET sends no body: set `method: POST` to send `body:` or `json:`."
	}

	if _, err := proxyAcceptedTypes(proxyContentTypeList(with["content_types"])); err != nil {
		return err.Error()
	}
	if raw, set := with["content_types"]; set {
		if _, list := raw.([]any); !list {
			if _, text := raw.(string); !text {
				return "`with.content_types` must be a list of media types."
			}
		}
	}
	if raw, set := with["max_bytes"]; set {
		if _, err := parseProxyMaxBytes(raw); err != nil {
			return err.Error()
		}
	}
	if problem := proxyTimeoutProblem(s); problem != "" {
		return problem
	}
	if raw, set := with["disposition"]; set {
		text, _ := raw.(string)
		if d := strings.ToLower(strings.TrimSpace(text)); d != "inline" && d != "attachment" {
			return fmt.Sprintf("`with.disposition: %v` must be `inline` or `attachment`, written literally. PDF, CSV and ZIP are always attachments.", raw)
		}
	}
	if raw, set := with["filename"]; set {
		text, ok := raw.(string)
		if !ok {
			return "`with.filename` must be text."
		}
		if literal := strings.TrimSpace(text); !strings.Contains(normalizeGHARefs(literal), "{{") && proxySafeFilename(literal) != literal {
			return fmt.Sprintf("`with.filename: %q` has characters a download name can't carry; use letters, digits, space, dot, dash and underscore (at most 128).", text)
		}
	}
	if raw, set := with["path_slashes"]; set {
		if _, ok := raw.(bool); !ok {
			return fmt.Sprintf("`with.path_slashes: %v` must be `true` or `false`, written literally. `true` lets a value from a data step (a stored file key such as `users/42/a.png`) span path segments; request input always stays one plain segment.", raw)
		}
	}
	if raw, set := with["cache_control"]; set {
		text, ok := raw.(string)
		if !ok {
			return "`with.cache_control` must be text, e.g. `private, max-age=300`."
		}
		_, shared, err := parseProxyCacheControl(normalizeGHARefs(text))
		if err != nil {
			return "`with." + strings.TrimPrefix(err.Error(), "`")
		}
		if shared && flowRequestSignedIn(req) {
			return fmt.Sprintf("`with.cache_control: %s` lets a shared cache (Cloudflare in front of the platform, any proxy) store the answer, on a flow that checks who the caller is (`auth: required` or `optional`, a role or permissions): the cache would hand one caller's bytes to anyone with the URL. Use a private form (`private, max-age=300`), or leave it out for `private, no-store`.", text)
		}
	}
	return ""
}

// proxyTimeoutProblem checks the step's timeout at either position: a
// duration from 1 s to the flow time limit's maximum.
func proxyTimeoutProblem(s FlowStepGHA) string {
	limit := flowRequestTimeoutMax()
	check := func(written string, d any, got bool) string {
		if !got {
			return ""
		}
		var parsed = withDuration(map[string]any{"t": d}, "t")
		if parsed < proxyMinTimeout || parsed > limit {
			return fmt.Sprintf("%s: %v is not a time limit a proxy step takes: write a duration from 1s to %s (the call also ends at the flow's own time limit).", written, d, limit)
		}
		return ""
	}
	if problem := check("`timeout`", s.Timeout, strings.TrimSpace(s.Timeout) != ""); problem != "" {
		return problem
	}
	raw, set := s.With["timeout"]
	return check("`with.timeout`", raw, set)
}

// proxyURLAuthorityProblem refuses a URL template whose scheme or host is
// not the author's: any `${{ }}` reference other than an env value, or a
// `:name` placeholder, before the first literal `/`, `?` or `#` of the path.
// An env value is taken to keep the host going, so a reference right after
// one is refused too (`${{ env.BASE }}/${{ params.x }}` is accepted). When
// the scheme and host are literal, the scheme must be http(s) and the host
// must not be a private name or address (no DNS lookup here: the step runs
// isPrivateURL and the dial-time check on every call).
func proxyURLAuthorityProblem(raw string) string {
	t := strings.TrimSpace(normalizeGHARefs(raw))
	// The references as the author wrote them, in order, for messages
	// (normalizeGHARefs rewrites `steps.x.outputs.y` to `x.y`).
	written := ghaRefRe.FindAllString(raw, -1)
	if len(written) != len(flowTemplateExprs(t)) {
		written = nil // mixed `{{ }}` forms: name the normalized expression
	}
	var s flowURLScanner
	sawRef, inBrackets, refs := false, false, 0
	literalAuthority, authorityKnown := "", false
	for i := 0; i < len(t); {
		if strings.HasPrefix(t[i:], "{{") {
			end := strings.Index(t[i+2:], "}}")
			if end < 0 {
				return "`with.url` has an unclosed `${{`."
			}
			expr := strings.TrimSpace(t[i+2 : i+2+end])
			if s.region == flowURLAuthority {
				if !flowExprIsEnvOnly(expr) {
					ref := "${{ " + expr + " }}"
					if refs < len(written) {
						ref = written[refs]
					}
					return fmt.Sprintf("`with.url` puts `%s` in the scheme or host. A proxy step's scheme and host must be literal text or an env value (`${{ env.API_BASE }}`); request input and step outputs may fill path segments and query values only, after a literal `/`, `?` or `#`.", truncate(ref, 80))
				}
				s.write("env.value")
			} else {
				s.write("x")
			}
			sawRef = true
			refs++
			i += 2 + end + 2
			continue
		}
		c := t[i]
		if s.region == flowURLAuthority {
			switch {
			case c == '[':
				inBrackets = true
			case c == ']':
				inBrackets = false
			case c == ':' && !inBrackets && i+1 < len(t) && isSQLIdentStart(t[i+1]):
				return "`with.url` has a `:name` placeholder in the scheme or host. A proxy step's scheme and host must be literal text or an env value; write a port as digits."
			}
		}
		before := s.region
		s.writeByte(c)
		if before == flowURLAuthority && s.region != flowURLAuthority && !sawRef {
			literalAuthority, authorityKnown = t[:i], true
		}
		i++
	}
	if s.region == flowURLAuthority && !sawRef {
		literalAuthority, authorityKnown = t, true
	}
	if !strings.HasPrefix(t, "{{") {
		lower := strings.ToLower(t)
		if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
			return "`with.url` must be an absolute http:// or https:// URL (or start with an env value that holds one)."
		}
	}
	if authorityKnown {
		u, err := neturl.Parse(literalAuthority)
		if err != nil || u.Hostname() == "" {
			return "`with.url` does not name a host."
		}
		if appMCPLiteralPrivateHost(u.Hostname()) {
			return fmt.Sprintf("`with.url` names the private or internal host %q; a proxy step may only reach public addresses.", u.Hostname())
		}
	}
	return ""
}
