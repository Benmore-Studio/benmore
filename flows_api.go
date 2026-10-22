//go:build !cli

package main

// Outbound API and webhook steps, pagination, and response envelopes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"time"
)

const maxAPIResponseBody = 1 << 20

func execStepAPI(ctx *FlowContext, step *FlowStep) error {
	return execStepAPIWithClient(ctx, step, ctx.apiClient)
}

func execStepAPIWithClient(ctx *FlowContext, step *FlowStep, client *http.Client) error {
	api := step.API
	if api == nil {
		return fmt.Errorf("api step has no config")
	}
	// Pagination wrapper: loops the single-shot path until the upstream
	// runs out of pages, accumulates items, sets the step output to
	// { items: [...], pages_fetched: N }. Without this, every flow with
	// a hardcoded `?limit=500` would silently drop data past the cap.
	if api.Paginate != nil {
		return execStepAPIPaginatedWithClient(ctx, step, client)
	}
	return execAPIRequestWithClient(ctx, step, api, nil, client)
}

// apiRequestURL renders an api step's URL plus its `with.query:` params.
// Keys and values are percent-encoded; template values resolve through
// interpolateCtx, so `${{ user.customer_id }}` and `${{ env.X }}` work.
// interpolateCtx resolves env refs in the author's template itself; its
// output holds request values and is never run through InterpolateEnv.
// literalQuery carries runtime values (a pagination cursor or page number
// taken from an upstream response): they replace the template entry of
// the same key and are sent as-is, never read as templates.
//
// The URL template itself goes through interpolateURLCtx, which encodes
// each substituted value for the part of the URL it lands in, so a value
// can't add path segments or query parameters (flows_api_url.go).
func apiRequestURL(ctx *FlowContext, api *FlowAPICall, literalQuery map[string]string) string {
	url, _ := buildAPIRequestURL(ctx, api, literalQuery)
	return url
}

func buildAPIRequestURL(ctx *FlowContext, api *FlowAPICall, literalQuery map[string]string) (string, error) {
	secrets, derived := apiCallCarriesSecrets(api), ""
	if !secrets {
		derived = ctx.apiCallSecretRef(api)
	}
	url, err := interpolateOutboundURL(api.URL, ctx, secrets, derived)
	if err != nil {
		return "", err
	}
	if len(api.Query) == 0 && len(literalQuery) == 0 {
		return url, nil
	}
	var parts []string
	for k, v := range api.Query {
		if _, ok := literalQuery[k]; ok {
			continue
		}
		parts = append(parts, neturl.QueryEscape(k)+"="+neturl.QueryEscape(interpolateCtx(v, ctx)))
	}
	for k, v := range literalQuery {
		parts = append(parts, neturl.QueryEscape(k)+"="+neturl.QueryEscape(v))
	}
	// Sorted so a request (and its signature, for signers that cover the
	// query) does not depend on map order.
	sort.Strings(parts)
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + strings.Join(parts, "&"), nil
}

// apiFormBody encodes a `form:` body. Keys and values are form-encoded, so
// a value such as `x&amount=1&customer=cus_other` stays one value instead
// of adding or overriding parameters on a request that carries the app's
// secret key. url.Values.Encode sorts by key, so the body is deterministic.
func apiFormBody(ctx *FlowContext, form map[string]string) []byte {
	values := make(neturl.Values, len(form))
	for k, v := range form {
		val := interpolateCtx(v, ctx)
		// A value written as one `{{x | urlencode}}` was encoded by the
		// author (the only way a + or & arrived intact before bodies were
		// encoded here); decode it so the body carries x, not its encoding.
		if expr, ok := soleFlowExpr(v); ok && flowExprEndsInURLEncode(expr) {
			if decoded, err := neturl.QueryUnescape(val); err == nil {
				val = decoded
			}
		}
		values.Set(k, val)
	}
	return []byte(values.Encode())
}

// soleFlowExpr returns the expression of a template that is exactly one
// `{{ ... }}` reference (surrounding whitespace allowed).
func soleFlowExpr(template string) (string, bool) {
	t := strings.TrimSpace(template)
	if !strings.HasPrefix(t, "{{") || !strings.HasSuffix(t, "}}") {
		return "", false
	}
	inner := t[2 : len(t)-2]
	if strings.Contains(inner, "{{") || strings.Contains(inner, "}}") {
		return "", false
	}
	return strings.TrimSpace(inner), true
}

// execAPIRequest sends one request for an api step. api may be a
// per-call copy of step.API (pagination), so the shared flow definition is
// never mutated while other requests run the same flow.
func execAPIRequest(ctx *FlowContext, step *FlowStep, api *FlowAPICall, literalQuery map[string]string) error {
	return execAPIRequestWithClient(ctx, step, api, literalQuery, nil)
}

// execAPIRequestWithClient keeps the production path on the strict SSRF client
// while allowing native tests to route an already-public URL through a local
// test server. The caller supplies this client per invocation; there is no
// app/YAML/global client override.
func execAPIRequestWithClient(ctx *FlowContext, step *FlowStep, api *FlowAPICall, literalQuery map[string]string, client *http.Client) error {
	timeout := 30 * time.Second
	if step.Timeout > 0 {
		timeout = step.Timeout
	}
	parentContext := context.Background()
	if ctx != nil && ctx.Request != nil {
		parentContext = ctx.Request.Context()
	}
	requestContext, cancel := context.WithTimeout(parentContext, timeout)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return err
	}
	url, err := buildAPIRequestURL(ctx, api, literalQuery)
	if err != nil {
		return err
	}

	// SSRF protection: block requests to private/internal IPs.
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked API request to private URL: %s", url)
	}
	if err := requestContext.Err(); err != nil {
		return fmt.Errorf("api %s: %w", url, err)
	}

	var body io.Reader
	var bodyBytes []byte // captured for signers that hash the payload (AWS sigv4 etc.)
	contentType := "application/json"

	if api.JSON != nil {
		// Recursively resolve string leaves (ctx interpolation) while keeping
		// nested arrays/objects intact, then marshal the whole structure.
		// interpolateJSONValues is the same resolver respond bodies use. #94.
		jsonData := interpolateJSONValues(api.JSON, ctx)
		bodyBytes, _ = json.Marshal(jsonData)
		body = bytes.NewReader(bodyBytes)
	} else if api.JSONArray != nil {
		// A list body (`json:` or `body:` written as a list), resolved the
		// same way element by element.
		bodyBytes, _ = json.Marshal(resolveJSONValue(api.JSONArray, ctx))
		body = bytes.NewReader(bodyBytes)
	} else if api.Form != nil {
		bodyBytes = apiFormBody(ctx, api.Form)
		body = bytes.NewReader(bodyBytes)
		contentType = "application/x-www-form-urlencoded"
	} else if api.Body != "" {
		bodyBytes = []byte(interpolateCtx(api.Body, ctx))
		body = bytes.NewReader(bodyBytes)
	}

	method := api.Method
	if method == "" {
		method = "GET"
	}

	// Circuit breaker: skip if endpoint is known-dead
	host := circuitKey(ctx.App, url)
	if err := CheckCircuit(host); err != nil {
		return fmt.Errorf("api %s: %s", url, err)
	}

	req, err := http.NewRequestWithContext(requestContext, method, url, body)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	if api.Auth != "" {
		auth := interpolateCtx(api.Auth, ctx)
		req.Header.Set("Authorization", auth)
	}
	for k, v := range api.Headers {
		if apiMethodOverrideHeader(k) {
			if key := ctx.taintedRef(v); key != "" {
				return fmt.Errorf("api %s: header %s would let request input %q pick the upstream method; a method-override header must be a literal or env value (write the method in `method:`)", url, k, key)
			}
		}
		req.Header.Set(k, interpolateCtx(v, ctx))
	}

	// Pluggable outbound signing - interpolates bindings against the
	// flow context + env, then runs the recipe (named built-in or
	// inline). The recipe mutates req headers / query before send.
	// bodyBytes is the source-of-truth payload for hashing.
	if api.Sign != nil {
		if err := requestContext.Err(); err != nil {
			return fmt.Errorf("api %s: %w", url, err)
		}
		signCfg := *api.Sign // shallow copy
		taintedBinding := ""
		if api.Sign.Bindings != nil {
			interpolated := make(map[string]string, len(api.Sign.Bindings))
			for k, v := range api.Sign.Bindings {
				interpolated[k] = interpolateCtx(v, ctx)
				if key := ctx.taintedRef(v); key != "" && (taintedBinding == "" || key < taintedBinding) {
					taintedBinding = key
				}
			}
			// A recipe with a token exchange posts the app's credentials to
			// a URL built from bindings. Request input may not choose that
			// URL's scheme or host, exactly as for the API URL above.
			exchangeParams, soleRef := signExchangeURLParams(api.Sign)
			for _, name := range exchangeParams {
				tmpl := api.Sign.Bindings[name]
				key := ctx.taintedRef(tmpl)
				if key == "" {
					continue
				}
				if !soleRef {
					return fmt.Errorf("api %s: sign: request input %q may not be part of the token exchange URL, which receives the app's credentials; keep that URL literal or in env", url, key)
				}
				exchangeURL, err := interpolateOutboundURL(tmpl, ctx, true, "")
				if err != nil {
					return fmt.Errorf("api %s: sign token exchange url: %w", url, err)
				}
				interpolated[name] = exchangeURL
			}
			signCfg.Bindings = interpolated
		}
		overrides := apiMethodOverrideValues(req.Header)
		// Signing can itself send a token-exchange request. Validate every
		// rendered field, including the bindings, before that first effect.
		if err := flowOutboundMissingRefs(ctx, "api"); err != nil {
			return err
		}
		if err := applySigner(req, bodyBytes, &signCfg, ctx.App); err != nil {
			return fmt.Errorf("api %s: %w", url, err)
		}
		// A recipe whose header name or value comes from bindings (bearer_token
		// `header:`) is the other way to set one.
		if taintedBinding != "" && !maps.Equal(overrides, apiMethodOverrideValues(req.Header)) {
			return fmt.Errorf("api %s: sign would let request input %q pick the upstream method through a method-override header; a method-override header must be a literal or env value (write the method in `method:`)", url, taintedBinding)
		}
	}

	if err := flowOutboundMissingRefs(ctx, "api"); err != nil {
		return err
	}
	if client == nil {
		client = safeHTTPClientStrict(timeout)
	}
	if err := requestContext.Err(); err != nil {
		return fmt.Errorf("api %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		RecordFailure(host)
		return fmt.Errorf("api %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBody+1))
	if resp.StatusCode >= 500 {
		RecordFailure(host)
	} else {
		RecordSuccess(host)
	}
	if err != nil {
		return fmt.Errorf("api %s response read: %w", url, err)
	}
	if len(respBody) > maxAPIResponseBody {
		return fmt.Errorf("api %s response exceeds the %d-byte limit", url, maxAPIResponseBody)
	}
	if err := requestContext.Err(); err != nil {
		return fmt.Errorf("api %s: %w", url, err)
	}

	if resp.StatusCode >= 400 && !apiHandlesStatus(api, resp.StatusCode) {
		return fmt.Errorf("api %s returned %d: %s", url, resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	if step.Name != "" {
		envelope := buildAPIResponseEnvelope(resp.StatusCode, resp.Header, respBody)
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = envelope
		flattenIntoCtx(ctx.Data, step.Name, envelope)
		ctx.DataMu.Unlock()
	}

	// success_when: predicate evaluated against the just-stored
	// response envelope. Catches the "API returned 200 + error
	// envelope" shape where the HTTP status alone lies (rss2json,
	// several CRM webhooks). Multiple real apps both ingested
	// error envelopes as data because the step claimed success.
	if step.API != nil && step.API.SuccessWhen != "" {
		if !evaluateFlowCondition(step.API.SuccessWhen, ctx) {
			return fmt.Errorf(
				"api: success_when failed (%s) - response was %d but the predicate evaluated false; check the response body via steps.%s.outputs.body",
				step.API.SuccessWhen, resp.StatusCode, step.Name,
			)
		}
	}

	return nil
}

// apiMethodOverrideHeaders make many servers (Express method-override,
// Google APIs, OData) run the request as another method. The flow fixes
// the method in `method:`, so request input may not set one.
var apiMethodOverrideHeaders = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}

func apiMethodOverrideHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
	for _, h := range apiMethodOverrideHeaders {
		if canonical == h {
			return true
		}
	}
	return false
}

// apiMethodOverrideValues returns the method-override headers h holds.
func apiMethodOverrideValues(h http.Header) map[string]string {
	out := map[string]string{}
	for _, name := range apiMethodOverrideHeaders {
		if v, ok := h[name]; ok {
			out[name] = strings.Join(v, "\x00")
		}
	}
	return out
}

func apiHandlesStatus(api *FlowAPICall, status int) bool {
	if status < 400 || status > 499 {
		return false
	}
	for _, handled := range api.HandledStatuses {
		if handled == status {
			return true
		}
	}
	return false
}

// buildAPIResponseEnvelope assembles the per-step output map that
// `${{ steps.<id>.outputs.<field> }}` reads from for a `run: api`
// step. Pulled out so the response-shaping logic can be unit-tested
// without standing up the network path (httptest binds to loopback,
// which the SSRF guard rightly rejects).
//
// Envelope shape - every key matches the build doc's promised access:
//   - status  (int):     HTTP status code
//   - body    (string):  raw response body
//   - headers (map):     response headers, single-value headers flattened
//     to a scalar, multi-value headers stay as []string
//   - json    (any):     parsed body when the response is valid JSON;
//     omitted otherwise
//
// Back-compat: when the body parses to a JSON object, its top-level
// fields are aliased onto the envelope directly so legacy flows that
// read `${{ steps.<id>.outputs.<field> }}` (without the `.json.`
// prefix) keep working. Conflicts with the four envelope keys
// (status/body/headers/json) leave the envelope key intact.
// execStepAPIPaginated loops the API call until the upstream stops
// returning items (or the next-cursor goes empty), accumulating items
// across pages into one combined slice. Step output is
// `{ items: [...], pages_fetched: N, last_status: 200 }`.
//
// Safety: hard-capped by MaxPages (default 50, cap 500) - silly upstreams
// that return one item per page can't lock the worker.
// Each page is sent from a copy of the call with the cursor or page as a
// literal query value; the shared step config is never written, so
// concurrent invocations stay independent.
func execStepAPIPaginated(ctx *FlowContext, step *FlowStep) error {
	return execStepAPIPaginatedWithClient(ctx, step, nil)
}

func execStepAPIPaginatedWithClient(ctx *FlowContext, step *FlowStep, client *http.Client) error {
	pag := step.API.Paginate
	strategy := pag.Strategy
	if strategy == "" {
		strategy = "cursor"
	}
	maxPages := pag.MaxPages
	if maxPages <= 0 {
		maxPages = 50
	}
	if maxPages > 500 {
		maxPages = 500
	}
	itemsField := pag.ItemsField
	if itemsField == "" {
		itemsField = "$.items" // sensible default
	}

	// Each page is sent from this copy with Paginate cleared, so the
	// single-shot path runs and step.API itself is never written.
	iterAPI := *step.API
	iterAPI.Paginate = nil

	var accum []any
	var lastStatus int
	pagesFetched := 0
	page := pag.PageStart
	if page <= 0 {
		page = 1
	}
	cursor := ""

	for i := 0; i < maxPages; i++ {
		// The cursor comes from the upstream's response: it is sent as a
		// literal value, never interpolated as a template.
		literal := map[string]string{}
		switch strategy {
		case "cursor":
			cp := pag.CursorParam
			if cp == "" {
				cp = "cursor"
			}
			if cursor != "" {
				literal[cp] = cursor
			}
		case "page":
			pp := pag.PageParam
			if pp == "" {
				pp = "page"
			}
			literal[pp] = fmt.Sprintf("%d", page)
		default:
			return fmt.Errorf("paginate: unknown strategy %q (use 'cursor' or 'page')", strategy)
		}

		// One single-shot request per page, on a copy of the call so the
		// shared flow definition is never mutated mid-request.
		if err := execAPIRequestWithClient(ctx, step, &iterAPI, literal, client); err != nil {
			return err
		}
		pagesFetched++

		// Pull the envelope back from ctx.Data, extract items + cursor.
		ctx.DataMu.Lock()
		var envelope any
		if step.Name != "" {
			envelope = ctx.Data[step.Name]
		}
		ctx.DataMu.Unlock()

		items, cur, status := extractPageItems(envelope, itemsField, pag.CursorField)
		lastStatus = status
		if len(items) == 0 {
			break
		}
		accum = append(accum, items...)
		if strategy == "cursor" {
			if cur == "" {
				break // upstream done
			}
			cursor = cur
		} else {
			page++
		}
	}

	// Set the accumulated output. Overwrites the single-shot envelope.
	if step.Name != "" {
		ctx.DataMu.Lock()
		out := map[string]any{
			"items":         accum,
			"pages_fetched": pagesFetched,
			"item_count":    len(accum),
			"last_status":   lastStatus,
		}
		ctx.Data[step.Name] = out
		flattenIntoCtx(ctx.Data, step.Name, out)
		ctx.DataMu.Unlock()
	}
	return nil
}

// extractPageItems pulls (items, nextCursor, statusCode) out of an
// API-step envelope based on the configured JSON paths. Lenient about
// shape: items_field can point at a top-level array or a nested one;
// cursor_field is treated as a plain dotted path under the JSON body.
// Returns zero items when paths don't resolve - the paginator treats
// that as "we're done."
func extractPageItems(envelope any, itemsField, cursorField string) ([]any, string, int) {
	envMap, _ := envelope.(map[string]any)
	if envMap == nil {
		return nil, "", 0
	}
	status, _ := envMap["status"].(int)
	body, _ := envMap["json"]
	if body == nil {
		// Try parsing the raw body if json didn't pre-parse.
		if raw, ok := envMap["body"].(string); ok && raw != "" {
			var parsed any
			if json.Unmarshal([]byte(raw), &parsed) == nil {
				body = parsed
			}
		}
	}
	items := lookupJSONPath(body, itemsField)
	itemsSlice, _ := items.([]any)
	cursor := ""
	if cursorField != "" {
		if v := lookupJSONPath(body, cursorField); v != nil {
			cursor = fmt.Sprintf("%v", v)
		}
	}
	return itemsSlice, cursor, status
}

// lookupJSONPath is a tiny dotted-path resolver: "$.foo.bar" reads
// body.foo.bar. Supports the leading "$." or bare-dotted form. No array
// indexing - agents who need that should use json_extract() in SQL
// instead.
func lookupJSONPath(body any, path string) any {
	if body == nil || path == "" {
		return nil
	}
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")
	cur := body
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	return cur
}

func buildAPIResponseEnvelope(statusCode int, header http.Header, respBody []byte) map[string]any {
	hdrs := make(map[string]any, len(header))
	for k, v := range header {
		if len(v) == 1 {
			hdrs[k] = v[0]
		} else {
			hdrs[k] = v
		}
	}
	envelope := map[string]any{
		"status":  statusCode,
		"body":    string(respBody),
		"headers": hdrs,
	}
	var parsed any
	if err := json.Unmarshal(respBody, &parsed); err == nil {
		envelope["json"] = parsed
		if m, ok := parsed.(map[string]any); ok {
			for k, v := range m {
				if _, taken := envelope[k]; !taken {
					envelope[k] = v
				}
			}
		}
	}
	return envelope
}

// webhookCallerMayChooseContextURL reports a caller trusted with the whole
// flow context at a URL of its choosing: the app's own global admin acting
// as itself (Notify Hub-style service accounts asking for a delivery
// callback, with a session or an API token of any scope), never an
// impersonated, act-as or connector session.
func webhookCallerMayChooseContextURL(s *Session) bool {
	return s != nil && s.IsAdmin() && !s.connectorGrant && s.ImpersonatorUserID == 0 && s.ActingAsGroup == ""
}

// dataWithoutSecrets is a copy of the flow context without the values the
// secret taint marks as env-derived (top-level step outputs and dotted keys).
func (ctx *FlowContext) dataWithoutSecrets() map[string]any {
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	out := make(map[string]any, len(ctx.Data))
	for k, v := range ctx.Data {
		if ctx.SecretKeys[k] {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			trimmed := make(map[string]any, len(m))
			for ck, cv := range m {
				if !ctx.SecretKeys[k+"."+ck] {
					trimmed[ck] = cv
				}
			}
			v = trimmed
		}
		out[k] = v
	}
	return out
}

func execStepWebhook(ctx *FlowContext, step *FlowStep) error {
	// The body may carry env secrets, written in or derived through an
	// earlier step; that decides whether request input may choose the host
	// (flows_api_url.go). A JSON payload counts leaf by leaf.
	secrets, derived := strings.Contains(step.Webhook, "env.") || strings.Contains(step.WebhookBody, "env.") || jsonTemplateRefsEnv(step.WebhookJSON), ""
	if !secrets {
		for _, template := range appendJSONTemplateStrings([]string{step.Webhook, step.WebhookBody}, step.WebhookJSON) {
			if derived = ctx.secretRef(template); derived != "" {
				break
			}
		}
	}
	url, err := interpolateOutboundURL(step.Webhook, ctx, secrets, derived)
	if err != nil {
		return err
	}

	// A declared payload (`with.payload`, or `body:` as a map or list) is
	// the JSON body, each value resolved like an api `json:` value. It used
	// to be dropped, and the step posted the whole flow context instead.
	// A value that does not resolve stops the step before anything is sent.
	var body string
	if step.WebhookJSON != nil {
		data, err := json.Marshal(resolveJSONValue(step.WebhookJSON, ctx))
		if err != nil {
			return fmt.Errorf("webhook: payload: %w", err)
		}
		body = string(data)
	} else {
		body = interpolateCtxJSON(step.WebhookBody, ctx)
	}
	if err := flowOutboundMissingRefs(ctx, "webhook"); err != nil {
		return err
	}
	// With no body the step sends the whole flow context: every request
	// field and step output, env-derived values included. That default is
	// kept only for a URL the author fixed; a request- or row-chosen URL
	// must say what it receives. A declared payload never reaches here.
	if body == "" {
		payload := ctx.Data
		if key := ctx.taintedRef(step.Webhook); key != "" {
			// A global admin of the app (a service account calling a
			// delivery callback) may still choose where the context goes,
			// minus env-derived values; anyone else must say what it sends.
			if !webhookCallerMayChooseContextURL(ctx.Session) {
				return fmt.Errorf("webhook: the URL takes request input %q, so the step must set `body:`; with no body it would send the whole flow context there", key)
			}
			payload = ctx.dataWithoutSecrets()
		}
		data, _ := json.Marshal(payload)
		body = string(data)
	}

	// SSRF protection: block requests to private/internal IPs
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked webhook to private URL: %s", url)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// ctx.apiClient is the per-run native-test transport (nil in production:
	// the strict SSRF-guarded client). The private-URL check above stays.
	client := ctx.apiClient
	if client == nil {
		client = safeHTTPClientStrict(10 * time.Second)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: delivery returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// The dispatcher's post-step check cannot undo an external effect. Call this
// after rendering all inputs, before signing/token exchange or delivery.
func flowOutboundMissingRefs(ctx *FlowContext, kind string) error {
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		return fmt.Errorf("%s: nothing was sent: %s had no value in scope", kind, strings.Join(missing, ", "))
	}
	return nil
}
