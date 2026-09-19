//go:build !cli

package main

// Outbound API and webhook steps, pagination, and response envelopes.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

func execStepAPI(ctx *FlowContext, step *FlowStep) error {
	api := step.API
	if api == nil {
		return fmt.Errorf("api step has no config")
	}
	// Pagination wrapper: loops the single-shot path until the upstream
	// runs out of pages, accumulates items, sets the step output to
	// { items: [...], pages_fetched: N }. Without this, every flow with
	// a hardcoded `?limit=500` would silently drop data past the cap.
	if api.Paginate != nil {
		return execStepAPIPaginated(ctx, step)
	}

	url := interpolateCtx(api.URL, ctx)
	url = InterpolateEnv(url, ctx.App.Dir)

	// Append `with.query:` params to the URL. Keys + values are
	// percent-encoded; values flow through ctx interpolation + env so
	// `${{ user.customer_id }}` or `${{ env.X }}` resolve here.
	if len(api.Query) > 0 {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		var parts []string
		for k, v := range api.Query {
			resolved := InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir)
			parts = append(parts, neturl.QueryEscape(k)+"="+neturl.QueryEscape(resolved))
		}
		url += sep + strings.Join(parts, "&")
	}

	// SSRF protection: block requests to private/internal IPs.
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked API request to private URL: %s", url)
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
	} else if api.Form != nil {
		var formParts []string
		for k, v := range api.Form {
			formParts = append(formParts, fmt.Sprintf("%s=%s", k, interpolateCtx(v, ctx)))
		}
		bodyBytes = []byte(strings.Join(formParts, "&"))
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
	host := extractHost(url)
	if err := CheckCircuit(host); err != nil {
		return fmt.Errorf("api %s: %s", url, err)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	if api.Auth != "" {
		auth := InterpolateEnv(interpolateCtx(api.Auth, ctx), ctx.App.Dir)
		req.Header.Set("Authorization", auth)
	}
	for k, v := range api.Headers {
		req.Header.Set(k, InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir))
	}

	// Pluggable outbound signing - interpolates bindings against the
	// flow context + env, then runs the recipe (named built-in or
	// inline). The recipe mutates req headers / query before send.
	// bodyBytes is the source-of-truth payload for hashing.
	if api.Sign != nil {
		signCfg := *api.Sign // shallow copy
		if api.Sign.Bindings != nil {
			interpolated := make(map[string]string, len(api.Sign.Bindings))
			for k, v := range api.Sign.Bindings {
				interpolated[k] = InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir)
			}
			signCfg.Bindings = interpolated
		}
		if err := applySigner(req, bodyBytes, &signCfg, ctx.App); err != nil {
			return fmt.Errorf("api %s: %w", url, err)
		}
	}

	timeout := 30 * time.Second
	if step.Timeout > 0 {
		timeout = step.Timeout
	}
	client := safeHTTPClientStrict(timeout)

	resp, err := client.Do(req)
	if err != nil {
		RecordFailure(host)
		return fmt.Errorf("api %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 500 {
		RecordFailure(host)
	} else {
		RecordSuccess(host)
	}

	if resp.StatusCode >= 400 {
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
// Mutates a local copy of api.Query each iteration; the original step
// config is left untouched so concurrent invocations stay independent.
func execStepAPIPaginated(ctx *FlowContext, step *FlowStep) error {
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

	// Per-iteration copy of api.Query so we can mutate cursor/page
	// values without affecting the source step config.
	baseQuery := map[string]string{}
	for k, v := range step.API.Query {
		baseQuery[k] = v
	}

	var accum []any
	var lastStatus int
	page := pag.PageStart
	if page <= 0 {
		page = 1
	}
	cursor := ""

	for i := 0; i < maxPages; i++ {
		iterQuery := map[string]string{}
		for k, v := range baseQuery {
			iterQuery[k] = v
		}
		switch strategy {
		case "cursor":
			cp := pag.CursorParam
			if cp == "" {
				cp = "cursor"
			}
			if cursor != "" {
				iterQuery[cp] = cursor
			}
		case "page":
			pp := pag.PageParam
			if pp == "" {
				pp = "page"
			}
			iterQuery[pp] = fmt.Sprintf("%d", page)
		default:
			return fmt.Errorf("paginate: unknown strategy %q (use 'cursor' or 'page')", strategy)
		}

		// Build a single-shot step for this iteration. Reuses
		// execStepAPI's single-request path by temporarily swapping
		// the Query map; restored before next iteration.
		origQuery := step.API.Query
		step.API.Query = iterQuery
		// Suppress recursion: clear the Paginate pointer for the inner
		// call so it takes the single-shot branch.
		origPaginate := step.API.Paginate
		step.API.Paginate = nil
		err := execStepAPI(ctx, step)
		step.API.Query = origQuery
		step.API.Paginate = origPaginate
		if err != nil {
			return err
		}

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
			"pages_fetched": len(accum) / max(1, len(accum)/maxPages+1), // best-effort
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

func execStepWebhook(ctx *FlowContext, step *FlowStep) error {
	url := InterpolateEnv(interpolateCtx(step.Webhook, ctx), ctx.App.Dir)

	// SSRF protection: block requests to private/internal IPs
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked webhook to private URL: %s", url)
	}

	body := interpolateCtx(step.WebhookBody, ctx)
	if body == "" {
		data, _ := json.Marshal(ctx.Data)
		body = string(data)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := safeHTTPClientStrict(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
