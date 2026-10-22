//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A form body value is one value: `x&amount=1&customer=cus_victim` must not
// add or override parameters on a request that carries the app's secret
// key (Stripe-style form APIs read the last or first duplicate).
func TestAPIFormBodyCannotInjectParameters(t *testing.T) {
	ctx := &FlowContext{
		Data:   map[string]any{"desc": "x&amount=1&customer=cus_victim"},
		Params: map[string]string{"desc": "x&amount=1&customer=cus_victim"},
	}
	body := apiFormBody(ctx, map[string]string{
		"description":       "{{desc}}",
		"amount":            "500",
		"metadata[note id]": "a=b",
	})
	values, err := neturl.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("form body is not valid form encoding: %v (%s)", err, body)
	}
	if got := values["amount"]; len(got) != 1 || got[0] != "500" {
		t.Fatalf("amount = %v, want only the author's 500 (body %s)", got, body)
	}
	if _, injected := values["customer"]; injected {
		t.Fatalf("request value added a customer parameter: %s", body)
	}
	if got := values.Get("description"); got != "x&amount=1&customer=cus_victim" {
		t.Fatalf("description = %q, want the whole request value", got)
	}
	if got := values.Get("metadata[note id]"); got != "a=b" {
		t.Fatalf("author key with brackets/space not round-tripped: %q", got)
	}
	if again := apiFormBody(ctx, map[string]string{"description": "{{desc}}", "amount": "500", "metadata[note id]": "a=b"}); string(again) != string(body) {
		t.Fatalf("form body is not deterministic: %s vs %s", body, again)
	}
}

// On main a form value holding + or & only arrived intact when the author
// wrote it as {{x | urlencode}} (Twilio's To=+1555...). Now that the body is
// form-encoded, that value must not be encoded a second time.
func TestAPIFormBodyKeepsURLEncodedValues(t *testing.T) {
	ctx := &FlowContext{
		Data:   map[string]any{"to": "+15551234567", "msg": "hi & bye"},
		Params: map[string]string{},
	}
	body := apiFormBody(ctx, map[string]string{
		"To":    "{{to | urlencode}}",
		"Body":  "{{ msg | urlencode }}",
		"Raw":   "{{msg}}",
		"Mixed": "note: {{msg | urlencode}}",
	})
	values, err := neturl.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"To": "+15551234567", "Body": "hi & bye", "Raw": "hi & bye", "Mixed": "note: hi+%26+bye"} {
		if got := values.Get(k); got != want {
			t.Errorf("%s = %q, want %q (body %s)", k, got, want, body)
		}
	}
}

func outboundURLCtx(data map[string]any, tainted ...string) *FlowContext {
	params := map[string]string{}
	for k, v := range data {
		if s, ok := v.(string); ok {
			params[k] = s
		}
	}
	keys := map[string]bool{}
	for _, k := range tainted {
		keys[k] = true
	}
	return &FlowContext{Data: data, Params: params, RequestKeys: keys}
}

// A request value placed in the path or query stays inside its segment or
// parameter: it can't climb to another endpoint or add query parameters to
// a request carrying the app's credentials.
func TestAPIRequestURLEncodesValuesByPosition(t *testing.T) {
	ctx := outboundURLCtx(map[string]any{
		"id":     "../admin/keys?x=",
		"expand": "a&limit=1000#frag",
	}, "id", "expand")
	api := &FlowAPICall{
		URL:     "https://api.example.com/v1/customers/{{id}}/charges?expand={{expand}}",
		Headers: map[string]string{"X-Api-Key": "{{env.KEY}}"},
	}
	got, err := buildAPIRequestURL(ctx, api, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := neturl.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "api.example.com" {
		t.Fatalf("host changed: %s", got)
	}
	if u.EscapedPath() != "/v1/customers/..%2Fadmin%2Fkeys%3Fx=/charges" {
		t.Fatalf("path = %q, want the id kept in one segment", u.EscapedPath())
	}
	q := u.Query()
	if len(q) != 1 || q.Get("expand") != "a&limit=1000#frag" || u.Fragment != "" {
		t.Fatalf("query = %v fragment = %q, want one expand value", q, u.Fragment)
	}

	// `:param` tokens get the same treatment.
	got, err = buildAPIRequestURL(ctx, &FlowAPICall{URL: "https://api.example.com/v1/items/:id"}, nil)
	if err != nil || !strings.HasSuffix(got, "/v1/items/..%2Fadmin%2Fkeys%3Fx=") {
		t.Fatalf(":param in path = %q, %v", got, err)
	}

	// A value that is only dots is still a traversal segment after
	// escaping, so it is refused.
	for _, dots := range []string{"..", "."} {
		dotCtx := outboundURLCtx(map[string]any{"id": dots}, "id")
		if _, err := buildAPIRequestURL(dotCtx, &FlowAPICall{URL: "https://api.example.com/v1/customers/{{id}}"}, nil); err == nil {
			t.Fatalf("dot segment %q was accepted in the path", dots)
		}
	}

	// Ordinary values are unchanged.
	plain := outboundURLCtx(map[string]any{"id": "cus_123", "q": "abc"}, "id", "q")
	got, err = buildAPIRequestURL(plain, &FlowAPICall{URL: "https://api.example.com/v1/customers/{{id}}?q={{q}}"}, nil)
	if err != nil || got != "https://api.example.com/v1/customers/cus_123?q=abc" {
		t.Fatalf("plain values = %q, %v", got, err)
	}
}

// Request input laundered through a run: set step, or placed with the
// :param or params.X forms, is still request input for the host check.
func TestAPIRequestURLHostTaintSurvivesSetAndParamForms(t *testing.T) {
	ctx := outboundURLCtx(map[string]any{"target": "https://evil.example/collect"}, "target")
	if err := execStepSet(ctx, &FlowStep{Type: "set", Name: "cfg", Set: map[string]string{"u": "{{target}}"}}); err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"{{u}}", "{{cfg.u}}", ":target", "{{params.target}}", "https://{{params.target | default:'x'}}/v1"} {
		call := &FlowAPICall{URL: url, Headers: map[string]string{"X-Api-Key": "{{env.K}}"}}
		if got, err := buildAPIRequestURL(ctx, call, nil); err == nil {
			t.Errorf("%s: request input chose the URL of a credentialed call: %s", url, got)
		}
	}
}

// Before values were encoded by position, `{{x | urlencode}}` was how a flow
// put a value in a URL safely. Its output is already query-escaped (no / ?
// # & =), so encoding it again would send `a+b%2526c` for "a b&c".
func TestAPIRequestURLKeepsURLEncodedValues(t *testing.T) {
	ctx := outboundURLCtx(map[string]any{"q": "a b&c", "name": "my file/x.pdf", "dots": ".."}, "q", "name", "dots")
	got, err := buildAPIRequestURL(ctx, &FlowAPICall{
		URL:     "https://api.example.com/files/{{name | urlencode}}?q={{ q | urlencode }}",
		Headers: map[string]string{"X-Api-Key": "{{env.KEY}}"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://api.example.com/files/my+file%2Fx.pdf?q=a+b%26c"; got != want {
		t.Fatalf("urlencoded values = %q, want %q", got, want)
	}
	u, _ := neturl.Parse(got)
	if u.Query().Get("q") != "a b&c" || len(u.Query()) != 1 {
		t.Fatalf("query = %v, want q = %q", u.Query(), "a b&c")
	}
	// Still one path segment, and still no dot segment.
	if _, err := buildAPIRequestURL(ctx, &FlowAPICall{URL: "https://api.example.com/v1/{{dots | urlencode}}/x"}, nil); err == nil {
		t.Fatal("a urlencoded dot segment was accepted in the path")
	}
	// The host still takes host characters only.
	if _, err := buildAPIRequestURL(ctx, &FlowAPICall{URL: "https://{{q | urlencode}}.example.com/x"}, nil); err == nil {
		t.Fatal("a urlencoded value was accepted in the host")
	}
}

// Request input may not choose the scheme or host of a request that carries
// credentials; a value spliced into a host may only hold host characters.
func TestAPIRequestURLHostIsNotRequestControlled(t *testing.T) {
	secretCall := func(url string) *FlowAPICall {
		return &FlowAPICall{URL: url, Auth: "Bearer {{env.STRIPE_KEY}}"}
	}
	evil := outboundURLCtx(map[string]any{"target": "https://evil.example/collect"}, "target")
	if _, err := buildAPIRequestURL(evil, secretCall("{{target}}"), nil); err == nil {
		t.Fatal("request value chose the whole URL of a credentialed call")
	}
	// Without credentials a caller-chosen public URL (link previews) still
	// works; the SSRF guard judges it.
	got, err := buildAPIRequestURL(evil, &FlowAPICall{URL: "{{target}}"}, nil)
	if err != nil || got != "https://evil.example/collect" {
		t.Fatalf("uncredentialed caller URL = %q, %v", got, err)
	}

	region := outboundURLCtx(map[string]any{"region": "evil.example/x?"}, "region")
	if _, err := buildAPIRequestURL(region, secretCall("https://{{region}}.api.example.com/v1"), nil); err == nil {
		t.Fatal("request value reached the host of a credentialed call")
	}
	// An untainted step output in the host must look like a host.
	stored := outboundURLCtx(map[string]any{"cfg": map[string]any{"sub": "evil.example/x?"}})
	if _, err := buildAPIRequestURL(stored, &FlowAPICall{URL: "https://{{cfg.sub}}.zendesk.com/api"}, nil); err == nil {
		t.Fatal("non-host step value was spliced into the host")
	}
	stored = outboundURLCtx(map[string]any{"cfg": map[string]any{"sub": "acme"}})
	got, err = buildAPIRequestURL(stored, &FlowAPICall{URL: "https://{{cfg.sub}}.zendesk.com/api"}, nil)
	if err != nil || got != "https://acme.zendesk.com/api" {
		t.Fatalf("host label from a step = %q, %v", got, err)
	}

	// A leading untainted value is the URL (an upstream `next` link).
	next := outboundURLCtx(map[string]any{"page": map[string]any{"next": "https://api.example.com/v1/items?cursor=a%2Fb"}})
	got, err = buildAPIRequestURL(next, secretCall("{{page.next}}"), nil)
	if err != nil || got != "https://api.example.com/v1/items?cursor=a%2Fb" {
		t.Fatalf("leading step URL = %q, %v", got, err)
	}
}

// env values are author-controlled and stay verbatim (a configured base URL
// with a path); request values after them are still encoded.
func TestAPIRequestURLKeepsEnvVerbatim(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "OUTBOUND_BASE", "https://api.example.com/v2")
	ctx := outboundURLCtx(map[string]any{"id": "a/b"}, "id")
	ctx.App = app
	got, err := buildAPIRequestURL(ctx, &FlowAPICall{URL: "{{env.OUTBOUND_BASE}}/items/{{id}}", Auth: "{{env.KEY}}"}, nil)
	if err != nil || got != "https://api.example.com/v2/items/a%2Fb" {
		t.Fatalf("env base URL = %q, %v", got, err)
	}
	got, err = buildAPIRequestURL(ctx, &FlowAPICall{URL: "https://{{env.OUTBOUND_HOST | default:'api.example.com'}}/items"}, nil)
	if err != nil || got != "https://api.example.com/items" {
		t.Fatalf("env default in host = %q, %v", got, err)
	}
}

func TestWebhookStepURLIsEncoded(t *testing.T) {
	ctx := outboundURLCtx(map[string]any{"id": "../internal?x="}, "id")
	got, err := interpolateURLCtx("https://hooks.example.com/notify/{{id}}", ctx, true)
	if err != nil || got != "https://hooks.example.com/notify/..%2Finternal%3Fx=" {
		t.Fatalf("webhook URL = %q, %v", got, err)
	}
}

type outboundRoundTrip func(*http.Request) (*http.Response, error)

func (f outboundRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A cross-origin redirect must not carry the author's secret headers or a
// signer's headers to the redirect target; net/http only strips
// Authorization and Cookie.
func TestStrictClientStripsSecretHeadersOnCrossOriginRedirect(t *testing.T) {
	const origin, other = "93.184.216.34", "93.184.216.35"
	var landed http.Header
	client := safeHTTPClientStrict(5 * time.Second)
	client.Transport = outboundRoundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case origin:
			if r.URL.Path == "/start" {
				h := http.Header{"Location": {"https://" + other + "/land"}}
				return &http.Response{StatusCode: http.StatusFound, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
		case other:
			landed = r.Header.Clone()
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	req, _ := http.NewRequest("GET", "https://"+origin+"/start?api_key=secret", nil)
	req.Header.Set("X-Api-Key", "sk_live_secret")
	req.Header.Set("X-Signature", "sig")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if landed == nil {
		t.Fatal("redirect target was not reached")
	}
	for _, h := range []string{"X-Api-Key", "X-Signature", "Authorization", "Referer"} {
		if v := landed.Get(h); v != "" {
			t.Errorf("%s = %q reached the cross-origin redirect target", h, v)
		}
	}
	if landed.Get("Accept") != "application/json" {
		t.Errorf("harmless Accept header was dropped: %v", landed)
	}
}

func TestStrictRedirectPolicy(t *testing.T) {
	mk := func(method, raw string) *http.Request {
		r, _ := http.NewRequest(method, raw, nil)
		r.Header.Set("X-Api-Key", "secret")
		return r
	}
	orig := mk("POST", "https://api.example.com/v1/x")
	same := mk("GET", "https://api.example.com/v1/y")
	if err := strictRedirectPolicy(same, []*http.Request{orig}); err != nil || same.Header.Get("X-Api-Key") == "" {
		t.Fatalf("same-origin redirect changed: %v %v", err, same.Header)
	}
	upgrade := mk("GET", "https://api.example.com/v1/y")
	if err := strictRedirectPolicy(upgrade, []*http.Request{mk("GET", "http://api.example.com/v1/x")}); err != nil || upgrade.Header.Get("X-Api-Key") == "" {
		t.Fatalf("http->https upgrade on the same host lost its headers: %v", err)
	}
	port := mk("GET", "https://api.example.com:8443/v1/y")
	if err := strictRedirectPolicy(port, []*http.Request{orig}); err != nil || port.Header.Get("X-Api-Key") != "" {
		t.Fatalf("another port is another origin: %v %v", err, port.Header)
	}
	body := mk("POST", "https://other.example.com/v1/y")
	if err := strictRedirectPolicy(body, []*http.Request{orig}); err == nil {
		t.Fatal("cross-origin 307/308 of a POST body was allowed")
	}
}

// All strict clients share one bounded transport that never routes through
// an environment proxy (the dial check would then see only the proxy).
func TestStrictClientsShareBoundedTransport(t *testing.T) {
	a, b := safeHTTPClientStrict(time.Second), safeHTTPClientStrict(30*time.Second)
	if a.Transport != b.Transport {
		t.Fatal("each strict client built its own transport")
	}
	tr, ok := a.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", a.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("strict transport honours environment proxies")
	}
	if tr.IdleConnTimeout <= 0 || tr.IdleConnTimeout > 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want a bounded idle lifetime", tr.IdleConnTimeout)
	}
	if tr.MaxIdleConnsPerHost <= 0 || tr.MaxIdleConnsPerHost > 32 {
		t.Fatalf("MaxIdleConnsPerHost = %d", tr.MaxIdleConnsPerHost)
	}
	if a.Timeout != time.Second || b.Timeout != 30*time.Second {
		t.Fatal("per-client timeout lost")
	}
}

// A request field named like a `run: set` output, a for_each loop variable
// or an unnamed parse step's output is shadowed like a step id, so it can't
// stand in for a set that was skipped.
func TestSetOutputNamesShadowRequestFields(t *testing.T) {
	app, mux := auditApp(t)
	file := filepath.Join(t.TempDir(), "gate.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/gate
    auth: none
jobs:
  main:
    steps:
      - if: ${{ params.mode }} == 'admin'
        run: set
        with:
          allowed: "yes"
      - if: ${{ allowed }}
        run: respond
        with:
          json: { granted: true, requested: "${{ params.allowed | default:'' }}" }
      - run: respond
        with:
          status: 403
          json: { granted: false, requested: "${{ params.allowed | default:'' }}" }
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := loadOneGHAFile(file)
	if len(flows) != 1 {
		t.Fatalf("flows = %d", len(flows))
	}
	RegisterFlows(mux, app, flows)
	call := func(body string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/api/flows/gate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	if code, out := call(`{"allowed":"yes"}`); code != 403 || out["granted"] != false {
		t.Fatalf("request field stood in for the skipped set: %d %v", code, out)
	} else if out["requested"] != "yes" {
		t.Fatalf("shadowed field is no longer readable as params.allowed: %v", out)
	}
	if code, out := call(`{"mode":"admin"}`); code != 200 || out["granted"] != true {
		t.Fatalf("the set itself no longer gates: %d %v", code, out)
	}

	ctx := &FlowContext{
		Data:        map[string]any{"row": "r", "item": "i", "body": "b", "other": "o"},
		Params:      map[string]string{},
		RequestKeys: map[string]bool{"row": true, "item": true, "body": true, "other": true},
	}
	steps := []FlowStep{
		{Type: "for_each", ForEach: "rows", ForAs: "row"},
		{Type: "if", Steps: []FlowStep{{Type: "for_each", ForEach: "rows"}}},
		{Type: "parse", Parse: "body"},
	}
	shadowStepNamedRequestKeys(ctx, steps)
	// Readable until execution reaches the step that defines the name
	// (TestRequestFieldReadableUntilItsDefiningStep), shadowed from then on.
	for _, k := range []string{"row", "item", "body"} {
		if _, ok := ctx.Data[k]; !ok {
			t.Errorf("request field %q was shadowed before its step was reached", k)
		}
	}
	shadowReachedSteps(ctx, steps, true)
	for _, k := range []string{"row", "item", "body"} {
		if _, ok := ctx.Data[k]; ok {
			t.Errorf("request field %q was not shadowed", k)
		}
	}
	if ctx.Data["other"] != "o" {
		t.Error("an unrelated request field was moved")
	}
}

// Shadowing a set key must not hide the request field from the set that
// writes it: `page: "${{ page | default:'1' }}"` normalizes the request's
// own page. Only a set that is skipped must not be stood in for.
func TestRunningSetStillReadsItsShadowedRequestField(t *testing.T) {
	app, mux := auditApp(t)
	file := filepath.Join(t.TempDir(), "list.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/list
    auth: none
jobs:
  main:
    steps:
      - run: set
        with:
          page: "${{ page | default:'1' }}"
          q: "${{ q || '' }}"
      - if: ${{ params.mode }} == 'admin'
        run: set
        with:
          allowed: "${{ allowed | default:'yes' }}"
      - run: respond
        with:
          json: { page: "${{ page }}", q: "${{ q }}", allowed: "${{ allowed | default:'unset' }}" }
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	RegisterFlows(mux, app, loadOneGHAFile(file))
	call := func(body string) map[string]any {
		req := httptest.NewRequest("POST", "/api/flows/list", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if out := call(`{"page":"3","q":"shoes"}`); out["page"] != "3" || out["q"] != "shoes" {
		t.Fatalf("a running set lost the request value it normalizes: %v", out)
	}
	if out := call(`{}`); out["page"] != "1" || out["q"] != "" {
		t.Fatalf("defaults: %v", out)
	}
	// The skipped set is still not stood in for by the request field.
	if out := call(`{"allowed":"no"}`); out["allowed"] != "unset" {
		t.Fatalf("request field stood in for a skipped set: %v", out)
	}
	if out := call(`{"mode":"admin","allowed":"no"}`); out["allowed"] != "no" {
		t.Fatalf("a running conditional set lost its request value: %v", out)
	}
}

// The _platform extract_source shape: an early step reads the request's
// `text`, and a later set (inside an if block) defines its own `text`. The
// request field is readable until execution reaches that set, run or
// skipped, and never stands in for it afterwards.
func TestRequestFieldReadableUntilItsDefiningStep(t *testing.T) {
	app, mux := auditApp(t)
	file := filepath.Join(t.TempDir(), "extract.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/extract
    auth: none
jobs:
  main:
    steps:
      - id: src
        run: set
        with:
          source_text: "${{ text | default:'' }}"
      - if: "${{ source_type | default:'' }} == 'agreement'"
        steps:
          - id: agreement_guidance
            run: set
            with:
              text: "GUIDANCE"
      - run: respond
        with:
          json:
            source_text: "${{ steps.src.outputs.source_text }}"
            text: "${{ text | default:'unset' }}"
            requested: "${{ params.text | default:'' }}"
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	RegisterFlows(mux, app, loadOneGHAFile(file))
	call := func(body string) map[string]any {
		req := httptest.NewRequest("POST", "/api/flows/extract", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	// The set runs: the early read saw the request text, later reads the set's.
	out := call(`{"source_type":"agreement","text":"AGREEMENT"}`)
	if out["source_text"] != "AGREEMENT" || out["text"] != "GUIDANCE" || out["requested"] != "AGREEMENT" {
		t.Fatalf("set ran: %v", out)
	}
	// The set is skipped: the early read still saw the request text, and the
	// request field does not stand in for the skipped set afterwards.
	out = call(`{"source_type":"meeting","text":"FORGED"}`)
	if out["source_text"] != "FORGED" || out["text"] != "unset" || out["requested"] != "FORGED" {
		t.Fatalf("set skipped: %v", out)
	}

	// Nested blocks and loops, step by step.
	newCtx := func() *FlowContext {
		data := map[string]any{"a": "ra", "b": "rb", "c": "rc", "row": "rrow", "d": "rd"}
		keys := map[string]bool{}
		for k := range data {
			keys[k] = true
		}
		data["flag"] = "yes" // not request input
		return &FlowContext{Data: data, Params: map[string]string{}, RequestKeys: keys}
	}
	steps := []FlowStep{
		{Type: "if", Condition: ghaIfToFlowCondition("${{ flag }} == 'yes'"),
			Steps:     []FlowStep{{Type: "set", Set: map[string]string{"a": "A"}}},
			ElseSteps: []FlowStep{{Type: "set", Set: map[string]string{"b": "B"}}}},
		{Type: "for_each", ForEach: "nothing", ForAs: "row", Steps: []FlowStep{{Type: "set", Set: map[string]string{"c": "C"}}}},
		{Type: "set", Set: map[string]string{"d": "D"}},
	}
	ctx := newCtx()
	shadowStepNamedRequestKeys(ctx, steps)
	for _, k := range []string{"a", "b", "c", "row", "d"} {
		if _, ok := ctx.Data[k]; !ok {
			t.Fatalf("request field %q hidden before any step that defines it ran", k)
		}
	}
	if err := executeStep(ctx, &steps[0]); err != nil {
		t.Fatal(err)
	}
	if ctx.Data["a"] != "A" {
		t.Fatalf("taken branch set: a = %v", ctx.Data["a"])
	}
	if _, ok := ctx.Data["b"]; ok {
		t.Fatal("the untaken else branch's set was stood in for by the request field")
	}
	if ctx.Data["c"] != "rc" || ctx.Data["d"] != "rd" {
		t.Fatal("fields defined only by later steps must still be readable")
	}
	if err := executeStep(ctx, &steps[1]); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"c", "row"} {
		if _, ok := ctx.Data[k]; ok {
			t.Fatalf("a loop that ran zero times left request field %q standing in", k)
		}
	}
	if ctx.Data["d"] != "rd" {
		t.Fatal("d is defined by a later step")
	}
	if store, _ := ctx.Data[flowStepNamedParamsKey].(map[string]any); store["b"] != "rb" || store["c"] != "rc" || store["row"] != "rrow" {
		t.Fatalf("shadowed fields must stay readable as params: %v", store)
	}
}

// A dotted `run: set` key is read as `{{gate.ok}}`, which a request object
// {"gate": {"ok": ...}} also flattens to. The request field must be
// shadowed so it can't stand in for the skipped set.
func TestDottedSetKeyShadowsNestedRequestObject(t *testing.T) {
	app, mux := auditApp(t)
	file := filepath.Join(t.TempDir(), "gate2.yaml")
	flow := `on:
  request:
    method: POST
    path: /api/flows/gate2
    auth: none
jobs:
  main:
    steps:
      - if: ${{ params.mode }} == 'admin'
        run: set
        with:
          gate.ok: "yes"
      - if: ${{ gate.ok }} == 'yes'
        run: respond
        with:
          json: { granted: true }
      - run: respond
        with:
          status: 403
          json: { granted: false }
`
	if err := os.WriteFile(file, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	RegisterFlows(mux, app, loadOneGHAFile(file))
	call := func(body string) map[string]any {
		req := httptest.NewRequest("POST", "/api/flows/gate2", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	for _, body := range []string{`{"gate":{"ok":"yes"}}`, `{"gate.ok":"yes"}`} {
		if out := call(body); out["granted"] != false {
			t.Errorf("request body %s stood in for the skipped dotted set: %v", body, out)
		}
	}
	if out := call(`{"mode":"admin"}`); out["granted"] != true {
		t.Fatalf("the dotted set itself no longer gates: %v", out)
	}

	ctx := &FlowContext{
		Data:        map[string]any{"a": map[string]any{"b": map[string]any{"c": 1}}, "a.b": "x", "gate": "g"},
		Params:      map[string]string{},
		RequestKeys: map[string]bool{"a": true, "a.b": true, "gate": true},
	}
	steps := []FlowStep{{Type: "set", Set: map[string]string{"a.b.c": "1"}}}
	shadowStepNamedRequestKeys(ctx, steps)
	shadowReachedSteps(ctx, steps, true) // the set is reached
	for _, k := range []string{"a", "a.b"} {
		if _, ok := ctx.Data[k]; ok {
			t.Errorf("request field %q (a prefix of set key a.b.c) was not shadowed", k)
		}
	}
	if ctx.Data["gate"] != "g" {
		t.Error("an unrelated request field was moved")
	}
}

// The flattened lookup table is reused while ctx.Data is unchanged and
// rebuilt after any change at the top level or inside a top-level map.
func TestFlatDataCacheInvalidates(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "FLAT_CACHE_ENV", "one")
	inner := map[string]any{"k": 1}
	ctx := &FlowContext{App: app, Data: map[string]any{"a": "1", "m": inner, "rows": []map[string]any{{"x": 1}}}, Params: map[string]string{}}
	first := flatDataForCtx(ctx)
	if reflect.ValueOf(flatDataForCtx(ctx)).UnsafePointer() != reflect.ValueOf(first).UnsafePointer() {
		t.Fatal("unchanged data rebuilt the table")
	}
	check := func(what, key string, want any) {
		t.Helper()
		got, ok := flatDataForCtx(ctx)[key]
		if want == nil {
			if ok {
				t.Fatalf("%s: %s still present (%v)", what, key, got)
			}
			return
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: %s = %v, want %v", what, key, got, want)
		}
	}
	ctx.Data["a"] = "2"
	check("scalar overwrite", "a", "2")
	inner["j"] = 2
	check("insert into a top-level map", "m.j", 2)
	delete(ctx.Data, "a")
	check("delete", "a", nil)
	ctx.Data["rows"] = []map[string]any{{"x": 9}}
	check("same-length slice replaced", "rows.0.x", 9)
	ctx.Data["b"] = "new"
	check("added key", "b", "new")
	check("env", "env.FLAT_CACHE_ENV", "one")
	SetAppEnv(app.Dir, "FLAT_CACHE_ENV", "two")
	check("env change", "env.FLAT_CACHE_ENV", "two")

	// A for_each run sees each iteration's own row.
	loop := &FlowContext{App: app, Data: map[string]any{"rows": []map[string]any{{"v": "a"}, {"v": "b"}, {"v": "c"}}}, Params: map[string]string{}}
	execStepForEach(loop, &FlowStep{Type: "for_each", ForEach: "rows", ForAs: "row", Steps: []FlowStep{
		{Type: "set", Name: "acc", Set: map[string]string{"trail": "{{trail | default:''}}{{row.v}}"}},
	}})
	if got := loop.Data["trail"]; got != "abc" {
		t.Fatalf("for_each trail = %v, want abc (stale cached row)", got)
	}
}

// A compute step gets copies of its args (cloneComputeArg), so a function
// that edits its argument changes only its copy: the source step output keeps
// its value. Templates after the step see the edited copy through the step's
// own output, never a stale cached one.
func TestFlatDataCacheAfterComputeEditsItsArgument(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "norm.ts"), []byte(`
		export function markPaid(order: any) { order.status = "paid"; return order; }
	`), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := &FlowContext{App: &App{Dir: dir}, Data: map[string]any{
		"order": []map[string]any{{"id": 1, "status": "open"}},
	}, Params: map[string]string{}}
	if got := interpolateCtx("{{order.status}}", ctx); got != "open" {
		t.Fatalf("before compute: %q", got)
	}
	step := &FlowStep{Name: "paid", Type: "compute", Compute: &FlowCompute{Module: "norm", Function: "markPaid", Args: "{{order.first}}"}}
	if err := execStepCompute(ctx, step); err != nil {
		t.Fatal(err)
	}
	if got := interpolateCtx("{{order.status}}|{{order.first.status}}|{{order.0.status}}|{{paid.status}}", ctx); got != "open|open|open|paid" {
		t.Fatalf("after compute edited its argument, templates read %q, want open|open|open|paid", got)
	}
}

// BenchmarkInterpolateLargeContext shows the per-template cost no longer
// scales with the size of ctx.Data when nothing changed between templates.
func BenchmarkInterpolateLargeContext(b *testing.B) {
	rows := make([]map[string]any, 5000)
	for i := range rows {
		rows[i] = map[string]any{"id": i, "name": fmt.Sprintf("row-%d", i), "email": fmt.Sprintf("u%d@example.com", i)}
	}
	ctx := &FlowContext{Data: map[string]any{"rows": rows, "id": "42"}, Params: map[string]string{}}
	b.ResetTimer()
	for b.Loop() {
		_ = interpolateCtx("customer {{id}} first {{rows.first.name}}", ctx)
	}
}

// Only headers that could hold a credential make a call "credentialed" for the
// host check. A literal Content-Type/Accept/User-Agent says how the request is
// encoded, not who sends it, so a stored or request URL may still be the host
// (a Slack webhook post, a link preview); any template, or any other header
// name (even a literal Authorization written into the flow), still counts.
func TestAPICallCarriesSecretsIgnoresLiteralContentNegotiationHeaders(t *testing.T) {
	benign := &FlowAPICall{URL: "{{u}}", Headers: map[string]string{
		"Content-Type": "application/json", "accept": "text/html", "User-Agent": "Bot/1.0", "Accept-Language": "en",
	}}
	if apiCallCarriesSecrets(benign) {
		t.Fatal("literal content-negotiation headers were treated as credentials")
	}
	for name, h := range map[string]map[string]string{
		"templated content-type": {"Content-Type": "{{env.CT}}"},
		"templated user-agent":   {"User-Agent": "Bot {{params.v}}"},
		"literal authorization":  {"Authorization": "Bearer sk_live_hardcoded"},
		"literal api key":        {"X-Api-Key": "abc"},
		"literal cookie":         {"Cookie": "s=1"},
	} {
		if !apiCallCarriesSecrets(&FlowAPICall{URL: "{{u}}", Headers: h}) {
			t.Errorf("%s: not treated as a credential", name)
		}
	}
	// End to end: a request-chosen URL with only a literal User-Agent is placed
	// verbatim; with an Authorization header it is refused.
	ctx := outboundURLCtx(map[string]any{"u": "https://example.com/page"}, "u")
	if got, err := interpolateURLCtx("{{u}}", ctx, apiCallCarriesSecrets(&FlowAPICall{Headers: map[string]string{"User-Agent": "Bot/1.0"}})); err != nil || got != "https://example.com/page" {
		t.Fatalf("benign-header call: %q, %v", got, err)
	}
	if _, err := interpolateURLCtx("{{u}}", ctx, apiCallCarriesSecrets(&FlowAPICall{Headers: map[string]string{"Authorization": "Bearer x"}})); err == nil {
		t.Fatal("credentialed call accepted a request-chosen host")
	}
}
