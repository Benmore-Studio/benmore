//go:build !cli

package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A `run: api` step's method is fixed by the flow, but X-HTTP-Method-Override
// and its variants make many servers (Express method-override, Google APIs,
// OData) run another method: a request value in that header turned a
// reviewed GET into an upstream DELETE.
func TestAPIMethodOverrideHeaderIsNotRequestControlled(t *testing.T) {
	var sent []http.Header
	client := &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		sent = append(sent, r.Header.Clone())
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	app := secretTaintApp(t)
	SetAppEnv(app.Dir, "OVERRIDE", "PATCH")
	run := func(api *FlowAPICall) error {
		t.Helper()
		sent = nil
		ctx := outboundURLCtx(map[string]any{"verb": "DELETE"}, "verb")
		ctx.App = app
		step := &FlowStep{Name: "call", Type: "api", API: api}
		return execAPIRequestWithClient(ctx, step, api, nil, client)
	}

	for name, api := range map[string]*FlowAPICall{
		"headers X-HTTP-Method-Override": {URL: "https://8.8.8.8/items", Headers: map[string]string{"X-HTTP-Method-Override": "{{verb}}"}},
		"headers x-http-method":          {URL: "https://8.8.8.8/items", Headers: map[string]string{"x-http-method": "{{ params.verb | upper }}"}},
		"headers X-Method-Override":      {URL: "https://8.8.8.8/items", Headers: map[string]string{"X-Method-Override": "{{verb}}"}},
		"signer header":                  {URL: "https://8.8.8.8/items", Sign: &FlowAPISign{Recipe: "bearer_token", Bindings: map[string]string{"header": "X-HTTP-Method-Override", "prefix": "", "token": "{{verb}}"}}},
	} {
		err := run(api)
		if err == nil || !strings.Contains(err.Error(), "method-override") {
			t.Errorf("%s: want a refusal, got %v (sent %v)", name, err, sent)
		}
		if len(sent) != 0 {
			t.Errorf("%s: request was sent with a request-chosen method override: %v", name, sent)
		}
	}

	// The author's own value still goes out: a literal, an env value, and a
	// signer that sets the header from env.
	for name, api := range map[string]*FlowAPICall{
		"literal":    {URL: "https://8.8.8.8/items", Method: "POST", Headers: map[string]string{"X-HTTP-Method-Override": "PATCH"}},
		"env":        {URL: "https://8.8.8.8/items", Method: "POST", Headers: map[string]string{"X-HTTP-Method-Override": "{{env.OVERRIDE}}"}},
		"signer env": {URL: "https://8.8.8.8/items", Sign: &FlowAPISign{Recipe: "bearer_token", Bindings: map[string]string{"header": "X-HTTP-Method-Override", "prefix": "", "token": "{{env.OVERRIDE}}"}}},
	} {
		if err := run(api); err != nil {
			t.Errorf("%s: author-written override refused: %v", name, err)
			continue
		}
		// bearer_token's prefix defaults to "Bearer " even when set to "".
		if len(sent) != 1 || strings.TrimPrefix(sent[0].Get("X-HTTP-Method-Override"), "Bearer ") != "PATCH" {
			t.Errorf("%s: sent %v, want X-HTTP-Method-Override: PATCH", name, sent)
		}
	}

	// Request input in any other header is unaffected.
	if err := run(&FlowAPICall{URL: "https://8.8.8.8/items", Headers: map[string]string{"X-Request-Note": "{{verb}}"}}); err != nil || len(sent) != 1 {
		t.Fatalf("ordinary request-derived header: err=%v sent=%v", err, sent)
	}
}
