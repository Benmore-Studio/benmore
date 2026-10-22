//go:build !cli

package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A `sign:` recipe with a token exchange (oauth_client_credentials, or an
// inline `before:`) posts the app's client secret to the exchange URL before
// the API call itself. The API URL already refuses request input in its
// scheme or host when the call carries credentials; the exchange URL is built
// from sign bindings and had no such rule, so a binding that read the request
// let the caller name the host that receives OAUTH_CLIENT_SECRET.
func TestSignTokenExchangeURLIsNotRequestControlled(t *testing.T) {
	type sentReq struct{ url, body string }
	var exchanges, calls []sentReq
	record := func(into *[]sentReq, reply string) *http.Client {
		return &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
			body := ""
			if r.Body != nil {
				b, _ := io.ReadAll(r.Body)
				body = string(b)
			}
			*into = append(*into, sentReq{r.URL.String(), body})
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(reply))}, nil
		})}
	}
	oldBefore := recipeBeforeClient
	recipeBeforeClient = record(&exchanges, `{"access_token":"tok","expires_in":0}`)
	defer func() { recipeBeforeClient = oldBefore }()
	apiClient := record(&calls, `{}`)

	app := secretTaintApp(t)
	SetAppEnv(app.Dir, "OAUTH_CLIENT_ID", "client-1")
	SetAppEnv(app.Dir, "OAUTH_CLIENT_SECRET", "s3cret-value")
	SetAppEnv(app.Dir, "TOKEN_URL", "https://8.8.4.4/oauth/token")

	run := func(sign *FlowAPISign, data map[string]any, tainted ...string) error {
		t.Helper()
		exchanges, calls = nil, nil
		ctx := outboundURLCtx(data, tainted...)
		ctx.App = app
		api := &FlowAPICall{URL: "https://8.8.8.8/v1/things", Sign: sign}
		return execAPIRequestWithClient(ctx, &FlowStep{Name: "call", Type: "api", API: api}, api, nil, apiClient)
	}
	oauth := func(tokenURL string) *FlowAPISign {
		return &FlowAPISign{Recipe: "oauth_client_credentials", Bindings: map[string]string{"token_url": tokenURL, "scope": "read"}}
	}
	inline := func(tokenURL string) *FlowAPISign {
		return &FlowAPISign{Bindings: map[string]string{"endpoint": tokenURL}, Inline: &Recipe{
			Before: &RecipeBefore{
				Request: &RecipeBeforeRequest{Method: "POST", URL: "{{params.endpoint}}",
					Form: map[string]string{"client_secret": "{{env.OAUTH_CLIENT_SECRET}}"}},
				Extract: []RecipeBinding{{Name: "access_token", Expr: "$.access_token"}},
			},
			Headers: []RecipeBinding{{Name: "Authorization", Expr: "Bearer {{access_token}}"}},
		}}
	}

	for name, tc := range map[string]struct {
		sign *FlowAPISign
		data map[string]any
	}{
		"whole url from the request":   {oauth("{{target}}"), map[string]any{"target": "https://9.9.9.9/collect"}},
		"host from the request":        {oauth("https://{{target}}/oauth/token"), map[string]any{"target": "9.9.9.9"}},
		"host suffix from the request": {oauth("https://8.8.4.4{{target}}/oauth/token"), map[string]any{"target": ".9.9.9.9"}},
		"inline before, whole url":     {inline("{{target}}"), map[string]any{"target": "https://9.9.9.9/collect"}},
		"inline before, host":          {inline("https://{{target}}/oauth/token"), map[string]any{"target": "9.9.9.9"}},
	} {
		err := run(tc.sign, tc.data, "target")
		if err == nil || !strings.Contains(err.Error(), "token exchange") {
			t.Errorf("%s: want a refusal naming the token exchange, got %v", name, err)
		}
		for _, x := range exchanges {
			t.Errorf("%s: the client secret was posted to %s (%s)", name, x.url, x.body)
		}
		if len(calls) != 0 {
			t.Errorf("%s: the API call went out after a refused exchange", name)
		}
	}

	// An embedded reference the recipe wraps in more text is refused outright:
	// the binding's own position rules cannot see what surrounds it there.
	wrapped := inline("{{target}}")
	wrapped.Inline.Before.Request.URL = "https://{{params.endpoint}}.auth.8.8.4.4/token"
	if err := run(wrapped, map[string]any{"target": "tenant"}, "target"); err == nil || !strings.Contains(err.Error(), "token exchange") || len(exchanges) != 0 {
		t.Errorf("request input inside a composed exchange URL: err=%v exchanges=%v", err, exchanges)
	}

	// Request input in the PATH of the exchange URL stays one path segment.
	if err := run(oauth("https://8.8.4.4/tenants/{{target}}/oauth/token"), map[string]any{"target": "../../admin?x="}, "target"); err != nil {
		t.Fatalf("request input in the exchange path: %v", err)
	}
	if len(exchanges) != 1 || exchanges[0].url != "https://8.8.4.4/tenants/..%2F..%2Fadmin%3Fx=/oauth/token" {
		t.Errorf("exchange went to %v", exchanges)
	}

	// The author's own URL - literal, env, or a value no request wrote - is
	// used exactly as before.
	for name, tc := range map[string]struct {
		sign *FlowAPISign
		data map[string]any
		want string
	}{
		"literal":         {oauth("https://8.8.4.4/oauth/token"), map[string]any{}, "https://8.8.4.4/oauth/token"},
		"env":             {oauth("{{env.TOKEN_URL}}"), map[string]any{}, "https://8.8.4.4/oauth/token"},
		"untainted value": {oauth("{{stored}}"), map[string]any{"stored": "https://8.8.4.4/a b/token"}, "https://8.8.4.4/a%20b/token"},
		"inline literal":  {inline("https://8.8.4.4/oauth/token"), map[string]any{}, "https://8.8.4.4/oauth/token"},
	} {
		if err := run(tc.sign, tc.data); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(exchanges) != 1 || exchanges[0].url != tc.want || !strings.Contains(exchanges[0].body, "client_secret=s3cret-value") {
			t.Errorf("%s: exchange = %v, want one POST to %s", name, exchanges, tc.want)
		}
		if len(calls) != 1 {
			t.Errorf("%s: API calls = %d", name, len(calls))
		}
	}
}
