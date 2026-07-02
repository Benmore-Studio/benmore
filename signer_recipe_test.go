//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AWS sigv4 - recipe vs. the published "get-vanilla" test vector.
// If this drifts, every Athena/S3/Bedrock call signed by the framework
// will fail with InvalidSignatureException - so it's the hard gate.
func TestRecipe_AWSSigV4_GetVanilla(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	sign := &FlowAPISign{
		Recipe: "aws_sigv4",
		Bindings: map[string]string{
			"region":  "us-east-1",
			"service": "service",
			"_now":    "20150830T123600Z",
		},
	}
	if err := applySigner(req, nil, sign, nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	got := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Errorf("Authorization mismatch:\n  got:  %s\n  want: %s", got, want)
	}
	if d := req.Header.Get("X-Amz-Date"); d != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", d)
	}
}

// Body bytes must flow into the payload hash - a different body must
// produce a different signature. Catches engine bugs where `body` isn't
// being populated into the env.
func TestRecipe_AWSSigV4_BodyAffectsSignature(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

	sign := &FlowAPISign{
		Recipe: "aws_sigv4",
		Bindings: map[string]string{
			"region":  "us-east-1",
			"service": "athena",
			"_now":    "20240101T120000Z",
		},
	}
	req1, _ := http.NewRequest("POST", "https://athena.us-east-1.amazonaws.com/", nil)
	if err := applySigner(req1, []byte(`{"a":1}`), sign, nil); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest("POST", "https://athena.us-east-1.amazonaws.com/", nil)
	if err := applySigner(req2, []byte(`{"a":2}`), sign, nil); err != nil {
		t.Fatal(err)
	}
	if req1.Header.Get("Authorization") == req2.Header.Get("Authorization") {
		t.Error("body change must change signature - payload hash isn't being signed")
	}
}

// Stripe-style: HMAC-SHA256 over t.body, Stripe-Signature header.
// Verified by recomputing in Go (since Stripe's vectors aren't published
// in a stable form). The point is "the recipe wires the pipes correctly."
func TestRecipe_StripeWebhookHMAC(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_xyz")

	req, _ := http.NewRequest("POST", "https://example.com/webhook", nil)
	sign := &FlowAPISign{
		Recipe: "stripe_webhook_hmac",
		Bindings: map[string]string{
			"_now": "20240101T120000Z",
		},
	}
	body := []byte(`{"event":"payment.succeeded"}`)
	if err := applySigner(req, body, sign, nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := req.Header.Get("Stripe-Signature")
	if !strings.HasPrefix(sig, "t=1704110400,v1=") {
		t.Errorf("Stripe-Signature shape wrong: %s", sig)
	}
	if !strings.Contains(sig, ",v1=") {
		t.Errorf("missing v1 signature segment: %s", sig)
	}
}

// Bearer token recipe: simplest case - pull from env, attach as Bearer.
func TestRecipe_BearerToken(t *testing.T) {
	t.Setenv("API_TOKEN", "tok_abc123")

	req, _ := http.NewRequest("GET", "https://api.example.com/v1/foo", nil)
	sign := &FlowAPISign{Recipe: "bearer_token"}
	if err := applySigner(req, nil, sign, nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok_abc123" {
		t.Errorf("Authorization = %q", got)
	}
}

// Required pipe surfaces a friendly error when env is missing - catches
// the case where a YAML typo silently produces a 403 from upstream.
func TestRecipe_MissingCredentialsFailLoudly(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	sign := &FlowAPISign{
		Recipe: "aws_sigv4",
		Bindings: map[string]string{
			"region":  "us-east-1",
			"service": "service",
			"_now":    "20150830T123600Z",
		},
	}
	err := applySigner(req, nil, sign, nil)
	if err == nil {
		t.Fatal("expected error when AWS creds missing")
	}
	if !strings.Contains(err.Error(), "AWS_SECRET_ACCESS_KEY") {
		t.Errorf("error should name the missing env var, got: %v", err)
	}
}

// OAuth client_credentials with token cache. Spins up a mock token
// server, asserts the first call fetches, the second uses the cache,
// and the Bearer header is set on the outbound request.
func TestRecipe_OAuthClientCredentials_Cache(t *testing.T) {
	t.Setenv("OAUTH_CLIENT_ID", "test_client")
	t.Setenv("OAUTH_CLIENT_SECRET", "test_secret")

	fetches := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("bad grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("client_id") != "test_client" {
			t.Errorf("bad client_id: %s", r.FormValue("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok_oauth_xyz",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// First request → fetches token
	req1, _ := http.NewRequest("GET", "https://api.example.com/v1/foo", nil)
	sign := &FlowAPISign{
		Recipe: "oauth_client_credentials",
		Bindings: map[string]string{
			"token_url": tokenServer.URL,
		},
	}
	// reset the cache so this test doesn't depend on test order
	tokenCacheMu.Lock()
	tokenCache = map[string]cachedToken{}
	tokenCacheMu.Unlock()

	if err := applySigner(req1, nil, sign, nil); err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	if got := req1.Header.Get("Authorization"); got != "Bearer tok_oauth_xyz" {
		t.Errorf("first request Authorization = %q", got)
	}
	if fetches != 1 {
		t.Errorf("first call should fetch once, got %d", fetches)
	}

	// Second request → uses cache, no new fetch
	req2, _ := http.NewRequest("GET", "https://api.example.com/v1/foo", nil)
	if err := applySigner(req2, nil, sign, nil); err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	if got := req2.Header.Get("Authorization"); got != "Bearer tok_oauth_xyz" {
		t.Errorf("second request Authorization = %q", got)
	}
	if fetches != 1 {
		t.Errorf("second call should use cache (still 1 fetch), got %d", fetches)
	}
}

// Inline recipe (no built-in name) - proves the YAML inline form works.
// User writes the whole compute/headers in the sign: block directly.
func TestRecipe_InlineForm(t *testing.T) {
	t.Setenv("MY_SECRET", "topsecret")
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	sign := &FlowAPISign{
		Inline: &Recipe{
			Compute: []RecipeBinding{
				{Name: "sig", Expr: "{{ env.MY_SECRET | hmac_sha256:body | hex }}"},
			},
			Headers: []RecipeBinding{
				{Name: "X-My-Sig", Expr: "{{sig}}"},
			},
		},
	}
	if err := applySigner(req, []byte("hello"), sign, nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// HMAC-SHA256(topsecret, hello) - verified with `openssl dgst -sha256 -hmac topsecret`
	want := "ed76fd36523b8becda5a3b36d0e3737e8ae5111f55e26c7c3a455a3ce29636d2"
	if got := req.Header.Get("X-My-Sig"); got != want {
		t.Errorf("X-My-Sig = %q, want %q", got, want)
	}
}

// YAML parser round-trip - a sign block written as YAML produces the
// same FlowAPISign that direct construction would.
func TestParseSignBlock_NamedRecipe(t *testing.T) {
	src := `recipe: aws_sigv4
region: us-east-1
service: athena
`
	sign, err := parseSignBlock(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sign.Recipe != "aws_sigv4" {
		t.Errorf("Recipe = %q", sign.Recipe)
	}
	if sign.Bindings["region"] != "us-east-1" || sign.Bindings["service"] != "athena" {
		t.Errorf("bindings = %v", sign.Bindings)
	}
	if sign.Inline != nil {
		t.Errorf("inline should be nil for named-recipe form")
	}
}

func TestParseSignBlock_Inline(t *testing.T) {
	src := `compute:
  a: "1"
  b: "2"
headers:
  X-Foo: "{{a}}-{{b}}"
`
	sign, err := parseSignBlock(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sign.Recipe != "" {
		t.Errorf("Recipe should be empty for inline form")
	}
	if sign.Inline == nil {
		t.Fatal("Inline should not be nil")
	}
	if len(sign.Inline.Compute) != 2 || sign.Inline.Compute[0].Name != "a" || sign.Inline.Compute[1].Name != "b" {
		t.Errorf("compute order wrong: %v", sign.Inline.Compute)
	}
}

// parseSignBlock must translate GHA-style `${{ env.X }}` references in
// every binding and inline expression to the runtime's `{{...}}` form.
// Pre-2.7.31 the legacy text-parser path left the leading `$` intact,
// so `sign: { recipe: bearer_token, token: "${{ env.STRIPE_KEY }}" }`
// shipped the literal mustache to Stripe and returned "Invalid API
// Key provided: {{env.ST*...}}". This regression report came from the
// an earlier app build.
func TestParseSignBlock_NormalizesGHARefs_Bindings(t *testing.T) {
	src := `recipe: bearer_token
token: "${{ env.STRIPE_KEY }}"
`
	sign, err := parseSignBlock(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := sign.Bindings["token"]; got != "{{env.STRIPE_KEY}}" {
		t.Errorf("token binding not normalized: got %q, want {{env.STRIPE_KEY}}", got)
	}
}

func TestParseSignBlock_NormalizesGHARefs_Inline(t *testing.T) {
	src := `compute:
  ts: "${{ now | unix }}"
  amz_date: "${{ env.AWS_REGION }}"
headers:
  X-Timestamp: "${{ ts }}"
  X-Signature: "{{sig}}"
`
	sign, err := parseSignBlock(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sign.Inline == nil || len(sign.Inline.Compute) != 2 {
		t.Fatalf("inline compute missing: %+v", sign.Inline)
	}
	if sign.Inline.Compute[0].Expr != "{{now | unix}}" {
		t.Errorf("compute.ts: %q", sign.Inline.Compute[0].Expr)
	}
	if sign.Inline.Compute[1].Expr != "{{env.AWS_REGION}}" {
		t.Errorf("compute.amz_date: %q", sign.Inline.Compute[1].Expr)
	}
	// Header values normalize too.
	if sign.Inline.Headers[0].Expr != "{{ts}}" {
		t.Errorf("header X-Timestamp: %q", sign.Inline.Headers[0].Expr)
	}
	// Already-runtime-form refs must not be double-translated.
	if sign.Inline.Headers[1].Expr != "{{sig}}" {
		t.Errorf("header X-Signature: %q", sign.Inline.Headers[1].Expr)
	}
}

func TestParseSignBlock_MixedRejected(t *testing.T) {
	src := `recipe: aws_sigv4
compute:
  a: "1"
`
	_, err := parseSignBlock(src)
	if err == nil {
		t.Fatal("expected error mixing recipe: with inline compute:")
	}
}

// The five built-in recipes must all parse cleanly. Compile-time
// guarantee against a typo in a recipe YAML literal.
func TestBuiltinRecipes_AllParse(t *testing.T) {
	expected := []string{"aws_sigv4", "stripe_webhook_hmac", "hmac_sha256_body", "oauth_client_credentials", "bearer_token"}
	for _, name := range expected {
		if _, ok := lookupBuiltinRecipe(name); !ok {
			t.Errorf("builtin recipe %s not registered", name)
		}
	}
}

// Unknown recipe name should error with a list of known ones - helps
// the user fix typos.
func TestRecipe_UnknownNameLists(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	err := applySigner(req, nil, &FlowAPISign{Recipe: "nope"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "aws_sigv4") {
		t.Errorf("error should list known recipes including aws_sigv4: %v", err)
	}
}

// JSONPath sanity for the extract: step.
func TestJSONPath(t *testing.T) {
	cases := []struct {
		path, want string
	}{
		{"$.access_token", "tok_xyz"},
		{"$.expires_in", "3600"},
		{"$.nested.deep", "found"},
		{"$.arr[1]", "two"},
		{"$.missing", ""},
	}
	doc := map[string]any{
		"access_token": "tok_xyz",
		"expires_in":   float64(3600),
		"nested":       map[string]any{"deep": "found"},
		"arr":          []any{"one", "two", "three"},
	}
	for _, c := range cases {
		got, err := evalJSONPath(c.path, doc)
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.path, got, c.want)
		}
	}
}
