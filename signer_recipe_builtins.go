//go:build !cli

package main

// Built-in sign recipes. Each one is a YAML document embedded as a Go
// string, parsed once at startup into a *Recipe and registered by name.
//
// A user writes `sign: { recipe: aws_sigv4, region: us-east-1, ... }`
// and the framework loads the corresponding entry here. Adding a new
// protocol is one YAML literal - no new Go code, no recompilation per
// protocol (the engine in signer_recipe.go is what runs all of them).
//
// Bindings the caller provides under sign: surface inside the recipe
// as `params.<name>` - so `region: us-east-1` becomes `params.region`.
//
// To add a new recipe: write the YAML below, add a registerBuiltin()
// call in the init() at the bottom. Test with a known-good vector
// alongside the existing tests.

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var (
	builtinRecipesMu sync.RWMutex
	builtinRecipes   = map[string]*Recipe{}
)

func registerBuiltinRecipe(name, yamlSrc string) {
	r, err := parseRecipeYAML(yamlSrc)
	if err != nil {
		panic(fmt.Sprintf("builtin recipe %s: %v", name, err))
	}
	builtinRecipesMu.Lock()
	builtinRecipes[name] = r
	builtinRecipesMu.Unlock()
}

func lookupBuiltinRecipe(name string) (*Recipe, bool) {
	builtinRecipesMu.RLock()
	defer builtinRecipesMu.RUnlock()
	r, ok := builtinRecipes[name]
	return r, ok
}

func builtinRecipeNames() []string {
	builtinRecipesMu.RLock()
	defer builtinRecipesMu.RUnlock()
	out := make([]string, 0, len(builtinRecipes))
	for n := range builtinRecipes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// parseRecipeYAML reads a recipe YAML document into the AST struct.
// Uses yaml.Node directly so compute/headers/query map ordering is
// preserved (ordering matters: compute bindings reference earlier ones).
func parseRecipeYAML(src string) (*Recipe, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return nil, fmt.Errorf("expected single document")
	}
	body := root.Content[0]
	if body.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("recipe root must be a map")
	}

	r := &Recipe{}
	for i := 0; i+1 < len(body.Content); i += 2 {
		key := body.Content[i].Value
		val := body.Content[i+1]
		switch key {
		case "compute":
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("compute: %w", err)
			}
			r.Compute = bs
		case "headers":
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("headers: %w", err)
			}
			r.Headers = bs
		case "query":
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("query: %w", err)
			}
			r.Query = bs
		case "before":
			before, err := parseBefore(val)
			if err != nil {
				return nil, fmt.Errorf("before: %w", err)
			}
			r.Before = before
		default:
			return nil, fmt.Errorf("unknown recipe key %q (want: before, compute, headers, query)", key)
		}
	}
	return r, nil
}

// parseOrderedBindings reads a YAML mapping into an ordered []RecipeBinding,
// preserving the source-file declaration order. yaml.Node is the only
// stdlib-supported way to do this - a plain map[string]string loses order.
func parseOrderedBindings(node *yaml.Node) ([]RecipeBinding, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping")
	}
	var out []RecipeBinding
	for i := 0; i+1 < len(node.Content); i += 2 {
		out = append(out, RecipeBinding{
			Name: node.Content[i].Value,
			Expr: node.Content[i+1].Value,
		})
	}
	return out, nil
}

func parseBefore(node *yaml.Node) (*RecipeBefore, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping")
	}
	b := &RecipeBefore{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "cache_key":
			b.CacheKey = val.Value
		case "request":
			req, err := parseBeforeRequest(val)
			if err != nil {
				return nil, fmt.Errorf("request: %w", err)
			}
			b.Request = req
		case "extract":
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("extract: %w", err)
			}
			b.Extract = bs
		}
	}
	return b, nil
}

func parseBeforeRequest(node *yaml.Node) (*RecipeBeforeRequest, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping")
	}
	r := &RecipeBeforeRequest{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "method":
			r.Method = val.Value
		case "url":
			r.URL = val.Value
		case "body":
			r.Body = val.Value
		case "headers":
			r.Headers = nodeToStringMap(val)
		case "form":
			r.Form = nodeToStringMap(val)
		case "json":
			r.JSON = nodeToStringMap(val)
		}
	}
	return r, nil
}

func nodeToStringMap(node *yaml.Node) map[string]string {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]string, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		out[node.Content[i].Value] = node.Content[i+1].Value
	}
	return out
}

// parseSignBlock reads the YAML text under a `sign:` key (already
// dedented to its leftmost column) and produces a FlowAPISign. Two
// shapes accepted: `recipe: <name>` + bindings, or inline keys
// (compute/headers/before/query). Any unknown top-level key becomes
// a binding (params.<key>).
func parseSignBlock(src string) (*FlowAPISign, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return nil, fmt.Errorf("empty sign block")
	}
	body := root.Content[0]
	if body.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("sign must be a map")
	}

	sign := &FlowAPISign{Bindings: map[string]string{}}
	var inline *Recipe

	for i := 0; i+1 < len(body.Content); i += 2 {
		key := body.Content[i].Value
		val := body.Content[i+1]
		switch key {
		case "recipe":
			sign.Recipe = val.Value
		case "compute":
			if inline == nil {
				inline = &Recipe{}
			}
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("compute: %w", err)
			}
			inline.Compute = bs
		case "headers":
			if inline == nil {
				inline = &Recipe{}
			}
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("headers: %w", err)
			}
			inline.Headers = bs
		case "query":
			if inline == nil {
				inline = &Recipe{}
			}
			bs, err := parseOrderedBindings(val)
			if err != nil {
				return nil, fmt.Errorf("query: %w", err)
			}
			inline.Query = bs
		case "before":
			if inline == nil {
				inline = &Recipe{}
			}
			b, err := parseBefore(val)
			if err != nil {
				return nil, fmt.Errorf("before: %w", err)
			}
			inline.Before = b
		default:
			sign.Bindings[key] = val.Value
		}
	}

	if inline != nil {
		if sign.Recipe != "" {
			return nil, fmt.Errorf("sign: cannot mix recipe: <name> with inline compute/headers")
		}
		sign.Inline = inline
	}
	// Normalize GHA-style `${{ ... }}` refs into the runtime's
	// `{{...}}` form across every binding and inline recipe expression.
	// The withToSign path (flows_gha.go) already pre-normalizes the
	// whole YAML tree, but the legacy text-parser path (flows.go
	// parseSignBlock callsite) hands us raw author text - pre-2.7.31
	// the agent's `token: "${{ env.STRIPE_SECRET_KEY }}"` shipped the
	// literal mustache through to Stripe, which is exactly the beacon
	// session footgun. Idempotent: a plain `{{...}}` doesn't match the
	// GHA pattern and survives untouched.
	normalizeSignRefs(sign)
	return sign, nil
}

// normalizeSignRefs walks a parsed FlowAPISign and translates every
// `${{...}}` GHA ref to the runtime's `{{...}}` form. Applied across
// recipe bindings (params.<name>) and every inline expression
// (compute/headers/query/before). Safe to call twice - normalizeGHARefs
// no-ops on text that's already in runtime form.
func normalizeSignRefs(sign *FlowAPISign) {
	if sign == nil {
		return
	}
	for k, v := range sign.Bindings {
		sign.Bindings[k] = normalizeGHARefs(v)
	}
	if sign.Inline != nil {
		for i, b := range sign.Inline.Compute {
			sign.Inline.Compute[i].Expr = normalizeGHARefs(b.Expr)
		}
		for i, b := range sign.Inline.Headers {
			sign.Inline.Headers[i].Name = normalizeGHARefs(b.Name)
			sign.Inline.Headers[i].Expr = normalizeGHARefs(b.Expr)
		}
		for i, b := range sign.Inline.Query {
			sign.Inline.Query[i].Name = normalizeGHARefs(b.Name)
			sign.Inline.Query[i].Expr = normalizeGHARefs(b.Expr)
		}
		if sign.Inline.Before != nil {
			before := sign.Inline.Before
			before.CacheKey = normalizeGHARefs(before.CacheKey)
			if before.Request != nil {
				r := before.Request
				r.Method = normalizeGHARefs(r.Method)
				r.URL = normalizeGHARefs(r.URL)
				r.Body = normalizeGHARefs(r.Body)
				for k, v := range r.Headers {
					r.Headers[k] = normalizeGHARefs(v)
				}
				for k, v := range r.Form {
					r.Form[k] = normalizeGHARefs(v)
				}
				for k, v := range r.JSON {
					r.JSON[k] = normalizeGHARefs(v)
				}
			}
			for i, b := range before.Extract {
				before.Extract[i].Expr = normalizeGHARefs(b.Expr)
			}
		}
	}
}

// --- The built-in recipes ---

// AWS Signature Version 4 - sign-per-request HMAC chain over a
// canonical-request string. Caller-supplied bindings: region, service.
// Required env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
//
// Limitations: does not support session-token credentials (STS) yet -
// those need conditional inclusion in the canonical headers, which
// requires recipe conditionals. Static IAM keys only.
const recipeAWSSigV4 = `
compute:
  amz_date:       "{{ now | fmt:'20060102T150405Z' }}"
  date_stamp:     "{{ now | fmt:'20060102' }}"
  payload_hash:   "{{ body | sha256 | hex }}"
  canonical_req:  "{{method}}\n{{url.path}}\n{{ query | sort_query }}\nhost:{{host}}\nx-amz-date:{{amz_date}}\n\nhost;x-amz-date\n{{payload_hash}}"
  cr_hash:        "{{ canonical_req | sha256 | hex }}"
  scope:          "{{date_stamp}}/{{params.region}}/{{params.service}}/aws4_request"
  string_to_sign: "AWS4-HMAC-SHA256\n{{amz_date}}\n{{scope}}\n{{cr_hash}}"
  secret_prefixed: "AWS4{{ env.AWS_SECRET_ACCESS_KEY | required:'AWS_SECRET_ACCESS_KEY not set' }}"
  k_date:         "{{ secret_prefixed | hmac_sha256:date_stamp }}"
  k_region:       "{{ k_date    | hmac_sha256:params.region }}"
  k_service:      "{{ k_region  | hmac_sha256:params.service }}"
  k_signing:      "{{ k_service | hmac_sha256:'aws4_request' }}"
  signature:      "{{ k_signing | hmac_sha256:string_to_sign | hex }}"
  access_key:     "{{ env.AWS_ACCESS_KEY_ID | required:'AWS_ACCESS_KEY_ID not set' }}"
headers:
  X-Amz-Date:    "{{amz_date}}"
  Authorization: "AWS4-HMAC-SHA256 Credential={{access_key}}/{{scope}}, SignedHeaders=host;x-amz-date, Signature={{signature}}"
`

// Stripe-style webhook HMAC: HMAC-SHA256 over "{timestamp}.{body}",
// attached as Stripe-Signature: t=...,v1=... Reusable for any service
// that follows this same wire shape.
//
// Caller-supplied: header (default Stripe-Signature). Env: STRIPE_WEBHOOK_SECRET.
const recipeStripeHMAC = `
compute:
  ts:  "{{ now | unix }}"
  sig: "{{ env.STRIPE_WEBHOOK_SECRET | required:'STRIPE_WEBHOOK_SECRET not set' | hmac_sha256:'{{ts}}.{{body}}' | hex }}"
headers:
  Stripe-Signature: "t={{ts}},v1={{sig}}"
`

// Generic HMAC-SHA256 body signature. The simplest webhook signer:
// HMAC the body with a secret, hex-encode, set a header.
//
// Caller-supplied bindings (all optional):
//   secret  - value of the signing secret. If omitted, falls back to
//             env.WEBHOOK_SECRET so the original single-secret demos
//             keep working. New code should pass `secret:` explicitly:
//
//                 sign:
//                   recipe: hmac_sha256_body
//                   secret: "${{ env.MY_API_SECRET }}"
//
//             so each integration can carry its own secret rather
//             than aliasing WEBHOOK_SECRET.
//   header  - header name to set the signature on. Default X-Signature.
//             Override for vendors that pick a different name
//             (e.g. `header: X-Hub-Signature-256` for GitHub-style).
//   prefix  - string prepended to the hex signature in the header.
//             Default empty. Use `prefix: "sha256="` for the GitHub
//             scheme.
const recipeHMACSHA256 = `
compute:
  secret: "{{ params.secret | or_env:'WEBHOOK_SECRET' | required:'sign.secret or env.WEBHOOK_SECRET must be set' }}"
  sig:    "{{ secret | hmac_sha256:body | hex }}"
  hdr:    "{{ params.header | default:'X-Signature' }}"
  pfx:    "{{ params.prefix | default:'' }}"
  out:    "{{pfx}}{{sig}}"
headers:
  "{{hdr}}": "{{out}}"
`

// OAuth client_credentials grant - POST credentials to a token URL,
// receive a bearer, cache till expiry, attach as Authorization.
// Caller-supplied bindings: token_url, client_id_env, client_secret_env,
// optional scope. Used by Auth0, Okta, Stripe Connect (M2M), Salesforce.
const recipeOAuthClientCredentials = `
before:
  cache_key: "oauth_cc:{{params.token_url}}:{{env.OAUTH_CLIENT_ID}}"
  request:
    method: POST
    url: "{{params.token_url}}"
    form:
      grant_type: "client_credentials"
      client_id: "{{ env.OAUTH_CLIENT_ID | required:'OAUTH_CLIENT_ID not set' }}"
      client_secret: "{{ env.OAUTH_CLIENT_SECRET | required:'OAUTH_CLIENT_SECRET not set' }}"
      scope: "{{params.scope}}"
  extract:
    access_token: "$.access_token"
    ttl: "$.expires_in"
headers:
  Authorization: "Bearer {{access_token}}"
`

// Plain bearer token. The common case where you've already gotten a
// long-lived token elsewhere and just need to attach it. No exchange
// step, no HMAC.
//
// Caller-supplied bindings (all optional):
//   token   - the bearer value WITHOUT the "Bearer " prefix. If omitted,
//             falls back to env.API_TOKEN. New code should pass
//             `token:` explicitly so each integration can carry its
//             own token without aliasing API_TOKEN.
//
//                 sign:
//                   recipe: bearer_token
//                   token: "${{ env.FREIGHTWISE_API_TOKEN }}"
//
//   header  - header name. Default Authorization. Override when the
//             vendor uses a non-standard name (e.g. x-api-key).
//   prefix  - string prepended to the token. Default "Bearer ".
//             Set to "" for raw token (e.g. `prefix: ""` with
//             `header: x-api-key` for Anthropic-style API keys).
const recipeBearerToken = `
compute:
  token:  "{{ params.token | or_env:'API_TOKEN' | required:'sign.token or env.API_TOKEN must be set' }}"
  hdr:    "{{ params.header | default:'Authorization' }}"
  pfx:    "{{ params.prefix | default:'Bearer ' }}"
  out:    "{{pfx}}{{token}}"
headers:
  "{{hdr}}": "{{out}}"
`

func init() {
	// Strip the leading newline + register each builtin. Panics on
	// parse error - should be caught immediately during dev / CI.
	registerBuiltinRecipe("aws_sigv4", strings.TrimSpace(recipeAWSSigV4))
	registerBuiltinRecipe("stripe_webhook_hmac", strings.TrimSpace(recipeStripeHMAC))
	registerBuiltinRecipe("hmac_sha256_body", strings.TrimSpace(recipeHMACSHA256))
	registerBuiltinRecipe("oauth_client_credentials", strings.TrimSpace(recipeOAuthClientCredentials))
	registerBuiltinRecipe("bearer_token", strings.TrimSpace(recipeBearerToken))
}
