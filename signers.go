//go:build !cli

package main

// Signed outbound HTTP for `run: api` flow steps.
//
// One generic shape covers every outbound auth scheme — AWS sigv4,
// Stripe/Slack webhook HMACs, OAuth client-credentials, GCP service
// accounts, Azure managed identity, JWT bearer — and the existing
// Benmore webhook signer. They all reduce to:
//
//   1. (optional) fetch a token from an exchange endpoint, cached
//      until expiry — the "exchange-then-attach" pattern.
//   2. compute derived values from request inputs + secrets — the
//      "sign-per-request" pattern (HMAC chains, JWT signing, etc).
//   3. mutate the outgoing request: set headers / query params.
//
// All three are expressed declaratively as a Recipe (see
// signer_recipe.go). Built-in recipes (signer_recipe_builtins.go)
// cover the common protocols; users can also write inline recipes
// in flows.yaml for one-off cases.
//
// This file holds only the FlowAPISign struct (parsed YAML form)
// and the entry point that flows.go calls from execStepAPI.

import (
	"fmt"
	"net/http"
)

// FlowAPISign is the parsed `sign:` block under a `run: api` step.
//
// Two equivalent forms supported in YAML:
//
//   1. Named built-in recipe + bindings:
//        sign:
//          recipe: aws_sigv4
//          region: us-east-1
//          service: athena
//
//   2. Inline recipe (compute / headers / before / query):
//        sign:
//          compute:
//            ts:  "{{ now | unix }}"
//            sig: "{{ env.STRIPE_SECRET | hmac_sha256:'{{ts}}.{{body}}' | hex }}"
//          headers:
//            Stripe-Signature: "t={{ts}},v1={{sig}}"
//
// If Recipe is non-empty, the named built-in is looked up and its
// definition is used (Inline is ignored). Bindings is passed in
// either case as initial variables (params.<key>).
type FlowAPISign struct {
	Recipe   string            // built-in recipe name (e.g. "aws_sigv4"), or empty for inline
	Bindings map[string]string // bindings passed in (region:, service:, etc.)
	Inline   *Recipe           // inline recipe, used when Recipe is empty
}

// applySigner is the single entry point that flows.go calls. It
// resolves the recipe (named or inline) and runs it against the
// outbound request. Returns nil if sign is nil (plain HTTP).
//
// If the YAML parser stored a parse error on the sign block (via the
// _parse_error sentinel binding), refuse to send the request — that
// guarantees a misconfigured flow never ships unsigned to the wire.
func applySigner(req *http.Request, body []byte, sign *FlowAPISign, app *App) error {
	if sign == nil {
		return nil
	}
	if perr := sign.Bindings["_parse_error"]; perr != "" {
		return fmt.Errorf("sign: invalid YAML block: %s", perr)
	}
	return runSignRecipe(req, body, sign, app)
}
