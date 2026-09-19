//go:build !cli

package main

// Legacy named-provider webhook signature verification.
// Structured verification recipes are implemented in verify_recipe.go.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func verifyWebhookSignature(flow *Flow, r *http.Request, appDir string) bool {
	secret := InterpolateEnv(flow.Secret, appDir)
	if secret == "" {
		// fail closed: an empty resolved secret must never authenticate a
		// webhook. When verification is requested (flow.Verify set) but the
		// secret resolves empty (e.g. missing/typo'd env var), rejecting is
		// the only safe outcome - accepting would treat ANY payload as
		// authentic. Mirrors runVerifyRecipe (verify_recipe.go) which errors
		// on an empty secret rather than passing.
		log.Printf("SECURITY: webhook verify %q requested but resolved secret is empty (check env.yaml / flow.secret) - rejecting request as unauthenticated", flow.Verify)
		return false
	}

	// Named provider shortcuts - use canonical signature formats.
	// These match the `verify: <name>` value in flows.yaml.
	switch strings.ToLower(flow.Verify) {
	case "stripe":
		return verifyStripeSignature(r.Header.Get("Stripe-Signature"), secret, r)
	case "github", "github_sha256":
		return verifyPrefixedHMAC(r.Header.Get("X-Hub-Signature-256"), "sha256=", secret, r)
	case "shopify":
		return verifyRawHMACBase64(r.Header.Get("X-Shopify-Hmac-Sha256"), secret, r)
	case "slack":
		return verifySlackSignature(r.Header.Get("X-Slack-Signature"), r.Header.Get("X-Slack-Request-Timestamp"), secret, r)
	}

	// Generic verification: check common auth patterns. Compare in constant
	// time (subtle.ConstantTimeCompare) - a plain `==` short-circuits on the
	// first differing byte and leaks the secret to a timing side-channel, the
	// same class of bug the HMAC paths already avoid with hmac.Equal.
	// 1. Bearer token in Authorization header
	if authHeader := r.Header.Get("Authorization"); subtle.ConstantTimeCompare([]byte(authHeader), []byte("Bearer "+secret)) == 1 {
		return true
	}
	// 2. Secret in X-Webhook-Secret header
	if secretHeader := r.Header.Get("X-Webhook-Secret"); subtle.ConstantTimeCompare([]byte(secretHeader), []byte(secret)) == 1 {
		return true
	}
	// 3. HMAC signature verification (works with any provider that uses HMAC-SHA256)
	// Check common signature headers
	for _, headerName := range []string{
		flow.Verify, // Custom header name from verify: field (e.g., "X-Hub-Signature-256")
		"X-Signature",
		"X-Webhook-Signature",
	} {
		if headerName == "" {
			continue
		}
		sig := r.Header.Get(headerName)
		if sig != "" && verifyHMACSHA256(sig, secret, r) {
			return true
		}
	}

	return false
}

// verifyStripeSignature validates a Stripe webhook per
// https://stripe.com/docs/webhooks/signatures. Header format:
//
//	Stripe-Signature: t=1492774577,v1=<hex>,v0=<hex>
//
// Signed payload is "<t>.<body>". Timestamps outside a 5 min window are
// rejected (replay protection). Both v1 and v0 (legacy) are accepted.
func verifyStripeSignature(header, secret string, r *http.Request) bool {
	if header == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1", "v0":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == "" || len(sigs) == 0 {
		return false
	}

	// Replay protection: 5 min window
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if skew := time.Now().Unix() - tsInt; skew < -300 || skew > 300 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, sig := range sigs {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return true
		}
	}
	return false
}

// verifyPrefixedHMAC checks a header like "sha256=<hex>" against HMAC of body.
// Used by GitHub (X-Hub-Signature-256) and compatible providers.
func verifyPrefixedHMAC(header, prefix, secret string, r *http.Request) bool {
	if header == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	sig := strings.TrimPrefix(header, prefix)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// verifyRawHMACBase64 checks a base64-encoded HMAC-SHA256 of the body.
// Used by Shopify (X-Shopify-Hmac-Sha256).
func verifyRawHMACBase64(header, secret string, r *http.Request) bool {
	if header == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(header), []byte(expected))
}

// verifySlackSignature validates a Slack webhook per
// https://api.slack.com/authentication/verifying-requests-from-slack
// Signed payload is "v0:<ts>:<body>"; header format "v0=<hex>".
func verifySlackSignature(sigHeader, tsHeader, secret string, r *http.Request) bool {
	if sigHeader == "" || tsHeader == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	tsInt, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	if skew := time.Now().Unix() - tsInt; skew < -300 || skew > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsHeader + ":" + string(body)))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sigHeader), []byte(expected))
}

// verifyHMACSHA256 verifies an HMAC-SHA256 signature against the request body.
func verifyHMACSHA256(signature, secret string, r *http.Request) bool {
	// Read body (already consumed by flow parsing, so check if available)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		return false
	}
	// Restore body for downstream processing
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Strip common prefixes (sha256=, v1=, etc.)
	sig := signature
	for _, prefix := range []string{"sha256=", "v1=", "sha1="} {
		sig = strings.TrimPrefix(sig, prefix)
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expected))
}
