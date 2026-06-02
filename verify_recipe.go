//go:build !cli

package main

// Inbound webhook signature verification — the recipe-form counterpart
// to the outbound `sign:` recipes in signer_recipe*.go. It exists to handle
// timestamp-dependent HMAC schemes (e.g. `timestamp + "." + body`) that the
// legacy string-form `verify:` field couldn't express — letting a receiver
// verify webhook authenticity in constant time instead of relying on
// `UNIQUE(event_id)` dedupe alone (which doesn't stop forged payloads).
//
// The recipe form declares:
//
//   verify:
//     recipe: hmac_timestamp_dot_body         # name of the built-in
//     header: X-Webhook-Signature              # where the actual sig is
//     timestamp_header: X-Webhook-Timestamp
//     secret: "{{ env.WEBHOOK_SECRET }}"
//     skew_seconds: 300                        # replay window
//
// Two built-ins ship in v2.5.13:
//   - hmac_sha256_body         — hex(hmac_sha256(secret, body))
//   - hmac_timestamp_dot_body  — hex(hmac_sha256(secret, ts + "." + body))
//                                 with replay protection via the
//                                 timestamp_header (default skew 5 min)
//
// Legacy named providers (stripe / github / slack / shopify) keep
// flowing through verifyWebhookSignature in flows.go for back-compat —
// the rich shape is opt-in by writing `verify:` as a YAML map.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// FlowVerify holds the rich `verify:` shape parsed off `on.request`. A
// nil pointer means the flow uses the legacy string form (Flow.Verify)
// or no verification at all.
type FlowVerify struct {
	// Recipe selects a built-in verifier. Empty + non-empty Compute is
	// the inline form (deferred to v2.5.14 — string is the only path
	// shipping in v2.5.13). Unknown recipe names fail loudly at parse.
	Recipe string

	// Header is the request header carrying the signature value to
	// compare against. Required for every built-in.
	Header string

	// TimestampHeader is the header carrying the unix-second timestamp
	// the signature was computed over. Required for
	// hmac_timestamp_dot_body; ignored by hmac_sha256_body.
	TimestampHeader string

	// SkewSeconds bounds how old a signed payload may be. Default 300
	// (5 minutes) when zero. Negative values are clamped to zero (no
	// replay protection — only allowed for tests).
	SkewSeconds int

	// Secret is env-interpolated at request time (so rotation in
	// env.yaml takes effect without a restart). Required.
	Secret string

	// Prefix, when non-empty, is stripped from the actual signature
	// header value before comparison. Lets `verify:` consume formats
	// like `sha256=<hex>` without bespoke parsing.
	Prefix string
}

// runVerifyRecipe validates an incoming request against the configured
// verifier. Returns nil on success, an error describing the failure
// reason on rejection. The caller (executeFlowHTTP) maps any error to
// a 401 — the granular reason is logged but never returned to the
// caller, to avoid leaking which check tripped.
//
// Body is read fully (with a sane cap) and re-installed on r.Body so
// downstream steps (`parse:`, `respond` echoing the payload, etc.) see
// the same bytes. This is the standard pattern used by every other
// signature-verifying webhook framework.
func runVerifyRecipe(v *FlowVerify, r *http.Request, appDir string) error {
	if v == nil {
		return fmt.Errorf("verify: nil config")
	}
	secret := InterpolateEnv(v.Secret, appDir)
	if secret == "" {
		return fmt.Errorf("verify: secret resolved empty (check env.yaml)")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20)) // 8MB cap
	if err != nil {
		return fmt.Errorf("verify: read body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	switch v.Recipe {
	case "hmac_sha256_body":
		return verifyHMACBody(v, r, body, secret)
	case "hmac_timestamp_dot_body":
		return verifyHMACTimestampDotBody(v, r, body, secret)
	default:
		return fmt.Errorf("verify: unknown recipe %q (known: hmac_sha256_body, hmac_timestamp_dot_body)", v.Recipe)
	}
}

// verifyHMACBody implements `recipe: hmac_sha256_body` — the simplest
// shape: hex(hmac_sha256(secret, body)) matches the configured header.
// Used by Shopify (with base64 instead of hex, but the recipe form
// forces hex for v2.5.13 simplicity; explicit Shopify support stays
// on the legacy verifier).
func verifyHMACBody(v *FlowVerify, r *http.Request, body []byte, secret string) error {
	if v.Header == "" {
		return fmt.Errorf("verify: header: is required for hmac_sha256_body")
	}
	actual := stripPrefix(r.Header.Get(v.Header), v.Prefix)
	if actual == "" {
		return fmt.Errorf("verify: header %q missing or empty", v.Header)
	}
	expected := hmacSHA256Hex(secret, body)
	if !hmac.Equal([]byte(expected), []byte(actual)) {
		return fmt.Errorf("verify: signature mismatch")
	}
	return nil
}

// verifyHMACTimestampDotBody is the Slack-style timestamp-dot-body pattern:
// hex(hmac_sha256(secret, ts + "." + body)). Replay-protects via a
// configurable skew window read off TimestampHeader. The `.` separator
// is literal — DO NOT change without updating every receiver that
// expects this shape.
func verifyHMACTimestampDotBody(v *FlowVerify, r *http.Request, body []byte, secret string) error {
	if v.Header == "" {
		return fmt.Errorf("verify: header: is required for hmac_timestamp_dot_body")
	}
	if v.TimestampHeader == "" {
		return fmt.Errorf("verify: timestamp_header: is required for hmac_timestamp_dot_body")
	}
	tsStr := strings.TrimSpace(r.Header.Get(v.TimestampHeader))
	if tsStr == "" {
		return fmt.Errorf("verify: timestamp header %q missing", v.TimestampHeader)
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("verify: timestamp %q is not a unix integer: %w", tsStr, err)
	}
	skew := v.SkewSeconds
	if skew == 0 {
		skew = 300 // 5 minutes default
	}
	if skew > 0 {
		delta := time.Now().Unix() - ts
		if delta < 0 {
			delta = -delta
		}
		if delta > int64(skew) {
			return fmt.Errorf("verify: timestamp drift %ds exceeds skew_seconds=%d (replay protection)", delta, skew)
		}
	}
	actual := stripPrefix(r.Header.Get(v.Header), v.Prefix)
	if actual == "" {
		return fmt.Errorf("verify: header %q missing or empty", v.Header)
	}
	// Signing input is `timestamp + "." + body` — literal "." separator.
	signedInput := make([]byte, 0, len(tsStr)+1+len(body))
	signedInput = append(signedInput, tsStr...)
	signedInput = append(signedInput, '.')
	signedInput = append(signedInput, body...)
	expected := hmacSHA256Hex(secret, signedInput)
	if !hmac.Equal([]byte(expected), []byte(actual)) {
		return fmt.Errorf("verify: signature mismatch")
	}
	return nil
}

func hmacSHA256Hex(secret string, msg []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func stripPrefix(value, prefix string) string {
	if prefix != "" && strings.HasPrefix(value, prefix) {
		return value[len(prefix):]
	}
	return value
}
