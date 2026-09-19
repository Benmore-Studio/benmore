//go:build !cli

package main

// Inbound webhook signature verification - the recipe-form counterpart
// to the outbound `sign:` recipes in signer_recipe*.go. It exists to handle
// timestamp-dependent HMAC schemes (e.g. `timestamp + "." + body`) that the
// legacy string-form `verify:` field couldn't express - letting a receiver
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
// Body-HMAC built-ins:
//   - hmac_sha256_body         - hex(hmac_sha256(secret, body))
//   - hmac_timestamp_dot_body  - hex(hmac_sha256(secret, ts + "." + body))
//                                 with replay protection via the
//                                 timestamp_header (default skew 5 min)
//   - hmac_sha1_body           - hex(hmac_sha1(secret, body)), with an
//                                 optional previous secret for rotation
//
// hmac_sha256_path_bearer derives an Authorization bearer from a route
// handle without consuming the request body.
//
// Legacy named providers (stripe / github / slack / shopify) keep
// flowing through verifyWebhookSignature in flows_verify.go for back-compat -
// the rich shape is opt-in by writing `verify:` as a YAML map.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const flowVerifyBodyMaxBytes int64 = 1 << 20 // matches flow JSON/parse body handling

var errVerifyBodyTooLarge = errors.New("verify: request body too large")

// FlowVerify holds the rich `verify:` shape parsed off `on.request`. A
// nil pointer means the flow uses the legacy string form (Flow.Verify)
// or no verification at all.
type FlowVerify struct {
	// Recipe selects a built-in verifier. Empty + non-empty Compute is
	// the inline form (deferred to v2.5.14 - string is the only path
	// shipping in v2.5.13). Unknown recipe names fail loudly at parse.
	Recipe string

	// Header is the request header carrying the signature value to
	// compare against. Required for body-HMAC recipes. Path-bearer uses
	// Authorization (a matching explicit Header value is accepted too).
	Header string

	// TimestampHeader is the header carrying the unix-second timestamp
	// the signature was computed over. Required for
	// hmac_timestamp_dot_body; ignored by hmac_sha256_body.
	TimestampHeader string

	// SkewSeconds bounds how old a signed payload may be. Default 300
	// (5 minutes) when zero. Negative values are clamped to zero (no
	// replay protection - only allowed for tests).
	SkewSeconds int

	// Secret is env-interpolated at request time (so rotation in
	// env.yaml takes effect without a restart). Required.
	Secret string

	// PreviousSecret is the optional prior env-backed secret accepted by
	// hmac_sha1_body during a bounded rotation window. No other recipe
	// accepts it: rotation must be explicit rather than accidentally
	// widening every verifier to a second credential.
	PreviousSecret string
	previousSet    bool

	// Prefix, when non-empty, is stripped from the actual signature
	// header value before comparison. Lets `verify:` consume formats
	// like `sha256=<hex>` without bespoke parsing.
	Prefix string

	// PathParam names the dynamic route segment used by
	// hmac_sha256_path_bearer. The loader validates both the identifier
	// grammar and that the named segment appears in the authored path.
	PathParam string

	// Context domain-separates path-derived bearer credentials. The
	// expected token is hex(HMAC-SHA256(secret, context + path value)).
	Context string
}

// validateFlowVerifyConfig is shared by the write-time gate and runtime
// loader. Runtime verification calls it too so hand-constructed Flow values
// and historical files that bypassed write validation still fail closed.
func validateFlowVerifyConfig(v *FlowVerify, routePath string) error {
	if v == nil {
		return fmt.Errorf("verify: nil config")
	}
	if strings.TrimSpace(v.Secret) == "" {
		return fmt.Errorf("verify: secret is required")
	}

	hasPrevious := v.previousSet || v.PreviousSecret != ""
	switch v.Recipe {
	case "hmac_sha256_body":
		if strings.TrimSpace(v.Header) == "" {
			return fmt.Errorf("verify: header is required for hmac_sha256_body")
		}
		if hasPrevious {
			return fmt.Errorf("verify: previous_secret is only valid for hmac_sha1_body")
		}
	case "hmac_timestamp_dot_body":
		if strings.TrimSpace(v.Header) == "" {
			return fmt.Errorf("verify: header is required for hmac_timestamp_dot_body")
		}
		if strings.TrimSpace(v.TimestampHeader) == "" {
			return fmt.Errorf("verify: timestamp_header is required for hmac_timestamp_dot_body")
		}
		if hasPrevious {
			return fmt.Errorf("verify: previous_secret is only valid for hmac_sha1_body")
		}
	case "hmac_sha1_body":
		if strings.TrimSpace(v.Header) == "" {
			return fmt.Errorf("verify: header is required for hmac_sha1_body")
		}
		if !verifyEnvReference(v.Secret) {
			return fmt.Errorf("verify: hmac_sha1_body secret must be one env reference such as {{ env.WEBHOOK_SECRET }}")
		}
		if hasPrevious && !verifyEnvReference(v.PreviousSecret) {
			return fmt.Errorf("verify: hmac_sha1_body previous_secret must be one env reference when configured")
		}
	case "hmac_sha256_path_bearer":
		if !verifyEnvReference(v.Secret) {
			return fmt.Errorf("verify: hmac_sha256_path_bearer secret must be one env reference such as {{ env.WEBHOOK_MASTER_SECRET }}")
		}
		if v.Header != "" && !strings.EqualFold(strings.TrimSpace(v.Header), "Authorization") {
			return fmt.Errorf("verify: hmac_sha256_path_bearer uses the Authorization header; omit header or set it to Authorization")
		}
		if v.Prefix == "" {
			return fmt.Errorf("verify: prefix is required for hmac_sha256_path_bearer")
		}
		if strings.TrimSpace(v.Context) == "" {
			return fmt.Errorf("verify: context is required for hmac_sha256_path_bearer")
		}
		if !verifyIdentifier(v.PathParam) {
			return fmt.Errorf("verify: path_param %q must match [A-Za-z_][A-Za-z0-9_]*", v.PathParam)
		}
		if routePath != "" && !verifyRouteHasParam(routePath, v.PathParam) {
			return fmt.Errorf("verify: path_param %q is not a dynamic segment in route %q", v.PathParam, routePath)
		}
		if hasPrevious {
			return fmt.Errorf("verify: previous_secret is only valid for hmac_sha1_body")
		}
	default:
		return fmt.Errorf("verify: unknown recipe %q (known: hmac_sha256_body, hmac_timestamp_dot_body, hmac_sha1_body, hmac_sha256_path_bearer)", v.Recipe)
	}
	return nil
}

func verifyEnvReference(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{{env.") || !strings.HasSuffix(s, "}}") {
		return false
	}
	return verifyIdentifier(strings.TrimSuffix(strings.TrimPrefix(s, "{{env."), "}}"))
}

func verifyIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !verifyIdentifierStart(r) {
				return false
			}
			continue
		}
		if !verifyIdentifierStart(r) && !verifyIdentifierDigit(r) {
			return false
		}
	}
	return true
}

func verifyIdentifierStart(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
}

func verifyIdentifierDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func verifyRouteHasParam(routePath, name string) bool {
	for _, segment := range strings.Split(routePath, "/") {
		if segment == ":"+name || segment == "{"+name+"}" {
			return true
		}
	}
	return false
}

// runVerifyRecipe validates an incoming request against the configured
// verifier. Returns nil on success, an error describing the failure
// reason on rejection. The caller (executeFlowHTTP) maps any error to
// a 401 - the granular reason is logged but never returned to the
// caller, to avoid leaking which check tripped. Oversized bodies are the
// exception: the caller maps errVerifyBodyTooLarge to 413.
//
// Body-HMAC recipes read up to flowVerifyBodyMaxBytes and re-install the
// captured bytes on r.Body so
// downstream steps (`parse:`, `respond` echoing the payload, etc.) see
// the same bytes. This is the standard pattern used by every other
// signature-verifying webhook framework.
func runVerifyRecipe(v *FlowVerify, r *http.Request, appDir string) error {
	if err := validateFlowVerifyConfig(v, ""); err != nil {
		return err
	}
	secret, err := resolveVerifySecret(v.Secret, appDir, "secret")
	if err != nil {
		return err
	}

	switch v.Recipe {
	case "hmac_sha256_body":
		body, err := readVerifyBody(r)
		if err != nil {
			return err
		}
		return verifyHMACBody(v, r, body, secret)
	case "hmac_timestamp_dot_body":
		body, err := readVerifyBody(r)
		if err != nil {
			return err
		}
		return verifyHMACTimestampDotBody(v, r, body, secret, appDir)
	case "hmac_sha1_body":
		body, err := readVerifyBody(r)
		if err != nil {
			return err
		}
		previous := ""
		if v.PreviousSecret != "" {
			previous, err = resolveVerifySecret(v.PreviousSecret, appDir, "previous_secret")
			if err != nil {
				return err
			}
		}
		return verifyHMACSHA1Body(v, r, body, secret, previous)
	case "hmac_sha256_path_bearer":
		return verifyHMACSHA256PathBearer(v, r, secret)
	default:
		return fmt.Errorf("verify: unknown recipe %q", v.Recipe)
	}
}

func resolveVerifySecret(ref, appDir, field string) (string, error) {
	secret := InterpolateEnv(ref, appDir)
	if secret == "" || strings.Contains(secret, "{{env.") {
		return "", fmt.Errorf("verify: %s resolved empty (check app environment)", field)
	}
	return secret, nil
}

func readVerifyBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if r.ContentLength > flowVerifyBodyMaxBytes {
		return nil, fmt.Errorf("%w: limit is %d bytes", errVerifyBodyTooLarge, flowVerifyBodyMaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, flowVerifyBodyMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("verify: read body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if int64(len(body)) > flowVerifyBodyMaxBytes {
		return nil, fmt.Errorf("%w: limit is %d bytes", errVerifyBodyTooLarge, flowVerifyBodyMaxBytes)
	}
	return body, nil
}

// verifyHMACBody implements `recipe: hmac_sha256_body` - the simplest
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

func verifyHMACSHA1Body(v *FlowVerify, r *http.Request, body []byte, secret, previousSecret string) error {
	actualText, err := requiredPrefixedSignature(r.Header.Get(v.Header), v.Prefix, v.Header)
	if err != nil {
		return err
	}
	actual, err := hex.DecodeString(actualText)
	if err != nil || len(actual) != sha1.Size {
		return fmt.Errorf("verify: malformed hmac_sha1_body signature")
	}

	current := hmacSHA1(secret, body)
	currentMatch := hmac.Equal(current, actual)
	previousMatch := false
	if previousSecret != "" {
		previousMatch = hmac.Equal(hmacSHA1(previousSecret, body), actual)
	}
	if !currentMatch && !previousMatch {
		return fmt.Errorf("verify: signature mismatch")
	}
	return nil
}

func verifyHMACSHA256PathBearer(v *FlowVerify, r *http.Request, secret string) error {
	actualText, err := requiredPrefixedSignature(r.Header.Get("Authorization"), v.Prefix, "Authorization")
	if err != nil {
		return err
	}
	actual, err := hex.DecodeString(actualText)
	if err != nil || len(actual) != sha256.Size {
		return fmt.Errorf("verify: malformed hmac_sha256_path_bearer token")
	}
	pathValue := r.PathValue(v.PathParam)
	if pathValue == "" {
		return fmt.Errorf("verify: path parameter %q missing", v.PathParam)
	}
	expected := verifyHMACSHA256Bytes(secret, []byte(v.Context+pathValue))
	if !hmac.Equal(expected, actual) {
		return fmt.Errorf("verify: signature mismatch")
	}
	return nil
}

func requiredPrefixedSignature(value, prefix, header string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("verify: header %q missing or empty", header)
	}
	if prefix != "" && !strings.HasPrefix(value, prefix) {
		return "", fmt.Errorf("verify: header %q has invalid prefix", header)
	}
	return strings.TrimPrefix(value, prefix), nil
}

// verifyHMACTimestampDotBody is the Slack-style timestamp-dot-body pattern:
// hex(hmac_sha256(secret, ts + "." + body)). Replay-protects via a
// configurable skew window read off TimestampHeader. The `.` separator
// is literal - DO NOT change without updating every receiver that
// expects this shape.
func verifyHMACTimestampDotBody(v *FlowVerify, r *http.Request, body []byte, secret string, appDir string) error {
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
	// Replay protection clamp: a negative skew_seconds disables the
	// timestamp-drift check entirely, which is only ever safe in tests.
	// In production, clamp negative -> 0 so it falls through to the 300s
	// default below and replay protection stays ON. A misconfigured or
	// hostile negative value must never silently open the replay window.
	// The escape hatch for tests is the explicit per-app env flag
	// WEBHOOK_SKEW_ALLOW_NEGATIVE=1 (opt-in, never the default).
	if skew < 0 && GetAppEnv(appDir, "WEBHOOK_SKEW_ALLOW_NEGATIVE") != "1" {
		skew = 0
	}
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
	// Signing input is `timestamp + "." + body` - literal "." separator.
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
	return hex.EncodeToString(verifyHMACSHA256Bytes(secret, msg))
}

func verifyHMACSHA256Bytes(secret string, msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func hmacSHA1(secret string, msg []byte) []byte {
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func stripPrefix(value, prefix string) string {
	if prefix != "" && strings.HasPrefix(value, prefix) {
		return value[len(prefix):]
	}
	return value
}
