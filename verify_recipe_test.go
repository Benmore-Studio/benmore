//go:build !cli

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hmacHex computes hex(hmac_sha256(secret, msg)) - local helper so the
// tests don't import the production helper (keeps the recipe logic
// honest: if the real `hmacSHA256Hex` ever diverges, tests catch it).
func hmacHex(t *testing.T, secret string, msg []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// hmac_sha256_body - the simplest shape. Pass: signature matches.
func TestVerifyRecipe_HMACBody_Pass(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"event_id":"abc"}`)
	sig := hmacHex(t, secret, body)

	r := httptest.NewRequest("POST", "/wh", bytes.NewReader(body))
	r.Header.Set("X-Signature", sig)

	v := &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Signature", Secret: secret}
	if err := runVerifyRecipe(v, r, ""); err != nil {
		t.Fatalf("expected pass, got err: %v", err)
	}

	// Body must remain readable for downstream steps - runVerifyRecipe
	// installs a fresh io.NopCloser around the captured bytes.
	got, _ := readAll(r.Body)
	if string(got) != string(body) {
		t.Errorf("body not restored: got %q want %q", got, body)
	}
}

// hmac_sha256_body - tampered body fails.
func TestVerifyRecipe_HMACBody_TamperFails(t *testing.T) {
	secret := "super-secret"
	body := []byte(`{"event_id":"abc"}`)
	sig := hmacHex(t, secret, body) // computed for original

	r := httptest.NewRequest("POST", "/wh", bytes.NewReader([]byte(`{"event_id":"FORGED"}`)))
	r.Header.Set("X-Signature", sig)

	v := &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Signature", Secret: secret}
	if err := runVerifyRecipe(v, r, ""); err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

// hmac_sha256_body - prefix: "sha256=" strips before compare (GitHub style).
func TestVerifyRecipe_HMACBody_StripsPrefix(t *testing.T) {
	secret := "gh"
	body := []byte(`{"ok":1}`)
	sig := "sha256=" + hmacHex(t, secret, body)

	r := httptest.NewRequest("POST", "/wh", bytes.NewReader(body))
	r.Header.Set("X-Hub-Signature-256", sig)

	v := &FlowVerify{
		Recipe: "hmac_sha256_body", Header: "X-Hub-Signature-256",
		Prefix: "sha256=", Secret: secret,
	}
	if err := runVerifyRecipe(v, r, ""); err != nil {
		t.Fatalf("expected pass with prefix strip, got err: %v", err)
	}
}

// hmac_timestamp_dot_body - a webhook provider/Slack pattern, in-window pass.
func TestVerifyRecipe_HMACTimestampDotBody_Pass(t *testing.T) {
	secret := "nx"
	body := []byte(`{"event_id":"x","exception_type":"weather"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	signed := []byte(ts + "." + string(body))
	sig := hmacHex(t, secret, signed)

	r := httptest.NewRequest("POST", "/wh", bytes.NewReader(body))
	r.Header.Set("X-Webhook-Timestamp", ts)
	r.Header.Set("X-Webhook-Signature", sig)

	v := &FlowVerify{
		Recipe:          "hmac_timestamp_dot_body",
		Header:          "X-Webhook-Signature",
		TimestampHeader: "X-Webhook-Timestamp",
		Secret:          secret,
		SkewSeconds:     300,
	}
	if err := runVerifyRecipe(v, r, ""); err != nil {
		t.Fatalf("expected pass, got err: %v", err)
	}
}

// hmac_timestamp_dot_body - stale timestamp outside the skew window
// fails even when the signature itself is valid (replay protection).
// This is the critical security property of the timestamp variant.
func TestVerifyRecipe_HMACTimestampDotBody_ReplayRejected(t *testing.T) {
	secret := "nx"
	body := []byte(`{"event_id":"x"}`)
	staleTs := strconv.FormatInt(time.Now().Add(-1*time.Hour).Unix(), 10)
	signed := []byte(staleTs + "." + string(body))
	sig := hmacHex(t, secret, signed)

	r := httptest.NewRequest("POST", "/wh", bytes.NewReader(body))
	r.Header.Set("X-Webhook-Timestamp", staleTs)
	r.Header.Set("X-Webhook-Signature", sig)

	v := &FlowVerify{
		Recipe:          "hmac_timestamp_dot_body",
		Header:          "X-Webhook-Signature",
		TimestampHeader: "X-Webhook-Timestamp",
		Secret:          secret,
		SkewSeconds:     300,
	}
	err := runVerifyRecipe(v, r, "")
	if err == nil {
		t.Fatal("expected replay rejection, got nil")
	}
	if !strings.Contains(err.Error(), "drift") {
		t.Errorf("error should mention drift, got: %v", err)
	}
}

// hmac_timestamp_dot_body - missing timestamp header fails loudly.
func TestVerifyRecipe_HMACTimestampDotBody_MissingTimestamp(t *testing.T) {
	r := httptest.NewRequest("POST", "/wh", bytes.NewReader([]byte("{}")))
	r.Header.Set("X-Sig", "anything")

	v := &FlowVerify{
		Recipe:          "hmac_timestamp_dot_body",
		Header:          "X-Sig",
		TimestampHeader: "X-Ts",
		Secret:          "s",
	}
	if err := runVerifyRecipe(v, r, ""); err == nil {
		t.Fatal("expected missing-timestamp error, got nil")
	}
}

// Unknown recipe names fail at runtime with a list of known options so
// the agent sees what to fix.
func TestVerifyRecipe_UnknownRecipeFails(t *testing.T) {
	r := httptest.NewRequest("POST", "/wh", bytes.NewReader([]byte("{}")))
	v := &FlowVerify{Recipe: "totally_made_up", Header: "X-Sig", Secret: "s"}
	err := runVerifyRecipe(v, r, "")
	if err == nil {
		t.Fatal("expected unknown-recipe error, got nil")
	}
	if !strings.Contains(err.Error(), "hmac_sha256_body") || !strings.Contains(err.Error(), "hmac_timestamp_dot_body") {
		t.Errorf("error should list known recipes, got: %v", err)
	}
}

// Empty secret (env var missing) is treated as a config failure rather
// than silently accepting every signature. This is the same defensive
// posture sign: recipes use.
func TestVerifyRecipe_EmptySecretFails(t *testing.T) {
	r := httptest.NewRequest("POST", "/wh", bytes.NewReader([]byte("{}")))
	r.Header.Set("X-Sig", "x")
	v := &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Sig", Secret: ""}
	if err := runVerifyRecipe(v, r, ""); err == nil {
		t.Fatal("expected empty-secret error, got nil")
	}
}

// Loader: the rich map shape round-trips into Flow.VerifyConfig.
func TestLoadFlowsGHA_VerifyRecipeShape(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/webhooks/inbound
    verify:
      recipe: hmac_timestamp_dot_body
      header: X-Webhook-Signature
      timestamp_header: X-Webhook-Timestamp
      secret: "{{ env.WEBHOOK_SECRET }}"
      skew_seconds: 300

jobs:
  receive:
    steps:
      - run: respond
        with: { status: 200 }
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	vc := flows[0].VerifyConfig
	if vc == nil {
		t.Fatal("VerifyConfig nil - verify map shape not parsed")
	}
	if vc.Recipe != "hmac_timestamp_dot_body" {
		t.Errorf("Recipe = %q, want hmac_timestamp_dot_body", vc.Recipe)
	}
	if vc.Header != "X-Webhook-Signature" {
		t.Errorf("Header = %q", vc.Header)
	}
	if vc.TimestampHeader != "X-Webhook-Timestamp" {
		t.Errorf("TimestampHeader = %q", vc.TimestampHeader)
	}
	if vc.SkewSeconds != 300 {
		t.Errorf("SkewSeconds = %d, want 300", vc.SkewSeconds)
	}
}

// readAll without the io import noise of the package under test.
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf.Bytes(), nil
			}
			return buf.Bytes(), err
		}
	}
}

// Silence unused import warning for net/http in environments where the
// test file is the only consumer - kept because httptest.NewRequest
// returns *http.Request and the type assertion below makes it visible.
var _ = http.MethodPost
