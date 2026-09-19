//go:build !cli

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

func hmacSHA1HexForTest(t *testing.T, secret string, msg []byte) string {
	t.Helper()
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyEnv(t *testing.T, values map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for key, value := range values {
		SetAppEnv(dir, key, value)
	}
	return dir
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

func TestVerifyRecipe_HMACSHA1Body_CurrentAndPreviousSecrets(t *testing.T) {
	body := []byte(`{"hookId":"autodesk-1"}`)
	appDir := verifyEnv(t, map[string]string{
		"AUTODESK_WEBHOOK_SECRET":          "current-secret",
		"AUTODESK_WEBHOOK_SECRET_PREVIOUS": "previous-secret",
	})
	v := &FlowVerify{
		Recipe:         "hmac_sha1_body",
		Header:         "X-Adsk-Signature",
		Prefix:         "sha1hash=",
		Secret:         "{{env.AUTODESK_WEBHOOK_SECRET}}",
		PreviousSecret: "{{env.AUTODESK_WEBHOOK_SECRET_PREVIOUS}}",
	}

	for _, secret := range []string{"current-secret", "previous-secret"} {
		r := httptest.NewRequest(http.MethodPost, "/api/autodesk-webhook", bytes.NewReader(body))
		r.Header.Set("X-Adsk-Signature", "sha1hash="+hmacSHA1HexForTest(t, secret, body))
		if err := runVerifyRecipe(v, r, appDir); err != nil {
			t.Fatalf("secret %q should be accepted: %v", secret, err)
		}
	}
}

func TestVerifyRecipe_HMACSHA1Body_RejectsWrongAndMalformed(t *testing.T) {
	body := []byte(`{"hookId":"autodesk-1"}`)
	appDir := verifyEnv(t, map[string]string{"AUTODESK_WEBHOOK_SECRET": "current-secret"})
	v := &FlowVerify{
		Recipe: "hmac_sha1_body", Header: "X-Adsk-Signature", Prefix: "sha1hash=",
		Secret: "{{env.AUTODESK_WEBHOOK_SECRET}}",
	}

	for name, signature := range map[string]string{
		"wrong":     "sha1hash=" + hmacSHA1HexForTest(t, "wrong-secret", body),
		"malformed": "sha1hash=not-hex",
		"no-prefix": hmacSHA1HexForTest(t, "current-secret", body),
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/autodesk-webhook", bytes.NewReader(body))
			r.Header.Set("X-Adsk-Signature", signature)
			if err := runVerifyRecipe(v, r, appDir); err == nil {
				t.Fatal("expected signature rejection")
			}
		})
	}
}

func TestVerifyRecipe_HMACSHA1Body_ConfiguredPreviousSecretMustResolve(t *testing.T) {
	body := []byte(`{}`)
	appDir := verifyEnv(t, map[string]string{"AUTODESK_WEBHOOK_SECRET": "current-secret"})
	v := &FlowVerify{
		Recipe:         "hmac_sha1_body",
		Header:         "X-Adsk-Signature",
		Prefix:         "sha1hash=",
		Secret:         "{{env.AUTODESK_WEBHOOK_SECRET}}",
		PreviousSecret: "{{env.AUTODESK_WEBHOOK_SECRET_PREVIOUS}}",
	}
	r := httptest.NewRequest(http.MethodPost, "/api/autodesk-webhook", bytes.NewReader(body))
	r.Header.Set("X-Adsk-Signature", "sha1hash="+hmacSHA1HexForTest(t, "current-secret", body))
	if err := runVerifyRecipe(v, r, appDir); err == nil || !strings.Contains(err.Error(), "previous_secret resolved empty") {
		t.Fatalf("expected unresolved previous-secret rejection, got %v", err)
	}
}

func TestVerifyRecipe_PathBearer(t *testing.T) {
	appDir := verifyEnv(t, map[string]string{"PROCORE_WEBHOOK_MASTER_SECRET": "master-secret"})
	v := &FlowVerify{
		Recipe:    "hmac_sha256_path_bearer",
		Secret:    "{{env.PROCORE_WEBHOOK_MASTER_SECRET}}",
		Prefix:    "Bearer ",
		PathParam: "handle",
		Context:   "procore-webhook:",
	}
	token := hmacHex(t, "master-secret", []byte("procore-webhook:handle-a"))

	t.Run("correct handle", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/handle-a", nil)
		r.SetPathValue("handle", "handle-a")
		r.Header.Set("Authorization", "Bearer "+token)
		if err := runVerifyRecipe(v, r, appDir); err != nil {
			t.Fatalf("expected valid bearer, got %v", err)
		}
	})

	t.Run("different handle", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/handle-b", nil)
		r.SetPathValue("handle", "handle-b")
		r.Header.Set("Authorization", "Bearer "+token)
		if err := runVerifyRecipe(v, r, appDir); err == nil {
			t.Fatal("token derived for handle-a must not authenticate handle-b")
		}
	})

	t.Run("missing path param", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/handle-a", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if err := runVerifyRecipe(v, r, appDir); err == nil || !strings.Contains(err.Error(), "path parameter") {
			t.Fatalf("expected missing path-param rejection, got %v", err)
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/handle-a", nil)
		r.SetPathValue("handle", "handle-a")
		r.Header.Set("Authorization", "Bearer not-hex")
		if err := runVerifyRecipe(v, r, appDir); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("expected malformed-token rejection, got %v", err)
		}
	})
}

func TestValidateFlowVerifyConfig(t *testing.T) {
	validSecret := "{{env.WEBHOOK_SECRET}}"
	cases := []struct {
		name string
		path string
		v    *FlowVerify
		want string
	}{
		{"unknown recipe", "/api/hook", &FlowVerify{Recipe: "unknown", Secret: "x"}, "unknown recipe"},
		{"missing header", "/api/hook", &FlowVerify{Recipe: "hmac_sha1_body", Secret: validSecret}, "header is required"},
		{"literal sha1 secret", "/api/hook", &FlowVerify{Recipe: "hmac_sha1_body", Header: "X-Sig", Secret: "literal"}, "must be one env reference"},
		{"empty configured previous", "/api/hook", &FlowVerify{Recipe: "hmac_sha1_body", Header: "X-Sig", Secret: validSecret, previousSet: true}, "previous_secret must be one env reference"},
		{"previous on wrong recipe", "/api/hook", &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Sig", Secret: "literal", PreviousSecret: validSecret}, "only valid"},
		{"invalid path identifier", "/api/hook/:handle", &FlowVerify{Recipe: "hmac_sha256_path_bearer", Secret: validSecret, Prefix: "Bearer ", Context: "hook:", PathParam: "bad-name"}, "must match"},
		{"path param absent", "/api/hook/:other", &FlowVerify{Recipe: "hmac_sha256_path_bearer", Secret: validSecret, Prefix: "Bearer ", Context: "hook:", PathParam: "handle"}, "not a dynamic segment"},
		{"missing context", "/api/hook/:handle", &FlowVerify{Recipe: "hmac_sha256_path_bearer", Secret: validSecret, Prefix: "Bearer ", PathParam: "handle"}, "context is required"},
		{"missing prefix", "/api/hook/:handle", &FlowVerify{Recipe: "hmac_sha256_path_bearer", Secret: validSecret, Context: "hook:", PathParam: "handle"}, "prefix is required"},
		{"custom path bearer header", "/api/hook/:handle", &FlowVerify{Recipe: "hmac_sha256_path_bearer", Header: "X-Token", Secret: validSecret, Prefix: "Bearer ", Context: "hook:", PathParam: "handle"}, "uses the Authorization header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFlowVerifyConfig(tc.v, tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestExecuteFlowHTTP_VerifiesRawBodyBeforeParsing(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "AUTODESK_WEBHOOK_SECRET", "autodesk-secret")
	SetAppEnv(app.Dir, "AUTODESK_WEBHOOK_SECRET_PREVIOUS", "autodesk-secret-previous")
	mustExec(t, app.DB, `CREATE TABLE webhook_log (event TEXT)`)

	flow := Flow{
		Name:    "autodesk_webhook",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/autodesk-webhook"},
		VerifyConfig: &FlowVerify{
			Recipe: "hmac_sha1_body", Header: "X-Adsk-Signature", Prefix: "sha1hash=",
			Secret:         "{{env.AUTODESK_WEBHOOK_SECRET}}",
			PreviousSecret: "{{env.AUTODESK_WEBHOOK_SECRET_PREVIOUS}}",
		},
		Steps: []FlowStep{
			{Type: "parse", Name: "payload", Parse: "body"},
			{Type: "sql", Name: "insert", SQL: "INSERT INTO webhook_log (event) VALUES (:event)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"event": "{{payload.event}}"}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})

	body := []byte(`{"event":"version.added"}`)
	request := func(signature string, requestBody []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/autodesk-webhook", bytes.NewReader(requestBody))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Adsk-Signature", signature)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr
	}

	bad := request("sha1hash="+hmacSHA1HexForTest(t, "wrong-secret", body), body)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d, want 401", bad.Code)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("verification must reject before SQL; count=%d err=%v", count, err)
	}
	malformed := request("sha1hash=not-hex", body)
	if malformed.Code != http.StatusUnauthorized {
		t.Fatalf("malformed signature status = %d, want 401", malformed.Code)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("malformed signature must reject before SQL; count=%d err=%v", count, err)
	}

	good := request("sha1hash="+hmacSHA1HexForTest(t, "autodesk-secret", body), body)
	if good.Code != http.StatusOK {
		t.Fatalf("good signature status = %d body=%s", good.Code, good.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(good.Body.Bytes(), &response); err != nil || response["event"] != "version.added" {
		t.Fatalf("downstream parse did not receive restored body: response=%v err=%v", response, err)
	}
	previous := request("sha1hash="+hmacSHA1HexForTest(t, "autodesk-secret-previous", body), body)
	if previous.Code != http.StatusOK {
		t.Fatalf("previous-secret signature status = %d body=%s", previous.Code, previous.Body.String())
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("current and previous secret requests should run SQL; count=%d err=%v", count, err)
	}
}

func TestExecuteFlowHTTP_VerifyBodyLimitRejectsWithoutSteps(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "AUTODESK_WEBHOOK_SECRET", "autodesk-secret")
	mustExec(t, app.DB, `CREATE TABLE webhook_log (event TEXT)`)
	flow := Flow{
		Name:         "autodesk_webhook",
		Trigger:      FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/autodesk-webhook"},
		VerifyConfig: &FlowVerify{Recipe: "hmac_sha1_body", Header: "X-Adsk-Signature", Prefix: "sha1hash=", Secret: "{{env.AUTODESK_WEBHOOK_SECRET}}"},
		Steps:        []FlowStep{{Type: "sql", SQL: "INSERT INTO webhook_log (event) VALUES ('ran')"}},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})
	body := bytes.Repeat([]byte("x"), int(flowVerifyBodyMaxBytes)+1)
	r := httptest.NewRequest(http.MethodPost, "/api/autodesk-webhook", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Adsk-Signature", "sha1hash="+hmacSHA1HexForTest(t, "autodesk-secret", body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized signed body status = %d, want 413", rr.Code)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("oversized body must reject before SQL; count=%d err=%v", count, err)
	}
}

func TestExecuteFlowHTTP_PathBearerRejectsBeforeSteps(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "PROCORE_WEBHOOK_MASTER_SECRET", "master-secret")
	mustExec(t, app.DB, `CREATE TABLE webhook_log (handle TEXT)`)
	flow := Flow{
		Name:    "procore_webhook",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/procore-webhook/:handle"},
		VerifyConfig: &FlowVerify{
			Recipe: "hmac_sha256_path_bearer", Secret: "{{env.PROCORE_WEBHOOK_MASTER_SECRET}}",
			Prefix: "Bearer ", PathParam: "handle", Context: "procore-webhook:",
		},
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO webhook_log (handle) VALUES (:handle)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})
	tokenA := hmacHex(t, "master-secret", []byte("procore-webhook:handle-a"))

	request := func(handle, token string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/"+handle, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr.Code
	}
	if code := request("handle-a", tokenA); code != http.StatusOK {
		t.Fatalf("correct path bearer status = %d", code)
	}
	if code := request("handle-b", tokenA); code != http.StatusUnauthorized {
		t.Fatalf("token replayed to another handle status = %d, want 401", code)
	}
	if code := request("handle-a", strings.Repeat("0", sha256.Size*2)); code != http.StatusUnauthorized {
		t.Fatalf("wrong path bearer status = %d, want 401", code)
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("only the authenticated request may run SQL; count=%d err=%v", count, err)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/procore-webhook/handle-a", nil)
	missing.Header.Set("Authorization", "Bearer "+tokenA)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flow, rr, missing)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing mux path value status = %d, want 401", rr.Code)
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
	if vc.Secret != "{{env.WEBHOOK_SECRET}}" {
		t.Errorf("Secret = %q, want compact env reference", vc.Secret)
	}
}

func TestLoadFlowsGHA_NewVerifyRecipeShapeAndValidation(t *testing.T) {
	dir := t.TempDir()
	valid := `
on:
  request:
    method: POST
    path: /api/procore-webhook/:handle
    verify:
      recipe: hmac_sha256_path_bearer
      secret: "${{ env.PROCORE_WEBHOOK_MASTER_SECRET }}"
      prefix: "Bearer "
      path_param: handle
      context: "procore-webhook:"
jobs:
  receive:
    steps:
      - run: respond
        with: { status: 200 }
`
	if msg := validateFlowsYAML(valid); msg != "" {
		t.Fatalf("valid path-bearer flow rejected: %s", msg)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || flows[0].VerifyConfig == nil {
		t.Fatalf("expected one loaded verified flow, got %#v", flows)
	}
	vc := flows[0].VerifyConfig
	if vc.Secret != "{{env.PROCORE_WEBHOOK_MASTER_SECRET}}" || vc.PathParam != "handle" || vc.Context != "procore-webhook:" {
		t.Fatalf("new recipe fields not preserved: %#v", vc)
	}

	invalid := strings.Replace(valid, "path_param: handle", "path_param: wrong", 1)
	if msg := validateFlowsYAML(invalid); !strings.Contains(msg, "not a dynamic segment") {
		t.Fatalf("write validator should reject unmatched path param, got %q", msg)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(invalid), 0644); err != nil {
		t.Fatal(err)
	}
	if got := LoadFlowsGHA(dir); len(got) != 0 {
		t.Fatalf("runtime loader must skip invalid verified flow, got %d", len(got))
	}
}

func TestValidateFlowsYAML_RejectsUnknownVerifyRecipe(t *testing.T) {
	yamlBody := `
on:
  request:
    method: POST
    path: /api/webhook
    verify:
      recipe: made_up
      secret: "{{ env.WEBHOOK_SECRET }}"
jobs:
  receive:
    steps:
      - run: respond
        with: { status: 200 }
`
	if msg := validateFlowsYAML(yamlBody); !strings.Contains(msg, "unknown recipe") {
		t.Fatalf("unknown verify recipe should fail write validation, got %q", msg)
	}
}

// readAll without the io import noise of the package under test.
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	return io.ReadAll(r)
}

// Silence unused import warning for net/http in environments where the
// test file is the only consumer - kept because httptest.NewRequest
// returns *http.Request and the type assertion below makes it visible.
var _ = http.MethodPost
