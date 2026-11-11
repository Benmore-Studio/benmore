//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A skew_seconds of 315360000 accepted a five-year-old signature: the replay
// window is now refused above a day at write time.
func TestVerifySkewSecondsRefusedAboveADayAtWriteTime(t *testing.T) {
	flow := func(skew string) string {
		return `on:
  request:
    method: POST
    path: /api/hooks/signed
    auth: none
    verify:
      recipe: hmac_timestamp_dot_body
      header: X-Signature
      timestamp_header: X-Timestamp
      secret: "{{ env.HOOK_SECRET }}"
      skew_seconds: ` + skew + `
jobs:
  run:
    steps:
      - run: respond
        with: { json: { ok: true } }
`
	}
	for _, skew := range []string{"300", "86400"} {
		if msg := validateFlowsYAML(flow(skew)); msg != "" {
			t.Fatalf("skew_seconds %s refused: %s", skew, msg)
		}
	}
	for _, skew := range []string{"86401", "315360000"} {
		if msg := validateFlowsYAML(flow(skew)); !strings.Contains(msg, "skew_seconds") || !strings.Contains(msg, "86400") {
			t.Fatalf("skew_seconds %s = %q, want a refusal naming the 86400 limit", skew, msg)
		}
	}
}

func signedTimestampRequest(t *testing.T, secret string, ts int64, prefix string) *http.Request {
	t.Helper()
	body := `{"event":"x"}`
	stamp := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "." + body))
	r := httptest.NewRequest("POST", "/api/hooks/signed", strings.NewReader(body))
	r.Header.Set("X-Timestamp", stamp)
	r.Header.Set("X-Signature", prefix+hex.EncodeToString(mac.Sum(nil)))
	return r
}

// A file written before the limit (or by hand) still loads, but the window it
// asks for is cut to a day at runtime.
func TestVerifySkewSecondsClampedToADayAtRuntime(t *testing.T) {
	dir := t.TempDir()
	v := &FlowVerify{Recipe: "hmac_timestamp_dot_body", Header: "X-Signature", TimestampHeader: "X-Timestamp", Secret: "fixture-secret", SkewSeconds: 315360000}
	if err := runVerifyRecipe(v, signedTimestampRequest(t, "fixture-secret", time.Now().Add(-5*365*24*time.Hour).Unix(), ""), dir); err == nil {
		t.Fatal("a five-year-old signature verified")
	}
	if err := runVerifyRecipe(v, signedTimestampRequest(t, "fixture-secret", time.Now().Add(-23*time.Hour).Unix(), ""), dir); err != nil {
		t.Fatalf("a signature inside a day failed: %v", err)
	}
}

// A declared prefix is part of the signature format: hmac_sha1_body required
// it, hmac_sha256_body and hmac_timestamp_dot_body only stripped it when
// present and accepted the bare hex.
func TestVerifyDeclaredPrefixIsRequired(t *testing.T) {
	dir := t.TempDir()
	body := `{"event":"x"}`
	mac := hmac.New(sha256.New, []byte("fixture-secret"))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	bodyRequest := func(header string) *http.Request {
		r := httptest.NewRequest("POST", "/api/hooks/signed", strings.NewReader(body))
		r.Header.Set("X-Signature", header)
		return r
	}
	v := &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Signature", Secret: "fixture-secret", Prefix: "sha256="}
	if err := runVerifyRecipe(v, bodyRequest("sha256="+sig), dir); err != nil {
		t.Fatalf("hmac_sha256_body with its prefix: %v", err)
	}
	if err := runVerifyRecipe(v, bodyRequest(sig), dir); err == nil {
		t.Fatal("hmac_sha256_body accepted a signature without its declared prefix")
	}
	v.Prefix = ""
	if err := runVerifyRecipe(v, bodyRequest(sig), dir); err != nil {
		t.Fatalf("hmac_sha256_body without a declared prefix: %v", err)
	}

	ts := &FlowVerify{Recipe: "hmac_timestamp_dot_body", Header: "X-Signature", TimestampHeader: "X-Timestamp", Secret: "fixture-secret", Prefix: "v0="}
	if err := runVerifyRecipe(ts, signedTimestampRequest(t, "fixture-secret", time.Now().Unix(), "v0="), dir); err != nil {
		t.Fatalf("hmac_timestamp_dot_body with its prefix: %v", err)
	}
	if err := runVerifyRecipe(ts, signedTimestampRequest(t, "fixture-secret", time.Now().Unix(), ""), dir); err == nil {
		t.Fatal("hmac_timestamp_dot_body accepted a signature without its declared prefix")
	}
}

// `run: webhook` shares run: api's per-app, per-host breaker: after the
// threshold of failures it stops calling a dead endpoint for the cooldown.
func TestWebhookStepUsesTheCircuitBreaker(t *testing.T) {
	resetCircuitsForTest(t)
	app := secretTaintApp(t)
	flow := parseExpectRowsFlow(t, app, stepKeyFlow("      - id: deliver\n        run: webhook\n        with:\n          url: https://8.8.8.8/callback\n          payload: { event: synthetic_audit }\n"))
	calls := 0
	client := &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("down")), Request: r}, nil
	})}
	run := func() error {
		return executeFlowHTTPAsWithAPIClient(app, &flow, httptest.NewRecorder(), httptest.NewRequest("POST", "/api/probe", strings.NewReader(`{}`)), nil, client)
	}
	for i := range cbFailureThreshold {
		if err := run(); err == nil {
			t.Fatalf("failing delivery %d succeeded", i+1)
		}
	}
	if calls != cbFailureThreshold {
		t.Fatalf("calls = %d, want %d", calls, cbFailureThreshold)
	}
	if err := run(); err == nil || calls != cbFailureThreshold {
		t.Fatalf("after %d failures the webhook was still called: calls=%d err=%v", cbFailureThreshold, calls, err)
	}
	if err := CheckCircuit(circuitKey(app, "https://8.8.8.8/other")); err == nil {
		t.Fatal("the host's circuit is not open for run: api either")
	}
}

// A Bearer-authenticated mutation is exempt from CSRF, but the check ran
// first and logged `validateCSRF: REJECT ... reason=missing` for every such
// write before it succeeded.
func TestBearerMutationsLogNoCSRFReject(t *testing.T) {
	app := newGateApp(t, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, user_id INTEGER, created_at DATETIME, updated_at DATETIME)`)
	EnsureWebhooksTable(app.DB)
	uid, sid := gateUser(t, app, "bearer-writer@example.com")
	for i := 1; i <= 4; i++ {
		mustExecArgs(t, app.DB, "INSERT INTO notes (id, title, user_id) VALUES (?, 'seed', ?)", i, uid)
	}
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	defer log.SetOutput(prev)

	for _, tc := range []struct {
		name                string
		handler             func(http.ResponseWriter, *http.Request, *App, string)
		method, path, ctype string
		body                string
	}{
		{"create", handleCreate, "POST", "/api/notes", "application/json", `{"title":"a"}`},
		{"update", handleUpdate, "PATCH", "/api/notes/1", "application/json", `{"title":"b"}`},
		{"delete", handleDelete, "DELETE", "/api/notes/2", "application/json", ``},
		{"batch create", handleBatchCreate, "POST", "/api/notes/batch", "application/json", `[{"title":"c"}]`},
		{"batch update", handleBatchUpdate, "PATCH", "/api/notes/batch", "application/json", `{"ids":[3],"fields":{"title":"d"}}`},
		{"batch delete", handleBatchDelete, "DELETE", "/api/notes/batch", "application/json", `{"ids":[4]}`},
		{"ingest", handleStreamingIngest, "POST", "/api/notes/ingest", "application/x-ndjson", "{\"title\":\"e\"}\n"},
	} {
		w := gateCall(app, tc.handler, "notes", tc.method, tc.path, tc.ctype, tc.body, sid)
		if w.Code >= 300 {
			t.Errorf("%s: HTTP %d %s\n%s", tc.name, w.Code, w.Body.String(), buf.String())
		}
	}
	if strings.Contains(buf.String(), "validateCSRF: REJECT") {
		t.Fatalf("Bearer writes logged a CSRF rejection:\n%s", buf.String())
	}
}

// A cross-origin page allowed by CORS_ORIGIN can read the headers that say a
// list was capped or a field or parameter was ignored.
func TestCORSExposesDiagnosticHeaders(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "CORS_ORIGIN", "https://client.example")
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), app)
	for _, origin := range []string{"https://client.example", "https://other.example"} {
		r := httptest.NewRequest("GET", "/api/notes", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		exposed := w.Header().Get("Access-Control-Expose-Headers")
		if origin != "https://client.example" {
			if exposed != "" {
				t.Fatalf("a disallowed origin got Expose-Headers %q", exposed)
			}
			continue
		}
		for _, name := range []string{"X-Limit-Capped", "X-Ignored-Params", "X-Ignored-Fields", "X-Stripped-Fields"} {
			if !strings.Contains(exposed, name) {
				t.Fatalf("Access-Control-Expose-Headers = %q, missing %s", exposed, name)
			}
		}
	}
}
