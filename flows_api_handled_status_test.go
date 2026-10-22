//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type apiStatusRouteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

type apiStatusRoundTripper func(*http.Request) (*http.Response, error)

func (f apiStatusRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type apiStatusReadErrorBody struct{}

func (apiStatusReadErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("injected response read failure")
}
func (apiStatusReadErrorBody) Close() error { return nil }

func (t apiStatusRouteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	u := *req.URL
	u.Scheme, u.Host = t.target.Scheme, t.target.Host
	copy.URL, copy.Host = &u, t.target.Host
	return t.base.RoundTrip(copy)
}

func publicAPIStatusTestClient(t *testing.T, target string) *http.Client {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: apiStatusRouteTransport{target: u, base: http.DefaultTransport}}
}

func TestRunAPIHandledStatusesCapturesOnlyOptedIn4xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/bad-request":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid"}`))
		case "/server-error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"upstream"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := publicAPIStatusTestClient(t, server.URL)
	ctx := &FlowContext{Data: map[string]any{}, Params: map[string]string{}}
	request := func(path string, handled []int, successWhen string) error {
		step := &FlowStep{Name: "fetch", API: &FlowAPICall{
			Method: http.MethodGet, URL: "https://8.8.8.8" + path,
			HandledStatuses: handled, SuccessWhen: successWhen,
		}}
		return execAPIRequestWithClient(ctx, step, step.API, nil, client)
	}

	if err := request("/bad-request", []int{http.StatusBadRequest}, ""); err != nil {
		t.Fatalf("listed 400 should be captured: %v", err)
	}
	envelope, ok := ctx.Data["fetch"].(map[string]any)
	if !ok || envelope["status"] != http.StatusBadRequest || envelope["body"] != `{"error":"invalid"}` {
		t.Fatalf("listed 400 envelope = %#v", ctx.Data["fetch"])
	}

	delete(ctx.Data, "fetch")
	if err := request("/bad-request", nil, ""); err == nil || !strings.Contains(err.Error(), "returned 400") {
		t.Fatalf("unlisted 400 error = %v, want HTTP 400 error", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("unlisted 400 must not publish a response envelope")
	}

	if err := request("/ok", []int{http.StatusBadRequest}, ""); err != nil {
		t.Fatalf("ordinary 200 should remain successful: %v", err)
	}
	delete(ctx.Data, "fetch")
	if err := request("/bad-request", []int{http.StatusBadRequest}, "fetch.status == 200"); err == nil || !strings.Contains(err.Error(), "success_when failed") {
		t.Fatalf("success_when must still reject a listed 400: %v", err)
	}
	delete(ctx.Data, "fetch")
	if err := request("/server-error", []int{http.StatusBadRequest}, ""); err == nil || !strings.Contains(err.Error(), "returned 500") {
		t.Fatalf("listed status must not capture 500: %v", err)
	}
	if err := request("/server-error", []int{http.StatusInternalServerError}, ""); err == nil || !strings.Contains(err.Error(), "returned 500") {
		t.Fatalf("invalid internal handled-status value captured 500: %v", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("500 must not publish a response envelope")
	}
}

func TestRunAPIHandledStatusesRejectsMalformedAndPaginatedConfig(t *testing.T) {
	tests := []struct {
		name string
		with string
	}{
		{"string status", "handled_statuses: ['400']"},
		{"fractional status", "handled_statuses: [400.0]"},
		{"below 4xx", "handled_statuses: [399]"},
		{"5xx", "handled_statuses: [500]"},
		{"duplicate", "handled_statuses: [400, 400]"},
		{"empty", "handled_statuses: []"},
		{"not a list", "handled_statuses: 400"},
		{"pagination", "handled_statuses: [400]\n          paginate: {}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			source := fmt.Sprintf(`on:
  request:
    method: POST
    path: /api/test
jobs:
  test:
    steps:
      - run: api
        with:
          url: https://example.com/path
          %s
`, tt.with)
			path := filepath.Join(dir, "flows.yaml")
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if msg := validateFlowsYAML(source); msg == "" {
				t.Fatal("write/check validator accepted malformed handled_statuses")
			}
			if _, err := parseGHAFlowFile(path, []byte(source)); err == nil {
				t.Fatal("flow loader accepted malformed handled_statuses")
			}
		})
	}

	dir := t.TempDir()
	valid := `on:
  request:
    method: POST
    path: /api/test
jobs:
  test:
    steps:
      - run: api
        with:
          url: https://example.com/path
          handled_statuses: [400, 422]
`
	path := filepath.Join(dir, "flows.yaml")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	flows, err := parseGHAFlowFile(path, []byte(valid))
	if err != nil {
		t.Fatalf("valid handled_statuses rejected: %v", err)
	}
	if got := flows[0].Steps[0].API.HandledStatuses; len(got) != 2 || got[0] != 400 || got[1] != 422 {
		t.Fatalf("parsed handled_statuses = %v", got)
	}
}

func TestRunAPIHandledStatusesRejectsLegacySyntax(t *testing.T) {
	source := `google_callback:
  trigger: POST /api/google-callback
  steps:
    - if: "{{state.valid}}"
      steps:
        - api:
            method: POST
            url: https://example.com/token
            handled_statuses: [400]
`
	if msg := validateFlowsYAML(source); !strings.Contains(msg, "legacy `api:` steps do not support handled_statuses") {
		t.Fatalf("write/check validator did not explain legacy rejection: %q", msg)
	}
	if _, err := parseLegacyFlowsYAML([]byte(source)); err == nil || !strings.Contains(err.Error(), "legacy `api:` steps do not support handled_statuses") {
		t.Fatalf("legacy runtime parser error = %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlowsChecked(dir, true); err == nil || !strings.Contains(err.Error(), "legacy `api:` steps do not support handled_statuses") {
		t.Fatalf("checked legacy flow loader error = %v", err)
	}
}

func TestRunAPIHandledStatusesPreservesLegacyJSONPayloadKey(t *testing.T) {
	source := `legacy_google_post:
  trigger: POST /api/test-google-post
  steps:
    - api:
        method: POST
        url: https://example.com/token
        json:
          handled_statuses: [400]
`
	flows, err := parseLegacyFlowsYAML([]byte(source))
	if err != nil || len(flows) != 1 {
		t.Fatalf("legacy JSON payload was rejected: flows=%d err=%v", len(flows), err)
	}
	if got := flows[0].Steps[0].API.JSON["handled_statuses"]; got == nil {
		t.Fatal("legacy API JSON payload lost its ordinary handled_statuses key")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlowsChecked(dir, true); err != nil {
		t.Fatalf("checked legacy loader rejected ordinary JSON payload: %v", err)
	}
}

func TestRunAPIHandledStatusesThroughParsedHTTPFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	source := `on:
  request:
    method: POST
    path: /api/test-google-callback
jobs:
  callback:
    steps:
      - id: provider
        run: api
        with:
          method: POST
          url: https://8.8.8.8/token
          handled_statuses: [400]
      - run: respond
        with:
          status: 200
          json:
            provider_status: "${{ steps.provider.outputs.status }}"
            provider_error: "${{ steps.provider.outputs.json.error }}"
`
	path := filepath.Join(dir, "google-callback.yaml")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	flows, err := parseGHAFlowFile(path, []byte(source))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: flows=%d err=%v", len(flows), err)
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/test-google-callback", nil)
	err = executeFlowHTTPAsWithAPIClient(app, &flows[0], recorder, request, nil, publicAPIStatusTestClient(t, server.URL))
	if err != nil {
		t.Fatalf("execute parsed flow: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("flow response status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse flow response %q: %v", recorder.Body.String(), err)
	}
	if result["provider_status"] != float64(http.StatusBadRequest) || result["provider_error"] != "invalid_grant" {
		t.Fatalf("flow did not consume the opted-in 400 response: %#v", result)
	}
}

func TestRunAPIHandledStatusesCannotBypassUnconditionalURLValidation(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{Name: "fetch", API: &FlowAPICall{
		Method: http.MethodGet, URL: "http://127.0.0.1/private", HandledStatuses: []int{400},
	}}
	client := &http.Client{Transport: apiStatusRouteTransport{}}
	if err := execAPIRequestWithClient(ctx, step, step.API, nil, client); err == nil || !strings.Contains(err.Error(), "blocked API request to private URL") {
		t.Fatalf("injected client bypassed unconditional URL validation: %v", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("blocked URL must not publish a response envelope")
	}
}

func TestRunAPIHandledStatusesKeepTransportReadAndOversizeAsErrors(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{Name: "fetch", API: &FlowAPICall{
		Method: http.MethodGet, URL: "https://8.8.8.8/transport", HandledStatuses: []int{http.StatusBadRequest},
	}}
	networkClient := &http.Client{Transport: apiStatusRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("injected transport failure")
	})}
	if err := execAPIRequestWithClient(ctx, step, step.API, nil, networkClient); err == nil || !strings.Contains(err.Error(), "injected transport failure") {
		t.Fatalf("transport error = %v", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("transport failure must not publish an envelope")
	}

	readClient := &http.Client{Transport: apiStatusRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: apiStatusReadErrorBody{}}, nil
	})}
	if err := execAPIRequestWithClient(ctx, step, step.API, nil, readClient); err == nil || !strings.Contains(err.Error(), "response read") {
		t.Fatalf("body read error = %v", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("body read failure must not publish a partial envelope")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, strings.Repeat("x", maxAPIResponseBody+1))
	}))
	defer server.Close()
	step.API.URL = "https://8.8.8.8/oversize"
	oversizeClient := publicAPIStatusTestClient(t, server.URL)
	if err := execAPIRequestWithClient(ctx, step, step.API, nil, oversizeClient); err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("oversize response error = %v", err)
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("oversize response must not publish a truncated envelope")
	}
}

func TestRunAPIHandledStatusesRespectRequestContextAndStepTimeout(t *testing.T) {
	started := make(chan struct{}, 2)
	releaseHandlers := make(chan struct{})
	var releaseOnce sync.Once
	var cancelRequests []context.CancelFunc
	requestDone, timeoutStarted, timeoutDone := false, false, false
	result := make(chan error, 1)
	timeoutResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-releaseHandlers:
		}
	}))
	t.Cleanup(func() {
		for _, cancel := range cancelRequests {
			cancel()
		}
		releaseOnce.Do(func() { close(releaseHandlers) })
		server.CloseClientConnections()
		if !requestDone {
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Error("canceled request did not join during cleanup")
			}
		}
		if timeoutStarted && !timeoutDone {
			select {
			case <-timeoutResult:
			case <-time.After(time.Second):
				t.Error("timed request did not join during cleanup")
			}
		}
		server.Close()
	})
	client := publicAPIStatusTestClient(t, server.URL) // supplied client has no timeout
	step := &FlowStep{Name: "fetch", API: &FlowAPICall{
		Method: http.MethodGet, URL: "https://8.8.8.8/callback", HandledStatuses: []int{http.StatusBadRequest},
	}}

	parent, cancel := context.WithCancel(context.Background())
	cancelRequests = append(cancelRequests, cancel)
	ctx := &FlowContext{Request: httptest.NewRequest(http.MethodPost, "/callback", nil).WithContext(parent), Data: map[string]any{}}
	go func() { result <- execAPIRequestWithClient(ctx, step, step.API, nil, client) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the test server")
	}
	cancel()
	select {
	case err := <-result:
		requestDone = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled request error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request did not return")
	}
	if _, exists := ctx.Data["fetch"]; exists {
		t.Fatal("canceled request published an envelope")
	}

	timeoutParent, cancelTimeout := context.WithCancel(context.Background())
	cancelRequests = append(cancelRequests, cancelTimeout)
	timeoutCtx := &FlowContext{Request: httptest.NewRequest(http.MethodPost, "/callback", nil).WithContext(timeoutParent), Data: map[string]any{}}
	timeoutStep := *step
	timeoutAPI := *step.API
	timeoutAPI.URL = "https://1.1.1.1/callback"
	timeoutStep.API = &timeoutAPI
	timeoutStep.Timeout = 25 * time.Millisecond
	timeoutStarted = true
	go func() {
		timeoutResult <- execAPIRequestWithClient(timeoutCtx, &timeoutStep, timeoutStep.API, nil, client)
	}()
	select {
	case err := <-timeoutResult:
		timeoutDone = true
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request past step timeout error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not return at its step timeout")
	}
	if _, exists := timeoutCtx.Data["fetch"]; exists {
		t.Fatal("timed-out request published an envelope")
	}
}
