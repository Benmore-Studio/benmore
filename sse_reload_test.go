//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// authApp builds a minimal app that requires auth (non-empty Design.Auth)
// with the testing feature toggled per the argument.
func reloadTestApp(t *testing.T, devMode, testing bool) *App {
	t.Helper()
	testingEnabled := testing
	return &App{
		Dir:     t.TempDir(),
		DevMode: devMode,
		Design: &DesignConfig{
			Auth:     map[string]string{"domain": "example.com"},
			Features: &FeaturesConfig{Testing: &testingEnabled},
		},
	}
}

// In testing mode the dev reload client is injected (devReloadClientEnabled),
// so the anonymous EventSource it opens must be accepted by /sse/events. This
// locks down the contract that the injection gate and the SSE auth gate agree.
func TestSSEEventsAllowsAnonymousInTestingMode(t *testing.T) {
	app := reloadTestApp(t, false, true)
	if !NeedsAuth(app) {
		t.Fatal("test app should require auth")
	}
	if !devReloadClientEnabled(app) {
		t.Fatal("testing mode should enable the dev reload client")
	}

	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/sse/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("anonymous SSE in testing mode was rejected with 401; injection and auth gates have drifted")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for anonymous SSE in testing mode, got %d", resp.StatusCode)
	}
}

// An auth app that is neither in DevMode nor testing mode must still reject
// anonymous SSE connections.
func TestSSEEventsRejectsAnonymousInProduction(t *testing.T) {
	app := reloadTestApp(t, false, false)
	if devReloadClientEnabled(app) {
		t.Fatal("production auth app should not enable the dev reload client")
	}

	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/sse/events")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for anonymous SSE on production auth app, got %d", resp.StatusCode)
	}
}

// BroadcastReload must frame its payload as `reload|<json>` with a JSON-safe
// body so a reason containing quotes cannot corrupt the SSE data field.
func TestBroadcastReloadPayloadIsJSON(t *testing.T) {
	client := &sseClient{ch: make(chan string, 1)}
	sseHub.mu.Lock()
	sseHub.clients[client] = true
	sseHub.mu.Unlock()
	defer func() {
		sseHub.mu.Lock()
		delete(sseHub.clients, client)
		sseHub.mu.Unlock()
	}()

	BroadcastReload(`weird"reason`)

	select {
	case payload := <-client.ch:
		prefix := "reload|"
		if !strings.HasPrefix(payload, prefix) {
			t.Fatalf("payload missing %q frame prefix: %q", prefix, payload)
		}
		var decoded map[string]string
		if err := json.Unmarshal([]byte(strings.TrimPrefix(payload, prefix)), &decoded); err != nil {
			t.Fatalf("payload body is not valid JSON (%v): %q", err, payload)
		}
		if decoded["reason"] != `weird"reason` {
			t.Fatalf("reason not round-tripped: got %q", decoded["reason"])
		}
	default:
		t.Fatal("BroadcastReload did not deliver a payload to the connected client")
	}
}
