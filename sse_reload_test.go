//go:build !cli

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reloadTestApp builds a minimal app that requires auth (non-empty
// Design.Auth) with the testing feature toggled per the argument. Its
// directory is named like a hosted instance: "shop" (prod) or "shop-dev".
func reloadTestApp(t *testing.T, devMode, testing bool) *App {
	t.Helper()
	return reloadTestAppIn(t, filepath.Join(t.TempDir(), "shop-dev"), devMode, testing)
}

func reloadTestAppIn(t *testing.T, dir string, devMode, testing bool) *App {
	t.Helper()
	testingEnabled := testing
	return &App{
		Dir:     dir,
		DevMode: devMode,
		Design: &DesignConfig{
			Auth:     map[string]string{"domain": "example.com"},
			Features: &FeaturesConfig{Testing: &testingEnabled},
		},
	}
}

// anonSSEStatus opens /sse/events with no session and returns the status.
func anonSSEStatus(t *testing.T, app *App) int {
	t.Helper()
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
	resp.Body.Close()
	return resp.StatusCode
}

// In testing mode on a hosted dev instance the dev reload client is injected
// (devReloadClientEnabled), so the anonymous EventSource it opens on a
// pre-auth page must be accepted by /sse/events.
func TestSSEEventsAllowsAnonymousInTestingMode(t *testing.T) {
	app := reloadTestApp(t, false, true)
	if !NeedsAuth(app) {
		t.Fatal("test app should require auth")
	}
	if !devReloadClientEnabled(app) {
		t.Fatal("testing mode should enable the dev reload client")
	}
	if code := anonSSEStatus(t, app); code != http.StatusOK {
		t.Fatalf("anonymous SSE on a testing-mode dev instance = %d; want 200 (the reload client would never fire)", code)
	}
	// `benmore serve --dev` (DevMode) admits it whatever the directory.
	if code := anonSSEStatus(t, reloadTestAppIn(t, filepath.Join(t.TempDir(), "shop"), true, false)); code != http.StatusOK {
		t.Fatalf("anonymous SSE in DevMode = %d; want 200", code)
	}
}

// features.testing stays on after promote, and a prod instance in testing
// mode accepted anonymous /sse/events (200, holding the per-address anonymous
// slots) although api(at:"sse") promises 401 when the app has auth. Only a
// development instance admits the anonymous reload stream; a signed-in tab on
// prod still connects and gets the reload.
func TestSSEEventsRejectsAnonymousOnTestingModeProdInstance(t *testing.T) {
	prod := reloadTestAppIn(t, filepath.Join(t.TempDir(), "shop"), false, true)
	if !devReloadClientEnabled(prod) || anonymousReloadStreamAllowed(prod) {
		t.Fatal("a testing-mode prod instance injects the reload client but must not admit anonymous streams")
	}
	if code := anonSSEStatus(t, prod); code != http.StatusUnauthorized {
		t.Fatalf("anonymous SSE on a testing-mode prod instance = %d; want 401", code)
	}

	// Signed in, the same prod instance still streams and gets reloads.
	app, _ := auditApp(t)
	testingOn := true
	app.Design = &DesignConfig{Auth: map[string]string{"domain": "example.com"}, Features: &FeaturesConfig{Testing: &testingOn}}
	if anonymousReloadStreamAllowed(app) {
		t.Fatal("fixture app should be a prod instance")
	}
	sid := createCrudScopeSession(t, app, "reload@example.com", "user", "", "")
	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code := anonSSEStatus(t, app); code != http.StatusUnauthorized {
		t.Fatalf("anonymous SSE on the fixture prod app = %d; want 401", code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/sse/events", nil)
	req.Header.Set("Authorization", "Bearer "+sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed-in SSE on a testing-mode prod instance = %d; want 200", resp.StatusCode)
	}
	reader := bufio.NewReader(resp.Body)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("stream did not open: %q %v", line, err)
	}
	BroadcastReload(app, "hot-reload")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("signed-in tab got no reload: %v", err)
		}
		if strings.HasPrefix(line, "event: reload") {
			break
		}
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
	app := &App{Dir: t.TempDir()}
	client := &sseClient{ch: make(chan string, 1), principal: realtimePrincipal{app: app}}
	sseHub.mu.Lock()
	sseHub.clients[client] = true
	sseHub.mu.Unlock()
	defer func() {
		sseHub.mu.Lock()
		delete(sseHub.clients, client)
		sseHub.mu.Unlock()
	}()

	BroadcastReload(app, `weird"reason`)

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
