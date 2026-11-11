//go:build !cli

package main

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Graceful shutdown must not wait out its deadline for an open SSE stream:
// the listener is already closed, so every second it waits is a second of
// refused connections (error pages through the router) during a restart.
func TestSSEStreamEndsWhenShutdownBegins(t *testing.T) {
	serverShutdown.Lock()
	old := serverShutdown.ch
	serverShutdown.ch = make(chan struct{})
	serverShutdown.Unlock()
	t.Cleanup(func() {
		serverShutdown.Lock()
		serverShutdown.ch = old
		serverShutdown.Unlock()
	})
	sseHub.mu.Lock()
	sseHub.clients = make(map[*sseClient]bool)
	sseHub.mu.Unlock()
	app, _ := auditApp(t)
	on := true
	app.Design = &DesignConfig{Features: &FeaturesConfig{WSAnonymous: &on}}
	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.RegisterOnShutdown(beginServerShutdown)
	srv.Start()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/sse/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("event stream: %d", resp.StatusCode)
	}
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Config.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown waited for the stream until %v: %v", time.Since(start), err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("shutdown took %v with an open event stream", took)
	}
}
