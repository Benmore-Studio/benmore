//go:build !cli

package main

import (
	"testing"
	"time"
)

// An anonymous stream was revalidated only as "still no session", so after
// the app stopped admitting anonymous realtime (features.ws_anonymous turned
// off, or auth added, then a reload) every anonymous /ws and /sse/events
// connection opened before kept receiving table events and room messages -
// a WebSocket for as long as it stayed open. The credential re-check now also
// asks whether the app still admits anonymous streams, so they stop receiving
// within realtimePrincipalTTL and close at the next heartbeat.
func TestRealtimeAnonymousStreamsEndWhenAnonymousAccessIsWithdrawn(t *testing.T) {
	resetWSHub(t)
	sseHub.mu.Lock()
	sseHub.clients = make(map[*sseClient]bool)
	sseHub.mu.Unlock()
	app, _ := auditApp(t)
	on := true
	app.Design = &DesignConfig{Auth: map[string]string{"session_duration": "7d"}, Features: &FeaturesConfig{WSAnonymous: &on}}
	if !NeedsAuth(app) {
		t.Fatal("fixture app must require auth")
	}
	srv := realtimePeerServer(t, app)
	if code := openAnonWS(t, srv, "198.51.100.20"); code != 101 {
		t.Fatalf("anonymous websocket on a ws_anonymous app: %d", code)
	}
	if code := openAnonSSE(t, srv, "198.51.100.21"); code != 200 {
		t.Fatalf("anonymous event stream on a ws_anonymous app: %d", code)
	}
	var ws *wsClient
	for deadline := time.Now().Add(2 * time.Second); ws == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if got := wsHubSnapshot(func(c *wsClient) bool { return c.appID == realtimeAppID(app.Dir) }); len(got) == 1 {
			ws = got[0]
		}
	}
	if ws == nil {
		t.Fatal("websocket never registered")
	}
	var sse *sseClient
	sseHub.mu.RLock()
	for c := range sseHub.clients {
		if c.appDir == app.Dir {
			sse = c
		}
	}
	sseHub.mu.RUnlock()
	if sse == nil {
		t.Fatal("event stream never registered")
	}
	if _, ok := ws.principal.refresh(); !ok {
		t.Fatal("anonymous websocket invalid while ws_anonymous is on")
	}
	if _, ok := sse.principal.refresh(); !ok {
		t.Fatal("anonymous event stream invalid while ws_anonymous is on")
	}

	off := false
	app.Design.Features = &FeaturesConfig{WSAnonymous: &off}
	if _, ok := ws.principal.refresh(); ok {
		t.Error("anonymous websocket still valid after ws_anonymous was turned off")
	}
	if _, ok := sse.principal.refresh(); ok {
		t.Error("anonymous event stream still valid after ws_anonymous was turned off")
	}
}
