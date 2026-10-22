//go:build !cli

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// realtimePeerServer serves the app's realtime routes with each request's
// client address taken from X-Test-Peer, standing in for the router-resolved
// client address of a hosted app.
func realtimePeerServer(t *testing.T, app *App) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	RegisterWebSocketRoutes(mux, app)
	RegisterSSERoutes(mux, app)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer := r.Header.Get("X-Test-Peer"); peer != "" {
			r.RemoteAddr = net.JoinHostPort(peer, "40000")
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// openAnonWS performs a WebSocket handshake as peer and returns the status
// code; on 101 the connection stays open until the test ends.
func openAnonWS(t *testing.T, srv *httptest.Server, peer string) int {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Test-Peer: %s\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"), peer)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		conn.Close()
		t.Fatalf("handshake as %s: %v", peer, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return resp.StatusCode
	}
	t.Cleanup(func() { conn.Close() })
	return resp.StatusCode
}

// waitWSHubClients waits until the hub holds n registered clients.
func waitWSHubClients(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		wsHub.mu.RLock()
		got := len(wsHub.clients)
		wsHub.mu.RUnlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub registered %d of %d websocket clients", got, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// openAnonSSE opens an event stream as peer and returns the status code; on
// 200 the stream stays open until the test ends.
func openAnonSSE(t *testing.T, srv *httptest.Server, peer string) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/sse/events", nil)
	req.Header.Set("X-Test-Peer", peer)
	resp, err := srv.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatalf("event stream as %s: %v", peer, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return resp.StatusCode
	}
	// The stream is registered once ": connected" arrives.
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatalf("event stream as %s: %v", peer, err)
	}
	t.Cleanup(func() { cancel(); resp.Body.Close() })
	return resp.StatusCode
}

// The anonymous per-address caps on /ws and /sse/events keyed on the full
// client address, so an IPv6 client could open a fresh allowance from every
// address of its /64 and fill the whole hub (every user's realtime). They now
// count an IPv6 client by its /64, as the rate limits do.
func TestRealtimeAnonCapsCountIPv6ByPrefix(t *testing.T) {
	resetWSHub(t)
	sseHub.mu.Lock()
	sseHub.clients = make(map[*sseClient]bool)
	sseHub.mu.Unlock()
	app := &App{Dir: t.TempDir()}
	srv := realtimePeerServer(t, app)

	for i := 1; i <= realtimeWSMaxConnsPerAnonIP; i++ {
		if code := openAnonWS(t, srv, fmt.Sprintf("2001:db8:1:2::%x", i)); code != http.StatusSwitchingProtocols {
			t.Fatalf("websocket %d within the cap: %d", i, code)
		}
		// The handler answers 101 and then registers the client, taking the
		// authoritative count under the hub lock. Wait for that before the
		// next handshake, so the status this test reads is the pre-upgrade
		// check's and not a 101 that the locked re-check closes right after.
		waitWSHubClients(t, i)
	}
	if code := openAnonWS(t, srv, "2001:db8:1:2::ffff"); code != http.StatusTooManyRequests {
		t.Errorf("websocket past the cap from another address of the same /64: %d, want 429", code)
	}
	if code := openAnonWS(t, srv, "2001:db8:1:3::1"); code != http.StatusSwitchingProtocols {
		t.Errorf("websocket from another /64: %d, want 101", code)
	}
	if code := openAnonWS(t, srv, "198.51.100.7"); code != http.StatusSwitchingProtocols {
		t.Errorf("websocket from an IPv4 client: %d, want 101", code)
	}

	for i := 1; i <= realtimeSSEMaxConnsPerAnonIP; i++ {
		if code := openAnonSSE(t, srv, fmt.Sprintf("2001:db8:5:6::%x", i)); code != http.StatusOK {
			t.Fatalf("event stream %d within the cap: %d", i, code)
		}
	}
	if code := openAnonSSE(t, srv, "2001:db8:5:6::ffff"); code != http.StatusTooManyRequests {
		t.Errorf("event stream past the cap from another address of the same /64: %d, want 429", code)
	}
	if code := openAnonSSE(t, srv, "2001:db8:5:7::1"); code != http.StatusOK {
		t.Errorf("event stream from another /64: %d, want 200", code)
	}
}

// The WebSocket per-user cap applied only when NeedsAuth(app), so in an app
// without an auth: block (users can still sign in, e.g. through OAuth) a
// signed-in user was neither per-user capped nor, having a user id, counted
// against the anonymous per-address cap: one account could take every slot
// up to the process-wide ceiling. The SSE cap never had that condition.
func TestWebSocketPerUserCapWithoutAuthBlock(t *testing.T) {
	resetWSHub(t)
	app, _ := auditApp(t)
	if NeedsAuth(app) {
		t.Fatal("fixture app must have no auth: block")
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (7, 'u', 'u@example.test')`)
	sid := CreateSession(app.DB, 7, "u@example.test", "", time.Hour)
	appID := realtimeAppID(app.Dir)
	for i := 0; i < wsMaxConnsPerUser; i++ {
		registerWSClient(&wsClient{appID: appID, userID: 7, send: make(chan []byte, 1), subscriptions: map[string]bool{}, rooms: map[string]bool{}})
	}
	mux := http.NewServeMux()
	RegisterWebSocketRoutes(mux, app)
	req := httptest.NewRequest("GET", "/ws", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("connection past the per-user cap in an app without auth: %d, want 429", rec.Code)
	}
}
