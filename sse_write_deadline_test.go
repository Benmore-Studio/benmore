//go:build !cli

package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The SSE handler cleared its write deadline for the whole stream, so a
// client that stopped reading (its receive window full) left the handler
// blocked in a write with no deadline: past the stream lifetime cap, past
// every heartbeat, holding its goroutine, socket and hub slot for good.
// Each write now carries its own deadline.
func TestSSEStalledReaderReleasesHandler(t *testing.T) {
	old := sseWriteTimeout
	sseWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { sseWriteTimeout = old })

	app := &App{Dir: t.TempDir()}
	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetReadBuffer(4096)
	}
	if _, err := conn.Write([]byte("GET /sse/events HTTP/1.1\r\nHost: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// Read the response head, then never read again.
	br := bufio.NewReader(conn)
	if line, err := br.ReadString('\n'); err != nil || !strings.Contains(line, "200") {
		t.Fatalf("response: %q %v", line, err)
	}

	clientFor := func() *sseClient {
		sseHub.mu.RLock()
		defer sseHub.mu.RUnlock()
		for c := range sseHub.clients {
			if c.appDir == app.Dir {
				return c
			}
		}
		return nil
	}
	var client *sseClient
	for deadline := time.Now().Add(2 * time.Second); client == nil && time.Now().Before(deadline); {
		client = clientFor()
		time.Sleep(10 * time.Millisecond)
	}
	if client == nil {
		t.Fatal("stream never registered")
	}

	// Fill the socket: large events until the handler's writes block.
	done := make(chan struct{})
	defer close(done)
	big := strings.Repeat("x", 64<<10)
	go func() {
		for {
			select {
			case client.ch <- big:
			case <-done:
				return
			}
		}
	}()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if clientFor() == nil {
			return // the handler gave up on the stalled client and unregistered
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("SSE handler stayed blocked writing to a client that stopped reading")
}
