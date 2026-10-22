//go:build !cli

package main

import (
	"bufio"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// The per-connection message limit bounds the work one socket can cause.
// Browsers never send ping frames, but a scripted client could send them at
// line rate and have every one answered with a pong: control frames count.
func TestWSReadLoopRateLimitsControlFrames(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()
	client := &wsClient{ws: &wsConn{conn: srv, br: bufio.NewReader(srv)}, send: make(chan []byte, 8),
		subscriptions: map[string]bool{}, rooms: map[string]bool{}}
	var pongs, closes atomic.Int32
	go func() {
		br := bufio.NewReader(cli)
		for {
			h := make([]byte, 2)
			if _, err := io.ReadFull(br, h); err != nil {
				return
			}
			io.CopyN(io.Discard, br, int64(h[1]&0x7f))
			switch h[0] & 0x0f {
			case wsOpPong:
				pongs.Add(1)
			case wsOpClose:
				closes.Add(1)
			}
		}
	}()
	done := make(chan struct{})
	go func() { wsReadLoop(client, &App{}); close(done) }()
	ping := []byte{0x80 | wsOpPing, 0x80, 0, 0, 0, 0} // FIN, masked, empty
	for i := 0; i < 200; i++ {
		if _, err := cli.Write(ping); err != nil {
			break
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("read loop still serving a ping flood (%d pongs)", pongs.Load())
	}
	if n := pongs.Load(); n > wsClientMsgRateLimit {
		t.Fatalf("answered %d pings in one window, limit %d", n, wsClientMsgRateLimit)
	}
}
