//go:build !cli

package main

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// A failed write does not imply that the read side of a connection has closed.
// Model that half-open state without opening a network listener.
type wsWriteFailureConn struct {
	net.Conn
	readStarted chan struct{}
	readOnce    sync.Once
}

func (c *wsWriteFailureConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (c *wsWriteFailureConn) Write([]byte) (int, error) {
	return 0, errors.New("synthetic write failure")
}

func TestWebSocketWriteFailureClosesReadLoop(t *testing.T) {
	server, peer := net.Pipe()
	t.Cleanup(func() { server.Close(); peer.Close() })
	conn := &wsWriteFailureConn{Conn: server, readStarted: make(chan struct{})}
	client := &wsClient{
		ws:   &wsConn{conn: conn, br: bufio.NewReader(conn)},
		send: make(chan []byte, 1),
		done: make(chan struct{}),
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		wsReadLoop(client, &App{})
	}()
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		t.Fatal("read loop did not start")
	}

	client.send <- []byte(`{"type":"change"}`)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		wsWriteLoop(client)
	}()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("write loop did not stop after the write failure")
	}
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("failed writer left the read loop blocked, preventing route cleanup")
	}
}
