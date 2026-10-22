package main

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestBrokerConnGateBoundsPerPeerAndOverall(t *testing.T) {
	g := newBrokerConnGate(3, 2)
	const a, b, c = 700001, 700002, 700003
	r1, ok1 := g.acquire(a)
	_, ok2 := g.acquire(a)
	if !ok1 || !ok2 {
		t.Fatal("first two connections from one peer refused")
	}
	if _, ok := g.acquire(a); ok {
		t.Error("per-peer cap not enforced")
	}
	if _, ok := g.acquire(b); !ok {
		t.Error("other peer refused below the global cap")
	}
	if _, ok := g.acquire(c); ok {
		t.Error("global cap not enforced")
	}
	r1()
	r1() // idempotent
	if _, ok := g.acquire(c); !ok {
		t.Error("released slot not reusable")
	}
}

// The router's own uid (first-party _platform mail) is bounded overall only.
func TestBrokerConnGateDoesNotPerUIDLimitTheRoutersOwnUID(t *testing.T) {
	g := newBrokerConnGate(8, 1)
	for i := 0; i < 8; i++ {
		if _, ok := g.acquire(os.Getuid()); !ok {
			t.Fatalf("first-party connection %d refused below the global cap", i)
		}
	}
	if _, ok := g.acquire(os.Getuid()); ok {
		t.Error("global cap not enforced for first party")
	}
}

func unixPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn)
		t.Cleanup(func() { c.Close() })
	}
	return conns[0], conns[1]
}

// A handler panic on a bare `go handleConn(...)` terminates the whole router.
func TestBrokerConnGateContainsHandlerPanic(t *testing.T) {
	g := newBrokerConnGate(4, 4)
	server, _ := unixPair(t)
	g.serve("test-broker", server, func() { panic("boom") })
	deadline := time.Now().Add(3 * time.Second)
	for {
		g.mu.Lock()
		n := g.total
		g.mu.Unlock()
		if n == 0 {
			return // panic recovered and the slot released; the test binary is still alive
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not released after handler panic: %d", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestBrokerConnGateClosesOverBudgetConnection(t *testing.T) {
	g := newBrokerConnGate(1, 1)
	block := make(chan struct{})
	s1, _ := unixPair(t)
	g.serve("test-broker", s1, func() { <-block })
	defer close(block)
	s2, c2 := unixPair(t)
	ran := false
	g.serve("test-broker", s2, func() { ran = true })
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("over-budget connection was not closed: %v", err)
	}
	if ran {
		t.Error("handler ran for an over-budget connection")
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
