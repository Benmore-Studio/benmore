//go:build !cli

package main

import "testing"

// Hosted units bind loopback through BENMORE_BIND_LOOPBACK, which also marks
// the process as a hosted tenant. A self-hoster behind a local proxy needs
// the loopback listener without those guards: BENMORE_LISTEN picks the
// address, and a value that isn't an IP stops startup instead of silently
// binding every interface. `serve --mcp-local` defaults to loopback too,
// unless the operator named an address.
func TestServeListenAddress(t *testing.T) {
	for _, c := range []struct {
		loopback, listen, want string
		fails, mcpLocal        bool
	}{
		{"", "", ":8080", false, false},
		{"1", "", "127.0.0.1:8080", false, false},
		{"", "127.0.0.1", "127.0.0.1:8080", false, false},
		{"", "::1", "[::1]:8080", false, false},
		{"1", "0.0.0.0", "127.0.0.1:8080", false, false}, // the hosted setting always wins
		{"", "localhost", "", true, false},
		{"", "127.0.0.1:9000", "", true, false},
		{"", "", "127.0.0.1:8080", false, true},      // --mcp-local: loopback by default
		{"", "0.0.0.0", "0.0.0.0:8080", false, true}, // an explicit address wins
		{"", "localhost", "", true, true},
	} {
		t.Setenv("BENMORE_BIND_LOOPBACK", c.loopback)
		t.Setenv("BENMORE_LISTEN", c.listen)
		got, err := serveListenAddr(8080, c.mcpLocal)
		if (err != nil) != c.fails || got != c.want {
			t.Errorf("loopback=%q listen=%q mcpLocal=%v: got %q, %v; want %q (fails=%v)", c.loopback, c.listen, c.mcpLocal, got, err, c.want, c.fails)
		}
	}
}
