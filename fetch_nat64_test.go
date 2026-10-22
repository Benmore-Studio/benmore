//go:build !cli

package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// NAT64 addresses carry an IPv4 destination; the outbound policy must judge
// that embedded address, while public IPv4 reached through NAT64 still works.
func TestBlockedOutboundIPJudgesNAT64EmbeddedAddress(t *testing.T) {
	cases := map[string]bool{
		"64:ff9b::a9fe:a9fe":     true,  // 169.254.169.254 (instance metadata)
		"64:ff9b::7f00:1":        true,  // 127.0.0.1
		"64:ff9b::a00:1":         true,  // 10.0.0.1
		"64:ff9b::6440:1":        true,  // 100.64.0.1 (CGNAT)
		"64:ff9b:1::a00:1":       true,  // RFC 8215 local-use prefix
		"64:ff9b::808:808":       false, // 8.8.8.8
		"8.8.8.8":                false,
		"2606:4700:4700::1111":   false,
		"::ffff:169.254.169.254": true,
		"0.1.2.3":                true,  // 0.0.0.0/8 "this network"
		"64:ff9b::1:203":         true,  // 0.1.2.3 through NAT64
		"fec0::1":                true,  // IPv6 site-local
		"feff::1":                true,  // top of fec0::/10
		"fe7f::1":                false, // below fe80::/10 and fec0::/10
	}
	for addr, want := range cases {
		if got := blockedOutboundIP(net.ParseIP(addr)); got != want {
			t.Errorf("blockedOutboundIP(%s) = %v, want %v", addr, got, want)
		}
	}

	// The dial-time guard applies the same policy before connecting.
	_, err := safeHTTPClientStrict(2 * time.Second).Get("http://[64:ff9b::a9fe:a9fe]/latest/meta-data/")
	if err == nil || !strings.Contains(err.Error(), "private/reserved IP blocked") {
		t.Fatalf("strict client dial to NAT64-embedded metadata address: err = %v, want the dial guard to refuse it", err)
	}
}
