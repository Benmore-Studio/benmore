//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Pending passkey challenges are capped per source (20) so one client can't
// fill the table. The source was the full client address: an IPv6 client,
// which is routinely handed a whole /64, got a fresh budget from every
// address in it. The source is now the same bucket every other per-address
// limit uses (clientRateBucket).
func TestPasskeyChallengeSourceCountsIPv6BySlash64(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	issue := func(remote string) error {
		r := httptest.NewRequest(http.MethodPost, "https://app.example/api/_auth/passkeys/login/begin", nil)
		r.RemoteAddr = remote
		_, err := newPasskeyChallenge(httptest.NewRecorder(), r, app, "login", 0)
		return err
	}
	for i := 0; i < 20; i++ {
		if err := issue(fmt.Sprintf("[2001:db8:7:7::%x]:4000", i+1)); err != nil {
			t.Fatalf("challenge %d: %v", i+1, err)
		}
	}
	if err := issue("[2001:db8:7:7:aaaa::1]:4000"); err == nil {
		t.Fatal("a 21st pending challenge from another address in the same /64 was issued")
	}
	// Another /64 and an IPv4 client keep their own budgets.
	if err := issue("[2001:db8:7:8::1]:4000"); err != nil {
		t.Fatalf("another /64 shared the budget: %v", err)
	}
	if err := issue("198.51.100.5:4000"); err != nil {
		t.Fatalf("an IPv4 client shared the budget: %v", err)
	}
}
