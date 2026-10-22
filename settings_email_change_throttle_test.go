//go:build !cli

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Any signed-in account (an open signup is enough) can ask to change its
// email to someone else's address, and each request mails that address a
// confirmation link. Without a per-recipient cap one account, or many, could
// use the app to mail-bomb an address.
func TestEmailChangeRequestThrottledPerRecipient(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	old := emailChangeRecipientLimiter
	emailChangeRecipientLimiter = NewRateLimiter(3, 15*time.Minute)
	t.Cleanup(func() { emailChangeRecipientLimiter = old })
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)

	// No mail provider in tests: an attempted send fails with the send error.
	attempted := func(uid int64, to string) bool {
		err := requestEmailChange(app, r, uid, to)
		if err != nil && strings.Contains(err.Error(), "could not send") {
			return true
		}
		if !errors.Is(err, errEmailChangeThrottled) {
			t.Fatalf("unexpected result for %s: %v", to, err)
		}
		return false
	}
	for i := 0; i < 3; i++ {
		if !attempted(1, "victim@example.com") {
			t.Fatalf("request %d to a fresh address was throttled", i+1)
		}
	}
	if attempted(1, "Victim@Example.com") {
		t.Fatal("a fourth confirmation mail went to the same address (case variant)")
	}
	if attempted(2, "victim@example.com") {
		t.Fatal("another account could keep mailing the same address")
	}
	if !attempted(1, "someone-else@example.com") {
		t.Fatal("the throttle is not per recipient")
	}
}
