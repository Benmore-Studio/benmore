//go:build !cli

package main

import (
	"strings"
	"testing"
)

// An anonymous CSRF token (nonce|ts|HMAC) must never verify as a temp auth
// cookie: that turned any page's meta-tag token into an MFA "password
// verified" cookie.
func TestCSRFTokenIsNotATempCookie(t *testing.T) {
	old := serverSecret
	serverSecret = "temp-cookie-test-secret"
	app := &App{Dir: t.TempDir()}
	defer func() { serverSecret = old }()
	for i := 0; i < 50; i++ {
		tok := authMintCSRFToken("")
		if v := verifyTempCookieFor(app, tempCookieMFA, tok); v != "" {
			t.Fatalf("CSRF token verified as temp cookie with value %q", v)
		}
	}
	signed := signTempCookieFor(app, tempCookieMFA, "42|user@example.com")
	if got := verifyTempCookieFor(app, tempCookieMFA, signed); got != "42|user@example.com" {
		t.Fatalf("round trip = %q", got)
	}
	// Tampering with the value or the embedded expiry breaks the MAC.
	parts := strings.Split(signed, "|")
	parts[2] = "99999999999"
	if verifyTempCookieFor(app, tempCookieMFA, strings.Join(parts, "|")) != "" {
		t.Fatal("extended expiry accepted")
	}
}

func TestParseTempCookieUserIDIsStrict(t *testing.T) {
	for in, want := range map[string]int64{"42": 42, "1c9e0f": 0, "0": 0, "-3": 0, "": 0, "7 ": 0, "12abc": 0} {
		if got := parseTempCookieUserID(in); got != want {
			t.Errorf("parseTempCookieUserID(%q) = %d, want %d", in, got, want)
		}
	}
}
