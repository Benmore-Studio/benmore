//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The documented CSRF contract for a signed-in cookie session (api(at:"csrf")
// → session_binding). Every page render mints an unbound token (the meta tag,
// injected form fields), and an SDK sign-in keeps the page's pre-login token,
// so an unbound token - also what an anonymous GET /api/_csrf returns - is
// accepted on any session. What stops a forged request is the origin gate and
// the SameSite session cookie, not the token. A token /api/_csrf minted for
// one session is refused on another.
func TestCSRFUnboundTokenContractOnSignedInSession(t *testing.T) {
	if serverSecret == "" {
		serverSecret = generateToken(32)
	}
	const victim, other = "victim-session-token", "other-session-token"
	unbound := authMintCSRFToken("")
	boundToOther := authMintCSRFToken(other)
	boundToVictim := authMintCSRFToken(victim)
	req := func(token string, set func(*http.Request)) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://app.example/api/notes", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", token)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: victim})
		if set != nil {
			set(r)
		}
		return r
	}
	sameOrigin := func(r *http.Request) { r.Header.Set("Origin", "https://app.example") }
	cases := []struct {
		name  string
		token string
		set   func(*http.Request)
		want  bool
	}{
		{"own bound token", boundToVictim, sameOrigin, true},
		{"unbound token, same origin", unbound, sameOrigin, true},
		{"unbound token, no Origin or fetch metadata", unbound, nil, true},
		{"another session's bound token", boundToOther, sameOrigin, false},
		{"unbound token, cross-site Origin", unbound, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, false},
		{"unbound token, sibling subdomain", unbound, func(r *http.Request) { r.Header.Set("Origin", "https://evil.app.example") }, false},
		{"unbound token, Sec-Fetch-Site same-site", unbound, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, false},
	}
	for _, c := range cases {
		if got := validateCSRF(req(c.token, c.set)); got != c.want {
			t.Errorf("%s: validateCSRF = %v, want %v", c.name, got, c.want)
		}
	}
}
