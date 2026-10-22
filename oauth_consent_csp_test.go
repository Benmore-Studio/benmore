//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOAuthConsentFormActionAllowsRedirectTarget(t *testing.T) {
	cases := map[string]string{
		"https://claude.ai/api/mcp/auth_callback": "'self' https://claude.ai",
		"http://127.0.0.1:33418/callback":         "'self' http://127.0.0.1:33418",
		"http://[::1]:8080/cb":                    "'self' http://[::1]:8080",
		"cursor://anysphere.cursor-mcp/oauth":     "'self' cursor://anysphere.cursor-mcp",
		"com.example.app:/oauth":                  "'self' com.example.app:",
		"https://evil.example; script-src *":      "'self'",
		"":                                        "'self'",
	}
	for in, want := range cases {
		if got := oauthConsentFormAction(in); got != want {
			t.Errorf("oauthConsentFormAction(%q) = %q, want %q", in, got, want)
		}
	}
	rec := httptest.NewRecorder()
	writeOAuthConsentPage(rec, "Claude", "Benmore", "a@b.c", "claude.ai", "apps:read", map[string]string{"redirect_uri": "https://claude.ai/api/mcp/auth_callback"}, "")
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://claude.ai;") {
		t.Fatalf("consent CSP does not allow the redirect: %s", csp)
	}
}
