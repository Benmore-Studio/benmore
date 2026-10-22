//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// Cloudflare's email obfuscation replaced the signed-in address with
// "[email protected]" and a decoder script the consent CSP blocks.
func TestOAuthConsentPageKeepsEmailOutOfCloudflareObfuscation(t *testing.T) {
	w := httptest.NewRecorder()
	writeOAuthConsentPage(w, "Tool", "Benmore", "owner@example.com", "tool.example", "apps:read", map[string]string{"redirect_uri": "https://tool.example/cb"}, "")
	if !strings.Contains(w.Body.String(), "<!--email_off--><strong>owner@example.com</strong><!--/email_off-->") {
		t.Fatal("signed-in email is not shielded from Cloudflare email obfuscation")
	}
}
