//go:build !cli

package main

import "testing"

// The oauth_only + allow_emails auth keys are real runtime keys (auth.go
// oauthOnly / emailMatchesGate); the antipattern validator's knownAuthKeys
// allowlist must recognize them so a correct app.yaml isn't rejected at
// write time (v2.7.207 drift fix).
func TestValidateAppYAMLRecognizesOAuthOnlyAndAllowEmails(t *testing.T) {
	good := `site_name: "X"
auth:
  identifier: email
  oauth_only: true
  allow_emails: "richard@benmore.tech"
  redirect: "/newsroom"
`
	if msg := validateAppYAML(good); msg != "" {
		t.Fatalf("valid auth keys rejected: %s", msg)
	}

	// A genuinely fabricated key must still be caught.
	bad := `auth:
  enabled: true
`
	if msg := validateAppYAML(bad); msg == "" {
		t.Fatal("fabricated auth.enabled should still be rejected")
	}
}
