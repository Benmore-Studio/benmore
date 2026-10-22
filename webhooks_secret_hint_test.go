//go:build !cli

package main

import "testing"

// The subscription list showed the last four characters of every signing
// secret, which is most of a short one ("hunter2" listed as "****ter2").
// Only a secret long enough for the hint not to give it away shows one.
func TestWebhookSecretHintHidesShortSecrets(t *testing.T) {
	for secret, want := range map[string]string{
		"":                           "****",
		"abcd":                       "****",
		"hunter2":                    "****",
		"fifteen-chars-x":            "****",
		"sixteen-chars-xy":           "****s-xy",
		"whsec_0123456789abcdefghij": "****ghij",
	} {
		if got := webhookSecretHint(secret); got != want {
			t.Errorf("hint for a %d-character secret = %q, want %q", len(secret), got, want)
		}
	}
}
