//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The string form of verify: (`verify: stripe`, a header name, ...) takes its
// secret from `secret:`, which the docs write as ${{ env.NAME }}. That shape
// used to reach verification unresolved, so the literal text "${{ env.NAME }}"
// was the secret: real senders failed, and anyone who could guess the text
// could authenticate. It now resolves like the map form, and a secret that
// still holds a template fails closed.
func TestLegacyVerifySecretResolvesGHAEnvRefs(t *testing.T) {
	dir := t.TempDir()
	SetAppEnv(dir, "HOOK_SECRET", "real-secret-value")
	t.Cleanup(func() { SetAppEnv(dir, "HOOK_SECRET", "") })
	bearer := func(flow *Flow, token string) bool {
		r := httptest.NewRequest("POST", "/api/hook", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+token)
		return verifyWebhookSignature(flow, r, dir)
	}
	for _, secret := range []string{"${{ env.HOOK_SECRET }}", "${{env.HOOK_SECRET}}", "{{ env.HOOK_SECRET }}", "{{env.HOOK_SECRET}}"} {
		flow := &Flow{Name: "hook", Verify: "X-Hook-Signature", Secret: secret}
		if !bearer(flow, "real-secret-value") {
			t.Errorf("secret %q: the real secret was rejected", secret)
		}
		if bearer(flow, secret) {
			t.Errorf("secret %q: the unresolved template text authenticated", secret)
		}
	}
	missing := &Flow{Name: "hook", Verify: "X-Hook-Signature", Secret: "${{ env.NOT_SET }}"}
	if bearer(missing, "${{ env.NOT_SET }}") || bearer(missing, "{{env.NOT_SET}}") || bearer(missing, "") {
		t.Error("a secret referencing an unset variable authenticated")
	}
}
