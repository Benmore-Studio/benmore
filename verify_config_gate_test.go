//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verifyGateFlow is a public webhook receiver whose on.request carries the
// given extra lines (verify:, secret:).
func verifyGateFlow(requestLines string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/hook\n" + requestLines +
		"jobs:\n  receive:\n    steps:\n      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
}

// A file that reads as a verified webhook receiver but is not one, or that
// can never accept a request, used to pass the write gate and `benmore
// check` (round 2026-11-04): `secret:` with no `verify:` served unsigned
// bodies with 200, and `verify: stripe` with no `secret:` answered every
// request 401 although the map form refuses a missing secret. Both are now
// refused; a deployed file still loads and behaves as before.
func TestVerifyWriteGateRefusesSecretVerifierMismatch(t *testing.T) {
	refused := map[string]struct{ lines, want string }{
		"secret without verify": {
			"    secret: \"${{ env.WEBHOOK_SECRET }}\"\n",
			"has no `verify:`",
		},
		"secret with an empty verify": {
			"    verify: \"\"\n    secret: \"${{ env.WEBHOOK_SECRET }}\"\n",
			"`verify:` is empty, so nothing checks a signature",
		},
		"stripe without secret": {
			"    verify: stripe\n",
			"needs `secret:`",
		},
		"benmore with an empty secret": {
			"    verify: benmore\n    secret: \"  \"\n",
			"needs `secret:`",
		},
		"header form without secret": {
			"    verify: X-Hook-Signature\n",
			"needs `secret:`",
		},
		"map form beside an on.request secret": {
			"    verify: { recipe: hmac_sha256_body, header: X-Hook-Signature, secret: \"${{ env.A }}\" }\n    secret: \"${{ env.B }}\"\n",
			"not read when `verify:` is a map",
		},
	}
	for name, c := range refused {
		msg := ValidateOnWrite("flows/hook.yaml", verifyGateFlow(c.lines))
		if !strings.Contains(msg, c.want) {
			t.Errorf("%s: write gate said %q, want it to contain %q", name, msg, c.want)
		}
	}
	for name, lines := range map[string]string{
		"stripe with secret":  "    verify: stripe\n    secret: \"${{ env.STRIPE_WEBHOOK_SECRET }}\"\n",
		"benmore with secret": "    verify: benmore\n    secret: \"${{ env.PARTNER_HOOK_SECRET }}\"\n",
		"header with secret":  "    verify: X-Hook-Signature\n    secret: \"{{env.HOOK_SECRET}}\"\n",
		"map form":            "    verify: { recipe: hmac_sha256_body, header: X-Hook-Signature, secret: \"${{ env.A }}\" }\n",
		"no verification":     "",
	} {
		if msg := ValidateOnWrite("flows/hook.yaml", verifyGateFlow(lines)); msg != "" {
			t.Errorf("%s was refused: %s", name, msg)
		}
	}

	// benmore check reads the same rule.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, lines string) {
		if err := os.WriteFile(filepath.Join(dir, "flows", name), []byte(verifyGateFlow(lines)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("open.yaml", refused["secret without verify"].lines)
	write("closed.yaml", refused["stripe without secret"].lines)
	report := runCheck(dir, "", false)
	if !checkReportHas(report, filepath.Join("flows", "open.yaml"), "has no `verify:`") {
		t.Error("benmore check did not refuse secret: without verify:")
	}
	if !checkReportHas(report, filepath.Join("flows", "closed.yaml"), "needs `secret:`") {
		t.Error("benmore check did not refuse verify: stripe without secret:")
	}

	// A deployed file keeps loading, with its old behavior.
	app, cleanup := newTestApp(t)
	defer cleanup()
	flows := []Flow{}
	for _, name := range []string{"open", "closed"} {
		data, err := os.ReadFile(filepath.Join(dir, "flows", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := parseGHAFlowFile("flows/"+name+".yaml", data)
		if err != nil || len(loaded) != 1 {
			t.Fatalf("deployed %s.yaml no longer loads: flows=%v err=%v", name, loaded, err)
		}
		loaded[0].Trigger.Path = "/api/" + name
		flows = append(flows, loaded[0])
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	post := func(path string) int {
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"event":"unsigned"}`)))
		r.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr.Code
	}
	if code := post("/api/open"); code != http.StatusOK {
		t.Fatalf("deployed secret-without-verify flow: status %d, want 200 (unchanged)", code)
	}
	if code := post("/api/closed"); code != http.StatusUnauthorized {
		t.Fatalf("deployed stripe-without-secret flow: status %d, want 401 (unchanged)", code)
	}
}

// A literal webhook signing secret in a pushed file is refused like the
// other provider key shapes (security rule 4b). `secret: "whsec_..."` used
// to pass the scan. The literals are assembled at run time so this source
// file holds no secret-shaped text.
func TestCommittedSecretScanRefusesWebhookSigningSecrets(t *testing.T) {
	hex32 := strings.Repeat("0a1b2c3d", 4)
	refused := map[string]string{
		"Stripe dashboard":     "whsec_" + strings.Repeat("Ab3dE", 7),
		"Stripe CLI":           "whsec_" + hex32 + hex32,
		"Svix (Clerk, Resend)": "whsec_" + strings.Repeat("Mf+Q9/r8", 4),
		"Shopify app secret":   "shp" + "ss_" + hex32,
		"Shopify access token": "shp" + "at_" + hex32,
	}
	for name, literal := range refused {
		msg := ValidateOnWrite("flows/hook.yaml", verifyGateFlow("    verify: stripe\n    secret: \""+literal+"\"\n"))
		if !strings.Contains(msg, "[secrets]") || strings.Contains(msg, literal) {
			t.Errorf("%s: write gate said %q, want a [secrets] refusal that does not repeat the secret", name, msg)
		}
		if got := redactErrorCredentials("verify failed for " + literal); strings.Contains(got, literal) {
			t.Errorf("%s: error redaction kept the secret: %q", name, got)
		}
	}
	for _, lines := range []string{
		"    verify: stripe\n    secret: \"${{ env.STRIPE_WEBHOOK_SECRET }}\"\n",
		"    verify: stripe\n    secret: \"${{ env.STRIPE_WEBHOOK_SECRET }}\"   # whsec_... from the Stripe dashboard\n",
	} {
		if msg := ValidateOnWrite("flows/hook.yaml", verifyGateFlow(lines)); msg != "" {
			t.Errorf("an env reference was refused: %s", msg)
		}
	}
}
