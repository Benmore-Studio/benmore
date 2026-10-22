//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// `benmore host` serves many tenants from one process and one serverSecret.
// The MFA-setup token names a user id and email and, once the caller verifies
// a code for the authenticator it enrolls, becomes a full session. A tenant
// that can get its own app to sign such a token for any (id, email) - it owns
// the rows - must not be able to present it at another tenant's app.
func TestTempCookiesAreBoundToTheirApp(t *testing.T) {
	old := serverSecret
	serverSecret = "shared-host-process-secret"
	defer func() { serverSecret = old }()
	a, closeA := newTestApp(t)
	defer closeA()
	b, closeB := newTestApp(t)
	defer closeB()
	// Both tenants hold a matching account (id and email), so the only thing
	// that can tell the token apart is the app it was signed for.
	for _, app := range []*App{a, b} {
		EnsureUsersTable(app.DB)
		mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (7, 'member', 'member@b.example', 'x')")
	}

	// The setup token as tenant A's login would mint it for a forged account
	// whose id and email match a member of tenant B.
	token := mintMFASetupToken(a, 7, "member@b.example")
	fromA := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
	fromA.Header.Set("X-MFA-Setup-Token", token)
	if uid, _, _, err := mfaCallerIdentity(a, fromA); err != nil || uid != 7 {
		t.Fatalf("control: the minting app rejects its own token: %d %v", uid, err)
	}
	if uid, _, _, err := mfaCallerIdentity(b, fromA); err == nil {
		t.Fatalf("another app accepted the setup token for user %d", uid)
	}

	// The same holds for the OTP / MFA step cookies.
	step := signTempCookieFor(a, tempCookieOTP, fmt.Sprintf("%d|%s|%s", 7, "member@b.example", "member@b.example"))
	if verifyTempCookieFor(a, tempCookieOTP, step) == "" {
		t.Fatal("control: the signing app rejects its own step cookie")
	}
	if verifyTempCookieFor(b, tempCookieOTP, step) != "" {
		t.Fatal("another app accepted a step cookie signed for a different app")
	}
}
