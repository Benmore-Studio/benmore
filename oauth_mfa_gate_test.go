//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A social login is one factor: an MFA-enrolled account must be sent to the
// second-factor step, with no session issued.
func TestOAuthMFAGateRequiresSecondFactor(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureMFAColumns(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, totp_secret) VALUES (7, 'mfa', 'mfa@example.com', 'JBSWY3DPEHPK3PXP'), (8, 'plain', 'plain@example.com', NULL)`)

	rec := httptest.NewRecorder()
	if !oauthMFAGate(rec, httptest.NewRequest("GET", "/auth/google/callback", nil), app, 7, "mfa@example.com", "4312") {
		t.Fatal("MFA-enrolled OAuth login was not gated")
	}
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "verify-mfa") {
		t.Fatalf("not redirected to MFA: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var mfaCookie, cliCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case flowCookieName("_benmore_mfa_uid", true):
			mfaCookie = c
		case flowCookieName("_benmore_mfa_cli", true):
			cliCookie = c
		case sessionCookieName:
			t.Fatal("a session cookie was issued before MFA")
		}
	}
	if mfaCookie == nil || cliCookie == nil {
		t.Fatalf("missing MFA/CLI cookies: %v %v", mfaCookie, cliCookie)
	}
	// The CLI cookie resumes only for the same user, and can't stand in as
	// the MFA identity cookie.
	req := httptest.NewRequest("POST", "/verify-mfa", nil)
	req.AddCookie(cliCookie)
	if port := oauthPendingCLIPort(httptest.NewRecorder(), req, app, 7); port != "4312" {
		t.Fatalf("CLI port not carried: %q", port)
	}
	if port := oauthPendingCLIPort(httptest.NewRecorder(), req, app, 8); port != "" {
		t.Fatalf("CLI continuation accepted for another user: %q", port)
	}
	parts := strings.SplitN(verifyTempCookieFor(app, tempCookieMFA, cliCookie.Value), "|", 2)
	if parseTempCookieUserID(parts[0]) != 0 {
		t.Fatal("CLI cookie parses as an MFA identity")
	}
	// No MFA enrolled: no gate.
	if oauthMFAGate(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), app, 8, "plain@example.com", "") {
		t.Fatal("user without MFA was gated")
	}
}
