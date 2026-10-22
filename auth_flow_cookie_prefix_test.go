//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The session cookie carries the __Host- prefix over HTTPS so a sibling
// subdomain cannot plant one with a Domain attribute. The cookies that carry a
// half-finished sign-in (OAuth state, PKCE verifier, OTP / MFA steps) did not,
// so any tenant on the parent domain could plant its OWN valid values in a
// victim's browser and finish the victim's sign-in as the attacker (login
// CSRF): the attacker knows the state and verifier of a flow it started, and
// the signed OTP / MFA / setup cookies of an account it owns.
func TestFlowCookiesAreHostPrefixedAndTossedOnesIgnored(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	provider := &OAuthProvider{Name: "Test", ClientID: "cid", ClientSecret: "sec", AuthURL: "https://idp.example/auth",
		TokenURL: "http://127.0.0.1:1/token", UserInfoURL: "https://idp.example/me", EmailField: "email"}
	https := func(r *http.Request) *http.Request { r.Header.Set("X-Forwarded-Proto", "https"); return r }

	// The redirect step names its cookies with the prefix.
	rr := httptest.NewRecorder()
	handleOAuthRedirect(rr, https(httptest.NewRequest(http.MethodGet, "/auth/test", nil)), app, provider, "test")
	var state string
	for _, want := range []string{"_oauth_state", "_oauth_pkce", "_oauth_nonce"} {
		found := false
		for _, c := range rr.Result().Cookies() {
			if c.Name == "__Host-"+want && c.Secure && c.Path == "/" && c.Domain == "" {
				found = true
				if want == "_oauth_state" {
					state = c.Value
				}
			}
		}
		if !found {
			t.Fatalf("redirect did not set __Host-%s", want)
		}
	}

	callback := func(cookieName string) int {
		r := https(httptest.NewRequest(http.MethodGet, "/auth/test/callback?code=x&state="+url.QueryEscape(state), nil))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: state})
		w := httptest.NewRecorder()
		handleOAuthCallback(w, r, app, provider, "test")
		return w.Code
	}
	// A planted, unprefixed state cookie never counts (400 = rejected at the
	// state check; anything else got as far as the token exchange).
	if code := callback("_oauth_state"); code != http.StatusBadRequest {
		t.Fatalf("unprefixed state cookie accepted over https: %d", code)
	}
	// Control: the real cookie passes the state check (and stops at the
	// private token URL).
	if code := callback("__Host-_oauth_state"); code == http.StatusBadRequest {
		t.Fatalf("the prefixed state cookie was refused")
	}

	// OTP step: a planted, unprefixed cookie is treated as absent. The step
	// completes only for an existing account, under its own email.
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (7, 'a', 'a@example.com', 'x')")
	mustExec(t, app.DB, "CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
	mustExec(t, app.DB, "INSERT INTO _benmore_otp (email, code, expires_at) VALUES ('a@example.com', '123456', datetime('now', '+10 minutes'))")
	verify := func(name string) *httptest.ResponseRecorder {
		r := https(httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {"123456"}}.Encode())))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: name, Value: mintSignInChallenge(app, tempCookieOTP, 7, "a@example.com", "a@example.com")})
		w := httptest.NewRecorder()
		handleVerifyOTP(w, r, app)
		return w
	}
	sessionIssued := func(w *httptest.ResponseRecorder) bool {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				return true
			}
		}
		return false
	}
	if sessionIssued(verify("_benmore_otp_uid")) {
		t.Fatal("a planted unprefixed OTP cookie completed a sign-in")
	}
	if !sessionIssued(verify("__Host-_benmore_otp_uid")) {
		t.Fatal("control: the prefixed OTP cookie did not complete the sign-in")
	}

	// MFA-setup cookie, read by the enrollment endpoints.
	mfaReq := https(httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil))
	mfaReq.AddCookie(&http.Cookie{Name: "_benmore_mfa_setup", Value: mintMFASetupToken(app, 7, "a@example.com")})
	if _, _, _, err := mfaCallerIdentity(app, mfaReq); err == nil {
		t.Fatal("a planted unprefixed MFA setup cookie authenticated an enrollment call")
	}
	mfaReq = https(httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil))
	mfaReq.AddCookie(&http.Cookie{Name: "__Host-_benmore_mfa_setup", Value: mintMFASetupToken(app, 7, "a@example.com")})
	if uid, _, fromSetup, err := mfaCallerIdentity(app, mfaReq); err != nil || uid != 7 || !fromSetup {
		t.Fatalf("control: prefixed setup cookie: %d %v", uid, err)
	}
}
