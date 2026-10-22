//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The OTP and MFA steps authenticate with a flow cookie and take no CSRF
// token (the code is the secret). The cookie is SameSite=Lax, which still
// rides a request from a sibling subdomain - another tenant on the same
// parent domain is same-site. Such a page could drive a visitor's
// half-finished sign-in: five posts burn the emailed code and lock the
// account's second-factor step for fifteen minutes. The browser-origin gate
// that every CSRF-checked form already has now covers these steps too.
func TestSignInStepsRefuseAnotherSitesPost(t *testing.T) {
	app, mux, secret := stepCookieFixture(t)
	passwordChangeExec(t, app.DB, "CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME)")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_otp (email, code, expires_at) VALUES ('member@corp.example', '123456', datetime('now', '+10 minutes'))")
	otpCookie := mintSignInChallenge(app, tempCookieOTP, 1, "member@corp.example", "member@corp.example")
	mfaCookie := mintSignInChallenge(app, tempCookieMFA, 2, "member@corp.example|x", "")

	post := func(path, cookieName, cookie, field, value string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://app.example"+path, strings.NewReader(url.Values{field: {value}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-Proto", "https")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		r.AddCookie(&http.Cookie{Name: "__Host-" + cookieName, Value: cookie})
		w := httptest.NewRecorder()
		if path == app.Paths.VerifyOTP {
			handleVerifyOTP(w, r, app)
		} else {
			mux.ServeHTTP(w, r)
		}
		return w
	}
	sessions := func() int {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions").Scan(&n)
		return n
	}
	count := func(q string) int {
		var n int
		app.DB.QueryRow(q).Scan(&n)
		return n
	}

	for _, foreign := range []map[string]string{
		{"Origin": "https://other-tenant.example"},
		{"Sec-Fetch-Site": "same-site"},
		{"Sec-Fetch-Site": "cross-site"},
	} {
		// Wrong codes from another site must not spend attempts or lock anything.
		post(app.Paths.VerifyOTP, flowCookieOTP, otpCookie, "code", "000000", foreign)
		post(app.Paths.VerifyMFA, flowCookieMFA, mfaCookie, "mfa_code", "000000", foreign)
		// ... and even the right code is not accepted from there.
		post(app.Paths.VerifyOTP, flowCookieOTP, otpCookie, "code", "123456", foreign)
		post(app.Paths.VerifyMFA, flowCookieMFA, mfaCookie, "mfa_code", GenerateTOTP(secret), foreign)
	}
	if n := count("SELECT COALESCE(MAX(attempts), 0) FROM _benmore_otp"); n != 0 {
		t.Fatalf("another site's posts spent %d attempts of the emailed code", n)
	}
	if n := count("SELECT COUNT(*) FROM _benmore_login_attempts WHERE success = 0"); n != 0 {
		t.Fatalf("another site's posts recorded %d failed step attempts", n)
	}
	if n := sessions(); n != 0 {
		t.Fatalf("another site's post completed a sign-in step (%d sessions)", n)
	}

	// The person's own page (same origin, or a client that sends neither
	// header) still completes both steps.
	if w := post(app.Paths.VerifyOTP, flowCookieOTP, otpCookie, "code", "123456", map[string]string{"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin"}); stepCookieValue(w, sessionCookieName) == "" {
		t.Fatalf("the app's own OTP form was refused: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := post(app.Paths.VerifyMFA, flowCookieMFA, mfaCookie, "mfa_code", GenerateTOTP(secret), nil); stepCookieValue(w, sessionCookieName) == "" {
		t.Fatalf("a client without fetch metadata was refused the MFA step: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// The MFA setup token also travels as a cookie. Another site's request would
// carry it and restart the enrollment (a new secret and new backup codes),
// leaving the QR code the person just scanned useless.
func TestMFASetupCookieRefusesAnotherSitesPost(t *testing.T) {
	app, mux := auditApp(t)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'enroll', 'enroll@corp.example', 'x', 'admin', 1)")
	token := mintMFASetupToken(app, 1, "enroll@corp.example")
	setup := func(headers map[string]string, viaHeader bool) int {
		r := httptest.NewRequest(http.MethodPost, "https://app.example/api/_auth/mfa/setup", strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Proto", "https")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		if viaHeader {
			r.Header.Set("X-MFA-Setup-Token", token)
		} else {
			r.AddCookie(&http.Cookie{Name: "__Host-" + flowCookieMFASetup, Value: token})
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	pending := func() string {
		var secret string
		app.DB.QueryRow("SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = 1").Scan(&secret)
		return secret
	}
	if code := setup(map[string]string{"Origin": "https://app.example"}, false); code != http.StatusOK || pending() == "" {
		t.Fatalf("the app's own enrollment page: %d", code)
	}
	started := pending()
	for _, foreign := range []map[string]string{{"Origin": "https://other-tenant.example"}, {"Sec-Fetch-Site": "same-site"}} {
		if code := setup(foreign, false); code != http.StatusForbidden {
			t.Fatalf("another site's post with the setup cookie = %d", code)
		}
	}
	if pending() != started {
		t.Fatal("another site's post replaced the pending enrollment")
	}
	// A native client presents the token in the header and sends no Origin.
	if code := setup(nil, true); code != http.StatusOK {
		t.Fatalf("header-presented setup token = %d", code)
	}
}
