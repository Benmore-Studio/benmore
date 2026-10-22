//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A browser sends `Origin: null` on a form POST from a page whose referrer
// policy is no-referrer, even to its own origin (Fetch: "append a request
// Origin header"; measured with Chrome 154: Origin: null, Sec-Fetch-Site:
// same-origin). The CSRF origin gate compared that literal with the Host and
// refused it, and the framework's own confirmation pages set exactly that
// policy: the required password change, the verify-email confirmation and
// the email-change confirmation could not be submitted from a browser.
func TestCSRFOriginGateAcceptsOpaqueOriginOnlyFromTheSameOrigin(t *testing.T) {
	post := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://app.example/settings/confirm-email", strings.NewReader(url.Values{"_csrf": {authMintCSRFToken("")}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	if !validateCSRF(post(map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"})) {
		t.Fatal("a same-origin form POST from a no-referrer page (Origin: null, Sec-Fetch-Site: same-origin) was refused")
	}
	for name, headers := range map[string]map[string]string{
		"opaque origin, cross-site":           {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
		"opaque origin, same-site":            {"Origin": "null", "Sec-Fetch-Site": "same-site"},
		"opaque origin, user-initiated":       {"Origin": "null", "Sec-Fetch-Site": "none"},
		"opaque origin, no fetch metadata":    {"Origin": "null"},
		"another origin claiming same-origin": {"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"},
	} {
		if validateCSRF(post(headers)) {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unchanged: the page's own origin, and a client that sends neither header.
	if !validateCSRF(post(map[string]string{"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin"})) || !validateCSRF(post(nil)) {
		t.Fatal("an ordinary same-origin or header-less POST was refused")
	}
}

// The pages that carry a secret in their URL keep it out of every other
// origin's Referer with a policy that still lets the browser name the page's
// origin on its own form POST.
func TestConfirmationPagesKeepTheirOriginOnPost(t *testing.T) {
	app, mux, uid, _ := newEmailChangeTestApp(t)
	EnsurePasswordResetsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	ensureEmailChangesTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	policy := func(h http.HandlerFunc, r *http.Request) string {
		w := httptest.NewRecorder()
		h(w, r)
		return w.Header().Get("Referrer-Policy")
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'next@example.com', ?, ?)",
		uid, hashResetToken("change"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 0")
	if _, err := app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'amy@example.com', ?, 'verify')",
		hashResetToken("verify"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"email-change confirmation": policy(mux.ServeHTTP, httptest.NewRequest(http.MethodGet, "/settings/confirm-email?token=change", nil)),
		"verify-email confirmation": policy(func(w http.ResponseWriter, r *http.Request) { handleVerifyEmail(w, r, app) }, httptest.NewRequest(http.MethodGet, "/verify-email?token=verify", nil)),
		"required password change":  policy(func(w http.ResponseWriter, r *http.Request) { renderPasswordChange(w, r, app, "", http.StatusOK) }, httptest.NewRequest(http.MethodGet, passwordChangePagePath, nil)),
	} {
		if got != "same-origin" {
			t.Errorf("%s page sends Referrer-Policy %q; with no-referrer its own form POST carries Origin: null", name, got)
		}
	}

	// What Chrome sends from the email-change page as it was served before:
	// the confirmation must go through.
	form := url.Values{"token": {"change"}, "_csrf": {authMintCSRFToken("")}, "password": {"Correct-Horse-1"}}
	r := httptest.NewRequest(http.MethodPost, "https://app.example/settings/confirm-email", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "null")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	mux.ServeHTTP(httptest.NewRecorder(), r)
	if got := currentEmail(t, app, uid); got != "next@example.com" {
		t.Fatalf("a browser's confirmation from the page was refused: email is still %q", got)
	}
}
