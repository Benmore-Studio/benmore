//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Managed-mode login CSRF: the assertion must be bound to the browser that
// started the sign-in, or an attacker can finish the flow with their own
// identity and hand a victim's browser the callback URL.

func managedNonceApp(t *testing.T) *http.ServeMux {
	t.Helper()
	t.Setenv("BENMORE_OAUTH_BROKER_URL", "https://broker.example.com")
	t.Setenv("BENMORE_OAUTH_BROKER_PROVIDERS", "google")
	t.Setenv("BENMORE_APP_NAME", "fixture")
	t.Setenv("BENMORE_OAUTH_REQUIRE_NONCE", "")
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	mux := http.NewServeMux()
	RegisterOAuthRoutes(mux, app)
	return mux
}

func managedAssertionToken(t *testing.T, n string) string {
	t.Helper()
	now := time.Now()
	payload, _ := json.Marshal(managedAssertion{
		Email: "attacker@example.com", Provider: "google", Aud: "fixture",
		Iat: now.Unix(), Exp: now.Add(60 * time.Second).Unix(), JTI: generateToken(16), N: n,
	})
	return brokerSign(payload, serverSecret)
}

func managedCallback(mux *http.ServeMux, token, cookieValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/auth/managed/callback?token="+url.QueryEscape(token), nil)
	if cookieValue != "" {
		// httptest requests are plain HTTP, so the unprefixed name applies.
		req.AddCookie(&http.Cookie{Name: managedNonceCookieName(false), Value: cookieValue})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func sessionIssued(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if (c.Name == sessionCookieName || c.Name == devSessionCookieName) && c.Value != "" {
			return true
		}
	}
	return false
}

func TestManagedStartBindsBrowserWithNonceCookie(t *testing.T) {
	mux := managedNonceApp(t)
	req := httptest.NewRequest("GET", "/auth/google", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start = %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	n := loc.Query().Get("n")
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "benmore_oauth_nonce") {
			cookie = c
		}
	}
	if n == "" || cookie == nil {
		t.Fatalf("start must set a nonce cookie and pass n (n=%q cookie=%v)", n, cookie)
	}
	if n == cookie.Value || n != managedNonceHash(cookie.Value) {
		t.Fatalf("n must be the hash of the cookie nonce, never the nonce itself")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 || cookie.MaxAge > 900 || cookie.Path != "/" {
		t.Fatalf("cookie flags wrong: %+v", cookie)
	}
	if !cookie.Secure || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatalf("over HTTPS the cookie must be Secure and __Host- prefixed: %+v", cookie)
	}
}

func TestManagedCallbackRequiresMatchingNonceCookie(t *testing.T) {
	mux := managedNonceApp(t)
	nonce := "victim-browser-nonce"

	// Victim browser never started the flow: no cookie.
	rec := managedCallback(mux, managedAssertionToken(t, managedNonceHash(nonce)), "")
	if rec.Code != http.StatusBadRequest || sessionIssued(rec) {
		t.Fatalf("assertion without a nonce cookie = %d session=%v, want 400 and none", rec.Code, sessionIssued(rec))
	}
	// A different browser's nonce.
	rec = managedCallback(mux, managedAssertionToken(t, managedNonceHash(nonce)), "some-other-nonce")
	if rec.Code != http.StatusBadRequest || sessionIssued(rec) {
		t.Fatalf("assertion with the wrong nonce cookie = %d session=%v, want 400 and none", rec.Code, sessionIssued(rec))
	}
	// The initiating browser.
	rec = managedCallback(mux, managedAssertionToken(t, managedNonceHash(nonce)), nonce)
	if rec.Code != http.StatusSeeOther || !sessionIssued(rec) {
		t.Fatalf("assertion with the matching cookie = %d session=%v, want 303 and a session", rec.Code, sessionIssued(rec))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "benmore_oauth_nonce") && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the nonce cookie must be cleared after use")
	}
}

func TestManagedCallbackLegacyAssertionHonoursRolloutFlag(t *testing.T) {
	mux := managedNonceApp(t)
	// Flag off (default): an assertion from an old router (no n) still works.
	if rec := managedCallback(mux, managedAssertionToken(t, ""), ""); rec.Code != http.StatusSeeOther || !sessionIssued(rec) {
		t.Fatalf("legacy assertion with flag off = %d loc=%q cookies=%v", rec.Code, rec.Header().Get("Location"), rec.Result().Cookies())
	}
	// Flag on: refused.
	t.Setenv("BENMORE_OAUTH_REQUIRE_NONCE", "1")
	if rec := managedCallback(mux, managedAssertionToken(t, ""), ""); rec.Code != http.StatusBadRequest || sessionIssued(rec) {
		t.Fatalf("legacy assertion with flag on = %d session=%v, want 400 and none", rec.Code, sessionIssued(rec))
	}
	// Flag on, bound assertion still works.
	if rec := managedCallback(mux, managedAssertionToken(t, managedNonceHash("ok")), "ok"); rec.Code != http.StatusSeeOther {
		t.Fatalf("bound assertion with flag on = %d, want 303", rec.Code)
	}
}
