//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Over HTTPS the session cookie carries the __Host- prefix (host-only, Secure,
// Path=/), so a sibling subdomain can't plant or shadow it; the unprefixed
// name counts only on plain-HTTP development requests.
func TestSessionCookieIsHostPrefixedOverHTTPS(t *testing.T) {
	app, _ := auditApp(t)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, verified) VALUES (7, 'u', 'u@example.com', 1)")
	token := CreateSession(app.DB, 7, "u@example.com", "", time.Hour)

	c := sessionCookie(token, false, time.Hour)
	if c.Name != "__Host-benmore_session" || !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Fatalf("production session cookie = %+v, want __Host- prefixed, Secure, Path=/, no Domain", c)
	}
	if dev := sessionCookie(token, true, time.Hour); dev.Name != devSessionCookieName {
		t.Fatalf("development session cookie named %q", dev.Name)
	}

	signedIn := func(r *http.Request) bool {
		s := getSession(app, r)
		return s != nil && s.UserID == 7
	}
	secure := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/x", nil)
	secure.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if !signedIn(secure) {
		t.Fatal("__Host- session cookie did not authenticate over HTTPS")
	}
	planted := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/x", nil)
	planted.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: token})
	if signedIn(planted) {
		t.Fatal("an unprefixed session cookie authenticated over HTTPS")
	}
	forwarded := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/x", nil)
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	forwarded.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: token})
	if signedIn(forwarded) {
		t.Fatal("an unprefixed session cookie authenticated behind a TLS proxy")
	}
	dev := httptest.NewRequest(http.MethodGet, "http://localhost/api/x", nil)
	dev.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: token})
	if !signedIn(dev) {
		t.Fatal("development cookie stopped working over plain HTTP")
	}

	w := httptest.NewRecorder()
	clearSessionCookies(w, false)
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	if !cleared[sessionCookieName] || !cleared[devSessionCookieName] {
		t.Fatalf("sign-out cleared %v, want both session cookie names", cleared)
	}
}
