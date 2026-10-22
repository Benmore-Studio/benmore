//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// startManaged runs /auth/google as a browser holding priorCookie and returns
// the start's redirect hash and the Set-Cookie it received.
func startManaged(t *testing.T, mux *http.ServeMux, priorCookie string) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "/auth/google", nil)
	if priorCookie != "" {
		req.AddCookie(&http.Cookie{Name: managedNonceCookieName(false), Value: priorCookie})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	for _, c := range rec.Result().Cookies() {
		if c.Name == managedNonceCookieName(false) && c.MaxAge > 0 {
			return loc.Query().Get("n"), c
		}
	}
	t.Fatal("start set no nonce cookie")
	return "", nil
}

// Starting a second sign-in in another tab must not strand the first tab.
func TestManagedNonceCookieSurvivesSecondTab(t *testing.T) {
	mux := managedNonceApp(t)
	n1, c1 := startManaged(t, mux, "")
	n2, c2 := startManaged(t, mux, c1.Value)
	if c2.MaxAge <= 0 || c2.MaxAge > 900 || !c2.HttpOnly || c2.SameSite != http.SameSiteLaxMode || c2.Path != "/" {
		t.Fatalf("cookie flags wrong: %+v", c2)
	}

	// Tab 1 finishes first, with the cookie tab 2 left behind.
	rec := managedCallback(mux, managedAssertionToken(t, n1), c2.Value)
	if rec.Code != http.StatusSeeOther || !sessionIssued(rec) {
		t.Fatalf("first tab callback = %d, want 303 and a session", rec.Code)
	}
	// Only the matching nonce was removed: the browser keeps tab 2's.
	var left *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == managedNonceCookieName(false) && c.MaxAge > 0 {
			left = c
		}
	}
	if left == nil {
		t.Fatal("the other tab's nonce was cleared with the first")
	}
	rec = managedCallback(mux, managedAssertionToken(t, n2), left.Value)
	if rec.Code != http.StatusSeeOther || !sessionIssued(rec) {
		t.Fatalf("second tab callback = %d, want 303 and a session", rec.Code)
	}
	// The consumed nonce cannot be replayed.
	if rec := managedCallback(mux, managedAssertionToken(t, n1), left.Value); rec.Code != http.StatusBadRequest {
		t.Fatalf("consumed nonce replayed = %d, want 400", rec.Code)
	}
}

func TestManagedNonceCookieHoldsThreeMostRecent(t *testing.T) {
	mux := managedNonceApp(t)
	var hashes []string
	cookie := ""
	for i := 0; i < 4; i++ {
		n, c := startManaged(t, mux, cookie)
		hashes = append(hashes, n)
		cookie = c.Value
	}
	if rec := managedCallback(mux, managedAssertionToken(t, hashes[0]), cookie); rec.Code != http.StatusBadRequest || sessionIssued(rec) {
		t.Fatalf("fourth-oldest nonce still accepted: %d", rec.Code)
	}
	for _, h := range hashes[1:] {
		if rec := managedCallback(mux, managedAssertionToken(t, h), cookie); rec.Code != http.StatusSeeOther {
			t.Fatalf("recent nonce refused: %d", rec.Code)
		}
	}
	// A wrong nonce still fails and leaves the held ones alone.
	if rec := managedCallback(mux, managedAssertionToken(t, managedNonceHash("stranger")), cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign nonce = %d, want 400", rec.Code)
	}
}
