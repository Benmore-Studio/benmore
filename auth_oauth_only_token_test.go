//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oauth_only must refuse the email+password → Bearer token exchange, not
// just the interactive login/signup. Otherwise a "social login only" app
// leaves POST /api/_auth/token open as a silent password sign-in path
// (v2.7.208).
func TestOAuthOnlyRefusesTokenEndpoint(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	req := func() *http.Request {
		return httptest.NewRequest("POST", "https://app.example.com/api/_auth/token",
			strings.NewReader(`{"email":"a@b.com","password":"whatever"}`))
	}

	// Without oauth_only: the handler proceeds past the gate (a bad
	// credential yields 401, NOT 403 - proving the gate didn't fire).
	w := httptest.NewRecorder()
	handleTokenAuth(w, req(), app)
	if w.Code == http.StatusForbidden {
		t.Fatalf("token endpoint should not be gated when oauth_only is unset (got 403)")
	}

	// With oauth_only: refused with 403 before any credential check.
	app.Design = &DesignConfig{Auth: map[string]string{"oauth_only": "true"}}
	w = httptest.NewRecorder()
	handleTokenAuth(w, req(), app)
	if w.Code != http.StatusForbidden {
		t.Fatalf("oauth_only must 403 the token endpoint, got %d: %s", w.Code, w.Body.String())
	}
}
