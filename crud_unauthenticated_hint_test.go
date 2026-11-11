//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A request whose token or session no longer resolves (revoked, expired, or
// issued after a restored snapshot) was told to declare `read: anon`, the fix
// for an anonymous visitor (round 2, L14). It is now told its credential is
// not valid; a request with no credential keeps the public-feed hint.
func TestUnauthenticatedHintDistinguishesRejectedCredentials(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureSessionsTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"redirect": "/login"}}
	app.Tables = []Table{{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "body"}}}}

	for _, c := range []struct {
		name, header, cookie string
		want, notWant        string
	}{
		{name: "anonymous", want: "read: anon", notWant: "not valid"},
		{name: "revoked bearer", header: "Bearer revoked-token", want: "not valid", notWant: "read: anon"},
		{name: "stale cookie", cookie: "stale-session", want: "not valid", notWant: "read: anon"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			if c.cookie != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.cookie})
			}
			w := httptest.NewRecorder()
			if !requireAPIAuthForOp(w, r, app, "notes", OpRead) {
				t.Fatal("request without a valid session was let through")
			}
			body := w.Body.String()
			if w.Code != http.StatusUnauthorized || !strings.Contains(body, c.want) || strings.Contains(body, c.notWant) {
				t.Fatalf("401 body = %d %s; want %q, not %q", w.Code, body, c.want, c.notWant)
			}
		})
	}
}
