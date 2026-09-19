//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The bmp-auth mint endpoint (POST /api/_auth/api-tokens) authenticates a
// browser via the session cookie. Like every sibling cookie-session mutation
// it MUST require a CSRF token, otherwise a logged-in victim navigated to
// /bmp-auth (or a cross-site POST) mints a full-scope bmr_ token. (Task 4/22.)
func TestCreateAPITokenRequiresCSRF(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	EnsureSessionsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}

	res, err := app.DB.Exec(
		"INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)",
		"bmp", "bmp@example.com",
	)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "bmp@example.com", "", time.Hour)
	if sid == "" {
		t.Fatal("CreateSession returned empty id")
	}

	mint := func(withCSRF bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://app.example.com/api/_auth/api-tokens",
			strings.NewReader(`{"name":"bmp","scopes":"*","expires_in":"90d"}`))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		if withCSRF {
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		}
		w := httptest.NewRecorder()
		handleCreateAPIToken(w, r, app)
		return w
	}

	// Cookie auth, NO CSRF header → rejected (403), no token minted.
	if w := mint(false); w.Code != http.StatusForbidden {
		t.Fatalf("cookie mint without CSRF must be 403, got %d: %s", w.Code, w.Body.String())
	}

	// Cookie auth WITH a valid session-bound CSRF token → succeeds. Proves the
	// gate accepts the exact header bmp-auth.html sends (no legitimate client
	// breaks).
	w := mint(true)
	if w.Code != http.StatusOK {
		t.Fatalf("cookie mint with valid CSRF must be 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bmr_") {
		t.Fatalf("expected a bmr_ token in the success body, got: %s", w.Body.String())
	}

	// The rejected attempt must not have persisted a token; the accepted one
	// leaves exactly one row.
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?", uid).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 minted token (only the CSRF-valid mint), got %d", n)
	}
}
