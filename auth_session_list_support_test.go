//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A support impersonation session is a row under the TARGET user's id, and
// AttachSessionContext stamps it with the admin's address and browser. The
// user's own session list (GET /api/_auth/sessions) returned every row for
// the user id, so the customer saw the support admin's IP and user agent,
// and could revoke the row by its listed id. The same held for the delegated
// sessions platform tooling mints as a user.
func TestSessionListHidesSupportSessions(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	seed := func(email, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	adminID := seed("admin@example.com", "admin")
	memberID := seed("member@example.com", "user")
	adminSID := CreateSession(app.DB, adminID, "admin@example.com", "", time.Hour)

	// The member's own sign-in, from their own device.
	memberSID := CreateSession(app.DB, memberID, "member@example.com", "", time.Hour)
	own := httptest.NewRequest(http.MethodGet, "/", nil)
	own.RemoteAddr = "198.51.100.20:5000"
	own.Header.Set("User-Agent", "MemberPhone/1.0")
	AttachSessionContext(app.DB, memberSID, own)

	// Support steps in from the admin's device.
	body, _ := json.Marshal(map[string]any{"user_id": memberID, "password": fixturePassword})
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(adminSID))
	r.Header.Set("User-Agent", "SupportDesk/9.9")
	r.RemoteAddr = "203.0.113.77:6000"
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSID})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var started map[string]any
	json.Unmarshal(w.Body.Bytes(), &started)
	supportToken, _ := started["token"].(string)
	if w.Code != http.StatusOK || supportToken == "" {
		t.Fatalf("impersonation did not start: %d %s", w.Code, w.Body.String())
	}
	// Platform tooling acting as the member (probe_route / browser_check `as`).
	delegated := createDelegatedSession(app.DB, memberID, "member@example.com", "", time.Hour)
	if delegated == "" {
		t.Fatal("no delegated session")
	}

	list := func(token string) (string, []map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "/api/_auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out struct {
			Sessions []map[string]any `json:"sessions"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("session list: %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String(), out.Sessions
	}
	raw, sessions := list(memberSID)
	if strings.Contains(raw, "203.0.113.77") || strings.Contains(raw, "SupportDesk") {
		t.Fatalf("the member's session list shows the support admin's address or browser: %s", raw)
	}
	if len(sessions) != 1 || sessions[0]["current"] != true || sessions[0]["ip"] != "198.51.100.20" {
		t.Fatalf("the member should see exactly their own sign-in: %s", raw)
	}

	// The member can't end the support session through the session API: it
	// isn't one of theirs.
	for _, hidden := range []string{supportToken, delegated} {
		req := httptest.NewRequest(http.MethodDelete, "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(hidden)), nil)
		req.Header.Set("X-CSRF-Token", authMintCSRFToken(memberSID))
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: memberSID})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("revoking a support/delegated session by id: %d %s", rec.Code, rec.Body.String())
		}
		if GetSessionFromDB(app.DB, hidden) == nil {
			t.Fatal("the member's session API deleted a support/delegated session")
		}
	}

	// Control: their own session still lists and revokes.
	second := CreateSession(app.DB, memberID, "member@example.com", "", time.Hour)
	if _, sessions := list(memberSID); len(sessions) != 2 {
		t.Fatalf("own sessions listed: %d, want 2", len(sessions))
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(second)), nil)
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(memberSID))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: memberSID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || GetSessionFromDB(app.DB, second) != nil {
		t.Fatalf("revoking an own session: %d %s", rec.Code, rec.Body.String())
	}

	// The support session itself gets no list at all: the member's sign-ins
	// are the member's to see and end.
	for _, token := range []string{supportToken, delegated} {
		req := httptest.NewRequest(http.MethodGet, "/api/_auth/sessions", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("session list through a support/delegated session: %d %s", rec.Code, rec.Body.String())
		}
	}
}
