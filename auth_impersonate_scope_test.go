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

// Impersonation yields a full-access session as another user. Like role
// grants, it must come from an admin's full-access credential: a token
// scoped to, say, notes:read must not widen into that.
func TestImpersonationRequiresFullAccessAdmin(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('admin', 'admin@example.com', ?, 'admin', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	adminSID := CreateSession(app.DB, adminID, "admin@example.com", "", time.Hour)
	scoped := auditToken(t, app, adminSID, "notes:read")
	target := seedMemberSession(t, app)
	targetID := GetSessionFromDB(app.DB, target).UserID

	impersonate := func(auth func(*http.Request)) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"user_id": targetID, "password": fixturePassword})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		auth(r)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := impersonate(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+scoped) }); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("scoped admin token started impersonation: %d %s", w.Code, w.Body.String())
	}
	// Control: the admin's own login session still can.
	w := impersonate(func(r *http.Request) {
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(adminSID))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSID})
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("admin session could not impersonate: %d %s", w.Code, w.Body.String())
	}
}
