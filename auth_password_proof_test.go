//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Re-entering the current password while signed in (password change, email
// change, impersonation / step-in re-auth) is a password check like login.
// Without a lockout a stolen session cookie is an unlimited online oracle
// for the password, which then unlocks email change or impersonation.
func TestCurrentPasswordProofsAreRateLimited(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(email, role string) (int64, string) {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		uid, _ := res.LastInsertId()
		return uid, CreateSession(app.DB, uid, email, "", time.Hour)
	}
	passwordIs := func(uid int64, pw string) bool {
		var h string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&h)
		return bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil
	}

	uid, sid := seed("user@example.com", "user")
	change := func(current string) {
		form := url.Values{"current_password": {current}, "new_password": {"Replaced!456"}, "confirm_password": {"Replaced!456"}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		mux.ServeHTTP(httptest.NewRecorder(), r)
	}
	for i := 0; i < 5; i++ {
		change(fmt.Sprintf("Wrong!%d", i))
	}
	change(fixturePassword)
	if !passwordIs(uid, fixturePassword) {
		t.Fatal("password changed after five wrong current-password guesses")
	}

	_, adminSID := seed("admin@example.com", "admin")
	impersonate := func(pw string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"user_id": uid, "password": pw})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(adminSID))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSID})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 5; i++ {
		impersonate(fmt.Sprintf("Wrong!%d", i))
	}
	if w := impersonate(fixturePassword); w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("impersonation started after five wrong re-auth guesses: %d %s", w.Code, w.Body.String())
	}
	var impersonations int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE COALESCE(is_impersonation,0) = 1").Scan(&impersonations)
	if impersonations != 0 {
		t.Fatalf("impersonation sessions: %d", impersonations)
	}
}
