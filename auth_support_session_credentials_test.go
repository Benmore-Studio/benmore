//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A support session is an admin driving a customer's account, and a delegated
// session is platform tooling doing the same: each is a session row under the
// customer's id. Both passed the account-management gate, so the admin could
// list and end the customer's own sign-ins, revoke their API tokens,
// disconnect their providers, register a push device on the account, and
// try the customer's password through the password and email-change forms.
// They may look and edit ordinary profile fields; the customer's credentials
// are the customer's.
func TestSupportSessionCannotManageTheAccountsCredentials(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureOAuthTokensTable(app.DB)
	EnsureDevicesTable(app.DB)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	RegisterOAuthTokensAPI(mux, app)
	RegisterDeviceRoutes(mux, app)
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
	memberSID := CreateSession(app.DB, memberID, "member@example.com", "", time.Hour)

	call := func(token, method, path, contentType, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	started := call(adminSID, http.MethodPost, "/api/_auth/impersonate", "application/json",
		`{"user_id":`+strconv.FormatInt(memberID, 10)+`,"password":"`+fixturePassword+`"}`)
	var out map[string]any
	json.Unmarshal(started.Body.Bytes(), &out)
	support, _ := out["token"].(string)
	if started.Code != http.StatusOK || support == "" {
		t.Fatalf("impersonation did not start: %d %s", started.Code, started.Body.String())
	}
	delegated := createDelegatedSession(app.DB, memberID, "member@example.com", "", time.Hour)
	if delegated == "" {
		t.Fatal("no delegated session")
	}

	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}
	passwordForm := url.Values{"current_password": {fixturePassword}, "new_password": {"Replaced!Password9"}, "confirm_password": {"Replaced!Password9"}}.Encode()
	emailForm := url.Values{"email": {"taken-over@example.com"}, "current_password": {fixturePassword}}.Encode()
	const form = "application/x-www-form-urlencoded"

	for name, token := range map[string]string{"support session": support, "delegated session": delegated} {
		mustExec(t, app.DB, "DELETE FROM _benmore_api_tokens")
		mustExec(t, app.DB, "DELETE FROM _benmore_oauth_tokens")
		mustExec(t, app.DB, "DELETE FROM _benmore_devices")
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_api_tokens (id, user_id, name, token_hash, scopes) VALUES (41, ?, 'ci', 'hash-ci', '*')", memberID)
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token) VALUES (?, 'google', 'enc:v2:x')", memberID)
		mustExecArgs(t, app.DB, "INSERT INTO _benmore_devices (user_id, token, platform) VALUES (?, 'members-phone', 'ios')", memberID)
		attemptsBefore := count("SELECT COUNT(*) FROM _benmore_login_attempts")

		refused := map[string]*httptest.ResponseRecorder{
			"list the account's sign-ins":       call(token, http.MethodGet, "/api/_auth/sessions", "", ""),
			"end one of the account's sign-ins": call(token, http.MethodDelete, "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(memberSID)), "", ""),
			"revoke an API token":               call(token, http.MethodDelete, "/api/_auth/api-tokens/41", "", ""),
			"disconnect a provider":             call(token, http.MethodDelete, "/api/_auth/oauth-tokens/google", "", ""),
			"start an email change (API)":       call(token, http.MethodPatch, "/api/_auth/profile", "application/json", `{"email":"taken-over@example.com","current_password":"`+fixturePassword+`"}`),
			"try a password (API)":              call(token, http.MethodPatch, "/api/_auth/profile", "application/json", `{"email":"taken-over@example.com","current_password":"not-the-password"}`),
			"change the password":               call(token, http.MethodPost, "/settings/password", form, passwordForm),
			"start an email change (form)":      call(token, http.MethodPost, "/settings/profile", form, emailForm),
			"register a push device":            call(token, http.MethodPost, "/api/_devices", "application/json", `{"token":"support-desk-phone","platform":"ios"}`),
			"remove the account's push devices": call(token, http.MethodDelete, "/api/_devices", "application/json", `{}`),
		}
		for action, w := range refused {
			if w.Code != http.StatusForbidden {
				t.Errorf("%s could %s: %d %s", name, action, w.Code, strings.TrimSpace(w.Body.String()))
			}
		}
		if GetSessionFromDB(app.DB, memberSID) == nil {
			t.Errorf("%s ended the member's own sign-in", name)
		}
		if n := count("SELECT COUNT(*) FROM _benmore_api_tokens WHERE id = 41"); n != 1 {
			t.Errorf("%s revoked the member's API token", name)
		}
		if n := count("SELECT COUNT(*) FROM _benmore_oauth_tokens WHERE user_id = ?", memberID); n != 1 {
			t.Errorf("%s disconnected the member's provider", name)
		}
		if n := count("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", memberID); n != 0 {
			t.Errorf("%s started an email change", name)
		}
		var stored string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", memberID).Scan(&stored)
		if stored != string(hash) {
			t.Errorf("%s changed the member's password", name)
		}
		if n := count("SELECT COUNT(*) FROM _benmore_devices WHERE user_id = ? AND token = 'members-phone'", memberID); n != 1 {
			t.Errorf("%s removed the member's push device", name)
		}
		if n := count("SELECT COUNT(*) FROM _benmore_devices WHERE user_id = ? AND token = 'support-desk-phone'", memberID); n != 0 {
			t.Errorf("%s registered its own device for the member's notifications", name)
		}
		// The refusal comes before the password is looked at: the forms are
		// not a way to test guesses, and cannot lock the member out.
		if n := count("SELECT COUNT(*) FROM _benmore_login_attempts"); n != attemptsBefore {
			t.Errorf("%s had %d password attempt(s) recorded against the member", name, n-attemptsBefore)
		}

		// What support is there for still works: seeing the account's tokens
		// and connected providers, and correcting an ordinary profile field.
		for action, w := range map[string]*httptest.ResponseRecorder{
			"read the profile":        call(token, http.MethodGet, "/api/_auth/profile", "", ""),
			"list API tokens":         call(token, http.MethodGet, "/api/_auth/api-tokens", "", ""),
			"list connected accounts": call(token, http.MethodGet, "/api/_auth/oauth-tokens", "", ""),
			"edit a profile field":    call(token, http.MethodPatch, "/api/_auth/profile", "application/json", `{"first_name":"Corrected"}`),
		} {
			if w.Code != http.StatusOK {
				t.Errorf("%s can no longer %s: %d %s", name, action, w.Code, strings.TrimSpace(w.Body.String()))
			}
		}
	}

	// Control: the member's own sign-in manages all of it.
	for action, w := range map[string]*httptest.ResponseRecorder{
		"list sign-ins":         call(memberSID, http.MethodGet, "/api/_auth/sessions", "", ""),
		"revoke an API token":   call(memberSID, http.MethodDelete, "/api/_auth/api-tokens/41", "", ""),
		"disconnect a provider": call(memberSID, http.MethodDelete, "/api/_auth/oauth-tokens/google", "", ""),
		"register a device":     call(memberSID, http.MethodPost, "/api/_devices", "application/json", `{"token":"members-tablet","platform":"ios"}`),
	} {
		if w.Code != http.StatusOK {
			t.Errorf("the member's own session could not %s: %d %s", action, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
	if w := call(memberSID, http.MethodPost, "/settings/password", form, passwordForm); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "success") {
		t.Errorf("the member's own password change: %d %q", w.Code, w.Header().Get("Location"))
	}
}
