//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A reset form whose password is rejected (mismatch, too weak) goes back to
// the reset page with the link's token, so the person can retry there. It
// used to drop the token, and every retry from that page failed as an
// invalid link until the email was opened again.
func TestResetPasswordRetryKeepsTheLinkToken(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = &AuthPaths{Login: "/login", ResetPassword: "/reset-password", ForgotPassword: "/forgot-password"}
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureAuditLogTable(app.DB)
	appOAuthEnsureTables(app)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (7, 'ada', 'ada@example.com', 'old-hash')`)
	token := "reset-token-for-retry"
	if !storeResetLink(app.DB, "ada@example.com", token) {
		t.Fatal("reset link not stored")
	}
	post := func(tok, password, confirm string) *httptest.ResponseRecorder {
		form := url.Values{"token": {tok}, "password": {password}, "confirm": {confirm}}
		req := httptest.NewRequest("POST", "/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handleResetPassword(rec, req, app)
		return rec
	}
	for name, tc := range map[string][2]string{
		"mismatch": {"N3w-Passw0rd!x", "different!X1"},
		"too weak": {"weakpassword", "weakpassword"},
		"empty":    {"", ""},
	} {
		rec := post(token, tc[0], tc[1])
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusSeeOther || loc == nil || loc.Path != "/reset-password" || loc.Query().Get("token") != token || loc.Query().Get("error") == "" {
			t.Errorf("%s: redirect %d %q should return to the reset page with the token and an error", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	// A link that does not work is not echoed back.
	if loc := post("not-a-real-token", "N3w-Passw0rd!x", "N3w-Passw0rd!x").Header().Get("Location"); strings.Contains(loc, "token=") {
		t.Errorf("an invalid token was sent back: %q", loc)
	}
	// The retry with the kept token still works.
	if loc := post(token, "N3w-Passw0rd!x", "N3w-Passw0rd!x").Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("retry with the kept token did not reset: %q", loc)
	}
}

// A settings form submitted with fetch that asks for JSON gets the result
// itself instead of a redirect to the app's settings path, which an app with
// its own account page may not serve (the dashboard showed a 404 page as the
// form's error).
func TestSettingsPasswordAnswersJSONWhenAsked(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('json', 'json@example.com', ?, 'user', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "json@example.com", "", time.Hour)
	change := func(next, confirm string) (*httptest.ResponseRecorder, map[string]any) {
		form := url.Values{"current_password": {fixturePassword}, "new_password": {next}, "confirm_password": {confirm}, "_csrf": {authMintCSRFToken(sid)}}
		r := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w, body
	}
	w, body := change("Replaced!456", "Different!789")
	if w.Code != http.StatusBadRequest || body["ok"] != false || !strings.Contains(body["error"].(string), "match") {
		t.Fatalf("mismatch: %d %s", w.Code, w.Body.String())
	}
	w, body = change("Replaced!456", "Replaced!456")
	if w.Code != http.StatusOK || body["ok"] != true || body["message"] == "" {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	var stored string
	app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&stored)
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("Replaced!456")) != nil {
		t.Fatal("the password was not changed")
	}
}

// The dashboard's account page sent its password form with fetch and a
// FormData body, which browsers encode as multipart/form-data. The handler
// parsed only URL-encoded bodies, so every field read empty and the change
// failed with "All password fields are required".
func TestSettingsPasswordReadsAMultipartForm(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('mp', 'mp@example.com', ?, 'user', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "mp@example.com", "", time.Hour)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range map[string]string{"current_password": fixturePassword, "new_password": "Multipart!456", "confirm_password": "Multipart!456"} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/settings/password", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("multipart password change: %d %s", w.Code, w.Body.String())
	}
	var stored string
	app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&stored)
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("Multipart!456")) != nil {
		t.Fatal("the password was not changed")
	}
}
