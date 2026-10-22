//go:build !cli

package main

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func stepCookieFixture(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	app, _ := auditApp(t) // groups: members(org_id, email)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("synthetic-totp-seed!"))
	// A verified member of tenant-a.
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (1, 'member', 'member@corp.example', ?, 'user', 1)", string(hash))
	passwordChangeExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'member@corp.example')")
	// An account whose stored email holds a "|" (an address a provider or an
	// operator wrote before the shape rule applied there), with a second
	// factor enrolled so its sign-ins pass through the step cookie.
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, totp_secret) VALUES (2, 'other', 'member@corp.example|x', ?, 'user', 1, ?)", string(hash), secret)
	mux := http.NewServeMux()
	RegisterMFALoginRoute(mux, app)
	return app, mux, secret
}

func stepCookieValue(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

func postMFAStep(t *testing.T, app *App, mux *http.ServeMux, stepCookie, code string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyMFA, strings.NewReader(url.Values{"mfa_code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName("_benmore_mfa_uid", true), Value: stepCookie})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// The MFA step cookie was "<id>|<email>" joined as-is, so for an account
// whose email holds a "|" the step read the part before it as the email and
// what followed as "password sign-in": the session was written for
// member@corp.example, in that address's tenant, under the other account's id.
func TestMFAStepCompletesForTheAccountNotAnEmailInTheCookie(t *testing.T) {
	app, mux, secret := stepCookieFixture(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/custom/callback", nil)
	if !oauthMFAGate(w, r, app, 2, "member@corp.example|x", "") {
		t.Fatal("an MFA-enrolled account was not sent to the second-factor step")
	}
	step := stepCookieValue(w, flowCookieName("_benmore_mfa_uid", true))
	if step == "" {
		t.Fatal("no MFA step cookie")
	}
	vw := postMFAStep(t, app, mux, step, GenerateTOTP(secret))
	token := stepCookieValue(vw, sessionCookieName)
	if token == "" {
		t.Fatalf("the account's own second-factor step did not sign it in: %d %q", vw.Code, vw.Header().Get("Location"))
	}
	var rowEmail, rowGroup string
	if err := app.DB.QueryRow("SELECT email, COALESCE(group_id, '') FROM _benmore_sessions WHERE user_id = 2").Scan(&rowEmail, &rowGroup); err != nil {
		t.Fatal(err)
	}
	if rowEmail != "member@corp.example|x" || (rowGroup != "" && rowGroup != "0") {
		t.Fatalf("session written for email %q in tenant %q; want the account's own email and no tenant", rowEmail, rowGroup)
	}
	sess := GetSessionFromDB(app.DB, token)
	if sess == nil || sess.UserID != 2 {
		t.Fatalf("session = %+v", sess)
	}
	if sess.Email != "member@corp.example|x" {
		t.Fatalf("session email = %q; the step took an address out of the cookie", sess.Email)
	}
}

// Unbound legacy MFA steps are refused, including correctly encoded accounts.
func TestLegacyStepCookieWithShiftedFieldsIsRefused(t *testing.T) {
	app, mux, secret := stepCookieFixture(t)

	shifted := signTempCookieFor(app, tempCookieMFA, "2|member@corp.example|x")
	w := postMFAStep(t, app, mux, shifted, GenerateTOTP(secret))
	var sessions int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions").Scan(&sessions)
	if stepCookieValue(w, sessionCookieName) != "" || sessions != 0 {
		t.Fatalf("a legacy step cookie whose fields shifted issued a session (sessions=%d)", sessions)
	}

	// An ordinary address is also refused: this value has no one-use state.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret = ? WHERE id = 1", secret)
	plain := signTempCookieFor(app, tempCookieMFA, "1|member@corp.example")
	w = postMFAStep(t, app, mux, plain, GenerateTOTP(secret))
	if stepCookieValue(w, sessionCookieName) != "" {
		t.Fatalf("an unbound legacy step cookie was accepted: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestStepValueRoundTripsAnyFieldContent(t *testing.T) {
	for _, c := range []struct{ email, key string }{
		{"person@corp.example", "person@corp.example"},
		{"person@corp.example", ""},
		{"a|b@corp.example", "user|name"},
		{"", "+15550100"},
		{"v2|9|x", "v2"},
	} {
		id, email, key, ok := parseStepValue(encodeStepValue(42, c.email, c.key))
		if !ok || id != 42 || email != c.email || key != c.key {
			t.Errorf("round trip of (%q, %q) = %d, %q, %q, %v", c.email, c.key, id, email, key, ok)
		}
	}
	for _, bad := range []string{"", "v2", "v2|1|!!|", "v2|0|" + stepField("a@b.example") + "|", "v2|x|" + stepField("a@b.example") + "|", "v2|1|" + stepField("a@b.example") + "||extra"} {
		if _, _, _, ok := parseStepValue(bad); ok {
			t.Errorf("parseStepValue accepted %q", bad)
		}
	}
}

// The MFA setup token ends in a session, so it too completes only for the
// account it names, under that account's current email.
func TestMFASetupTokenBindsToTheAccountsCurrentEmail(t *testing.T) {
	app, _, _ := stepCookieFixture(t)
	call := func(token string) (int64, string, error) {
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
		r.Header.Set("X-MFA-Setup-Token", token)
		uid, email, _, err := mfaCallerIdentity(app, r)
		return uid, email, err
	}
	if uid, email, err := call(mintMFASetupToken(app, 2, "member@corp.example|x")); err != nil || uid != 2 || email != "member@corp.example|x" {
		t.Fatalf("setup token for an email holding | = %d, %q, %v", uid, email, err)
	}
	if uid, email, err := call(mintMFASetupToken(app, 1, "member@corp.example")); err != nil || uid != 1 || email != "member@corp.example" {
		t.Fatalf("setup token = %d, %q, %v", uid, email, err)
	}
	// The address changed after the token was issued.
	stale := mintMFASetupToken(app, 1, "member@corp.example")
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET email = 'moved@corp.example' WHERE id = 1")
	if _, _, err := call(stale); err == nil {
		t.Fatal("a setup token issued for the account's previous email was accepted")
	}
}
