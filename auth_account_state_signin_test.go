//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// accountStateApp is an app with sign-in tables and the profile route, for
// the deactivated / unverified sign-in tests below.
func accountStateApp(t *testing.T, auth map[string]string) (*App, *http.ServeMux) {
	t.Helper()
	app, mux := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: auth, SEO: map[string]string{"url": "https://app.example.test"}}
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	EnsurePasswordResetsTable(app.DB)
	registerSettingsRoutes(mux, app)
	return app, mux
}

// accountStateUser inserts a password account with a production-cost hash,
// so a skipped bcrypt comparison shows in the response time.
func accountStateUser(t *testing.T, app *App, email string, verified int, deactivated bool) int64 {
	t.Helper()
	hash, err := generateBcryptHash([]byte(fixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	deactivatedAt := any(nil)
	if deactivated {
		deactivatedAt = "2026-11-01 00:00:00"
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, verified, email_grandfathered, deactivated_at) VALUES (?, ?, ?, ?, 0, ?)",
		email, email, string(hash), verified, deactivatedAt)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func accountStateLogin(app *App, email, password string, jsonClient bool) *httptest.ResponseRecorder {
	form := url.Values{"email": {email}, "password": {password}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if jsonClient {
		r.Header.Set("Accept", "application/json")
	}
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	return w
}

func accountStateToken(app *App, email, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleTokenAuth(w, r, app)
	return w
}

func accountStateSessionCookie(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge >= 0 && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func accountStateCount(t *testing.T, app *App, q string, args ...any) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// The answer to a failed sign-in, without anything that varies per request.
func accountStateAnswer(w *httptest.ResponseRecorder) string {
	return w.Header().Get("Location") + "|" + w.Body.String()
}

// F9 (round 1105): POST /login for a deactivated account said "Credentials
// changed. Sign in again." with a right OR wrong password, while a wrong
// password on an active account and an unknown address said "Invalid
// credentials". So anyone could tell, without the password, that an address
// belonged to a deactivated account. No bcrypt ran and no failed attempt was
// recorded either. A deactivated account now answers exactly as a wrong
// password does.
func TestDeactivatedAccountSignInAnswersAsAWrongPassword(t *testing.T) {
	app, _ := accountStateApp(t, map[string]string{})
	accountStateUser(t, app, "active@corp.example", 1, false)
	offID := accountStateUser(t, app, "off@corp.example", 1, true)
	ipKey := authIPLockKey(clientIP(httptest.NewRequest(http.MethodPost, "/", nil)))
	failures := func(key string) int {
		return accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE email = ? AND success = 0", key)
	}

	for _, jsonClient := range []bool{false, true} {
		reference := accountStateLogin(app, "active@corp.example", "Wrong!"+fixturePassword, jsonClient)
		want := accountStateAnswer(reference)
		if !strings.Contains(want, "Invalid") {
			t.Fatalf("json=%v: wrong password on an active account answered %d %q", jsonClient, reference.Code, want)
		}
		for _, password := range []string{"Wrong!" + fixturePassword, fixturePassword} {
			beforeAccount, beforeIP := failures("off@corp.example"), failures(ipKey)
			start := time.Now()
			w := accountStateLogin(app, "off@corp.example", password, jsonClient)
			elapsed := time.Since(start)
			if got := accountStateAnswer(w); w.Code != reference.Code || got != want {
				t.Errorf("json=%v right=%v: deactivated account answered %d %q, a wrong password answers %d %q",
					jsonClient, password == fixturePassword, w.Code, got, reference.Code, want)
			}
			if failures("off@corp.example") != beforeAccount+1 || failures(ipKey) != beforeIP+1 {
				t.Errorf("json=%v right=%v: the attempt was not recorded as a failure (account %d->%d, ip %d->%d)",
					jsonClient, password == fixturePassword, beforeAccount, failures("off@corp.example"), beforeIP, failures(ipKey))
			}
			// A bcrypt comparison at the production cost takes far longer
			// than the two lookups; skipping it made deactivation a timing
			// oracle too.
			if elapsed < 40*time.Millisecond {
				t.Errorf("json=%v right=%v: deactivated sign-in returned in %v, without a password check", jsonClient, password == fixturePassword, elapsed)
			}
			if accountStateSessionCookie(w) != "" {
				t.Errorf("json=%v: deactivated account got a session cookie", jsonClient)
			}
		}
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", offID); n != 0 {
		t.Fatalf("deactivated account holds %d session rows", n)
	}
}

// F9: POST /api/_auth/token with the right password for a deactivated
// account returned 200 and a token that every later call refused. Each
// exchange created a session row, bumped last_login_at and fired user hooks.
// It is now refused like a wrong password, before any of that.
func TestTokenExchangeRefusesDeactivatedAccountWithoutSideEffects(t *testing.T) {
	app, _ := accountStateApp(t, map[string]string{})
	accountStateUser(t, app, "active@corp.example", 1, false)
	offID := accountStateUser(t, app, "off@corp.example", 1, true)

	reference := accountStateToken(app, "active@corp.example", "Wrong!"+fixturePassword)
	if reference.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password on an active account: %d %s", reference.Code, reference.Body.String())
	}
	for _, password := range []string{fixturePassword, "Wrong!" + fixturePassword} {
		before := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE email = 'off@corp.example' AND success = 0")
		w := accountStateToken(app, "off@corp.example", password)
		if w.Code != reference.Code || w.Body.String() != reference.Body.String() {
			t.Errorf("right=%v: deactivated token exchange = %d %q, a wrong password answers %d %q",
				password == fixturePassword, w.Code, w.Body.String(), reference.Code, reference.Body.String())
		}
		if strings.Contains(w.Body.String(), `"token"`) {
			t.Errorf("right=%v: deactivated account was issued a token: %s", password == fixturePassword, w.Body.String())
		}
		if after := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE email = 'off@corp.example' AND success = 0"); after != before+1 {
			t.Errorf("right=%v: failed attempt not recorded (%d -> %d)", password == fixturePassword, before, after)
		}
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", offID); n != 0 {
		t.Errorf("token exchange left %d session rows for a deactivated account", n)
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND last_login_at IS NOT NULL", offID); n != 0 {
		t.Error("token exchange bumped last_login_at of a deactivated account")
	}
}

// F9: with auth.require_verified, signup, /login and the token exchange
// succeeded for an unverified account and every later call answered 401
// "Sign in again or use a current token", so the scaffold said "You're not
// signed in" with no hint that the email needed verifying. Each now answers
// 403 email_verification_required with no session or token, and only after
// the right password.
func TestRequireVerifiedSignInSaysVerificationIsRequired(t *testing.T) {
	app, _ := accountStateApp(t, map[string]string{"require_verified": "true"})
	pendingID := accountStateUser(t, app, "pending@corp.example", 0, false)
	accountStateUser(t, app, "ok@corp.example", 1, false)

	decode := func(w *httptest.ResponseRecorder) map[string]any {
		var body map[string]any
		json.Unmarshal(w.Body.Bytes(), &body)
		return body
	}

	// JSON client (bm.auth.signIn): 403 with the code and a message to show.
	w := accountStateLogin(app, "pending@corp.example", fixturePassword, true)
	body := decode(w)
	if w.Code != http.StatusForbidden || body["error"] != "email_verification_required" || !strings.Contains(strings.ToLower(accountStateString(body["message"])), "verif") {
		t.Fatalf("JSON login for an unverified account = %d %s", w.Code, w.Body.String())
	}
	if accountStateSessionCookie(w) != "" {
		t.Fatal("JSON login set a session cookie for an unverified account")
	}
	// Browser form: back to the login page with the message.
	w = accountStateLogin(app, "pending@corp.example", fixturePassword, false)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, app.Paths.Login+"?error=") || !strings.Contains(strings.ToLower(loc), "verif") || accountStateSessionCookie(w) != "" {
		t.Fatalf("form login for an unverified account = %d %q cookie=%v", w.Code, loc, accountStateSessionCookie(w) != "")
	}
	// The verification state is shown only to the right password.
	w = accountStateLogin(app, "pending@corp.example", "Wrong!"+fixturePassword, true)
	if body := decode(w); w.Code != http.StatusUnauthorized || body["error"] != "Invalid credentials" {
		t.Fatalf("wrong password on an unverified account = %d %s", w.Code, w.Body.String())
	}

	// Token exchange: the same code, no token.
	w = accountStateToken(app, "pending@corp.example", fixturePassword)
	if body := decode(w); w.Code != http.StatusForbidden || body["error"] != "email_verification_required" || body["token"] != nil {
		t.Fatalf("token exchange for an unverified account = %d %s", w.Code, w.Body.String())
	}

	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", pendingID); n != 0 {
		t.Fatalf("unverified sign-ins left %d dead session rows", n)
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND last_login_at IS NOT NULL", pendingID); n != 0 {
		t.Fatal("a refused sign-in bumped last_login_at")
	}

	// Signup creates the account but no session it couldn't use.
	form := url.Values{"email": {"new@corp.example"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	sr := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	sr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sr.Header.Set("Accept", "application/json")
	sw := httptest.NewRecorder()
	handleSignup(sw, sr, app)
	if body := decode(sw); sw.Code != http.StatusForbidden || body["error"] != "email_verification_required" || body["account_created"] != true {
		t.Fatalf("signup with require_verified = %d %s", sw.Code, sw.Body.String())
	}
	if accountStateSessionCookie(sw) != "" {
		t.Fatal("signup set a session cookie for an unverified account")
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_users u JOIN _benmore_sessions s ON s.user_id = u.id WHERE u.email = 'new@corp.example'"); n != 0 {
		t.Fatalf("signup left %d dead session rows", n)
	}
	if n := accountStateCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE email = 'new@corp.example'"); n != 1 {
		t.Fatal("signup did not create the account")
	}

	// A verified account signs in as before.
	if w := accountStateLogin(app, "ok@corp.example", fixturePassword, false); accountStateSessionCookie(w) == "" {
		t.Fatalf("verified account could not sign in: %d %v", w.Code, w.Header())
	}
	if w := accountStateToken(app, "ok@corp.example", fixturePassword); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("verified token exchange = %d %s", w.Code, w.Body.String())
	}
}

// With auth.verify_email also on, the refused sign-in mails a fresh link (the
// one from signup expires after an hour), at most once per five minutes.
func TestRequireVerifiedSignInResendsTheLink(t *testing.T) {
	app, _ := accountStateApp(t, map[string]string{"require_verified": "true", "verify_email": "true"})
	accountStateUser(t, app, "pending@corp.example", 0, false)
	var sent []string
	orig := sendVerificationEmail
	sendVerificationEmail = func(_ *App, to, _, body string) error { sent = append(sent, to); return nil }
	t.Cleanup(func() { sendVerificationEmail = orig })

	w := accountStateLogin(app, "pending@corp.example", fixturePassword, true)
	if w.Code != http.StatusForbidden || len(sent) != 1 || sent[0] != "pending@corp.example" {
		t.Fatalf("first refused sign-in: %d %s sent=%v", w.Code, w.Body.String(), sent)
	}
	if !strings.Contains(w.Body.String(), "sent") {
		t.Fatalf("message does not say a link was sent: %s", w.Body.String())
	}
	accountStateLogin(app, "pending@corp.example", fixturePassword, true)
	accountStateToken(app, "pending@corp.example", fixturePassword)
	if len(sent) != 1 {
		t.Fatalf("retries within minutes sent %d links", len(sent))
	}
	// A wrong password sends nothing.
	accountStateLogin(app, "pending@corp.example", "Wrong!"+fixturePassword, true)
	if len(sent) != 1 {
		t.Fatalf("a wrong password sent a link")
	}
}

// F9: a credential that exists but belongs to an unverified account (issued
// before the app turned require_verified on, or before this change) got the
// generic 401 "Sign in again or use a current token". The 401 now names the
// reason; an unknown token and an anonymous request answer as before.
func TestUnverifiedCredentialGets401NamingVerification(t *testing.T) {
	app, mux := accountStateApp(t, map[string]string{"require_verified": "true"})
	pendingID := accountStateUser(t, app, "pending@corp.example", 0, false)
	sid := CreateSession(app.DB, pendingID, "pending@corp.example", "", time.Hour)
	flow := &Flow{
		Name:    "whoami",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodGet, Path: "/api/whoami"},
		Auth:    "required",
		Steps:   []FlowStep{{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}}},
	}

	call := func(path, bearer, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.test"+path, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		w := httptest.NewRecorder()
		if path == "/api/whoami" {
			executeFlowHTTP(app, flow, w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
		return w
	}
	for _, path := range []string{"/api/_auth/profile", "/api/notes", "/api/whoami"} {
		for _, cred := range []struct{ bearer, cookie string }{{sid, ""}, {"", sid}} {
			w := call(path, cred.bearer, cred.cookie)
			var body map[string]any
			json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != http.StatusUnauthorized || body["error"] != "email_verification_required" || accountStateString(body["message"]) == "" {
				t.Errorf("%s with an unverified account's credential (bearer=%v) = %d %s", path, cred.bearer != "", w.Code, w.Body.String())
			}
		}
		if w := call(path, "not-a-session", ""); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "verification") {
			t.Errorf("%s with an unknown token = %d %s", path, w.Code, w.Body.String())
		}
		if w := call(path, "", ""); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "verification") {
			t.Errorf("%s anonymous = %d %s", path, w.Code, w.Body.String())
		}
	}

	// Once verified, the same session works.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET verified = 1 WHERE id = ?", pendingID)
	if w := call("/api/_auth/profile", sid, ""); w.Code != http.StatusOK {
		t.Fatalf("verified account's session = %d %s", w.Code, w.Body.String())
	}
}

func accountStateString(v any) string {
	s, _ := v.(string)
	return s
}
