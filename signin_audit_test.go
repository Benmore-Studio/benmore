//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newSignInTrailFixture(t *testing.T, hipaa bool) *accountAuditFixture {
	t.Helper()
	return newAccountAuditFixtureWith(t, hipaa, func(app *App) { app.Design.Auth["sign_in_audit"] = "true" })
}

// exchange signs in at POST /api/_auth/token.
func (f *accountAuditFixture) exchange(email, password, mfaCode string) (int, string) {
	f.t.Helper()
	code, out := f.call("POST", "/api/_auth/token", "", map[string]string{"email": email, "password": password, "mfa_code": mfaCode})
	token, _ := out["token"].(string)
	return code, token
}

// formLogin posts the sign-in form and returns the session cookie it set.
func (f *accountAuditFixture) formLogin(email, password string) string {
	f.t.Helper()
	form := url.Values{"email": {email}, "password": {password}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, f.app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, f.app)
	for _, c := range w.Result().Cookies() {
		if c.Name == devSessionCookieName || strings.HasSuffix(c.Name, "benmore_session") {
			return c.Value
		}
	}
	return ""
}

// The trail is opt-in: an app that does not set auth.sign_in_audit writes no
// row for a sign-in or a refusal, with or without compliance: hipaa.
func TestSignInTrailIsOffByDefault(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	if code, token := f.exchange(accountAuditEmail, accountAuditPassword, ""); code != http.StatusOK || token == "" {
		t.Fatalf("sign-in: %d", code)
	}
	if code, _ := f.exchange(accountAuditEmail, "Wrong-Horse-1", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if f.formLogin(accountAuditEmail, accountAuditPassword) == "" {
		t.Fatal("the form sign-in set no session cookie")
	}
	f.none("sign_in", "the switch is off")
	f.none("sign_in_refused", "the switch is off")

	h := newAccountAuditFixture(t, true)
	EnsureLoginAttemptsTable(h.app.DB)
	_, codes, _ := h.enroll(h.sid)
	if code, _ := h.exchange(accountAuditEmail, accountAuditPassword, codes[0]); code != http.StatusOK {
		t.Fatalf("hipaa sign-in: %d", code)
	}
	h.none("sign_in", "compliance: hipaa does not turn the trail on")
}

// With the switch on, each issued session and each refusal writes one row:
// the method, the account as other rows name it, and no password or token.
func TestSignInTrailRecordsSignInsAndRefusals(t *testing.T) {
	f := newSignInTrailFixture(t, false)
	code, token := f.exchange(accountAuditEmail, accountAuditPassword, "")
	if code != http.StatusOK || token == "" {
		t.Fatalf("sign-in: %d", code)
	}
	if r := f.one("sign_in", "_benmore_users", f.uidText()); r.new != `{"method":"token_exchange"}` || r.old != "" {
		t.Fatalf("sign_in values = %s / %s", r.old, r.new)
	}
	cookie := f.formLogin(accountAuditEmail, accountAuditPassword)
	if cookie == "" {
		t.Fatal("the form sign-in set no session cookie")
	}
	if rows := f.rows("sign_in"); len(rows) != 2 || rows[1].new != `{"method":"password"}` || rows[1].userID != f.uid || rows[1].email != accountAuditEmail {
		t.Fatalf("sign_in rows = %+v", rows)
	}

	if code, _ := f.exchange(accountAuditEmail, "Wrong-Horse-1", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if r := f.one("sign_in_refused", "_benmore_users", f.uidText()); r.new != `{"method":"token_exchange","reason":"invalid_credentials"}` {
		t.Fatalf("sign_in_refused values = %s", r.new)
	}
	// No account: the address tried is kept, anything else typed there is not.
	if code, _ := f.exchange("nobody@example.com", "Wrong-Horse-2", ""); code != http.StatusUnauthorized {
		t.Fatalf("unknown address: %d", code)
	}
	if f.formLogin("nobody@example.com", "Wrong-Horse-3") != "" {
		t.Fatal("an unknown address signed in")
	}
	refused := f.rows("sign_in_refused")
	if len(refused) != 3 || refused[1].userID != 0 || refused[1].rowID != "" || refused[1].email != "nobody@example.com" ||
		refused[2].new != `{"method":"password","reason":"invalid_credentials"}` || refused[2].email != "nobody@example.com" {
		t.Fatalf("sign_in_refused rows = %+v", refused)
	}
	auditSignInRefused(f.app, "password", "invalid_credentials", 0, "Typed-My-Pass-9")
	if refused = f.rows("sign_in_refused"); len(refused) != 4 || refused[3].email != "" {
		t.Fatalf("text that is no address was kept: %+v", refused)
	}
	f.noSecret(accountAuditPassword, "Wrong-Horse-1", "Wrong-Horse-2", "Wrong-Horse-3", "Typed-My-Pass-9", token, cookie, sessionStorageKey(token))

	// A locked account's attempts are refused before the password is read.
	// (Failures count from the last success, to the second: drop the ones
	// this test recorded a moment ago.)
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_login_attempts WHERE success = 1`); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		f.exchange(accountAuditEmail, "Wrong-Horse-1", "")
	}
	if code, _ := f.exchange(accountAuditEmail, accountAuditPassword, ""); code != http.StatusTooManyRequests {
		t.Fatalf("the locked account answered %d", code)
	}
	refused = f.rows("sign_in_refused")
	if last := refused[len(refused)-1]; last.new != `{"method":"token_exchange","reason":"locked"}` || last.userID != f.uid {
		t.Fatalf("the lockout refusal row = %+v", last)
	}
}

// A sign-in whose row cannot be written issues no session.
func TestSignInIsRefusedWhenItsAuditRowCannotBeWritten(t *testing.T) {
	f := newSignInTrailFixture(t, false)
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_sessions`); err != nil {
		t.Fatal(err)
	}
	f.refuseAuditRows()
	if code, token := f.exchange(accountAuditEmail, accountAuditPassword, ""); code == http.StatusOK || token != "" {
		t.Fatalf("a Bearer session was issued with no audit row: %d", code)
	}
	if f.formLogin(accountAuditEmail, accountAuditPassword) != "" {
		t.Fatal("a cookie session was issued with no audit row")
	}
	if got := createAuditedSignInSession(f.app, "oauth", f.uid, accountAuditEmail, ""); got != "" {
		t.Fatal("a social sign-in session was issued with no audit row")
	}
	var sessions int
	f.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_sessions`).Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("%d sessions exist although no sign-in could be recorded", sessions)
	}
}

// Under compliance: hipaa (append-only audit tables) the trail writes through
// the same transactions: the sign-in with a second factor is recorded once.
func TestSignInTrailUnderHIPAA(t *testing.T) {
	f := newSignInTrailFixture(t, true)
	EnsureLoginAttemptsTable(f.app.DB)
	_, codes, _ := f.enroll(f.sid)
	if code, _ := f.exchange(accountAuditEmail, accountAuditPassword, "000000"); code != http.StatusForbidden {
		t.Fatalf("a wrong code signed in: %d", code)
	}
	if code, token := f.exchange(accountAuditEmail, accountAuditPassword, codes[0]); code != http.StatusOK || token == "" {
		t.Fatalf("sign-in: %d", code)
	}
	if r := f.one("sign_in", "_benmore_users", f.uidText()); r.new != `{"method":"token_exchange"}` {
		t.Fatalf("sign_in values = %s", r.new)
	}
	if r := f.one("sign_in_refused", "_benmore_users", f.uidText()); r.new != `{"method":"token_exchange","reason":"invalid_code"}` {
		t.Fatalf("sign_in_refused values = %s", r.new)
	}
	f.noSecret(codes[0], accountAuditPassword)
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_audit_log WHERE action = 'sign_in'`); err == nil {
		t.Error("a sign_in row was deleted under hipaa")
	}
}

// The switch is an auth: flag: every spelling of true turns it on, a value
// that is no boolean and a misspelt key are refused when app.yaml is written.
func TestSignInAuditSwitchInAppYAML(t *testing.T) {
	for _, on := range []string{"true", "yes", "on", "1"} {
		raw, _, err := parseAppConfigDocument([]byte("site_name: x\nauth:\n  sign_in_audit: " + on + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		app := &App{Design: designFromAppYAML(raw)}
		if !signInAudited(app) {
			t.Errorf("sign_in_audit: %s did not turn the trail on", on)
		}
		if msg := validateAppYAML("site_name: x\nauth:\n  sign_in_audit: " + on + "\n"); msg != "" {
			t.Errorf("sign_in_audit: %s was refused: %s", on, msg)
		}
	}
	for _, off := range []string{"false", "no", "off", "0"} {
		raw, _, _ := parseAppConfigDocument([]byte("site_name: x\nauth:\n  sign_in_audit: " + off + "\n"))
		if signInAudited(&App{Design: designFromAppYAML(raw)}) {
			t.Errorf("sign_in_audit: %s turned the trail on", off)
		}
	}
	if signInAudited(&App{Design: designFromAppYAML(map[string]any{"site_name": "x"})}) {
		t.Error("the trail is on for an app that does not set the switch")
	}
	if msg := validateAppYAML("site_name: x\nauth:\n  sign_in_audit: sometimes\n"); !strings.Contains(msg, "sign_in_audit") {
		t.Errorf("a value that is no boolean was accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\nauth:\n  sign_ins_audit: true\n"); !strings.Contains(msg, "sign_ins_audit") {
		t.Errorf("a misspelt key was accepted: %q", msg)
	}
	if msg := validateAppYAML("site_name: x\naudit:\n  sign_ins: true\n"); msg == "" {
		t.Error("an audit: block, which nothing reads, was accepted")
	}
}
