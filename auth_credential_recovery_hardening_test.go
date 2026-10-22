//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func recoveryHardeningApp(t *testing.T) *App {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsureMFAColumns(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	app.SessionDuration = time.Hour
	app.Stop = make(chan struct{})
	return app
}

func recoveryUser(t *testing.T, app *App, email, password string, verified int) int64 {
	t.Helper()
	var hash any
	if password != "" {
		h, err := generateBcryptHash([]byte(password))
		if err != nil {
			t.Fatal(err)
		}
		hash = string(h)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES (?, ?, ?, ?)",
		GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0), email, hash, verified)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func recoveryPasskey(t *testing.T, app *App, uid int64) {
	t.Helper()
	if _, err := app.DB.Exec("INSERT INTO _benmore_passkeys (user_id, credential_id, public_key, alg) VALUES (?, ?, x'00', -7)", uid, generateToken(16)); err != nil {
		t.Fatal(err)
	}
}

func recoveryCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// Pre-claim takeover: someone registers the victim's address, adds a passkey,
// and waits. The victim's password reset (or Google sign-in, which claims an
// unverified account) wiped the password, MFA, sessions and tokens but kept
// the squatter's passkey, which kept signing in.
func TestCredentialRecoveryRemovesPasskeys(t *testing.T) {
	app := recoveryHardeningApp(t)

	// Password reset, verified account.
	uid := recoveryUser(t, app, "victim@corp.example", "Old!Password1", 1)
	recoveryPasskey(t, app, uid)
	mustExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES ('"+hashResetToken("reset-tok")+"', 'victim@corp.example', '"+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+"', 'reset')")
	form := url.Values{"token": {"reset-tok"}, "password": {"New!Password22"}, "confirm": {"New!Password22"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, app)
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("reset did not complete: %d %q", w.Code, w.Header().Get("Location"))
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", uid); n != 0 {
		t.Fatalf("password reset kept %d passkey(s)", n)
	}

	// OAuth claim of an unverified account.
	squatted := recoveryUser(t, app, "owner@corp.example", "Squatter!Pass1", 0)
	recoveryPasskey(t, app, squatted)
	if err := claimUnverifiedAccount(app, squatted, "owner@corp.example"); err != nil {
		t.Fatal(err)
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", squatted); n != 0 {
		t.Fatalf("claim kept %d passkey(s)", n)
	}

	// A signed-in change keeps passkeys (as it keeps the TOTP factor) unless
	// the person asks to remove them.
	owner := recoveryUser(t, app, "self@corp.example", "Mine!Password1", 1)
	recoveryPasskey(t, app, owner)
	sid := CreateSession(app.DB, owner, "self@corp.example", "", time.Hour)
	sess := GetSessionFromDB(app.DB, sid)
	proof, _ := currentPasswordProof(app, owner, "Mine!Password1")
	if _, err := changeSignedInPasswordWith(app, sess, proof, "$2a$12$replacementhashreplacementhashreplacementhashrepl", false); err != nil {
		t.Fatal(err)
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", owner); n != 1 {
		t.Fatalf("ordinary password change removed passkeys: %d left", n)
	}
	if _, err := changeSignedInPasswordWith(app, sess, "$2a$12$replacementhashreplacementhashreplacementhashrepl", "$2a$12$replacementhashreplacementhashreplacementhashrep2", true); err != nil {
		t.Fatal(err)
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", owner); n != 0 {
		t.Fatalf("revoke_passkeys change kept %d passkey(s)", n)
	}
}

// An operator reset (set-password, or a flow that can't reach passkeys) leaves
// the account pending a password change, and passkey sign-in is refused while
// it is pending. Finishing the change re-enabled every passkey the account had
// before the reset, so a key someone planted came back with the owner's new
// password.
func TestRequiredPasswordChangeRemovesPasskeys(t *testing.T) {
	app, mux, uid, sid, _ := passwordChangeFixture(t)
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	recoveryPasskey(t, app, uid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
	if w.Code != http.StatusOK {
		t.Fatalf("change failed: %d %s", w.Code, w.Body.String())
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", uid); n != 0 {
		t.Fatalf("replacing a temporary password kept %d passkey(s)", n)
	}
}

// A stolen or script-driven session could add the attacker's own passkey and
// keep the account after the session ended. Adding one now needs the
// password; no challenge is issued without it.
func TestPasskeyRegistrationNeedsAccountProof(t *testing.T) {
	app := recoveryHardeningApp(t)
	cookies, sid, uid := loginTestUser(app, "ada@example.com", "user")
	client := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	for _, ck := range cookies {
		client.cookies[ck.Name] = ck
	}
	csrf := authMintCSRFToken(sid)
	challenges := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkey_challenges WHERE user_id = ?", uid)
	}
	if code, _ := client.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{}, csrf); code != http.StatusBadRequest {
		t.Fatalf("no proof: %d", code)
	}
	if code, _ := client.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"password": "wrong-password"}, csrf); code != http.StatusForbidden {
		t.Fatalf("wrong password: %d", code)
	}
	// An authenticator code counts only when MFA is enrolled.
	if code, _ := client.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"mfa_code": "123456"}, csrf); code != http.StatusBadRequest {
		t.Fatalf("code without an enrolled factor: %d", code)
	}
	if challenges() != 0 {
		t.Fatal("a registration challenge was issued without proof")
	}
	if code, out := client.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"password": "testpass123"}, csrf); code != http.StatusOK || out["challenge"] == nil {
		t.Fatalf("correct password: %d %v", code, out)
	}
	if challenges() != 1 {
		t.Fatal("no challenge after the password proof")
	}

	// Remove-all control.
	recoveryPasskey(t, app, uid)
	recoveryPasskey(t, app, uid)
	if code, out := client.do(passkeyDeleteAll(app), "DELETE", "/api/_auth/passkeys", nil, csrf); code != http.StatusOK || out["removed"] != float64(2) {
		t.Fatalf("delete all: %d %v", code, out)
	}
}

func verifyLinkRequest(app *App, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, app.Paths.VerifyEmail+"?token="+url.QueryEscape(token), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handleVerifyEmail(w, r, app)
	return w
}

func verifyConfirmRequest(app *App, token, password string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "password": {password}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyEmail, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleVerifyEmailConfirm(w, r, app)
	return w
}

func insertVerifyToken(t *testing.T, app *App, email, token string) {
	t.Helper()
	mustExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES ('"+hashResetToken(token)+"', '"+email+"', '"+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+"', 'verify')")
}

// An attacker registers victim@corp with a password they chose; the victim
// clicks the "verify your email" mail. That click must not verify the
// attacker's account (and so hand it the invites and tenants addressed to
// victim@corp) unless the clicker is the account's own session or knows its
// password.
func TestVerificationLinkDoesNotVerifyAStrangersCredentials(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "victim@corp.example", "Attacker!Pass1", 0)
	attackerSession := CreateSession(app.DB, uid, "victim@corp.example", "", time.Hour)
	insertVerifyToken(t, app, "victim@corp.example", "verify-tok")
	verified := func() int {
		return recoveryCount(t, app.DB, "SELECT COALESCE(verified,0) FROM _benmore_users WHERE id = ?", uid)
	}

	// The victim's browser is not signed in as the account: a password
	// prompt, nothing verified, the token still unspent.
	w := verifyLinkRequest(app, "verify-tok", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Confirm your email") {
		t.Fatalf("expected the password prompt: %d", w.Code)
	}
	if verified() != 0 {
		t.Fatal("a click from outside the account verified it")
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_password_resets WHERE used = 0 AND type = 'verify'"); n != 1 {
		t.Fatal("the prompt spent the token")
	}
	// The victim doesn't know the attacker's password.
	if w := verifyConfirmRequest(app, "verify-tok", "Guess!Pass1"); w.Code != http.StatusForbidden || verified() != 0 {
		t.Fatalf("wrong password: %d verified=%d", w.Code, verified())
	}
	// A browser signed in as someone else is not the account's session.
	_, otherSID, _ := loginTestUser(app, "other@example.com", "user")
	if w := verifyLinkRequest(app, "verify-tok", &http.Cookie{Name: devSessionCookieName, Value: otherSID}); w.Code != http.StatusOK || verified() != 0 {
		t.Fatalf("another account's session verified it: %d", w.Code)
	}

	// The real registrant on a second device proves the password: verified,
	// and every earlier session ends.
	if w := verifyConfirmRequest(app, "verify-tok", "Attacker!Pass1"); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("password proof: %d %q", w.Code, w.Header().Get("Location"))
	}
	if verified() != 1 {
		t.Fatal("password proof did not verify")
	}
	if GetSessionFromDB(app.DB, attackerSession) != nil {
		t.Fatal("sessions created before the proof survived")
	}
	if w := verifyConfirmRequest(app, "verify-tok", "Attacker!Pass1"); w.Code != http.StatusSeeOther || strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatal("a spent token verified again")
	}
}

// The normal flow - sign up, click the link in the same browser - still
// verifies at once and keeps that session.
func TestVerificationLinkInTheRegistrantsBrowser(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "new@corp.example", "Owner!Pass11", 0)
	mine := CreateSession(app.DB, uid, "new@corp.example", "", time.Hour)
	stray := CreateSession(app.DB, uid, "new@corp.example", "", time.Hour)
	insertVerifyToken(t, app, "new@corp.example", "own-tok")
	w := verifyLinkRequest(app, "own-tok", &http.Cookie{Name: devSessionCookieName, Value: mine})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("same-browser verification: %d", w.Code)
	}
	if recoveryCount(t, app.DB, "SELECT verified FROM _benmore_users WHERE id = ?", uid) != 1 {
		t.Fatal("same-browser click did not verify")
	}
	if GetSessionFromDB(app.DB, mine) == nil || GetSessionFromDB(app.DB, stray) != nil {
		t.Fatal("expected the clicking session kept and the other revoked")
	}
}

// With no password anyone chose, the link claims the account: passkeys,
// MFA, sessions and tokens set up before the proof are cleared.
func TestVerificationLinkClaimsAPasswordlessAccount(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "nopass@corp.example", "", 0)
	recoveryPasskey(t, app, uid)
	mustExec(t, app.DB, "UPDATE _benmore_users SET totp_secret = 'SECRET' WHERE email = 'nopass@corp.example'")
	insertVerifyToken(t, app, "nopass@corp.example", "claim-tok")
	if w := verifyLinkRequest(app, "claim-tok", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("passwordless verification: %d", w.Code)
	}
	if recoveryCount(t, app.DB, "SELECT verified FROM _benmore_users WHERE id = ?", uid) != 1 {
		t.Fatal("not verified")
	}
	if recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?", uid) != 0 ||
		recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND totp_secret IS NOT NULL", uid) != 0 {
		t.Fatal("the claim kept a passkey or MFA factor")
	}
}

// Each temp cookie verifies only for the step it was minted for. Unlabelled
// cookies from the previous binary are accepted only in the short window
// after startup.
func TestTempCookiePurposesAreSeparate(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	otp := signTempCookieFor(app, tempCookieOTP, "7|a@example.com|a@example.com")
	if verifyTempCookieFor(app, tempCookieOTP, otp) != "7|a@example.com|a@example.com" {
		t.Fatal("round trip failed")
	}
	for _, other := range []string{tempCookieMFA, tempCookieMFASetup, tempCookieMFACLI, tempCookiePasskey} {
		if verifyTempCookieFor(app, other, otp) != "" {
			t.Fatalf("an OTP step cookie verified as %s", other)
		}
	}
	payload := "7|a@example.com|a@example.com|9999999999" // value|exp, as the old binary signed it
	legacy := payload + "|" + tempCookieMAC(app, payload)
	old := tempCookieLegacyUntil
	defer func() { tempCookieLegacyUntil = old }()
	tempCookieLegacyUntil = time.Now().Add(time.Minute)
	if verifyTempCookieFor(app, tempCookieMFA, legacy) == "" {
		t.Fatal("an in-flight unlabelled cookie was refused during the transition")
	}
	tempCookieLegacyUntil = time.Now().Add(-time.Second)
	if verifyTempCookieFor(app, tempCookieMFA, legacy) != "" {
		t.Fatal("an unlabelled cookie verified after the transition")
	}
}

// /api/_auth/token is a password sign-in: it honours and feeds the same
// per-IP failure cap as /login.
func TestTokenAuthAppliesIPLockout(t *testing.T) {
	app := recoveryHardeningApp(t)
	recoveryUser(t, app, "api@example.com", "Api!Password1", 1)
	exchange := func(ip, password string) int {
		body, _ := json.Marshal(map[string]string{"email": "api@example.com", "password": password})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(string(body)))
		r.RemoteAddr = ip + ":4000"
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		return w.Code
	}
	if code := exchange("192.0.2.10", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE email = ?", authIPLockKey("192.0.2.10")) != 1 {
		t.Fatal("a failed token exchange was not counted against its IP")
	}
	for i := 0; i < authIPLoginLimit; i++ {
		recordLoginAttempt(app.DB, authIPLockKey("192.0.2.20"), false)
	}
	if code := exchange("192.0.2.20", "Api!Password1"); code != http.StatusTooManyRequests {
		t.Fatalf("a locked IP exchanged a password for a token: %d", code)
	}
	if code := exchange("192.0.2.30", "Api!Password1"); code != http.StatusOK {
		t.Fatalf("control from another IP: %d", code)
	}
}

// Public signup may fill only plain profile columns, whatever
// auth.signup_fields lists.
func TestSignupFieldsCannotSetAuthority(t *testing.T) {
	app := recoveryHardeningApp(t)
	ensureUserColumn(app.DB, "org_id", "test")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT)")
	app.Design.Auth["signup_fields"] = "first_name, role, verified, totp_secret, org_id, bad-name"
	form := url.Values{"email": {"eve@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")},
		"first_name": {"Eve"}, "role": {"admin"}, "verified": {"1"}, "totp_secret": {"PLANTED"}, "org_id": {"tenant-b"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleSignup(w, r, app)
	var role, first string
	var verified int
	var totp, org sql.NullString
	if err := app.DB.QueryRow("SELECT COALESCE(role,''), COALESCE(first_name,''), COALESCE(verified,0), totp_secret, org_id FROM _benmore_users WHERE email = 'eve@example.com'").Scan(&role, &first, &verified, &totp, &org); err != nil {
		t.Fatalf("signup did not create the account (%d %q): %v", w.Code, w.Header().Get("Location"), err)
	}
	if role == "admin" || verified != 0 || (totp.Valid && totp.String != "") || (org.Valid && org.String != "") {
		t.Fatalf("signup set authority: role=%q verified=%d totp=%v org=%v", role, verified, totp, org)
	}
	if first != "Eve" {
		t.Fatalf("plain profile field not stored: %q", first)
	}

	// The write gate refuses the declaration.
	msg := ValidateOnWrite("app.yaml", "auth:\n  signup_fields: first_name,role,verified\n")
	if !strings.Contains(msg, "signup-fields-protected") || !strings.Contains(msg, `"role"`) || !strings.Contains(msg, `"verified"`) {
		t.Fatalf("validator: %q", msg)
	}
	if msg := validateSignupFields("auth:\n  signup_fields: first_name, last_name, email, password\n"); msg != "" {
		t.Fatalf("plain fields refused: %q", msg)
	}
	if msg := validateSignupFields("groups:\n  table: members\n  key: org_id\n  user_field: email\nauth:\n  signup_fields: first_name, org_id\n"); !strings.Contains(msg, "org_id") {
		t.Fatalf("tenant key accepted: %q", msg)
	}
}

// Forgot-password requires CSRF like login and sends mail off the request
// path.
func TestForgotPasswordHardening(t *testing.T) {
	app := recoveryHardeningApp(t)
	recoveryUser(t, app, "reset@example.com", "Reset!Pass11", 1)
	var sends int
	old := dispatchAuthEmail
	dispatchAuthEmail = func(send func()) { sends++ }
	defer func() { dispatchAuthEmail = old }()
	forgot := func(email string, withCSRF bool) {
		form := url.Values{"email": {email}}
		if withCSRF {
			form.Set("_csrf", authMintCSRFToken(""))
		}
		r := httptest.NewRequest(http.MethodPost, app.Paths.ForgotPassword, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handleForgotPassword(httptest.NewRecorder(), r, app)
	}
	live := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_password_resets WHERE type='reset' AND used=0")
	}
	forgot("reset@example.com", false)
	if live() != 0 || sends != 0 {
		t.Fatal("a request without CSRF minted a reset link")
	}
	forgot("reset@example.com", true)
	forgot("reset@example.com", true)
	if total := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_password_resets WHERE type='reset'"); total != 2 || live() != 2 {
		t.Fatalf("want 2 live links; total=%d live=%d", total, live())
	}
	if sends != 2 {
		t.Fatalf("mail dispatched %d times", sends)
	}
	forgot("nobody@example.com", true)
	if sends != 2 {
		t.Fatal("mail dispatched for an unknown address")
	}
}

// Anyone can ask for a reset link for any address. Each request used to
// retire the address's earlier unused links, so a stranger could keep killing
// the link the owner was about to click. Pending links now stay valid until
// they expire or one is used; at most three are live per address, and
// further requests send nothing until one of them ends.
func TestForgotPasswordRequestCannotRetireAPendingLink(t *testing.T) {
	app := recoveryHardeningApp(t)
	recoveryUser(t, app, "owner@example.com", "Owner!Pass11", 1)
	var sends int
	oldDispatch, oldLimiter := dispatchAuthEmail, forgotPasswordLimiter
	dispatchAuthEmail = func(func()) { sends++ }
	forgotPasswordLimiter = NewRateLimiter(100, time.Minute) // the per-address cap is under test, not the limiter
	defer func() { dispatchAuthEmail, forgotPasswordLimiter = oldDispatch, oldLimiter }()
	forgot := func() {
		form := url.Values{"email": {"owner@example.com"}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, app.Paths.ForgotPassword, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handleForgotPassword(httptest.NewRecorder(), r, app)
	}
	live := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_password_resets WHERE type='reset' AND used=0 AND datetime(expires_at) > datetime('now')")
	}
	// The link already in the owner's inbox.
	mustExec(t, app.DB, "INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES ('"+hashResetToken("owners-link")+"', 'owner@example.com', '"+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+"', 'reset')")

	// A stranger asks for links to the same address.
	forgot()
	forgot()
	if live() != 3 || sends != 2 {
		t.Fatalf("a request retired a pending link: live=%d sends=%d", live(), sends)
	}
	forgot()
	if live() != 3 || sends != 2 {
		t.Fatalf("minted past three live links: live=%d sends=%d", live(), sends)
	}

	// The owner's link still works, and using it ends every other one.
	form := url.Values{"token": {"owners-link"}, "password": {"New!Password22"}, "confirm": {"New!Password22"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, app)
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("the owner's link no longer resets: %d %q", w.Code, w.Header().Get("Location"))
	}
	if live() != 0 {
		t.Fatalf("%d link(s) survived the reset", live())
	}

	// Expired links neither work nor count toward the cap.
	mustExec(t, app.DB, "UPDATE _benmore_password_resets SET used = 0, expires_at = '"+time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)+"'")
	forgot()
	if live() != 1 || sends != 3 {
		t.Fatalf("expired links blocked a new one: live=%d sends=%d", live(), sends)
	}
}

// Deleting the account from /settings removes every credential, not just
// the sessions: API tokens, passkeys and role grants included.
func TestSettingsDeleteAccountPurgesCredentials(t *testing.T) {
	app := recoveryHardeningApp(t)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	_, sid, uid := loginTestUser(app, "leaving@example.com", "user")
	recoveryPasskey(t, app, uid)
	mustExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES ("+itoa(int(uid))+", 't', 'h', '')")
	mustExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES ("+itoa(int(uid))+", 'editor')")
	form := url.Values{"confirm": {"DELETE"}, "_csrf": {authMintCSRFToken(sid)}}
	r := httptest.NewRequest(http.MethodPost, "/settings/delete-account", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete account: %d %s", w.Code, w.Body.String())
	}
	for table, q := range map[string]string{
		"sessions":    "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?",
		"api tokens":  "SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?",
		"passkeys":    "SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id = ?",
		"role grants": "SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ?",
		"live login":  "SELECT COUNT(*) FROM _benmore_users WHERE id = ? AND email IS NOT NULL",
	} {
		if n := recoveryCount(t, app.DB, q, uid); n != 0 {
			t.Errorf("%s survived account deletion: %d", table, n)
		}
	}
}
