//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// supportFixture is an app with one admin and one member, and the auth and
// settings routes a support (impersonation) session goes through.
type supportFixture struct {
	t                 *testing.T
	app               *App
	mux               *http.ServeMux
	adminID, memberID int64
}

const (
	supportAdminEmail  = "admin@example.com"
	supportMemberEmail = "member@example.com"
)

func newSupportFixture(t *testing.T) *supportFixture {
	t.Helper()
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(email, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	return &supportFixture{t: t, app: app, mux: mux, adminID: seed(supportAdminEmail, "admin"), memberID: seed(supportMemberEmail, "user")}
}

// adminSignIn is one more sign-in of the admin; memberSignIn one of the member.
func (f *supportFixture) adminSignIn() string {
	f.t.Helper()
	token := CreateSession(f.app.DB, f.adminID, supportAdminEmail, "", time.Hour)
	if token == "" {
		f.t.Fatal("no admin session")
	}
	return token
}

func (f *supportFixture) memberSignIn() string {
	f.t.Helper()
	token := CreateSession(f.app.DB, f.memberID, supportMemberEmail, "", time.Hour)
	if token == "" {
		f.t.Fatal("no member session")
	}
	return token
}

// send makes one request with credential as the session cookie (with its
// CSRF token) or as a Bearer header.
func (f *supportFixture) send(method, path, credential string, bearer bool, contentType, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("Accept", "application/json")
	if bearer {
		r.Header.Set("Authorization", "Bearer "+credential)
	} else {
		r.AddCookie(&http.Cookie{Name: sessionCookieNameFor(!f.app.DevMode), Value: credential})
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(credential))
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

// startSupport starts a support session as the member from the admin
// credential and returns the support session's token.
func (f *supportFixture) startSupport(adminCredential string, bearer bool) string {
	f.t.Helper()
	w := f.send(http.MethodPost, "/api/_auth/impersonate", adminCredential, bearer, "application/json",
		`{"user_id":`+strconv.FormatInt(f.memberID, 10)+`,"password":"`+fixturePassword+`"}`)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	token, _ := out["token"].(string)
	if w.Code != http.StatusOK || token == "" {
		f.t.Fatalf("impersonation did not start: %d %s", w.Code, w.Body.String())
	}
	if got := f.signedInAs(token); got != supportMemberEmail {
		f.t.Fatalf("a new support session resolves as %q, want the member", got)
	}
	return token
}

// signedInAs is the account a request carrying the session token acts as
// ("" when the token no longer authenticates).
func (f *supportFixture) signedInAs(token string) string {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if s := getSession(f.app, r); s != nil {
		return s.Email
	}
	return ""
}

func (f *supportFixture) supportRows() int {
	f.t.Helper()
	var n int
	if err := f.app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE is_impersonation = 1 AND impersonator_user_id = ?", f.adminID).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// A support session is the admin acting as a customer, on the admin's
// authority. Its row sits under the customer's user id, so the admin's own
// password change (which ends the admin's sessions by user id) left it
// running: after changing a compromised password, every support session
// opened with the old one kept full access as that customer for the rest of
// its hour, and no session list showed it.
func TestAdminPasswordChangeEndsTheSupportSessionsTheAdminStarted(t *testing.T) {
	f := newSupportFixture(t)
	changing := f.adminSignIn()  // where the admin changes the password
	elsewhere := f.adminSignIn() // another sign-in (the one somebody else may hold)
	inBrowser := f.adminSignIn() // a browser whose cookie the support session replaces
	memberOwn := f.memberSignIn()
	apiToken := "bmr_" + generateToken(32)
	mustExecArgs(t, f.app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'automation', ?, '*')", f.adminID, hashToken(apiToken))

	fromChanging := f.startSupport(changing, true)
	fromElsewhere := f.startSupport(elsewhere, true)
	fromBrowser := f.startSupport(inBrowser, false)
	fromAPIToken := f.startSupport(apiToken, true)

	next := "Changed!" + generateToken(6)
	form := url.Values{"current_password": {fixturePassword}, "new_password": {next}, "confirm_password": {next}}
	w := f.send(http.MethodPost, "/settings/password", changing, false, "application/x-www-form-urlencoded", form.Encode())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("password change did not succeed: %d %s", w.Code, w.Body.String())
	}

	for from, token := range map[string]string{
		"another sign-in of the admin": fromElsewhere,
		"the admin's browser":          fromBrowser,
		"an API token of the admin":    fromAPIToken,
	} {
		if got := f.signedInAs(token); got != "" {
			t.Errorf("the support session started from %s still acts as %q after the admin's password change", from, got)
		}
	}
	// What the change already ended: the admin's other sign-ins and tokens.
	if f.signedInAs(elsewhere) != "" || f.signedInAs(inBrowser) != "" || GetSessionFromAPIToken(f.app.DB, apiToken) != nil {
		t.Error("another sign-in or API token of the admin survived the password change")
	}
	// The session that proved the old password stays, and with it the
	// support session it started; the customer's own sign-in is untouched.
	if got := f.signedInAs(changing); got != supportAdminEmail {
		t.Errorf("the session that changed the password acts as %q, want the admin", got)
	}
	if got := f.signedInAs(fromChanging); got != supportMemberEmail {
		t.Errorf("the support session started by the kept session acts as %q, want the member", got)
	}
	if got := f.signedInAs(memberOwn); got != supportMemberEmail {
		t.Errorf("the member's own sign-in acts as %q after the admin's password change", got)
	}
	if n := f.supportRows(); n != 1 {
		t.Errorf("%d support session rows of the admin remain, want only the kept session's", n)
	}
}

// Reset link, forced change, unverified-account claim, email change and the
// operator reset all revoke through revokePasswordCredentials with no session
// kept: every support session the account started ends with them.
func TestCredentialRevocationEndsEverySupportSessionTheAdminStarted(t *testing.T) {
	f := newSupportFixture(t)
	memberOwn := f.memberSignIn()
	apiToken := "bmr_" + generateToken(32)
	mustExecArgs(t, f.app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'automation', ?, '*')", f.adminID, hashToken(apiToken))
	support := []string{f.startSupport(f.adminSignIn(), true), f.startSupport(f.adminSignIn(), false), f.startSupport(apiToken, true)}

	tx, err := f.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := revokePasswordCredentials(tx, f.adminID); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for i, token := range support {
		if got := f.signedInAs(token); got != "" {
			t.Errorf("support session %d still acts as %q after the admin's credentials were revoked", i, got)
		}
	}
	if n := f.supportRows(); n != 0 {
		t.Errorf("%d support session rows of the admin remain", n)
	}
	if got := f.signedInAs(memberOwn); got != supportMemberEmail {
		t.Errorf("the member's own sign-in acts as %q, want it untouched", got)
	}
}

// A session table no current runtime has prepared for auth (it lacks the
// support columns) holds no support session; revoking an account's
// credentials there must still work, not fail on the missing columns.
func TestCredentialRevocationWorksOnASessionTableWithoutSupportColumns(t *testing.T) {
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE _benmore_sessions (id TEXT PRIMARY KEY, user_id INTEGER, expires_at TEXT)`)
	mustExec(t, db, `INSERT INTO _benmore_sessions VALUES ('a', 1, '2999-01-01'), ('kept', 1, '2999-01-01'), ('b', 2, '2999-01-01')`)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := revokeUserAccessExcept(tx, 1, "kept"); err != nil {
		tx.Rollback()
		t.Fatalf("revocation failed on a session table without the support columns: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var left string
	if err := db.QueryRow(`SELECT group_concat(id) FROM (SELECT id FROM _benmore_sessions ORDER BY id)`).Scan(&left); err != nil || left != "b,kept" {
		t.Fatalf("sessions left = %q (%v), want the kept session and the other account's", left, err)
	}
}

// Ending the sign-in a support session was started from ends the support
// session: the admin who revokes a session they do not recognize, or logs
// out, must not leave an hour of access as a customer behind. The starting
// sign-in counts whether its token was the cookie or a Bearer header.
func TestSupportSessionEndsWithTheSignInThatStartedIt(t *testing.T) {
	ends := map[string]func(f *supportFixture, starter, other string){
		"revoked from the session list": func(f *supportFixture, starter, other string) {
			w := f.send(http.MethodDelete, "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(starter)), other, false, "", "")
			if w.Code != http.StatusOK {
				f.t.Fatalf("revoke = %d %s", w.Code, w.Body.String())
			}
		},
		"logged out": func(f *supportFixture, starter, _ string) {
			if w := f.send(http.MethodPost, f.app.Paths.Logout, starter, true, "", ""); w.Code >= 400 {
				f.t.Fatalf("logout = %d %s", w.Code, w.Body.String())
			}
		},
		"ended by an operator": func(f *supportFixture, starter, _ string) {
			if n, err := revokeSessionByOperatorID(f.app.DB, sessionStorageKey(starter)); err != nil || n != 1 {
				f.t.Fatalf("operator revoke = %d, %v", n, err)
			}
		},
		"expired": func(f *supportFixture, starter, _ string) {
			mustExecArgs(f.t, f.app.DB, "UPDATE _benmore_sessions SET expires_at = datetime('now', '-1 minute') WHERE id = ?", sessionStorageKey(starter))
		},
	}
	for name, end := range ends {
		for _, bearer := range []bool{false, true} {
			how := "from the cookie"
			if bearer {
				how = "from a Bearer header"
			}
			t.Run(name+", started "+how, func(t *testing.T) {
				f := newSupportFixture(t)
				starter, other := f.adminSignIn(), f.adminSignIn()
				memberOwn := f.memberSignIn()
				support := f.startSupport(starter, bearer)
				control := f.startSupport(other, true)

				end(f, starter, other)

				if got := f.signedInAs(support); got != "" {
					t.Errorf("the support session still acts as %q after its starting sign-in was %s", got, name)
				}
				if got := f.signedInAs(control); got != supportMemberEmail {
					t.Errorf("a support session started from another sign-in acts as %q, want the member", got)
				}
				if got := f.signedInAs(memberOwn); got != supportMemberEmail {
					t.Errorf("the member's own sign-in acts as %q, want it untouched", got)
				}
				if got := f.signedInAs(other); got != supportAdminEmail {
					t.Errorf("the admin's other sign-in acts as %q, want the admin", got)
				}
			})
		}
	}
}

// Ending one support session hands the admin's session back under a new
// token (rekeySession). A second support session started from the same
// sign-in must follow the session to its new key, not be cut off by it.
func TestSupportSessionFollowsItsStartingSignInAcrossARestore(t *testing.T) {
	f := newSupportFixture(t)
	admin := f.adminSignIn()
	overBearer := f.startSupport(admin, true)
	inBrowser := f.startSupport(admin, false)

	w := f.send(http.MethodPost, "/api/_auth/end-impersonation", inBrowser, false, "", "")
	restored := sessionCookieSet(w)
	if w.Code != http.StatusOK || restored == nil || f.signedInAs(restored.Value) != supportAdminEmail {
		t.Fatalf("end impersonation = %d %s, restored cookie %+v does not act as the admin", w.Code, w.Body.String(), restored)
	}
	if got := f.signedInAs(overBearer); got != supportMemberEmail {
		t.Fatalf("the other support session of the same sign-in acts as %q after the restore, want the member", got)
	}
	// It now ends with the session under its new token.
	if w := f.send(http.MethodPost, f.app.Paths.Logout, restored.Value, true, "", ""); w.Code >= 400 {
		t.Fatalf("logout = %d %s", w.Code, w.Body.String())
	}
	if got := f.signedInAs(overBearer); got != "" {
		t.Fatalf("the support session still acts as %q after its (restored) starting sign-in logged out", got)
	}
}

// A support session started over a Bearer header is not one the browser
// flow can end: its token is handed to the API caller, who may pass it on.
// Whoever holds it must not be able to trade it for the admin's own session.
func TestBearerStartedSupportSessionCannotRestoreTheAdminSession(t *testing.T) {
	f := newSupportFixture(t)
	admin := f.adminSignIn()
	support := f.startSupport(admin, true)
	w := f.send(http.MethodPost, "/api/_auth/end-impersonation", support, false, "", "")
	if w.Code == http.StatusOK || sessionCookieSet(w) != nil {
		t.Fatalf("a Bearer-started support token was traded for a session: %d %s", w.Code, w.Body.String())
	}
	if got := f.signedInAs(admin); got != supportAdminEmail {
		t.Fatalf("the admin's own Bearer session acts as %q afterwards, want the admin", got)
	}
}

// With auth.idle_timeout, the admin's own session row is not touched while
// they work inside the support session. Ending it restored that row with its
// old activity time, so the answer was "restored" and the next request
// signed the admin out, although they had been active the whole time.
func TestEndingASupportSessionKeepsAnActiveAdminSignedInUnderIdleTimeout(t *testing.T) {
	f := newSupportFixture(t)
	f.app.Design = &DesignConfig{Auth: map[string]string{"idle_timeout": "2m"}}
	backdate := func(token string) {
		t.Helper()
		mustExecArgs(t, f.app.DB, "UPDATE _benmore_sessions SET created_at = datetime('now', '-10 minutes'), last_seen_at = 0 WHERE id = ?", sessionStorageKey(token))
	}
	lastSeen := func(storedID string) int64 {
		var v int64
		f.app.DB.QueryRow("SELECT last_seen_at FROM _benmore_sessions WHERE id = ?", storedID).Scan(&v)
		return v
	}

	admin := f.adminSignIn()
	support := f.startSupport(admin, false)
	backdate(admin) // ten minutes inside the support session, which stays active
	w := f.send(http.MethodPost, "/api/_auth/end-impersonation", support, false, "", "")
	restored := sessionCookieSet(w)
	if w.Code != http.StatusOK || restored == nil {
		t.Fatalf("end impersonation = %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: restored.Name, Value: restored.Value})
	if s := getSession(f.app, r); s == nil || s.Email != supportAdminEmail {
		t.Fatalf("the first request with the restored admin cookie resolved %+v, want the admin still signed in", s)
	}
	if seen := lastSeen(sessionStorageKey(restored.Value)); time.Now().Unix()-seen > 5 {
		t.Fatalf("the restored admin session's last activity is %d, want now", seen)
	}

	// An idle support cookie is a dead credential like any other idle
	// session: it must not be traded for a fresh admin session.
	admin = f.adminSignIn()
	support = f.startSupport(admin, false)
	backdate(admin)
	backdate(support)
	w = f.send(http.MethodPost, "/api/_auth/end-impersonation", support, false, "", "")
	if w.Code == http.StatusOK || sessionCookieSet(w) != nil {
		t.Fatalf("an idle support cookie restored an admin session: %d %s", w.Code, w.Body.String())
	}
	if seen := lastSeen(sessionStorageKey(admin)); seen != 0 {
		t.Fatalf("an idle support cookie refreshed the admin session's activity time (%d)", seen)
	}
	if got := f.signedInAs(admin); got != "" {
		t.Fatalf("the idle admin session acts as %q, want it ended by the idle timeout", got)
	}
}

// Sign-in names the session cookie by the app's mode (sessionCookie), and
// the server reads the prefixed name first. Impersonation named its cookie
// by the request scheme instead, so on plain HTTP in production mode
// (`benmore serve` on http://localhost, or behind a TLS proxy whose scheme
// is not forwarded) it set the unprefixed name next to the admin's prefixed
// one: the answer was 200 and the browser kept acting as the admin.
func TestSupportSessionCookieUsesTheSignInCookieName(t *testing.T) {
	for _, devMode := range []bool{false, true} {
		mode := "production mode"
		if devMode {
			mode = "dev mode"
		}
		t.Run(mode+" over plain HTTP", func(t *testing.T) {
			f := newSupportFixture(t)
			f.app.DevMode = devMode
			signIn := sessionCookie(f.adminSignIn(), devMode, time.Hour)
			other := sessionCookieNameFor(devMode)
			if signIn.Name == other {
				t.Fatalf("fixture: sign-in cookie and the other name are both %q", other)
			}
			// The browser: the cookie sign-in set. In production mode it
			// also holds a stale cookie under the other name (what an older
			// runtime's impersonation left behind).
			jar := map[string]string{signIn.Name: signIn.Value}
			if !devMode {
				jar[other] = "left-by-an-older-runtime"
			}
			browse := func(method, path, body string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json")
				for name, value := range jar {
					r.AddCookie(&http.Cookie{Name: name, Value: value})
				}
				r.Header.Set("X-CSRF-Token", authMintCSRFToken(authRawSessionID(r)))
				w := httptest.NewRecorder()
				f.mux.ServeHTTP(w, r)
				expired := map[string]bool{}
				for _, c := range w.Result().Cookies() {
					if c.MaxAge < 0 || c.Value == "" {
						delete(jar, c.Name)
						expired[c.Name] = true
					} else {
						jar[c.Name] = c.Value
					}
				}
				if w.Code == http.StatusOK && method == http.MethodPost && !expired[other] {
					t.Errorf("%s %s did not expire the %s cookie", method, path, other)
				}
				return w
			}
			browserIs := func() string {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				for name, value := range jar {
					r.AddCookie(&http.Cookie{Name: name, Value: value})
				}
				if s := getSession(f.app, r); s != nil {
					return s.Email
				}
				return ""
			}
			if got := browserIs(); got != supportAdminEmail {
				t.Fatalf("fixture: the browser starts as %q, want the admin", got)
			}

			w := browse(http.MethodPost, "/api/_auth/impersonate", `{"user_id":`+strconv.FormatInt(f.memberID, 10)+`,"password":"`+fixturePassword+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("impersonate = %d %s", w.Code, w.Body.String())
			}
			if got := browserIs(); got != supportMemberEmail {
				t.Fatalf("after a 200 from impersonate the browser acts as %q, want the member (cookies: %v)", got, cookieNames(jar))
			}
			if len(jar) != 1 || jar[signIn.Name] == "" {
				t.Fatalf("the browser holds %v after impersonate, want only %s", cookieNames(jar), signIn.Name)
			}

			w = browse(http.MethodPost, "/api/_auth/end-impersonation", "")
			if w.Code != http.StatusOK {
				t.Fatalf("end impersonation = %d %s", w.Code, w.Body.String())
			}
			if got := browserIs(); got != supportAdminEmail {
				t.Fatalf("after ending the support session the browser acts as %q, want the admin (cookies: %v)", got, cookieNames(jar))
			}
			if len(jar) != 1 || jar[signIn.Name] == "" {
				t.Fatalf("the browser holds %v after end-impersonation, want only %s", cookieNames(jar), signIn.Name)
			}
		})
	}
}

// sessionCookieSet is the session cookie a response handed out, under either
// name (nil if it set none; an expired cookie is not one).
func sessionCookieSet(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if (c.Name == sessionCookieName || c.Name == devSessionCookieName) && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func cookieNames(jar map[string]string) []string {
	names := make([]string, 0, len(jar))
	for name := range jar {
		names = append(names, name)
	}
	return names
}

// A customer deactivated (or sent to a password change) while a support
// session runs stops that session resolving. Ending it still restores the
// admin's own session instead of answering 400 and leaving a dead cookie.
func TestEndingASupportSessionWhoseCustomerWasDeactivated(t *testing.T) {
	f := newSupportFixture(t)
	admin := f.adminSignIn()
	support := f.startSupport(admin, false)
	mustExecArgs(t, f.app.DB, "UPDATE _benmore_users SET deactivated_at = datetime('now') WHERE id = ?", f.memberID)
	w := f.send(http.MethodPost, "/api/_auth/end-impersonation", support, false, "", "")
	restored := sessionCookieSet(w)
	if w.Code != http.StatusOK || restored == nil {
		t.Fatalf("end impersonation after the customer was deactivated = %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: restored.Name, Value: restored.Value})
	if s := getSession(f.app, r); s == nil || s.Email != supportAdminEmail {
		t.Fatalf("restored cookie resolved %+v, want the admin", s)
	}
	if n := f.supportRows(); n != 0 {
		t.Fatalf("%d support rows left after ending it", n)
	}
}
