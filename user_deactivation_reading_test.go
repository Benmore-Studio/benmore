//go:build !cli

package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A stored empty string in _benmore_users.deactivated_at (the admin panel's
// edit form wrote one on every save before it stored NULL) was read two
// ways: the session and API-token lookups refused it, while password
// sign-in, the one-time-code step, the last-admin guard and the user
// directory list took it for an active account. The account signed in and
// its new session was refused on the next request, and the guard counted an
// admin that could not hold a session. Every reader now uses one reading:
// only NULL is active.

// storedDeactivations is each way the column can be stored.
var storedDeactivations = []struct {
	name        string
	value       any
	deactivated bool
}{
	{"NULL", nil, false},
	{"an empty string", "", true},
	{"spaces", "  ", true},
	{"a timestamp", "2026-01-01 00:00:00", true},
}

// storedSessionKey is the _benmore_sessions id of a session token.
func storedSessionKey(t *testing.T, token string) string {
	t.Helper()
	key, ok := presentedSessionKey(token)
	if !ok {
		t.Fatal("not a session token")
	}
	return key
}

func storeDeactivation(t *testing.T, f *lastAdminFixture, id int, value any) {
	t.Helper()
	mustExecArgs(t, f.db, `UPDATE _benmore_users SET deactivated_at = ? WHERE id = ?`, value, id)
}

func TestStoredDeactivationIsReadOneWayBySignInSessionsAndTokens(t *testing.T) {
	f := newDeactivationFixture(t)
	const eve = "eve@example.com"
	mustExecArgs(t, f.db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'ci', ?, '*')`, userColsEve, hashToken("reading-fixture-token"))
	existing := f.session(userColsEve, eve)
	// What a wrong password answers on an active account.
	wrongForm := accountStateAnswer(accountStateLogin(f.app, eve, "Wrong!"+fixturePassword, true))
	wrongToken := accountStateToken(f.app, eve, "Wrong!"+fixturePassword)

	for _, stored := range storedDeactivations {
		t.Run(stored.name, func(t *testing.T) {
			storeDeactivation(t, f, userColsEve, stored.value)
			mustExecArgs(t, f.db, `DELETE FROM _benmore_sessions WHERE user_id = ? AND id <> ?`, userColsEve, storedSessionKey(t, existing))
			mustExec(t, f.db, `DELETE FROM _benmore_login_attempts`)
			active := !stored.deactivated

			if got := sessionAnswers(f, existing) == http.StatusOK; got != active {
				t.Errorf("an existing session answered=%v, want %v", got, active)
			}
			if got := GetSessionFromAPIToken(f.db, "reading-fixture-token") != nil; got != active {
				t.Errorf("an API token resolved=%v, want %v", got, active)
			}

			// The browser form.
			sid := signsIn(f, eve)
			if got := sid != ""; got != active {
				t.Errorf("POST /login gave a session=%v, want %v", got, active)
			}
			if sid != "" && sessionAnswers(f, sid) != http.StatusOK {
				t.Errorf("POST /login gave a session that the next request refused")
			}
			// The JSON form: a deactivated account answers as a wrong password.
			if w := accountStateLogin(f.app, eve, fixturePassword, true); stored.deactivated && accountStateAnswer(w) != wrongForm {
				t.Errorf("JSON sign-in answered %d %q, a wrong password answers %q", w.Code, accountStateAnswer(w), wrongForm)
			}
			// The token exchange.
			w := accountStateToken(f.app, eve, fixturePassword)
			if stored.deactivated && (w.Code != wrongToken.Code || w.Body.String() != wrongToken.Body.String()) {
				t.Errorf("token exchange answered %d %s, a wrong password answers %d %s", w.Code, w.Body.String(), wrongToken.Code, wrongToken.Body.String())
			}
			if active && w.Code != http.StatusOK {
				t.Errorf("token exchange of an active account answered %d %s", w.Code, w.Body.String())
			}
			// The account state every one-time-code and authenticator step
			// re-reads before it issues a session.
			_, _, _, err := mfaSetupAccountState(f.app, f.db, userColsEve, eve)
			if got := err == nil; got != active {
				t.Errorf("the code step's account check passed=%v (%v), want %v", got, err, active)
			}
			if stored.deactivated {
				if n := f.count(`SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ? AND id <> ?`, userColsEve, storedSessionKey(t, existing)); n != 0 {
					t.Errorf("refused sign-ins left %d session rows", n)
				}
			}
		})
	}
}

func TestStoredDeactivationRefusesProviderSignIn(t *testing.T) {
	f := newDeactivationFixture(t)
	const eve = "eve@example.com"
	for _, stored := range storedDeactivations {
		storeDeactivation(t, f, userColsEve, stored.value)
		id, err := oauthFindOrCreateUser(f.app, eve, "Eve", true)
		if stored.deactivated {
			if !errors.Is(err, errOAuthAccountDeactivated) || id != 0 {
				t.Errorf("%s: provider sign-in matched account %d (err %v), want the deactivated refusal", stored.name, id, err)
			}
		} else if err != nil || id != userColsEve {
			t.Errorf("%s: provider sign-in = %d, %v; want the account", stored.name, id, err)
		}
		// An address the provider did not prove learns nothing about the
		// account's state.
		if _, err := oauthFindOrCreateUser(f.app, eve, "Eve", false); !errors.Is(err, errOAuthUnverifiedLink) {
			t.Errorf("%s: unproven address answered %v, want the unverified-link refusal", stored.name, err)
		}
	}
}

// The managed (platform-brokered) callback, end to end: a deactivated account
// gets the sign-in page's ordinary refusal and no session.
func TestStoredDeactivationRefusesManagedProviderCallback(t *testing.T) {
	for _, stored := range storedDeactivations {
		t.Run(stored.name, func(t *testing.T) {
			t.Setenv("BENMORE_OAUTH_BROKER_URL", "https://broker.example.com")
			t.Setenv("BENMORE_OAUTH_BROKER_PROVIDERS", "google")
			t.Setenv("BENMORE_APP_NAME", "fixture")
			t.Setenv("BENMORE_OAUTH_REQUIRE_NONCE", "")
			f := newDeactivationFixture(t)
			RegisterOAuthRoutes(f.mux, f.app)
			// managedAssertionToken signs in attacker@example.com.
			mustExecArgs(t, f.db, `UPDATE _benmore_users SET email = 'attacker@example.com', deactivated_at = ? WHERE id = ?`, stored.value, userColsEve)
			rec := managedCallback(f.mux, managedAssertionToken(t, ""), "")
			if got := sessionIssued(rec); got == stored.deactivated {
				t.Fatalf("callback issued a session=%v (%d %s)", got, rec.Code, rec.Body.String())
			}
			if !stored.deactivated {
				return
			}
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != http.StatusSeeOther || loc == nil || loc.Path != f.app.Paths.Login || !strings.Contains(loc.RawQuery, "Invalid") {
				t.Fatalf("callback answered %d to %q, want the sign-in page with the ordinary refusal", rec.Code, rec.Header().Get("Location"))
			}
			if n := f.count(`SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?`, userColsEve); n != 0 {
				t.Fatalf("a refused callback left %d session rows", n)
			}
		})
	}
}

func TestStoredDeactivationRefusesPasskeySignIn(t *testing.T) {
	f := newDeactivationFixture(t)
	app := f.app
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	const eve = "eve@example.com"
	sid := f.session(userColsEve, eve)
	signedIn := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{
		"s": {Name: sessionCookie("x", app.DevMode, app.SessionDuration).Name, Value: sid},
	}}
	csrf := authMintCSRFToken(sid)
	auth := newTestAuthenticator(t, false)
	code, opts := signedIn.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"password": fixturePassword}, csrf)
	if code != http.StatusOK {
		t.Fatalf("register options: %d %v", code, opts)
	}
	challenge, _ := b64url(opts["challenge"].(string))
	cd, att := auth.create(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV|webauthnFlagAT)
	cred := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key", "name": "Laptop",
		"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "attestationObject": b64urlEncode(att)}}
	if code, out := signedIn.do(passkeyRegister(app), "POST", "/api/_auth/passkeys/register", cred, csrf); code != http.StatusOK {
		t.Fatalf("register: %d %v", code, out)
	}
	sessionName := sessionCookie("x", app.DevMode, app.SessionDuration).Name
	signIn := func() (int, bool) {
		anon := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
		anonCSRF := authMintCSRFToken("")
		code, o := anon.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, anonCSRF)
		if code != http.StatusOK {
			t.Fatalf("login options: %d %v", code, o)
		}
		ch, _ := b64url(o["challenge"].(string))
		cd, ad, sig := auth.get(testRP, testOrigin, ch, webauthnFlagUP|webauthnFlagUV)
		body := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key",
			"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "authenticatorData": b64urlEncode(ad), "signature": b64urlEncode(sig), "userHandle": b64urlEncode(passkeyUserHandle(app, userColsEve))}}
		code, _ = anon.do(passkeyLogin(app), "POST", "/api/_auth/passkeys/login", body, anonCSRF)
		_, session := anon.cookies[sessionName]
		return code, session
	}
	for _, stored := range storedDeactivations {
		storeDeactivation(t, f, userColsEve, stored.value)
		mustExec(t, f.db, `DELETE FROM _benmore_login_attempts`)
		code, session := signIn()
		if stored.deactivated && (code != http.StatusUnauthorized || session) {
			t.Errorf("%s: passkey sign-in answered %d, session=%v; want 401 and none", stored.name, code, session)
		}
		if !stored.deactivated && (code != http.StatusOK || !session) {
			t.Errorf("%s: passkey sign-in answered %d, session=%v; want 200 and a session", stored.name, code, session)
		}
	}
}

// The last-admin guard counts only admins that can hold a session.
func TestLastAdminGuardDoesNotCountAStoredEmptyDeactivation(t *testing.T) {
	f := newLastAdminFixture(t)
	// spare (7) is an admin whose row was saved in the panel before it
	// stored NULL: no session of it resolves.
	mustExec(t, f.db, `INSERT INTO _benmore_users (id, username, email, role, verified, deactivated_at) VALUES (7, 'spare', 'spare@example.com', 'admin', 1, '')`)
	if sid := CreateSession(f.db, 7, "spare@example.com", "", f.app.SessionDuration); sessionStatus(f, sid) != http.StatusUnauthorized {
		t.Fatal("fixture: the spare admin's session resolved")
	}
	if self, others, err := durableAdminCounts(f.app, f.db, 1); err != nil || !self || others != 0 {
		t.Fatalf("usable durable admins beside boss = %d (self %v, err %v), want 0", others, self, err)
	}
	boss := f.session(1, "boss@example.com")
	w := f.form(boss, "/_admin/set-role", url.Values{"user_id": {"1"}, "role": {"user"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "last active admin") || f.role(1) != "admin" {
		t.Fatalf("the only usable admin stepped down beside an admin that cannot sign in: %d %q, role now %q", w.Code, w.Body.String(), f.role(1))
	}

	// An account that is not usable is not the last usable admin: the guard
	// has nothing to refuse about it, so it cannot get in the way of
	// repairing it.
	if self, _, err := durableAdminCounts(f.app, f.db, 7); err != nil || self {
		t.Fatalf("an admin with a stored empty value counted as usable (err %v)", err)
	}
	if err := refuseLastDurableAdmin(f.app, f.db, 7, dropsAccount); err != nil {
		t.Fatalf("the guard refused a change to an account that cannot sign in: %v", err)
	}

	// Emptying the field in the panel stores NULL: the spare admin is usable
	// again and boss may step down.
	cols, err := GetTableColumns(f.db, "_benmore_users")
	if err != nil {
		t.Fatal(err)
	}
	f.app.Tables = append(f.app.Tables, Table{Name: "_benmore_users", Columns: cols})
	if w := f.form(boss, "/_admin/api/_benmore_users/update/7", url.Values{"deactivated_at": {""}}); w.Code != http.StatusOK {
		t.Fatalf("empty the field in the panel: %d %s", w.Code, w.Body.String())
	}
	if _, others, err := durableAdminCounts(f.app, f.db, 1); err != nil || others != 1 {
		t.Fatalf("after reactivation, usable durable admins beside boss = %d (err %v), want 1", others, err)
	}
	if w := f.form(boss, "/_admin/set-role", url.Values{"user_id": {"1"}, "role": {"user"}}); w.Code != http.StatusSeeOther || f.role(1) != "user" {
		t.Fatalf("stepping down beside a reactivated admin: %d %q, role %q", w.Code, w.Body.String(), f.role(1))
	}
}

// sessionStatus is GET /api/_auth/profile's status for a session.
func sessionStatus(f *lastAdminFixture, sid string) int {
	f.t.Helper()
	return f.api(sid, http.MethodGet, "/api/_auth/profile", "").Code
}

// The user directory lists and looks up the same accounts.
func TestUserDirectoryHidesAStoredEmptyDeactivation(t *testing.T) {
	app, mux := userDirectoryFixture(t, "everyone", nil)
	mustExec(t, app.DB, `UPDATE _benmore_users SET deactivated_at = '' WHERE id = 6`)
	code, ids := directoryList(t, app, mux, 3, "member@corp.example", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	for _, id := range ids {
		if id == 6 || id == 7 {
			t.Fatalf("the directory lists a deactivated account: %v", ids)
		}
	}
	if len(ids) != 5 {
		t.Fatalf("the directory lists %v, want the five active accounts", ids)
	}
	for _, id := range []int{6, 7} {
		if code := directoryLookup(app, mux, 3, "member@corp.example", "", id); code != http.StatusNotFound {
			t.Fatalf("lookup of deactivated account %d answered %d, want 404", id, code)
		}
	}
	// A support session resolves only while its admin is active.
	for _, stored := range storedDeactivations {
		mustExecArgs(t, app.DB, `UPDATE _benmore_users SET deactivated_at = ? WHERE id = 1`, stored.value)
		live, err := impersonatorStillAdmin(app.DB, 1, false)
		if err != nil || live == stored.deactivated {
			t.Fatalf("%s: the admin behind a support session counted as active=%v (err %v)", stored.name, live, err)
		}
	}
}
