//go:build !cli

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These handlers used to answer from what they intended to write, not from
// what the database did: a dropped DELETE or UPDATE result still said
// "revoked", "cleared" or "verified". Each test forces the write to fail (a
// trigger that aborts it) or to change no row (a trigger that skips the row,
// or a row that is gone) and reads back what the caller was told.

func writeResultAdmin(t *testing.T, app *App, password string) int64 {
	t.Helper()
	hash, err := generateBcryptHash([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('boss', 'boss@example.com', ?, 'admin', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func writeResultJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer is not JSON (%d): %s", w.Code, w.Body.String())
	}
	return out
}

// DELETE /api/_auth/sessions/{id} answered "revoked" whatever the DELETE did.
func TestSessionRevokeAnswersWhatTheDeleteDid(t *testing.T) {
	app, mux := actAsCredentialApp(t)
	uid := writeResultAdmin(t, app, "Admin!Pass1")
	mine := CreateSession(app.DB, uid, "boss@example.com", "", time.Hour)
	other := CreateSession(app.DB, uid, "boss@example.com", "", time.Hour)
	revoke := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(other)), nil)
		r.Header.Set("Authorization", "Bearer "+mine)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// The DELETE fails: a server error with the route's generic text, and
	// the session the caller wanted gone still signs in.
	mustExec(t, app.DB, "CREATE TRIGGER revoke_fails BEFORE DELETE ON _benmore_sessions BEGIN SELECT RAISE(ABORT, 'synthetic revoke failure'); END")
	w := revoke()
	out := writeResultJSON(t, w)
	if w.Code != http.StatusInternalServerError || out["status"] == "revoked" {
		t.Fatalf("a failed delete answered %d %s", w.Code, w.Body.String())
	}
	if out["error"] != "revoke failed" || out["request_id"] == nil || strings.Contains(w.Body.String(), "synthetic") {
		t.Fatalf("outside dev mode the answer is the generic text and a request id, got %s", w.Body.String())
	}
	if GetSessionFromDB(app.DB, other) == nil {
		t.Fatal("fixture: the aborted delete removed the session")
	}
	mustExec(t, app.DB, "DROP TRIGGER revoke_fails")

	// The DELETE matches nothing (the row went away after the lookup, here
	// a trigger that skips it): not found, not "revoked".
	mustExec(t, app.DB, "CREATE TRIGGER revoke_skips BEFORE DELETE ON _benmore_sessions BEGIN SELECT RAISE(IGNORE); END")
	w = revoke()
	out = writeResultJSON(t, w)
	if w.Code != http.StatusNotFound || out["status"] == "revoked" || out["error"] != "session not found" {
		t.Fatalf("a delete that removed nothing answered %d %s", w.Code, w.Body.String())
	}
	mustExec(t, app.DB, "DROP TRIGGER revoke_skips")

	// Control: the delete happens and says so.
	w = revoke()
	if out = writeResultJSON(t, w); w.Code != http.StatusOK || out["status"] != "revoked" {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if GetSessionFromDB(app.DB, other) != nil || GetSessionFromDB(app.DB, mine) == nil {
		t.Fatal("revoke should end the named session and keep the caller's")
	}
}

// POST /api/_auth/impersonate checked the marker UPDATE's error but not that
// it changed the row. A session without the marker is an ordinary session as
// the target: nothing it does names the admin.
func TestImpersonationNeedsItsMarkerStored(t *testing.T) {
	app, mux := actAsCredentialApp(t)
	adminID := writeResultAdmin(t, app, "Admin!Pass1")
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('member', 'member@example.com', 'x', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	memberID, _ := res.LastInsertId()
	adminSID := CreateSession(app.DB, adminID, "boss@example.com", "", time.Hour)
	impersonate := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"user_id": memberID, "password": "Admin!Pass1"})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(adminSID))
		r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: adminSID})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	memberSessions := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", memberID)
	}
	audited := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'impersonate'")
	}

	// The UPDATE runs without error and marks nothing.
	mustExec(t, app.DB, "CREATE TRIGGER marker_skipped BEFORE UPDATE OF is_impersonation ON _benmore_sessions BEGIN SELECT RAISE(IGNORE); END")
	w := impersonate()
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("an unmarked support session was handed out: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "benmore_session") && c.Value != "" {
			t.Fatalf("the refused request still set a session cookie: %s", c.Name)
		}
	}
	if n := memberSessions(); n != 0 {
		t.Fatalf("the unmarked session was left behind: %d session(s) as the member", n)
	}
	if audited() != 0 {
		t.Fatal("an impersonation that did not start was audited as started")
	}
	mustExec(t, app.DB, "DROP TRIGGER marker_skipped")

	// Control: with the marker stored the support session starts.
	w = impersonate()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("impersonate: %d %s", w.Code, w.Body.String())
	}
	marked := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ? AND COALESCE(is_impersonation, 0) = 1 AND impersonator_user_id = ?", memberID, adminID)
	if memberSessions() != 1 || marked != 1 || audited() != 1 {
		t.Fatal("the support session should carry the marker and the admin's id, and be audited once")
	}
}

// DELETE /api/_auth/act_as dropped the UPDATE's result, then wrote the
// act_as_end audit row and answered "cleared".
func TestActAsClearAnswersWhatTheUpdateDid(t *testing.T) {
	app, mux := actAsCredentialApp(t)
	adminID := writeResultAdmin(t, app, "Admin!Pass1")
	stepIn := func(token string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"group_id": "7", "password": "Admin!Pass1"})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/act_as", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("fixture step-in: %d %s", w.Code, w.Body.String())
		}
	}
	clearRequest := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodDelete, "/api/_auth/act_as", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	actingAs := func(token string) string {
		var group string
		app.DB.QueryRow("SELECT COALESCE(acting_as_group, '') FROM _benmore_sessions WHERE id = ?", sessionStorageKey(token)).Scan(&group)
		return group
	}
	ended := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'act_as_end'")
	}

	// The UPDATE fails: a server error, no audit row, and the session is
	// still stepped in (which is what the caller must not be told otherwise).
	token := CreateSession(app.DB, adminID, "boss@example.com", "", time.Hour)
	stepIn(token)
	mustExec(t, app.DB, "CREATE TRIGGER clear_fails BEFORE UPDATE OF acting_as_group ON _benmore_sessions BEGIN SELECT RAISE(ABORT, 'synthetic clear failure'); END")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, clearRequest(token))
	out := writeResultJSON(t, w)
	if w.Code != http.StatusInternalServerError || out["status"] == "cleared" || strings.Contains(w.Body.String(), "synthetic") {
		t.Fatalf("a failed clear answered %d %s", w.Code, w.Body.String())
	}
	if actingAs(token) != "7" {
		t.Fatal("fixture: the aborted update cleared the step-in")
	}
	if ended() != 0 {
		t.Fatal("a step-in that did not end was audited as ended")
	}
	mustExec(t, app.DB, "DROP TRIGGER clear_fails")

	// Control: the clear happens, is audited once and says so.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, clearRequest(token))
	if out = writeResultJSON(t, w); w.Code != http.StatusOK || out["status"] != "cleared" {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	if actingAs(token) != "" || ended() != 1 {
		t.Fatalf("clear should empty acting_as_group and audit once: group=%q audited=%d", actingAs(token), ended())
	}

	// The session row is gone by the time the handler writes (it was
	// resolved earlier in the request, as the password-change gate does, and
	// ended in between): nothing was cleared, so no audit row and no
	// "cleared"; the caller is no longer signed in.
	gone := CreateSession(app.DB, adminID, "boss@example.com", "", time.Hour)
	stepIn(gone)
	resolvedThenEnded := requestSessionCacheMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := getSession(app, r); s == nil || s.ActingAsGroup != "7" {
			t.Fatalf("fixture: the stepped-in session did not resolve: %+v", s)
		}
		if _, err := app.DB.Exec("DELETE FROM _benmore_sessions WHERE id = ?", sessionStorageKey(gone)); err != nil {
			t.Fatal(err)
		}
		mux.ServeHTTP(w, r)
	}))
	w = httptest.NewRecorder()
	resolvedThenEnded.ServeHTTP(w, clearRequest(gone))
	out = writeResultJSON(t, w)
	if w.Code != http.StatusUnauthorized || out["status"] == "cleared" {
		t.Fatalf("clearing a session that no longer exists answered %d %s", w.Code, w.Body.String())
	}
	if ended() != 1 {
		t.Fatalf("an update that changed no row was audited as an ended step-in (%d rows)", ended())
	}
}

// A verification link reported the address verified whether or not
// `verified = 1` was stored, and the link was spent either way.
func TestEmailVerificationNotReportedWhenNotStored(t *testing.T) {
	linkUnspent := func(t *testing.T, app *App) bool {
		t.Helper()
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_password_resets WHERE used = 0 AND type = 'verify'") == 1
	}
	verified := func(t *testing.T, app *App, uid int64) int {
		t.Helper()
		return recoveryCount(t, app.DB, "SELECT COALESCE(verified, 0) FROM _benmore_users WHERE id = ?", uid)
	}

	// The registrant's own browser; the UPDATE fails.
	t.Run("link in the account's session", func(t *testing.T) {
		app := recoveryHardeningApp(t)
		uid := recoveryUser(t, app, "new@corp.example", "Owner!Pass11", 0)
		mine := CreateSession(app.DB, uid, "new@corp.example", "", time.Hour)
		stray := CreateSession(app.DB, uid, "new@corp.example", "", time.Hour)
		insertVerifyToken(t, app, "new@corp.example", "own-tok")
		mustExec(t, app.DB, "CREATE TRIGGER verify_fails BEFORE UPDATE OF verified ON _benmore_users BEGIN SELECT RAISE(ABORT, 'synthetic verify failure'); END")
		w := verifyLinkRequest(app, "own-tok", &http.Cookie{Name: devSessionCookieName, Value: mine})
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "synthetic") {
			t.Fatalf("an unstored verification answered %d %q (Location %q)", w.Code, w.Body.String(), w.Header().Get("Location"))
		}
		if verified(t, app, uid) != 0 {
			t.Fatal("fixture: the aborted update verified the account")
		}
		if !linkUnspent(t, app) {
			t.Fatal("the link was spent on a verification that did not happen")
		}
		if GetSessionFromDB(app.DB, stray) == nil {
			t.Fatal("the account's other session was ended for a verification that did not happen")
		}
		// The same link works once the write does.
		mustExec(t, app.DB, "DROP TRIGGER verify_fails")
		if w := verifyLinkRequest(app, "own-tok", &http.Cookie{Name: devSessionCookieName, Value: mine}); w.Code != http.StatusSeeOther {
			t.Fatalf("retry: %d", w.Code)
		}
		if verified(t, app, uid) != 1 || linkUnspent(t, app) {
			t.Fatal("the retried link should verify the account and be spent")
		}
	})

	// Another device proves the password; the UPDATE runs but changes no
	// row (the account's address is no longer the one the link names).
	t.Run("link confirmed with the password", func(t *testing.T) {
		app := recoveryHardeningApp(t)
		uid := recoveryUser(t, app, "second@corp.example", "Owner!Pass11", 0)
		insertVerifyToken(t, app, "second@corp.example", "confirm-tok")
		mustExec(t, app.DB, "CREATE TRIGGER verify_skipped BEFORE UPDATE OF verified ON _benmore_users BEGIN SELECT RAISE(IGNORE); END")
		w := verifyConfirmRequest(app, "confirm-tok", "Owner!Pass11")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Header().Get("Location"), "success=") {
			t.Fatalf("an unstored verification answered %d (Location %q)", w.Code, w.Header().Get("Location"))
		}
		if verified(t, app, uid) != 0 || !linkUnspent(t, app) {
			t.Fatal("nothing was verified, so the link must still be usable")
		}
		mustExec(t, app.DB, "DROP TRIGGER verify_skipped")
		if w := verifyConfirmRequest(app, "confirm-tok", "Owner!Pass11"); w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "success=") {
			t.Fatalf("retry: %d %q", w.Code, w.Header().Get("Location"))
		}
		if verified(t, app, uid) != 1 {
			t.Fatal("the retried link did not verify the account")
		}
	})

	// An account nobody chose a password for is claimed first. A claim that
	// fails rolls back, so nothing is verified and the link is not spent.
	t.Run("link that claims a passwordless account", func(t *testing.T) {
		app := recoveryHardeningApp(t)
		uid := recoveryUser(t, app, "nopass@corp.example", "", 0)
		insertVerifyToken(t, app, "nopass@corp.example", "claim-tok")
		mustExec(t, app.DB, "CREATE TRIGGER claim_fails BEFORE UPDATE OF password_hash ON _benmore_users BEGIN SELECT RAISE(ABORT, 'synthetic claim failure'); END")
		w := verifyLinkRequest(app, "claim-tok", nil)
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "synthetic") {
			t.Fatalf("a failed claim answered %d %q (Location %q)", w.Code, w.Body.String(), w.Header().Get("Location"))
		}
		if verified(t, app, uid) != 0 || !linkUnspent(t, app) {
			t.Fatal("nothing was claimed or verified, so the link must still be usable")
		}
		mustExec(t, app.DB, "DROP TRIGGER claim_fails")
		if w := verifyLinkRequest(app, "claim-tok", nil); w.Code != http.StatusSeeOther {
			t.Fatalf("retry: %d", w.Code)
		}
		if verified(t, app, uid) != 1 || linkUnspent(t, app) {
			t.Fatal("the retried link should claim and verify the account and be spent")
		}
	})
}

// A provider-verified OAuth sign-in went ahead on an account whose
// `verified = 1` was never stored.
func TestOAuthSignInFailsWhenVerificationNotStored(t *testing.T) {
	app := recoveryHardeningApp(t)
	grandfathered := recoveryUser(t, app, "old@corp.example", "Owner!Pass11", 0)
	mustExec(t, app.DB, "UPDATE _benmore_users SET email_grandfathered = 1 WHERE email = 'old@corp.example'")
	mustExec(t, app.DB, "CREATE TRIGGER verify_fails BEFORE UPDATE OF verified ON _benmore_users BEGIN SELECT RAISE(ABORT, 'synthetic verify failure'); END")

	if id, err := oauthFindOrCreateUser(app, "old@corp.example", "", true); err == nil {
		t.Fatalf("an existing account signed in (id %d) although it could not be marked verified", id)
	}
	if id, err := oauthFindOrCreateUser(app, "fresh@corp.example", "Fresh Person", true); err == nil {
		t.Fatalf("a new account signed in (id %d) although it could not be marked verified", id)
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_users WHERE COALESCE(verified, 0) = 1"); n != 0 {
		t.Fatalf("fixture: %d account(s) verified through the aborted update", n)
	}

	// The next sign-in, once the write works, verifies both.
	mustExec(t, app.DB, "DROP TRIGGER verify_fails")
	if id, err := oauthFindOrCreateUser(app, "old@corp.example", "", true); err != nil || id != grandfathered {
		t.Fatalf("retry, existing account: id=%d err=%v", id, err)
	}
	if id, err := oauthFindOrCreateUser(app, "fresh@corp.example", "Fresh Person", true); err != nil || id == 0 {
		t.Fatalf("retry, new account: id=%d err=%v", id, err)
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_users WHERE COALESCE(verified, 0) = 1"); n != 2 {
		t.Fatalf("after the retry %d of 2 accounts are verified", n)
	}
}

// markEmailVerified said nothing when its UPDATE failed or matched no row.
func TestMarkEmailVerifiedReportsWhatWasStored(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "person@corp.example", "Owner!Pass11", 0)
	verified := func() int {
		return recoveryCount(t, app.DB, "SELECT COALESCE(verified, 0) FROM _benmore_users WHERE id = ?", uid)
	}

	// A proof for an address the account no longer holds, an account that
	// does not exist, and missing arguments change nothing and say so.
	for name, err := range map[string]error{
		"stale address":   markEmailVerified(app, uid, "old-address@corp.example"),
		"unknown account": markEmailVerified(app, uid+100, "person@corp.example"),
		"no account id":   markEmailVerified(app, 0, "person@corp.example"),
		"no address":      markEmailVerified(app, uid, ""),
	} {
		if !errors.Is(err, errEmailNotMarkedVerified) {
			t.Errorf("%s: err = %v, want errEmailNotMarkedVerified", name, err)
		}
	}
	if verified() != 0 {
		t.Fatal("a proof that names another address verified the account")
	}

	// The write fails: the error comes back, wrapped.
	mustExec(t, app.DB, "CREATE TRIGGER verify_fails BEFORE UPDATE OF verified ON _benmore_users BEGIN SELECT RAISE(ABORT, 'synthetic verify failure'); END")
	if err := markEmailVerified(app, uid, "person@corp.example"); err == nil || errors.Is(err, errEmailNotMarkedVerified) || !strings.Contains(err.Error(), "synthetic verify failure") {
		t.Fatalf("failed write: err = %v", err)
	}
	if verified() != 0 {
		t.Fatal("fixture: the aborted update verified the account")
	}
	mustExec(t, app.DB, "DROP TRIGGER verify_fails")

	// Stored: nil, in any letter case of the address, and again when the
	// account is already verified (the repeat only attaches invites).
	for _, address := range []string{"Person@Corp.Example", "person@corp.example"} {
		if err := markEmailVerified(app, uid, address); err != nil {
			t.Fatalf("markEmailVerified(%q): %v", address, err)
		}
		if verified() != 1 {
			t.Fatalf("markEmailVerified(%q) returned nil without storing verified = 1", address)
		}
	}
}

// activateEmailInvites dropped its UPDATE's error. An app without the invite
// table is not an error; a failed write on one that has it is, and it must
// not undo or fail the verification it follows.
func TestInviteActivationFailureIsReportedNotSilent(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "invited@corp.example", "Owner!Pass11", 1)
	active := func() int {
		return recoveryCount(t, app.DB, "SELECT COUNT(*) FROM user_roles WHERE email = 'invited@corp.example' AND user_id = ? AND is_active = 1 AND invite_accepted_at IS NOT NULL", uid)
	}

	// No user_roles table: the app has no invites.
	if err := activateEmailInvites(app, uid, "invited@corp.example"); err != nil {
		t.Fatalf("no user_roles table: %v", err)
	}
	// A user_roles table of the app's own shape, without the invite
	// columns, is not an invite table either.
	mustExec(t, app.DB, "CREATE TABLE user_roles (id INTEGER PRIMARY KEY, user_id INTEGER, role TEXT)")
	if err := activateEmailInvites(app, uid, "invited@corp.example"); err != nil {
		t.Fatalf("user_roles without invite columns: %v", err)
	}
	mustExec(t, app.DB, "DROP TABLE user_roles")

	mustExec(t, app.DB, "CREATE TABLE user_roles (id INTEGER PRIMARY KEY, Email TEXT, user_id INTEGER, is_active INTEGER DEFAULT 0, invite_accepted_at TEXT)")
	mustExec(t, app.DB, "INSERT INTO user_roles (Email) VALUES ('invited@corp.example')")
	mustExec(t, app.DB, "CREATE TRIGGER invite_fails BEFORE UPDATE ON user_roles BEGIN SELECT RAISE(ABORT, 'synthetic invite failure'); END")
	if err := activateEmailInvites(app, uid, "invited@corp.example"); err == nil || !strings.Contains(err.Error(), "synthetic invite failure") {
		t.Fatalf("a failed invite write returned %v", err)
	}
	if active() != 0 {
		t.Fatal("fixture: the aborted update attached the invite")
	}

	// The same failure behind a verification: the address is verified and
	// reported so; only the invite is still pending (and logged).
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 0 WHERE email = 'invited@corp.example'")
	if err := markEmailVerified(app, uid, "invited@corp.example"); err != nil {
		t.Fatalf("a failed invite write failed the verification: %v", err)
	}
	if recoveryCount(t, app.DB, "SELECT COALESCE(verified, 0) FROM _benmore_users WHERE id = ?", uid) != 1 || active() != 0 {
		t.Fatal("the account should be verified with its invite still pending")
	}

	// Once the write works, the next proof attaches the invite.
	mustExec(t, app.DB, "DROP TRIGGER invite_fails")
	if err := markEmailVerified(app, uid, "invited@corp.example"); err != nil || active() != 1 {
		t.Fatalf("retry: err=%v attached=%d", err, active())
	}
	// Nobody invited: zero rows is not a failure.
	if err := activateEmailInvites(app, uid, "nobody-invited@corp.example"); err != nil {
		t.Fatalf("no pending invite: %v", err)
	}
}

// The OIDC nonce check in the OAuth callback compares in constant time now;
// what it accepts and refuses is unchanged.
func TestOAuthIDTokenNonceMismatch(t *testing.T) {
	idToken := func(claims string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
	}
	sent := "5f2b6c0e9d3a4b1c8e7f6a5d4c3b2a19"
	for name, c := range map[string]struct {
		token    string
		mismatch bool
	}{
		"the nonce this sign-in sent":   {idToken(`{"nonce":"` + sent + `"}`), false},
		"another sign-in's nonce":       {idToken(`{"nonce":"0f2b6c0e9d3a4b1c8e7f6a5d4c3b2a19"}`), true},
		"a prefix of the nonce":         {idToken(`{"nonce":"` + sent[:len(sent)-1] + `"}`), true},
		"the nonce in another case":     {idToken(`{"nonce":"` + strings.ToUpper(sent) + `"}`), true},
		"no nonce claim (plain OAuth2)": {idToken(`{"sub":"1"}`), false},
		"an empty nonce claim":          {idToken(`{"nonce":""}`), false},
		"a non-string nonce claim":      {idToken(`{"nonce":7}`), false},
		"not a JWT":                     {"opaque-token", false},
	} {
		if got := oauthIDTokenNonceMismatch(c.token, sent); got != c.mismatch {
			t.Errorf("%s: mismatch = %v, want %v", name, got, c.mismatch)
		}
	}
}
