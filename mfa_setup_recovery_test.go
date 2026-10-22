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
)

func mfaRecoveryLogin(t *testing.T, app *App, email, password string) string {
	t.Helper()
	form := url.Values{"email": {email}, "password": {password}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	cookie := setupTokenFromRecorder(w)
	if cookie == nil || cookie.Value == "" || w.Header().Get("Location") != "/mfa-setup" {
		t.Fatalf("login did not issue an enrollment grant: %d %q", w.Code, w.Header().Get("Location"))
	}
	return cookie.Value
}

func mfaRecoveryCall(mux *http.ServeMux, token, endpoint, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/"+endpoint, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-MFA-Setup-Token", token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func mfaRecoverySetup(t *testing.T, mux *http.ServeMux, token string) string {
	t.Helper()
	w := mfaRecoveryCall(mux, token, "setup", "{}")
	var result struct{ Secret string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Secret == "" {
		t.Fatalf("current grant could not start enrollment: %d %s", w.Code, w.Body.String())
	}
	return result.Secret
}

func mfaRecoveryReset(t *testing.T, app *App, email string) {
	t.Helper()
	const reset = "synthetic-mfa-recovery-link"
	if !storeResetLink(app.DB, email, reset) {
		t.Fatal("could not store synthetic reset link")
	}
	form := url.Values{"token": {reset}, "password": {"Recovered!Password2"}, "confirm": {"Recovered!Password2"}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, app)
	if !strings.Contains(w.Header().Get("Location"), "success=") {
		t.Fatalf("password recovery failed: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestMFASetupGrantRevokedByPasswordRecovery(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(fmt.Sprintf("enrollment_started_%t", started), func(t *testing.T) {
			app := recoveryHardeningApp(t)
			app.Design.Auth["require_mfa_for_roles"] = "user"
			const email = "owner@example.test"
			uid := recoveryUser(t, app, email, "Original!Password1", 1)
			mux := http.NewServeMux()
			RegisterMFARoutes(mux, app)
			oldGrant := mfaRecoveryLogin(t, app, email, "Original!Password1")
			var oldSecret string
			if started {
				oldSecret = mfaRecoverySetup(t, mux, oldGrant)
			}
			mfaRecoveryReset(t, app, email)
			var before string
			if err := app.DB.QueryRow("SELECT COALESCE(totp_secret,'') FROM _benmore_users WHERE id=?", uid).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"setup", "verify"} {
				body := "{}"
				if oldSecret != "" {
					body = `{"code":"` + GenerateTOTP(oldSecret) + `"}`
				}
				w := mfaRecoveryCall(mux, oldGrant, endpoint, body)
				if w.Code != http.StatusUnauthorized {
					t.Errorf("pre-reset grant on %s: got %d, want 401", endpoint, w.Code)
				}
			}
			var after string
			if err := app.DB.QueryRow("SELECT COALESCE(totp_secret,'') FROM _benmore_users WHERE id=?", uid).Scan(&after); err != nil || after != before {
				t.Fatalf("rejected old grant changed enrollment: %v", err)
			}
			if got := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid); got != 0 {
				t.Fatalf("old enrollment grant created %d session(s)", got)
			}
			// Recovery does not disable enrollment: the new password can start
			// a fresh attempt and exchange that grant for a direct sign-in.
			fresh := mfaRecoveryLogin(t, app, email, "Recovered!Password2")
			secret := mfaRecoverySetup(t, mux, fresh)
			w := mfaRecoveryCall(mux, fresh, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
			var result struct{ Token string }
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Token == "" {
				t.Fatalf("fresh enrollment failed: %d %s", w.Code, w.Body.String())
			}
			session := GetSessionFromDB(app.DB, result.Token)
			if session == nil || session.UserID != uid || !CheckMFA(app.DB, uid) {
				t.Fatal("fresh enrollment did not enable MFA and create the account's session")
			}
			var loginAt int64
			if err := app.DB.QueryRow("SELECT login_at FROM _benmore_sessions WHERE id=?", sessionStorageKey(result.Token)).Scan(&loginAt); err != nil || loginAt <= 0 {
				t.Fatalf("enrollment lost direct sign-in time: %d %v", loginAt, err)
			}
		})
	}
}

func TestMFASetupGrantRejectsUnboundVersions(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "Original!Password1", 1)
	exp := time.Now().Add(time.Minute).Unix()
	for _, payload := range []string{
		fmt.Sprintf("mfa-setup|%d|owner@example.test|%d", uid, exp),
		fmt.Sprintf("mfa-setup|v2|%d|%s|%d", uid, stepField("owner@example.test"), exp),
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
		r.Header.Set("X-MFA-Setup-Token", signTempCookieFor(app, tempCookieMFASetup, payload))
		if _, _, _, err := mfaCallerIdentity(app, r); err == nil {
			t.Error("accepted an old grant that cannot prove its password state")
		}
	}
}

func TestMFASetupGrantTracksAccountState(t *testing.T) {
	for _, change := range []struct {
		name, query string
	}{
		{"password", "UPDATE _benmore_users SET password_hash='replacement-fixture-hash' WHERE id=?"},
		{"created_at", "UPDATE _benmore_users SET created_at='2000-01-01 00:00:00' WHERE id=?"},
		{"email", "UPDATE _benmore_users SET email='changed@example.test' WHERE id=?"},
		{"deactivation", "UPDATE _benmore_users SET deactivated_at=datetime('now') WHERE id=?"},
		{"temporary_password", "UPDATE _benmore_users SET password_change_required=1 WHERE id=?"},
		{"deleted", "DELETE FROM _benmore_users WHERE id=?"},
	} {
		t.Run(change.name, func(t *testing.T) {
			app := recoveryHardeningApp(t)
			uid := recoveryUser(t, app, "owner@example.test", "", 1)
			token := mintMFASetupToken(app, uid, "owner@example.test")
			r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/setup", nil)
			r.Header.Set("X-MFA-Setup-Token", token)
			if _, _, _, err := mfaCallerIdentity(app, r); err != nil {
				t.Fatalf("unchanged account rejected current grant: %v", err)
			}
			passwordChangeExec(t, app.DB, change.query, uid)
			if _, _, _, err := mfaCallerIdentity(app, r); err == nil {
				t.Fatal("accepted grant after account state changed")
			}
		})
	}
}

func TestMFASetupGrantCannotRebindAnOldPasswordProof(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='old-verified-hash' WHERE id=?", uid)
	if mintMFASetupToken(app, uid, "owner@example.test", "old-verified-hash") == "" {
		t.Fatal("current password proof did not mint a setup token")
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='new-recovered-hash' WHERE id=?", uid)
	if mintMFASetupToken(app, uid, "owner@example.test", "old-verified-hash") != "" {
		t.Fatal("old password proof minted a token for the recovered credentials")
	}
	if mintMFASetupToken(app, uid, "owner@example.test", "new-recovered-hash") == "" {
		t.Fatal("recovered password proof did not mint a setup token")
	}
}

type mfaRecoveryReadHook struct {
	*strings.Reader
	before func()
}

func (r *mfaRecoveryReadHook) Read(p []byte) (int, error) {
	if r.before != nil {
		f := r.before
		r.before = nil
		f()
	}
	return r.Reader.Read(p)
}

func TestMFASetupGrantRecheckedBeforeVerificationWrite(t *testing.T) {
	app := recoveryHardeningApp(t)
	app.Design.Auth["require_mfa_for_roles"] = "user"
	const email = "owner@example.test"
	uid := recoveryUser(t, app, email, "Original!Password1", 1)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	grant := mfaRecoveryLogin(t, app, email, "Original!Password1")
	secret := mfaRecoverySetup(t, mux, grant)
	// Body decoding happens after the initial identity check. Complete an
	// ordinary recovery then, before the final activation/session transaction.
	body := &mfaRecoveryReadHook{
		Reader: strings.NewReader(`{"code":"` + GenerateTOTP(secret) + `"}`),
		before: func() { mfaRecoveryReset(t, app, email) },
	}
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/verify", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-MFA-Setup-Token", grant)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("reset during verify: got %d, want 401", w.Code)
	}
	if CheckMFA(app.DB, uid) || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 0 {
		t.Fatal("reset during verify left an active factor or a valid session")
	}
}

func TestMFASetupSessionFailureRollsBackActivation(t *testing.T) {
	app := recoveryHardeningApp(t)
	app.DB.SetMaxOpenConns(1) // the new transaction must not recurse into app.DB
	uid := recoveryUser(t, app, "owner@example.test", "", 1)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	grant := mintMFASetupToken(app, uid, "owner@example.test")
	secret := mfaRecoverySetup(t, mux, grant)
	var pending string
	if err := app.DB.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=?", uid).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, `CREATE TRIGGER fixture_reject_mfa_session BEFORE INSERT ON _benmore_sessions BEGIN
		SELECT RAISE(ABORT, 'synthetic session write failure'); END`)
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failed session insert reported %d, want 500", w.Code)
	}
	var after string
	if err := app.DB.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id=?", uid).Scan(&after); err != nil || after != pending {
		t.Fatalf("failed session insert changed factor: %v", err)
	}
	if got := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid); got != 0 {
		t.Fatalf("failed verification left %d session(s)", got)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName || c.Name == devSessionCookieName {
			t.Fatal("failed verification sent a session cookie")
		}
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER fixture_reject_mfa_session")
	w = mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	if w.Code != http.StatusOK || !CheckMFA(app.DB, uid) {
		t.Fatalf("enrollment could not retry after storage recovery: %d", w.Code)
	}
}

func TestMFASetupGrantPreservesRequiredPasswordChange(t *testing.T) {
	app := recoveryHardeningApp(t)
	app.Design.Auth["require_mfa_for_roles"] = "user"
	const email = "owner@example.test"
	uid := recoveryUser(t, app, email, "Temporary!Password1", 1)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=1 WHERE id=?", uid)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	grant := mfaRecoveryLogin(t, app, email, "Temporary!Password1")
	secret := mfaRecoverySetup(t, mux, grant)
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	var result struct{ Token string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Token == "" {
		t.Fatalf("required MFA did not finish pending sign-in: %d %s", w.Code, w.Body.String())
	}
	if GetSessionFromDB(app.DB, result.Token) != nil {
		t.Fatal("MFA enrollment bypassed the required password change")
	}
	r := httptest.NewRequest(http.MethodGet, passwordChangePagePath, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: result.Token})
	if pending := pendingPasswordChange(app, r); pending == nil || pending.UserID != uid {
		t.Fatal("MFA enrollment did not allow the existing password-change step")
	}
}
