//go:build !cli

package main

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func loginChallengeFixture(t *testing.T) (*App, *http.ServeMux, int64, string, []string) {
	t.Helper()
	app := recoveryHardeningApp(t)
	const email = "challenge@example.test"
	uid := recoveryUser(t, app, email, "Original!Password1", 1)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("login-challenge-fixture"))
	codes := []string{"backup-one", "backup-two", "backup-three"}
	hashed := []string{}
	for _, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		hashed = append(hashed, string(hash))
	}
	encoded, _ := json.Marshal(hashed)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=?, backup_codes=? WHERE id=?", secret, string(encoded), uid)
	mux := http.NewServeMux()
	RegisterMFALoginRoute(mux, app)
	return app, mux, uid, secret, codes
}

func passwordLoginChallenge(t *testing.T, app *App) string {
	t.Helper()
	form := url.Values{"email": {"challenge@example.test"}, "password": {"Original!Password1"}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	step := stepCookieValue(w, flowCookieName(flowCookieMFA, true))
	if step == "" || w.Header().Get("Location") != app.Paths.VerifyMFA {
		t.Fatalf("no MFA challenge: %d %q", w.Code, w.Header().Get("Location"))
	}
	return step
}

func challengeFactorState(t *testing.T, app *App, uid int64) string {
	t.Helper()
	var state string
	if err := app.DB.QueryRow("SELECT json_array(backup_codes,mfa_last_totp,mfa_last_totp_at) FROM _benmore_users WHERE id=?", uid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestMFALoginChallengeRevokedByCredentialWrite(t *testing.T) {
	for _, kind := range []string{"password_change", "password_recovery", "same_hash_reset", "required_password", "deactivation"} {
		t.Run(kind, func(t *testing.T) {
			app, mux, uid, _, codes := loginChallengeFixture(t)
			step := passwordLoginChallenge(t, app)
			switch kind {
			case "password_change":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash='replaced' WHERE id=?", uid)
			case "password_recovery":
				mfaRecoveryReset(t, app, "challenge@example.test")
			case "same_hash_reset":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
			case "required_password":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=1 WHERE id=?", uid)
			case "deactivation":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET deactivated_at=datetime('now') WHERE id=?", uid)
			}
			before := challengeFactorState(t, app, uid)
			w := postMFAStep(t, app, mux, step, codes[0])
			if stepCookieValue(w, sessionCookieName) != "" || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 0 {
				t.Error("stale MFA challenge issued a session")
			}
			if after := challengeFactorState(t, app, uid); after != before {
				t.Error("stale challenge consumed second-factor state")
			}
		})
	}
}

func TestMFALoginChallengeSingleUse(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequential", true: "concurrent"}[concurrent], func(t *testing.T) {
			app, mux, uid, _, codes := loginChallengeFixture(t)
			step := passwordLoginChallenge(t, app)
			results := make([]*httptest.ResponseRecorder, 2)
			if concurrent {
				var wg sync.WaitGroup
				for i := range results {
					wg.Add(1)
					go func(i int) { defer wg.Done(); results[i] = postMFAStep(t, app, mux, step, codes[i]) }(i)
				}
				wg.Wait()
			} else {
				for i := range results {
					results[i] = postMFAStep(t, app, mux, step, codes[i])
				}
			}
			successes := 0
			for _, w := range results {
				if stepCookieValue(w, sessionCookieName) != "" {
					successes++
				}
			}
			if successes != 1 || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 1 {
				t.Fatalf("one challenge produced %d sessions", successes)
			}
			var remaining string
			app.DB.QueryRow("SELECT backup_codes FROM _benmore_users WHERE id=?", uid).Scan(&remaining)
			var codesLeft []string
			json.Unmarshal([]byte(remaining), &codesLeft)
			if len(codesLeft) != 2 {
				t.Fatalf("replay consumed a second backup code: %d left", len(codesLeft))
			}
		})
	}
}

func TestMFALoginChallengeSessionFailureRollsBackFactor(t *testing.T) {
	app, mux, uid, _, codes := loginChallengeFixture(t)
	step := passwordLoginChallenge(t, app)
	before := challengeFactorState(t, app, uid)
	passwordChangeExec(t, app.DB, `CREATE TRIGGER reject_mfa_session BEFORE INSERT ON _benmore_sessions BEGIN SELECT RAISE(ABORT,'fixture session failure'); END`)
	w := postMFAStep(t, app, mux, step, codes[0])
	if stepCookieValue(w, sessionCookieName) != "" {
		t.Error("failed session insert returned a credential")
	}
	if after := challengeFactorState(t, app, uid); after != before {
		t.Error("failed sign-in consumed the backup factor")
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER reject_mfa_session")
	if w = postMFAStep(t, app, mux, step, codes[0]); stepCookieValue(w, sessionCookieName) == "" {
		t.Error("rolled-back challenge and factor could not be retried")
	}
}

func TestOTPLoginStepRevokedByPasswordWrite(t *testing.T) {
	app, _, uid, _, _ := loginChallengeFixture(t)
	passwordChangeExec(t, app.DB, "CREATE TABLE IF NOT EXISTS _benmore_otp (email TEXT,code TEXT,attempts INTEGER DEFAULT 0,expires_at DATETIME)")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_otp(email,code,expires_at) VALUES ('challenge@example.test','123456',datetime('now','+10 minutes'))")
	step := mintSignInChallenge(app, tempCookieOTP, uid, "challenge@example.test", "challenge@example.test")
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader("code=123456"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
	w := httptest.NewRecorder()
	handleVerifyOTP(w, r, app)
	if stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("pre-reset OTP proof issued a session")
	}
}

func TestSignInChallengeIssuanceBindsExactCredentialProof(t *testing.T) {
	app, _, uid, _, _ := loginChallengeFixture(t)
	_, _, binding, err := mfaSetupAccountState(app, app.DB, uid, "challenge@example.test")
	if err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
	if token := mintSignInChallenge(app, tempCookieMFA, uid, "challenge@example.test", "challenge@example.test", binding); token != "" {
		t.Fatal("old password proof minted a challenge after same-hash reset")
	}
	if got := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_signin_challenges"); got != 0 {
		t.Fatalf("failed issuance persisted %d challenges", got)
	}
}

func TestSignInChallengesRevokedWithAllAccountAccess(t *testing.T) {
	app, mux, uid, _, codes := loginChallengeFixture(t)
	step := passwordLoginChallenge(t, app)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = revokeUserAccessExcept(tx, uid, ""); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before := challengeFactorState(t, app, uid)
	w := postMFAStep(t, app, mux, step, codes[0])
	if stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("revoked challenge issued session")
	}
	if challengeFactorState(t, app, uid) != before {
		t.Fatal("revoked challenge consumed factor")
	}
}

func TestSignInChallengeBoundedPurposeAndExpiry(t *testing.T) {
	app, mux, uid, _, codes := loginChallengeFixture(t)
	for i := 0; i < 25; i++ {
		if token := mintSignInChallenge(app, tempCookieMFA, uid, "challenge@example.test", ""); token == "" {
			t.Fatal("issuance failed")
		}
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_signin_challenges WHERE user_id=?", uid); n != 20 {
		t.Fatalf("unbounded challenges: %d", n)
	}
	token := mintSignInChallenge(app, tempCookieOTP, uid, "challenge@example.test", "challenge@example.test")
	if w := postMFAStep(t, app, mux, token, codes[0]); stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("OTP challenge substituted for MFA")
	}
	token = passwordLoginChallenge(t, app)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_signin_challenges SET expires_at=0")
	if w := postMFAStep(t, app, mux, token, codes[0]); stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("expired challenge accepted")
	}
}

func TestOTPChallengeSessionFailureRollsBack(t *testing.T) {
	app, _, uid, _, _ := loginChallengeFixture(t)
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	code, step, err := prepareLoginOTPTx(app, tx, uid, "challenge@example.test", "challenge@example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
		w := httptest.NewRecorder()
		handleVerifyOTP(w, r, app)
		return w
	}
	passwordChangeExec(t, app.DB, `CREATE TRIGGER reject_otp_session BEFORE INSERT ON _benmore_sessions BEGIN SELECT RAISE(ABORT,'fixture session failure'); END`)
	if w := call(); stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("failed OTP session save returned credential")
	}
	if n := recoveryCount(t, app.DB, "SELECT attempts FROM _benmore_otp"); n != 0 {
		t.Fatal("failed OTP sign-in consumed attempt")
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER reject_otp_session")
	if w := call(); stepCookieValue(w, sessionCookieName) == "" {
		t.Fatal("rolled-back OTP proof cannot be retried")
	}
	if w := call(); stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("OTP challenge replay succeeded")
	}
}

func TestMFADisableCancelsPendingSignInSteps(t *testing.T) {
	app, mux, uid, secret, _ := loginChallengeFixture(t)
	RegisterMFARoutes(mux, app)
	passwordLoginChallenge(t, app)
	if mintSignInChallenge(app, tempCookieOTP, uid, "challenge@example.test", "challenge@example.test") == "" {
		t.Fatal("OTP continuation fixture failed")
	}
	sid := createSignInSession(app.DB, uid, "challenge@example.test", "", app.SessionDuration)
	w := auditPost(mux, sid, "/api/_auth/mfa/disable", "", `{"code":"`+GenerateTOTP(secret)+`"}`, true)
	if w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_signin_challenges WHERE user_id=?", uid); n != 0 {
		t.Fatalf("disable left %d pending sign-ins", n)
	}
}

func TestInlineMFALoginSessionFailureRollsBackFactor(t *testing.T) {
	app, _, uid, _, codes := loginChallengeFixture(t)
	before := challengeFactorState(t, app, uid)
	call := func() *httptest.ResponseRecorder {
		form := url.Values{"email": {"challenge@example.test"}, "password": {"Original!Password1"}, "mfa_code": {codes[0]}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleLogin(w, r, app)
		return w
	}
	passwordChangeExec(t, app.DB, `CREATE TRIGGER reject_inline_session BEFORE INSERT ON _benmore_sessions BEGIN SELECT RAISE(ABORT,'fixture inline session failure'); END`)
	if w := call(); stepCookieValue(w, sessionCookieName) != "" {
		t.Error("failed inline sign-in returned credential")
	}
	if challengeFactorState(t, app, uid) != before {
		t.Error("failed inline sign-in consumed factor")
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER reject_inline_session")
	if w := call(); stepCookieValue(w, sessionCookieName) == "" {
		t.Error("rolled-back inline MFA factor cannot retry")
	}
}

func TestSignInChallengesNeverExposedThroughCRUD(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "challenge-owner@example.test", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if mintSignInChallenge(app, tempCookieMFA, uid, "challenge-owner@example.test", "") == "" {
		t.Fatal("fixture challenge missing")
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		w := crudScopeRequest(t, mux, method, "/api/_benmore_signin_challenges", sid, map[string]any{"user_id": uid})
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("internal challenge route exposed: %s %d", method, w.Code)
		}
	}
	if n := recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_signin_challenges"); n != 1 {
		t.Fatal("CRUD mutated challenge store")
	}
}

func TestInlineMFARefusesStalePasswordProofWithoutSpendingFactor(t *testing.T) {
	app, _, uid, _, codes := loginChallengeFixture(t)
	_, hash, binding, err := mfaSetupAccountState(app, app.DB, uid, "challenge@example.test")
	if err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
	before := challengeFactorState(t, app, uid)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, nil)
	completeInlineMFALogin(w, r, app, uid, "challenge@example.test", "challenge@example.test", hash, binding, codes[0])
	if stepCookieValue(w, sessionCookieName) != "" || challengeFactorState(t, app, uid) != before {
		t.Fatal("stale inline proof changed factor/session state")
	}
}

func TestOTPChallengeCannotSkipNewlyActivatedMFA(t *testing.T) {
	app, mux, uid, secret, _ := loginChallengeFixture(t)
	RegisterMFARoutes(mux, app)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id=?", totpPendingPrefix+secret, uid)
	_, _, binding, err := mfaSetupAccountState(app, app.DB, uid, "challenge@example.test")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := signInWriteTx(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	code, step, err := prepareLoginOTPTx(app, tx, uid, "challenge@example.test", "challenge@example.test", binding)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	sid := createSignInSession(app.DB, uid, "challenge@example.test", "", app.SessionDuration)
	w := auditPost(mux, sid, "/api/_auth/mfa/verify", "", `{"code":"`+GenerateTOTP(secret)+`"}`, true)
	if w.Code != http.StatusOK || !CheckMFA(app.DB, uid) {
		t.Fatalf("MFA activation control failed: %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
	w = httptest.NewRecorder()
	handleVerifyOTP(w, r, app)
	if stepCookieValue(w, sessionCookieName) != "" || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 1 {
		t.Error("OTP proof started before MFA activation bypassed the newly enabled factor")
	}
	if token := mintSignInChallenge(app, tempCookieOTP, uid, "challenge@example.test", "challenge@example.test", binding); token != "" {
		t.Error("password proof from before MFA activation minted a new OTP continuation")
	}
}

func TestSignupOTPStillUsesEmailWithPhoneLogin(t *testing.T) {
	app := signupLimitFixture(t, map[string]string{"otp": "true", "identifier": "phone"})
	var w *httptest.ResponseRecorder
	out := captureLog(t, func() { w = postSignup(app, "signup-otp@example.test", "198.51.100.92:4000") })
	step := stepCookieValue(w, flowCookieName(flowCookieOTP, true))
	if w.Code != http.StatusOK || step == "" || !strings.Contains(out, "signup OTP email failed") {
		t.Fatalf("signup no longer attempts email delivery with phone login: status=%d step=%t email=%t", w.Code, step != "", strings.Contains(out, "signup OTP email failed"))
	}
	var code string
	if err := app.DB.QueryRow("SELECT code FROM _benmore_otp WHERE email=?", "signup-otp@example.test").Scan(&code); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
	w = httptest.NewRecorder()
	handleVerifyOTP(w, r, app)
	if stepCookieValue(w, sessionCookieName) == "" {
		t.Fatal("email signup challenge did not complete with phone login configured")
	}
}

func TestMFALoginTOTPFailureRollbackAndReplay(t *testing.T) {
	app, mux, uid, secret, _ := loginChallengeFixture(t)
	step := passwordLoginChallenge(t, app)
	code := GenerateTOTP(secret)
	before := challengeFactorState(t, app, uid)
	passwordChangeExec(t, app.DB, `CREATE TRIGGER reject_totp_session BEFORE INSERT ON _benmore_sessions BEGIN SELECT RAISE(ABORT,'fixture TOTP session failure'); END`)
	if w := postMFAStep(t, app, mux, step, code); stepCookieValue(w, sessionCookieName) != "" || challengeFactorState(t, app, uid) != before {
		t.Fatal("failed session save consumed TOTP or returned credential")
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER reject_totp_session")
	if w := postMFAStep(t, app, mux, step, code); stepCookieValue(w, sessionCookieName) == "" {
		t.Fatal("rolled-back TOTP proof did not complete")
	}
	step = passwordLoginChallenge(t, app)
	if w := postMFAStep(t, app, mux, step, code); stepCookieValue(w, sessionCookieName) != "" {
		t.Fatal("a fresh challenge replayed a consumed TOTP step")
	}
}

func TestMFALoginOTPChainCompletesOnce(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate_page", true: "inline"}[inline], func(t *testing.T) {
			app, mux, uid, _, codes := loginChallengeFixture(t)
			app.Design.Auth["otp"] = "true"
			var w *httptest.ResponseRecorder
			if inline {
				form := url.Values{"email": {"challenge@example.test"}, "password": {"Original!Password1"}, "mfa_code": {codes[0]}, "_csrf": {authMintCSRFToken("")}}
				r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w = httptest.NewRecorder()
				handleLogin(w, r, app)
			} else {
				step := passwordLoginChallenge(t, app)
				w = postMFAStep(t, app, mux, step, codes[0])
				if replay := postMFAStep(t, app, mux, step, codes[1]); stepCookieValue(replay, flowCookieName(flowCookieOTP, true)) != "" {
					t.Fatal("MFA challenge replay issued another OTP step")
				}
			}
			step := stepCookieValue(w, flowCookieName(flowCookieOTP, true))
			if step == "" || stepCookieValue(w, sessionCookieName) != "" || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 0 {
				t.Fatalf("MFA did not withhold session for OTP: status=%d", w.Code)
			}
			var code string
			if err := app.DB.QueryRow("SELECT code FROM _benmore_otp WHERE email=?", "challenge@example.test").Scan(&code); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
				w = httptest.NewRecorder()
				handleVerifyOTP(w, r, app)
				if (stepCookieValue(w, sessionCookieName) != "") != (i == 0) {
					t.Fatalf("OTP completion %d had wrong session outcome", i)
				}
			}
			if recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 1 {
				t.Fatal("MFA + OTP chain created wrong session count")
			}
		})
	}
}

func TestOTPCompletionUsesCurrentRequiredRole(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "primary", true: "global_grant"}[granted], func(t *testing.T) {
			app, _, uid, _, _ := loginChallengeFixture(t)
			app.Design.Auth["require_mfa_for_roles"] = "manager"
			passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=NULL,backup_codes=NULL WHERE id=?", uid)
			code, step, err := prepareLoginOTP(app, uid, "challenge@example.test", "challenge@example.test", "")
			if err != nil {
				t.Fatal(err)
			}
			// The role changes after issuance; completion must use the live role.
			if granted {
				EnsureUserRolesTable(app.DB)
				passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles(user_id,role) VALUES (?,'manager')", uid)
			} else {
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET role='manager' WHERE id=?", uid)
			}
			r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieOTP, true), Value: step})
			w := httptest.NewRecorder()
			handleVerifyOTP(w, r, app)
			if stepCookieValue(w, sessionCookieName) != "" || stepCookieValue(w, flowCookieName(flowCookieMFASetup, true)) == "" || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 0 {
				t.Fatal("OTP skipped current role's required MFA enrollment")
			}
		})
	}
}

func TestPlainPasswordSessionRechecksAcceptedProof(t *testing.T) {
	for _, change := range []string{"unchanged", "same_hash_reset", "mfa_activation", "required_role"} {
		t.Run(change, func(t *testing.T) {
			app, _, uid, _, _ := loginChallengeFixture(t)
			passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=NULL,backup_codes=NULL WHERE id=?", uid)
			_, _, binding, err := mfaSetupAccountState(app, app.DB, uid, "challenge@example.test")
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "same_hash_reset":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
			case "mfa_activation":
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret='active-fixture-secret', mfa_setup_nonce=lower(hex(randomblob(16))) WHERE id=?", uid)
			case "required_role":
				app.Design.Auth["require_mfa_for_roles"] = "manager"
				passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET role='manager' WHERE id=?", uid)
			}
			token, err := createPasswordSignInSession(app, uid, "challenge@example.test", "", binding)
			if change == "unchanged" {
				if err != nil || token == "" || GetSessionFromDB(app.DB, token) == nil {
					t.Fatal("unchanged password proof could not create a session")
				}
			} else if token != "" || err == nil || recoveryCount(t, app.DB, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=?", uid) != 0 {
				t.Fatal("stale password proof created a session")
			}
		})
	}
}

func TestPasswordEnrollmentGrantRechecksExactGeneration(t *testing.T) {
	app, _, uid, _, _ := loginChallengeFixture(t)
	_, hash, binding, err := mfaSetupAccountState(app, app.DB, uid, "challenge@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if mintMFASetupToken(app, uid, "challenge@example.test", hash, binding) == "" {
		t.Fatal("current accepted proof failed enrollment issuance")
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=password_hash WHERE id=?", uid)
	if mintMFASetupToken(app, uid, "challenge@example.test", hash, binding) != "" {
		t.Fatal("old same-hash proof minted a fresh enrollment grant")
	}
}
