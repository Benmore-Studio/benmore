//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mfaFactorAction(t *testing.T, mux *http.ServeMux, sid, action, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"code": code})
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/"+action, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestMFAEnrollmentSpendsActivationCode(t *testing.T) {
	app := recoveryHardeningApp(t)
	uid := recoveryUser(t, app, "enrollment@example.test", "", 1)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	grant := mintMFASetupToken(app, uid, "enrollment@example.test")
	secret := mfaRecoverySetup(t, mux, grant)
	code := GenerateTOTP(secret)
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d", w.Code)
	}
	if ValidateMFACode(app.DB, uid, code) {
		t.Fatal("enrollment code could be replayed for a second sign-in")
	}
}

func TestMFADisableRefusesSpentSignInCode(t *testing.T) {
	app, mux := auditApp(t)
	EnsureLoginAttemptsTable(app.DB)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	const secret = "JBSWY3DPEHPK3PXP"
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id=?", secret, uid)
	code := GenerateTOTP(secret)
	if !ValidateMFACode(app.DB, uid, code) {
		t.Fatal("unused sign-in code refused")
	}
	w := mfaFactorAction(t, mux, sid, "disable", code)
	if w.Code != http.StatusForbidden || !CheckMFA(app.DB, uid) {
		t.Fatalf("spent sign-in code disabled MFA: status=%d enabled=%t", w.Code, CheckMFA(app.DB, uid))
	}
}

func TestMFADisableFailureRollsBackCodeConsumption(t *testing.T) {
	app, mux := auditApp(t)
	EnsureLoginAttemptsTable(app.DB)
	// A legacy plaintext factor is resealed by successful consumption. Its
	// previous stored bytes must not prevent removal in the same transaction.
	withTOTPKey(t, app, testKeyBytes(0x3D), false)
	app.DB.SetMaxOpenConns(1)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	const secret = "JBSWY3DPEHPK3PXP"
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=? WHERE id=?", secret, uid)
	passwordChangeExec(t, app.DB, `CREATE TRIGGER fixture_refuse_factor_removal BEFORE UPDATE OF totp_secret ON _benmore_users
		WHEN NEW.totp_secret IS NULL BEGIN SELECT RAISE(ABORT, 'synthetic factor removal failure'); END`)
	code := GenerateTOTP(secret)
	w := mfaFactorAction(t, mux, sid, "disable", code)
	if w.Code != http.StatusInternalServerError || !CheckMFA(app.DB, uid) {
		t.Fatalf("failed removal was not rolled back: %d", w.Code)
	}
	var consumed string
	if err := app.DB.QueryRow("SELECT COALESCE(mfa_last_totp,'') FROM _benmore_users WHERE id=?", uid).Scan(&consumed); err != nil || consumed != "" {
		t.Fatalf("failed removal consumed code: %q %v", consumed, err)
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER fixture_refuse_factor_removal")
	w = mfaFactorAction(t, mux, sid, "disable", code)
	if w.Code != http.StatusOK || CheckMFA(app.DB, uid) {
		t.Fatalf("unused code did not disable after storage recovered: %d", w.Code)
	}
}

func TestMFAEnrollmentFailureRollsBackCodeConsumption(t *testing.T) {
	app := recoveryHardeningApp(t)
	app.DB.SetMaxOpenConns(1)
	uid := recoveryUser(t, app, "enrollment-rollback@example.test", "", 1)
	mux := http.NewServeMux()
	RegisterMFARoutes(mux, app)
	grant := mintMFASetupToken(app, uid, "enrollment-rollback@example.test")
	secret := mfaRecoverySetup(t, mux, grant)
	passwordChangeExec(t, app.DB, `CREATE TRIGGER fixture_refuse_enrollment_session BEFORE INSERT ON _benmore_sessions
		BEGIN SELECT RAISE(ABORT, 'synthetic session failure'); END`)
	code := GenerateTOTP(secret)
	w := mfaRecoveryCall(mux, grant, "verify", `{"code":"`+code+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failed enrollment status: %d", w.Code)
	}
	var consumed string
	if err := app.DB.QueryRow("SELECT COALESCE(mfa_last_totp,'') FROM _benmore_users WHERE id=?", uid).Scan(&consumed); err != nil || consumed != "" {
		t.Fatalf("failed enrollment consumed code: %q %v", consumed, err)
	}
	passwordChangeExec(t, app.DB, "DROP TRIGGER fixture_refuse_enrollment_session")
	w = mfaRecoveryCall(mux, grant, "verify", `{"code":"`+code+`"}`)
	if w.Code != http.StatusOK || !CheckMFA(app.DB, uid) {
		t.Fatalf("enrollment could not retry: %d", w.Code)
	}
	if ValidateMFACode(app.DB, uid, code) {
		t.Fatal("committed enrollment left code replayable")
	}
	// A different factor's watermark must not carry over across enrollment.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret=NULL,mfa_last_totp=? WHERE id=?", "s:9999999999", uid)
	grant = mintMFASetupToken(app, uid, "enrollment-rollback@example.test")
	secret = mfaRecoverySetup(t, mux, grant)
	w = mfaRecoveryCall(mux, grant, "verify", `{"code":"`+GenerateTOTP(secret)+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("previous factor watermark blocked replacement: %d", w.Code)
	}
	var at string
	if err := app.DB.QueryRow("SELECT mfa_last_totp_at FROM _benmore_users WHERE id=?", uid).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Fatal("enrollment did not persist the consumed-code timestamp")
	}
}
