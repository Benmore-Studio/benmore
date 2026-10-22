//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Disabling MFA is proven by a current TOTP code. Like the login MFA step it
// must be brute-force limited, or a stolen session can guess the 6 digits,
// remove the factor, and enroll its own.
func TestMFADisableIsBruteForceLimited(t *testing.T) {
	app, mux := auditApp(t)
	EnsureLoginAttemptsTable(app.DB)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	const secret = "JBSWY3DPEHPK3PXP"
	mustExec(t, app.DB, fmt.Sprintf("UPDATE _benmore_users SET totp_secret = '%s' WHERE id = %d", secret, uid))

	disable := func(code string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"code": code})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/mfa/disable", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 5; i++ {
		disable(fmt.Sprintf("guess%d", i))
	}
	w := disable(GenerateTOTP(secret))
	if !CheckMFA(app.DB, uid) {
		t.Fatalf("MFA disabled after five wrong codes: %d %s", w.Code, w.Body.String())
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked disable returned %d: %s", w.Code, w.Body.String())
	}
}
