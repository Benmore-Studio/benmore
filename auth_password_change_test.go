//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func passwordChangeFixture(t *testing.T) (*App, *http.ServeMux, int64, string, string) {
	t.Helper()
	app, mux := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	registerPasswordChangeRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	tok := auditToken(t, app, sid, "*")
	hash, err := bcrypt.GenerateFromPassword([]byte("Temporary!123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=?,password_change_required=1 WHERE id=?", string(hash), uid)
	passwordChangeExec(t, app.DB, "INSERT INTO notes(user_id,title) VALUES (?,?)", uid, "private")
	return app, mux, uid, sid, tok
}

func passwordChangeRequest(sid, current, next string, csrf bool) *http.Request {
	form := url.Values{"current_password": {current}, "new_password": {next}, "confirm_password": {next}}
	if csrf {
		form.Set("_csrf", authMintCSRFToken(sid))
	}
	r := httptest.NewRequest(http.MethodPost, passwordChangeAPIPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	return r
}

func TestRequiredPasswordChangeCannotBypassOTPUsingPasswordToken(t *testing.T) {
	app, _, uid, _, _ := passwordChangeFixture(t)
	app.Design = &DesignConfig{Auth: map[string]string{"otp": "true"}}
	var email string
	if err := app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id=?", uid).Scan(&email); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"email": email, "password": "Temporary!123"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/_auth/token", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleTokenAuth(w, r, app)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "password_change_required") || strings.Contains(w.Body.String(), `"token":`) {
		t.Fatalf("password token bypass: %d %s", w.Code, w.Body.String())
	}
}

func TestRequiredPasswordChangeDeniesCredentialSurfaces(t *testing.T) {
	app, mux, uid, sid, tok := passwordChangeFixture(t)
	if GetSessionFromDB(app.DB, sid) != nil {
		t.Fatal("pending cookie/session accepted")
	}
	if GetSessionFromAPIToken(app.DB, tok) != nil {
		t.Fatal("pending API token accepted")
	}
	if actor, err := loadScheduledActor(app, uid, nil); err == nil || actor != nil {
		t.Fatal("pending scheduled authority accepted")
	}
	for _, credential := range []string{sid, tok} {
		r := httptest.NewRequest("GET", "/api/notes", nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("protected read: %d %s", w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/dashboard", "/api/notes", "/api/_auth/api-tokens", "/auth/change-password/extra"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		passwordChangeMiddleware(mux, app).ServeHTTP(w, r)
		if strings.HasPrefix(path, "/api/") {
			if w.Code != 403 || !strings.Contains(w.Body.String(), "password_change_required") {
				t.Fatalf("API gate %s: %d %s", path, w.Code, w.Body.String())
			}
		} else if w.Code != 303 || w.Header().Get("Location") != passwordChangePagePath {
			t.Fatalf("page gate %s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", passwordChangePagePath, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	passwordChangeMiddleware(mux, app).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "autocomplete=\"new-password\"") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("change form unavailable: %d", w.Code)
	}
}

func TestRequiredPasswordChangeValidation(t *testing.T) {
	for _, tc := range []struct {
		name, current, next string
		csrf                bool
		status              int
	}{
		{"csrf", "Temporary!123", "Replacement!123", false, 403},
		{"wrong proof", "Wrong!123", "Replacement!123", true, 403},
		{"same password", "Temporary!123", "Temporary!123", true, 400},
		{"weak password", "Temporary!123", "short", true, 400},
		{"bcrypt byte limit", "Temporary!123", strings.Repeat("A", 72) + "!", true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, mux, uid, sid, _ := passwordChangeFixture(t)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, passwordChangeRequest(sid, tc.current, tc.next, tc.csrf))
			if w.Code != tc.status {
				t.Fatalf("status=%d: %s", w.Code, w.Body.String())
			}
			var pending int
			if err := app.DB.QueryRow("SELECT password_change_required FROM _benmore_users WHERE id=?", uid).Scan(&pending); err != nil || pending != 1 {
				t.Fatalf("gate changed: %d %v", pending, err)
			}
		})
	}
}

func TestRequiredPasswordChangeRevokesAndAuditsAtomically(t *testing.T) {
	app, mux, uid, sid, tok := passwordChangeFixture(t)
	other := CreateSession(app.DB, uid, "member@test.com", "", time.Hour)
	passwordChangeExec(t, app.DB, "CREATE TABLE _benmore_oauth_codes (id INTEGER PRIMARY KEY,user_id INTEGER)")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_oauth_codes(user_id) VALUES (?)", uid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
	if w.Code != 200 {
		t.Fatalf("change failed: %d %s", w.Code, w.Body.String())
	}
	var hash string
	var pending int
	if err := app.DB.QueryRow("SELECT password_hash,password_change_required FROM _benmore_users WHERE id=?", uid).Scan(&hash, &pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || bcrypt.CompareHashAndPassword([]byte(hash), []byte("Replacement!123")) != nil {
		t.Fatal("new credential not committed")
	}
	if GetSessionFromDB(app.DB, sid) != nil || GetSessionFromDB(app.DB, other) != nil || GetSessionFromAPIToken(app.DB, tok) != nil {
		t.Fatal("old credentials survived")
	}
	for _, table := range []string{"_benmore_sessions", "_benmore_api_tokens", "_benmore_oauth_codes"} {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE user_id=?", uid).Scan(&n); err != nil || n != 0 {
			t.Fatalf("revocation %s: %d %v", table, n, err)
		}
	}
	var audit int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action='required_password_change' AND user_id=?", uid).Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("audit=%d %v", audit, err)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Another!123", true))
	if w.Code != 401 {
		t.Fatalf("replay accepted: %d", w.Code)
	}
	fresh := CreateSession(app.DB, uid, "member@test.com", "", time.Hour)
	if GetSessionFromDB(app.DB, fresh) == nil {
		t.Fatal("fresh session denied after password replacement")
	}
}

func TestRequiredPasswordChangeRollsBackOnRevocationFailure(t *testing.T) {
	app, mux, uid, sid, tok := passwordChangeFixture(t)
	passwordChangeExec(t, app.DB, "CREATE TRIGGER fail_revoke BEFORE DELETE ON _benmore_api_tokens BEGIN SELECT RAISE(ABORT,'synthetic revocation failure'); END")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
	if w.Code != 500 {
		t.Fatalf("failed revocation returned %d", w.Code)
	}
	var hash string
	var flag int
	if err := app.DB.QueryRow("SELECT password_hash,password_change_required FROM _benmore_users WHERE id=?", uid).Scan(&hash, &flag); err != nil {
		t.Fatal(err)
	}
	if flag != 1 || bcrypt.CompareHashAndPassword([]byte(hash), []byte("Temporary!123")) != nil {
		t.Fatal("failed transaction changed credential")
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE id=?", sid).Scan(&n); err != nil || n != 1 {
		t.Fatal("session deletion did not roll back")
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE token_hash=?", hashToken(tok)).Scan(&n); err != nil || n != 1 {
		t.Fatal("token deletion did not roll back")
	}
}

func TestRequiredPasswordChangeRejectsDelegatedSessions(t *testing.T) {
	for _, column := range []string{"is_impersonation", "acting_as_group", "scopes"} {
		t.Run(column, func(t *testing.T) {
			app, mux, _, sid, _ := passwordChangeFixture(t)
			value := "1"
			if column == "scopes" {
				value = "notes:read"
			}
			passwordChangeExec(t, app.DB, "UPDATE _benmore_sessions SET "+column+"=? WHERE id=?", value, sid)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
			if w.Code != 403 {
				t.Fatalf("delegated password change accepted: %d", w.Code)
			}
		})
	}
}

func passwordChangeExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredPasswordChangeRecoveryIsAtomic(t *testing.T) {
	for _, failRevoke := range []bool{false, true} {
		t.Run(fmt.Sprint(failRevoke), func(t *testing.T) {
			app, _, uid, sid, _ := passwordChangeFixture(t)
			EnsurePasswordResetsTable(app.DB)
			passwordChangeExec(t, app.DB, "INSERT INTO _benmore_password_resets(token,email,expires_at) SELECT ?,email,datetime('now','+1 hour') FROM _benmore_users WHERE id=?", hashResetToken("synthetic-reset"), uid)
			if failRevoke {
				passwordChangeExec(t, app.DB, "CREATE TRIGGER fail_reset_revoke BEFORE DELETE ON _benmore_sessions BEGIN SELECT RAISE(ABORT,'synthetic'); END")
			}
			form := url.Values{"token": {"synthetic-reset"}, "password": {"Replacement!123"}, "confirm": {"Replacement!123"}}
			r := httptest.NewRequest("POST", app.Paths.ResetPassword, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handleResetPassword(w, r, app)
			var flag, used, sessions int
			if err := app.DB.QueryRow("SELECT password_change_required FROM _benmore_users WHERE id=?", uid).Scan(&flag); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT used FROM _benmore_password_resets WHERE token=?", hashResetToken("synthetic-reset")).Scan(&used); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE id=?", sid).Scan(&sessions); err != nil {
				t.Fatal(err)
			}
			if failRevoke {
				if flag != 1 || used != 0 || sessions != 1 {
					t.Fatalf("failure did not roll back: flag=%d used=%d sessions=%d", flag, used, sessions)
				}
			} else if flag != 0 || used != 1 || sessions != 0 || !strings.HasPrefix(w.Header().Get("Location"), app.Paths.Login) {
				t.Fatalf("reset failed: flag=%d used=%d sessions=%d location=%s", flag, used, sessions, w.Header().Get("Location"))
			}
		})
	}
}

func TestRequiredPasswordChangeUpgradesLegacySchema(t *testing.T) {
	app, _ := auditApp(t)
	passwordChangeExec(t, app.DB, "ALTER TABLE _benmore_users DROP COLUMN password_change_required")
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	var notNull int
	var defaultValue string
	if err := app.DB.QueryRow(`SELECT "notnull",dflt_value FROM pragma_table_info('_benmore_users') WHERE name='password_change_required'`).Scan(&notNull, &defaultValue); err != nil {
		t.Fatal(err)
	}
	if notNull != 1 || defaultValue != "0" {
		t.Fatalf("migration contract: notnull=%d default=%s", notNull, defaultValue)
	}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordRecoveryForAccountWithoutPassword(t *testing.T) {
	app, _, uid, _, _ := passwordChangeFixture(t)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash=NULL,password_change_required=0 WHERE id=?", uid)
	EnsurePasswordResetsTable(app.DB)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_password_resets(token,email,expires_at) SELECT ?,email,datetime('now','+1 hour') FROM _benmore_users WHERE id=?", hashResetToken("synthetic-reset"), uid)
	form := url.Values{"token": {"synthetic-reset"}, "password": {"Replacement!123"}, "confirm": {"Replacement!123"}}
	r := httptest.NewRequest("POST", app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, app)
	var hash string
	if err := app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id=?", uid).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("Replacement!123")) != nil || !strings.HasPrefix(w.Header().Get("Location"), app.Paths.Login) {
		t.Fatalf("passwordless account recovery failed: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestRequiredPasswordChangeAcceptsJSONWithBearerSession(t *testing.T) {
	_, mux, _, sid, _ := passwordChangeFixture(t)
	r := httptest.NewRequest("POST", passwordChangeAPIPath, strings.NewReader(`{"current_password":"Temporary!123","new_password":"Replacement!123","confirm_password":"Replacement!123"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("bearer change failed: %d %s", w.Code, w.Body.String())
	}
}

func TestRequiredPasswordChangeAfterOTPVerification(t *testing.T) {
	app, mux, uid, _, _ := passwordChangeFixture(t)
	var email string
	if err := app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id=?", uid).Scan(&email); err != nil {
		t.Fatal(err)
	}
	// Synthetic proof exercises the existing OTP completion path without mail.
	passwordChangeExec(t, app.DB, "CREATE TABLE _benmore_otp (email TEXT,code TEXT,attempts INTEGER DEFAULT 0,expires_at DATETIME)")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_otp(email,code,expires_at) VALUES (?,'123456',datetime('now','+10 minutes'))", email)
	r := httptest.NewRequest("POST", app.Paths.VerifyOTP, strings.NewReader("code=123456"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "_benmore_otp_uid", Value: signTempCookie(fmt.Sprintf("%d|%s|%s", uid, email, email))})
	w := httptest.NewRecorder()
	handleVerifyOTP(w, r, app)
	var sid string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sid = cookie.Value
		}
	}
	if sid == "" || GetSessionFromDB(app.DB, sid) != nil {
		t.Fatal("OTP must issue only a restricted session for a pending account")
	}
	r = httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w = httptest.NewRecorder()
	passwordChangeMiddleware(mux, app).ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != passwordChangePagePath {
		t.Fatalf("OTP session did not reach password change: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	passwordChangeMiddleware(mux, app).ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
	if w.Code != 200 {
		t.Fatalf("OTP session cannot replace password: %d %s", w.Code, w.Body.String())
	}
}

func TestGeneratedPasswordChangeTestsExerciseRegisteredRoutes(t *testing.T) {
	app, mux, _, _, _ := passwordChangeFixture(t)
	server := httptest.NewServer(passwordChangeMiddleware(mux, app))
	t.Cleanup(server.Close)
	tests := generatePasswordChangeTests(app)
	for name, tc := range tests.Tests {
		t.Run(name, func(t *testing.T) {
			if result := runSingleTest(app, server.URL, tests.Name, name, tc); !result.Pass {
				t.Fatalf("generated framework check failed: %+v", result)
			}
		})
	}
}

func TestRequiredPasswordChangeConcurrentRequestsHaveOneWinner(t *testing.T) {
	_, mux, _, sid, _ := passwordChangeFixture(t)
	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, passwordChangeRequest(sid, "Temporary!123", "Replacement!123", true))
			results <- w.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for code := range results {
		switch code {
		case 200:
			winners++
		case 401, 409:
		default:
			t.Errorf("unexpected concurrent response: %d", code)
		}
	}
	if winners != 1 {
		t.Fatalf("password changes committed=%d, want one", winners)
	}
}

func TestRequiredPasswordChangeInvalidatesExistingRealtimePrincipal(t *testing.T) {
	app, _, uid, sid, _ := passwordChangeFixture(t)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=0 WHERE id=?", uid)
	r := httptest.NewRequest("GET", "/sse/events", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	p := realtimePrincipal{app: app, request: r, session: getSession(app, r)}
	if p.session == nil {
		t.Fatal("fixture has no initial identity")
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required=1 WHERE id=?", uid)
	if _, valid := p.current(); valid {
		t.Fatal("connected principal survived password-change restriction")
	}
}
