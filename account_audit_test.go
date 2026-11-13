//go:build !cli

package main

import (
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	accountAuditEmail    = "amy@example.com"
	accountAuditPassword = "Correct-Horse-1"
)

// accountAuditFixture is one account of an app that serves the sign-in,
// second-factor and settings routes over the product database driver.
type accountAuditFixture struct {
	t   *testing.T
	app *App
	mux *http.ServeMux
	uid int64
	sid string // a sign-in session of the account
}

func newAccountAuditFixture(t *testing.T, hipaa bool) *accountAuditFixture {
	t.Helper()
	return newAccountAuditFixtureWith(t, hipaa, nil)
}

// newAccountAuditFixtureWith runs configure on the app before its first
// route is registered.
func newAccountAuditFixtureWith(t *testing.T, hipaa bool, configure func(*App)) *accountAuditFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour, Paths: DiscoverAuthPaths(nil),
		Design: &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.example"}}}
	if hipaa {
		app.Design.Compliance = complianceHIPAA
	}
	t.Cleanup(app.Shutdown)
	if configure != nil {
		configure(app)
	}
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	RegisterMFARoutes(mux, app)
	RegisterSettingsRoutes(mux, app)
	if hipaa {
		if err := ensureAuditAppendOnly(app); err != nil {
			t.Fatal(err)
		}
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(accountAuditPassword), bcrypt.MinCost)
	res, err := db.Exec(`INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('amy', ?, ?, 1)`, accountAuditEmail, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	f := &accountAuditFixture{t: t, app: app, mux: mux, uid: uid}
	f.sid = f.session()
	return f
}

func (f *accountAuditFixture) session() string {
	f.t.Helper()
	sid := CreateSession(f.app.DB, f.uid, accountAuditEmail, "", time.Hour)
	if sid == "" {
		f.t.Fatal("no session")
	}
	return sid
}

// call sends a JSON request as the holder of the Bearer credential ("" for
// none) and returns the status and the decoded body.
func (f *accountAuditFixture) call(method, path, bearer string, body any) (int, map[string]any) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

type accountAuditRow struct {
	table, rowID, email, old, new string
	userID                        int64
}

func (f *accountAuditFixture) rows(action string) []accountAuditRow {
	f.t.Helper()
	rows, err := f.app.DB.Query(`SELECT table_name, COALESCE(row_id, ''), COALESCE(user_id, 0), COALESCE(user_email, ''),
		COALESCE(old_values, ''), COALESCE(new_values, '') FROM _benmore_audit_log WHERE action = ? ORDER BY id`, action)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []accountAuditRow
	for rows.Next() {
		var r accountAuditRow
		if err := rows.Scan(&r.table, &r.rowID, &r.userID, &r.email, &r.old, &r.new); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// one is the single row of an action, written by the account under its
// address, on the given table and row.
func (f *accountAuditFixture) one(action, table, rowID string) accountAuditRow {
	f.t.Helper()
	rows := f.rows(action)
	if len(rows) != 1 {
		f.t.Fatalf("%d %s audit rows, want exactly 1: %+v", len(rows), action, rows)
	}
	r := rows[0]
	if r.table != table || r.rowID != rowID || r.userID != f.uid || r.email != accountAuditEmail {
		f.t.Fatalf("%s row = %+v, want table %s row %s by account %d <%s>", action, r, table, rowID, f.uid, accountAuditEmail)
	}
	return r
}

func (f *accountAuditFixture) none(action, why string) {
	f.t.Helper()
	if rows := f.rows(action); len(rows) != 0 {
		f.t.Fatalf("%s: %d %s audit rows: %+v", why, len(rows), action, rows)
	}
}

// noSecret fails when any column of any audit row holds one of the secrets.
func (f *accountAuditFixture) noSecret(secrets ...string) {
	f.t.Helper()
	rows, err := f.app.DB.Query(`SELECT action, COALESCE(row_id, '') || ' ' || COALESCE(user_email, '') || ' ' || COALESCE(old_values, '') || ' ' || COALESCE(new_values, '') FROM _benmore_audit_log`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, text string
		if err := rows.Scan(&action, &text); err != nil {
			f.t.Fatal(err)
		}
		for _, secret := range secrets {
			if secret == "" {
				f.t.Fatal("fixture: empty secret")
			}
			if strings.Contains(text, secret) {
				f.t.Fatalf("the %s audit row holds a secret (%q): %s", action, secret, text)
			}
		}
	}
}

// totpAt is the account's code for a time step.
func totpAt(t *testing.T, secretB32 string, step uint64) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	return computeHOTP(secret, step)
}

// totpStep is the current time step, taken with room before the next one so
// the codes a test derives from it are all still accepted when it sends them.
func totpStep() uint64 {
	if left := 30 - time.Now().Unix()%30; left < 4 {
		time.Sleep(time.Duration(left) * time.Second)
	}
	return uint64(time.Now().Unix() / 30)
}

// enroll runs setup and verify as the session's holder and returns the secret,
// the backup codes and the time step whose code the factor has now spent.
func (f *accountAuditFixture) enroll(sid string) (secret string, codes []string, spent uint64) {
	f.t.Helper()
	code, out := f.call("POST", "/api/_auth/mfa/setup", sid, map[string]string{"password": accountAuditPassword})
	if code != http.StatusOK {
		f.t.Fatalf("mfa setup: %d %v", code, out)
	}
	secret, _ = out["secret"].(string)
	for _, c := range out["backup_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	spent = totpStep() - 1
	if code, out := f.call("POST", "/api/_auth/mfa/verify", sid, map[string]string{"code": totpAt(f.t, secret, spent)}); code != http.StatusOK {
		f.t.Fatalf("mfa verify: %d %v", code, out)
	}
	return secret, codes, spent
}

func (f *accountAuditFixture) uidText() string { return strconv.FormatInt(f.uid, 10) }

// Starting an enrollment records the backup codes it issued, activating the
// factor records the enrollment, removing it records the removal; a wrong
// code records nothing, and no row holds the secret or a code.
func TestAccountAuditMFAEnrollmentAndRemoval(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	code, out := f.call("POST", "/api/_auth/mfa/setup", f.sid, map[string]string{"password": accountAuditPassword})
	if code != http.StatusOK {
		t.Fatalf("mfa setup: %d %v", code, out)
	}
	secret, _ := out["secret"].(string)
	var codes []string
	for _, c := range out["backup_codes"].([]any) {
		codes = append(codes, c.(string))
	}
	if r := f.one("mfa_backup_codes_generated", "_benmore_users", f.uidText()); !strings.Contains(r.new, `"count":10`) {
		t.Fatalf("the row does not say how many codes were issued: %s", r.new)
	}
	f.none("mfa_enrolled", "the factor is not active before a code proves it")

	step := totpStep()
	if code, _ := f.call("POST", "/api/_auth/mfa/verify", f.sid, map[string]string{"code": "000000"}); code != http.StatusForbidden {
		t.Fatalf("a wrong code activated the factor: %d", code)
	}
	f.none("mfa_enrolled", "a refused code")
	if code, out := f.call("POST", "/api/_auth/mfa/verify", f.sid, map[string]string{"code": totpAt(t, secret, step-1)}); code != http.StatusOK {
		t.Fatalf("mfa verify: %d %v", code, out)
	}
	if r := f.one("mfa_enrolled", "_benmore_users", f.uidText()); r.new != `{"factor":"totp"}` {
		t.Fatalf("mfa_enrolled values = %s", r.new)
	}

	if code, _ := f.call("POST", "/api/_auth/mfa/disable", f.sid, map[string]string{"code": "000000"}); code != http.StatusForbidden {
		t.Fatalf("a wrong code removed the factor: %d", code)
	}
	f.none("mfa_removed", "a refused code")
	if code, out := f.call("POST", "/api/_auth/mfa/disable", f.sid, map[string]string{"code": totpAt(t, secret, step)}); code != http.StatusOK {
		t.Fatalf("mfa disable: %d %v", code, out)
	}
	if r := f.one("mfa_removed", "_benmore_users", f.uidText()); r.old != `{"factor":"totp"}` || r.new != "" {
		t.Fatalf("mfa_removed values = %s / %s", r.old, r.new)
	}
	var stored string
	f.app.DB.QueryRow(`SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?`, f.uid).Scan(&stored)
	if stored != "" {
		t.Fatal("the factor is still there")
	}
	f.noSecret(append(codes, secret)...)
}

// A backup code spent at sign-in is recorded once, with how many are left and
// never the code; a code that was refused, or spent before, records nothing.
func TestAccountAuditBackupCodeUse(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	_, codes, _ := f.enroll(f.sid)
	signIn := func(mfaCode string) int {
		code, _ := f.call("POST", "/api/_auth/token", "", map[string]string{"email": accountAuditEmail, "password": accountAuditPassword, "mfa_code": mfaCode})
		return code
	}
	if code := signIn("not-a-backup-code"); code == http.StatusOK {
		t.Fatal("a made-up backup code signed in")
	}
	f.none("mfa_backup_code_used", "a refused code")
	if code := signIn(codes[0]); code != http.StatusOK {
		t.Fatalf("sign-in with a backup code: %d", code)
	}
	if r := f.one("mfa_backup_code_used", "_benmore_users", f.uidText()); r.new != `{"remaining":9}` {
		t.Fatalf("mfa_backup_code_used values = %s", r.new)
	}
	if code := signIn(codes[0]); code == http.StatusOK {
		t.Fatal("a spent backup code signed in again")
	}
	f.one("mfa_backup_code_used", "_benmore_users", f.uidText())
	f.noSecret(codes...)
}

// Minting and revoking an API token each record one row naming the token by
// id, name and scopes; neither holds the token or its stored hash.
func TestAccountAuditAPITokenMintAndRevoke(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	code, out := f.call("POST", "/api/_auth/api-tokens", f.sid, map[string]string{"name": "ci deploys", "scopes": "notes:read", "expires_in": "30d"})
	token, _ := out["token"].(string)
	if code != http.StatusOK || token == "" {
		t.Fatalf("mint: %d %v", code, out)
	}
	var id int64
	if err := f.app.DB.QueryRow(`SELECT id FROM _benmore_api_tokens WHERE token_hash = ?`, hashToken(token)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tokenID := strconv.FormatInt(id, 10)
	created := f.one("api_token_created", "_benmore_api_tokens", tokenID)
	var values map[string]any
	if err := json.Unmarshal([]byte(created.new), &values); err != nil || values["name"] != "ci deploys" || values["scopes"] != "notes:read" || values["expires_at"] != out["expires_at"] {
		t.Fatalf("api_token_created values = %s (%v), want the name, scopes and expiry %v", created.new, err, out["expires_at"])
	}

	if code, _ := f.call("DELETE", "/api/_auth/api-tokens/"+tokenID, f.sid, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if r := f.one("api_token_revoked", "_benmore_api_tokens", tokenID); r.old != `{"name":"ci deploys","scopes":"notes:read"}` {
		t.Fatalf("api_token_revoked values = %s", r.old)
	}
	if code, _ := f.call("DELETE", "/api/_auth/api-tokens/"+tokenID, f.sid, nil); code != http.StatusNotFound {
		t.Fatalf("revoking a token that is gone: %d", code)
	}
	f.one("api_token_revoked", "_benmore_api_tokens", tokenID)
	f.noSecret(token, strings.TrimPrefix(token, "bmr_"), hashToken(token))
}

// Ending one of the account's sessions records one row under the id the
// session list shows; the row holds neither the session token nor its key.
func TestAccountAuditSessionRevoked(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	other := f.session()
	listed := sessionOpaqueID(sessionStorageKey(other))
	if code, out := f.call("DELETE", "/api/_auth/sessions/"+listed, f.sid, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if r := f.one("session_revoked", "_benmore_sessions", listed); r.new != `{"current":false}` {
		t.Fatalf("session_revoked values = %s", r.new)
	}
	if GetSessionFromDB(f.app.DB, other) != nil {
		t.Fatal("the session is still there")
	}
	if code, _ := f.call("DELETE", "/api/_auth/sessions/"+listed, f.sid, nil); code != http.StatusNotFound {
		t.Fatalf("revoking a session that is gone: %d", code)
	}
	f.one("session_revoked", "_benmore_sessions", listed)
	f.noSecret(other, sessionStorageKey(other), f.sid, sessionStorageKey(f.sid))
}

// confirmPending replaces the account's pending email change with one for a
// known link token (the mailed token is never stored) and confirms it with
// the account's password.
func (f *accountAuditFixture) confirmPending(newEmail, token string) int {
	f.t.Helper()
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_email_changes WHERE user_id = ?`, f.uid); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
		f.uid, newEmail, hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		f.t.Fatal(err)
	}
	form := url.Values{"token": {token}, "_csrf": {authMintCSRFToken("")}, "password": {accountAuditPassword}}
	r := httptest.NewRequest(http.MethodPost, "/settings/confirm-email", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w.Code
}

// requestEmail asks for an email change through the profile API.
func (f *accountAuditFixture) requestEmail(sid, newEmail string) (int, map[string]any) {
	f.t.Helper()
	return f.call("PATCH", "/api/_auth/profile", sid, map[string]string{"email": newEmail, "current_password": accountAuditPassword})
}

// An email change records the request (current and requested address) and
// the confirmed change (old and new address), each once, with the link token
// in neither; a confirmation refused for a wrong password records nothing.
func TestAccountAuditEmailChange(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	EnsureLoginAttemptsTable(f.app.DB)
	mail := captureSMTP(t, f.app)
	const next = "amy@new.example"
	if code, out := f.requestEmail(f.sid, next); code != http.StatusAccepted {
		t.Fatalf("email change request: %d %v", code, out)
	}
	if got := <-mail; got.err != nil || len(got.recipients) != 1 {
		t.Fatalf("confirmation mail: %+v", got)
	}
	r := f.one("email_change_requested", "_benmore_users", f.uidText())
	if r.old != `{"email":"amy@example.com"}` || r.new != `{"requested_email":"amy@new.example"}` {
		t.Fatalf("email_change_requested values = %s / %s", r.old, r.new)
	}
	f.none("email_changed", "nothing changes before the new inbox confirms")

	const token = "link-token-of-the-confirmation-mail"
	form := url.Values{"token": {token}, "_csrf": {authMintCSRFToken("")}, "password": {"not-the-password"}}
	if _, err := f.app.DB.Exec(`UPDATE _benmore_email_changes SET token_hash = ? WHERE user_id = ?`, hashResetToken(token), f.uid); err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRequest(http.MethodPost, "/settings/confirm-email", strings.NewReader(form.Encode()))
	wrong.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, wrong)
	if got := currentEmail(t, f.app, f.uid); got != accountAuditEmail {
		t.Fatalf("a wrong password confirmed the change (%d): %s", w.Code, got)
	}
	f.none("email_changed", "a refused confirmation")

	if code := f.confirmPending(next, token); currentEmail(t, f.app, f.uid) != next {
		t.Fatalf("the change was not applied (%d)", code)
	}
	// Recorded under the address the account held when it confirmed.
	r = f.one("email_changed", "_benmore_users", f.uidText())
	if r.old != `{"email":"amy@example.com"}` || r.new != `{"email":"amy@new.example"}` {
		t.Fatalf("email_changed values = %s / %s", r.old, r.new)
	}
	f.one("email_change_requested", "_benmore_users", f.uidText())
	f.noSecret(token, hashResetToken(token), accountAuditPassword)
}

// A request whose confirmation mail cannot be sent is refused and leaves no
// pending change, and the request the account made is still on record.
func TestAccountAuditEmailChangeRequestKeptWhenMailFails(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	if code, _ := f.requestEmail(f.sid, "amy@new.example"); code == http.StatusAccepted {
		t.Fatal("fixture: the request succeeded with no mail provider")
	}
	var pending int
	f.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_email_changes`).Scan(&pending)
	if pending != 0 {
		t.Fatal("a failed request left a pending change")
	}
	f.one("email_change_requested", "_benmore_users", f.uidText())
}

// A row that cannot be written refuses the change it would record: the audit
// row is part of the change, not a note made after it.
func TestAccountEventIsRefusedWhenItsAuditRowCannotBeWritten(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	other := f.session()
	if _, err := f.app.DB.Exec(`CREATE TRIGGER refuse_account_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'audit log refused'); END`); err != nil {
		t.Fatal(err)
	}
	if code, out := f.call("POST", "/api/_auth/api-tokens", f.sid, map[string]string{"name": "ci", "scopes": "*"}); code == http.StatusOK {
		t.Fatalf("a token was minted with no audit row: %v", out)
	}
	var tokens int
	f.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_api_tokens`).Scan(&tokens)
	if tokens != 0 {
		t.Fatal("the token was stored although its audit row was refused")
	}
	if code, _ := f.call("DELETE", "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(other)), f.sid, nil); code == http.StatusOK {
		t.Fatal("a session was ended with no audit row")
	}
	if GetSessionFromDB(f.app.DB, other) == nil {
		t.Fatal("the session was ended although its audit row was refused")
	}
	if code, _ := f.call("POST", "/api/_auth/mfa/setup", f.sid, map[string]string{"password": accountAuditPassword}); code == http.StatusOK {
		t.Fatal("an enrollment started with no audit row")
	}
	var pendingSecret string
	f.app.DB.QueryRow(`SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?`, f.uid).Scan(&pendingSecret)
	if pendingSecret != "" {
		t.Fatal("the pending factor was stored although its audit row was refused")
	}
}

// Under compliance: hipaa the audit tables are append-only. Every account
// event still writes its row, once, and the triggers are intact afterwards.
func TestAccountAuditEventsUnderHIPAAAppendOnly(t *testing.T) {
	f := newAccountAuditFixture(t, true)
	EnsureLoginAttemptsTable(f.app.DB)
	// The account must enroll before its session is of any other use.
	secret, codes, spent := f.enroll(f.sid)

	code, out := f.call("POST", "/api/_auth/api-tokens", f.sid, map[string]string{"name": "ci", "scopes": "*", "expires_in": "30d"})
	token, _ := out["token"].(string)
	if code != http.StatusOK || token == "" {
		t.Fatalf("mint: %d %v", code, out)
	}
	var tokenID int64
	f.app.DB.QueryRow(`SELECT id FROM _benmore_api_tokens WHERE token_hash = ?`, hashToken(token)).Scan(&tokenID)
	if code, out := f.call("DELETE", fmt.Sprintf("/api/_auth/api-tokens/%d", tokenID), f.sid, nil); code != http.StatusOK {
		t.Fatalf("revoke token: %d %v", code, out)
	}
	other := f.session()
	if code, out := f.call("DELETE", "/api/_auth/sessions/"+sessionOpaqueID(sessionStorageKey(other)), f.sid, nil); code != http.StatusOK {
		t.Fatalf("revoke session: %d %v", code, out)
	}
	// Removing the factor, with the code of a step after the one enrollment spent.
	if code, out := f.call("POST", "/api/_auth/mfa/disable", f.sid, map[string]string{"code": totpAt(t, secret, spent+1)}); code != http.StatusOK {
		t.Fatalf("mfa disable: %d %v", code, out)
	}
	// Enrolled again (the role requires it), then signed in with a backup code.
	_, codes, _ = f.enroll(f.sid)
	if code, out := f.call("POST", "/api/_auth/token", "", map[string]string{"email": accountAuditEmail, "password": accountAuditPassword, "mfa_code": codes[0]}); code != http.StatusOK {
		t.Fatalf("sign-in with a backup code: %d %v", code, out)
	}
	mail := captureSMTP(t, f.app)
	if code, out := f.requestEmail(f.sid, "amy@new.example"); code != http.StatusAccepted {
		t.Fatalf("email change request: %d %v", code, out)
	}
	if got := <-mail; got.err != nil {
		t.Fatalf("confirmation mail: %+v", got)
	}
	if f.confirmPending("amy@new.example", "hipaa-link-token"); currentEmail(t, f.app, f.uid) != "amy@new.example" {
		t.Fatal("the email change was not applied")
	}

	want := map[string]int{"mfa_backup_codes_generated": 2, "mfa_enrolled": 2, "mfa_removed": 1, "mfa_backup_code_used": 1,
		"api_token_created": 1, "api_token_revoked": 1, "session_revoked": 1, "email_change_requested": 1, "email_changed": 1}
	for action, n := range want {
		if rows := f.rows(action); len(rows) != n {
			t.Errorf("%d %s audit rows under hipaa, want %d: %+v", len(rows), action, n, rows)
		}
	}
	f.noSecret(append(codes, secret, token, hashToken(token))...)
	// Still append-only: the rows just written cannot be changed or removed.
	if _, err := f.app.DB.Exec(`UPDATE _benmore_audit_log SET user_email = '' WHERE action = 'mfa_enrolled'`); err == nil {
		t.Error("an audit row of an account event was rewritten under hipaa")
	}
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_audit_log WHERE action = 'api_token_created'`); err == nil {
		t.Error("an audit row of an account event was deleted under hipaa")
	}
}

// Every account event writes under a table whose audit rows a database
// restore carries forward, and every action has one.
func TestAccountAuditEventsAreCarriedByRestore(t *testing.T) {
	carried := restoreAuditTables()
	for action, table := range accountAuditEventTables {
		if !slices.Contains(carried, table) {
			t.Errorf("%s is recorded under %s, whose audit rows a restore does not copy", action, table)
		}
	}
	if err := auditAccountEvent(nil, nil, "account_event_nobody_declared", "1", nil, nil, nil); err == nil {
		t.Error("an action with no declared table was written")
	}
}

// Account erasure leaves no address behind in the rows of these events: the
// rows stay, by action and account id, without the addresses an email change
// recorded and without the actor's address.
func TestAccountErasureBlanksAddressesInAccountEventRows(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	EnsureLoginAttemptsTable(f.app.DB)
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'x@x.example', 'unused', '2999-01-01T00:00:00Z')`, f.uid); err != nil {
		t.Fatal(err)
	}
	if f.confirmPending("amy@new.example", "erasure-link-token"); currentEmail(t, f.app, f.uid) != "amy@new.example" {
		t.Fatal("fixture: the email change was not applied")
	}
	if code, out := f.call("POST", "/api/_auth/api-tokens", f.session(), map[string]string{"name": "ci", "scopes": "*"}); code != http.StatusOK {
		t.Fatalf("fixture: mint: %d %v", code, out)
	}
	tx, err := f.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := purgeAuditLogIdentity(tx, f.uid, "amy@new.example"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var rows, addressed int
	f.app.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(instr(COALESCE(user_email, '') || COALESCE(old_values, '') || COALESCE(new_values, ''), '@') > 0), 0)
		FROM _benmore_audit_log WHERE user_id = ? AND action IN ('email_changed', 'api_token_created')`, f.uid).Scan(&rows, &addressed)
	if rows != 2 || addressed != 0 {
		t.Fatalf("%d account event rows after erasure, %d still holding an address; want 2 and 0", rows, addressed)
	}
}
