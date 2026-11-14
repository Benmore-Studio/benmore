//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const adminAuditMemberEmail = "bo@example.com"

// adminAuditFixture is an app with tenants whose account (the fixture's uid)
// is its admin, beside one ordinary member, serving the role, admin-panel,
// support-session, act-as and connected-provider routes.
type adminAuditFixture struct {
	*accountAuditFixture
	member int64
}

func newAdminAuditFixture(t *testing.T, hipaa bool) *adminAuditFixture {
	t.Helper()
	base := newAccountAuditFixtureWith(t, hipaa, func(app *App) {
		if _, err := app.DB.Exec(`CREATE TABLE members (id INTEGER PRIMARY KEY, org_id INTEGER, user_id INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec(`INSERT INTO members (org_id, user_id) VALUES (7, 900)`); err != nil {
			t.Fatal(err)
		}
		app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	})
	RegisterRoleRoutes(base.mux, base.app)
	RegisterAdminRoutes(base.mux, base.app)
	RegisterOAuthTokensAPI(base.mux, base.app)
	if _, err := base.app.DB.Exec(`UPDATE _benmore_users SET role = 'admin' WHERE id = ?`, base.uid); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(accountAuditPassword), bcrypt.MinCost)
	res, err := base.app.DB.Exec(`INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('bo', ?, ?, 1)`, adminAuditMemberEmail, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := res.LastInsertId()
	return &adminAuditFixture{accountAuditFixture: base, member: member}
}

func (f *adminAuditFixture) memberText() string { return fmt.Sprint(f.member) }

// setRole posts the admin panel's role form as the admin's cookie session.
func (f *adminAuditFixture) setRole(role string) int {
	f.t.Helper()
	form := url.Values{"user_id": {f.memberText()}, "role": {role}, "_csrf": {authMintCSRFToken(f.sid)}}
	r := httptest.NewRequest(http.MethodPost, "/_admin/set-role", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: f.sid})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w.Code
}

func (f *adminAuditFixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *adminAuditFixture) text(query string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.app.DB.QueryRow(query, args...).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// refuseAuditRows makes every insert into the audit log fail.
func (f *accountAuditFixture) refuseAuditRows() {
	f.t.Helper()
	if _, err := f.app.DB.Exec(`CREATE TRIGGER refuse_account_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'audit log refused'); END`); err != nil {
		f.t.Fatal(err)
	}
}

func (f *adminAuditFixture) connectProvider(provider, accessToken string) {
	f.t.Helper()
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_oauth_tokens (user_id, provider, access_token, refresh_token, scopes) VALUES (?, ?, ?, ?, 'openid email')`,
		f.uid, provider, accessToken, accessToken+"-refresh"); err != nil {
		f.t.Fatal(err)
	}
}

// Disconnecting a provider removes tokens an app's flows act with, and wrote
// no row. It is recorded once, by the account, naming the provider and the
// scopes and never a token; a provider that was not connected records nothing.
func TestAccountAuditOAuthProviderDisconnect(t *testing.T) {
	f := newAdminAuditFixture(t, false)
	access := "ya29." + generateToken(12)
	f.connectProvider("google", access)
	tokenID := f.text(`SELECT id FROM _benmore_oauth_tokens WHERE provider = 'google'`)

	if code, _ := f.call("DELETE", "/api/_auth/oauth-tokens/github", f.sid, nil); code != http.StatusNotFound {
		t.Fatalf("disconnecting a provider that is not connected: %d", code)
	}
	f.none("oauth_provider_disconnected", "nothing was disconnected")
	if code, out := f.call("DELETE", "/api/_auth/oauth-tokens/google", f.sid, nil); code != http.StatusOK || out["status"] != "disconnected" {
		t.Fatalf("disconnect: %d %v", code, out)
	}
	if n := f.count(`SELECT COUNT(*) FROM _benmore_oauth_tokens`); n != 0 {
		t.Fatal("the provider's tokens are still stored")
	}
	r := f.one("oauth_provider_disconnected", "_benmore_oauth_tokens", tokenID)
	if r.old != `{"provider":"google","scopes":"openid email"}` || r.new != "" {
		t.Fatalf("oauth_provider_disconnected values = %s / %s", r.old, r.new)
	}
	f.noSecret(access, access+"-refresh")
}

// resetWithLink spends a reset link for the address through the handler.
func (f *accountAuditFixture) resetWithLink(email string) int {
	f.t.Helper()
	EnsurePasswordResetsTable(f.app.DB)
	link := generateToken(16)
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_password_resets (token, email, expires_at, used, type) VALUES (?, ?, ?, 0, 'reset')`,
		hashResetToken(link), email, time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		f.t.Fatal(err)
	}
	form := url.Values{"token": {link}, "password": {"Brand-New-Pass-9"}, "confirm": {"Brand-New-Pass-9"}}
	r := httptest.NewRequest(http.MethodPost, f.app.Paths.ResetPassword, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleResetPassword(w, r, f.app)
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "success=") {
		return http.StatusInternalServerError
	}
	return w.Code
}

func (f *accountAuditFixture) setFactor(uid int64, verified int, secret string) {
	f.t.Helper()
	EnsureMFAColumns(f.app.DB)
	if _, err := f.app.DB.Exec(`UPDATE _benmore_users SET verified = ?, totp_secret = NULLIF(?, ''), backup_codes = NULLIF(?, '') WHERE id = ?`,
		verified, secret, secret, uid); err != nil {
		f.t.Fatal(err)
	}
}

// A reset link takes the second factor from an account whose address was
// never verified. That removal gets a row of its own, naming the reset as its
// reason; a verified account keeps its factor and a pending enrollment is no
// factor, so neither writes one.
func TestAccountAuditMFARemovedByPasswordReset(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	f := newAccountAuditFixture(t, false)

	f.setFactor(f.uid, 1, secret)
	if code := f.resetWithLink(accountAuditEmail); code != http.StatusSeeOther {
		t.Fatalf("reset of the verified account: %d", code)
	}
	f.none("mfa_removed", "a verified account keeps its factor through a reset")

	f.setFactor(f.uid, 0, "pending:"+secret)
	if code := f.resetWithLink(accountAuditEmail); code != http.StatusSeeOther {
		t.Fatalf("reset with a pending enrollment: %d", code)
	}
	f.none("mfa_removed", "a pending enrollment is not a factor")

	f.setFactor(f.uid, 0, secret)
	if code := f.resetWithLink(accountAuditEmail); code != http.StatusSeeOther {
		t.Fatalf("reset of the unverified account: %d", code)
	}
	var stored string
	f.app.DB.QueryRow(`SELECT COALESCE(totp_secret, '') FROM _benmore_users WHERE id = ?`, f.uid).Scan(&stored)
	if stored != "" {
		t.Fatal("fixture: the reset kept the unverified account's factor")
	}
	if r := f.one("mfa_removed", "_benmore_users", f.uidText()); r.old != `{"factor":"totp"}` || r.new != `{"reason":"password_reset"}` {
		t.Fatalf("mfa_removed values = %s / %s", r.old, r.new)
	}
	if rows := f.rows("password_reset"); len(rows) != 3 {
		t.Fatalf("%d password_reset rows, want the 3 resets", len(rows))
	}
	f.noSecret(secret)
}

// A claim of an unverified account (its verification link, or a social
// sign-in that proves the address) takes the registrant's factor too, and
// names itself as the reason.
func TestAccountAuditMFARemovedByClaim(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	for _, claim := range []string{"email_claim_unverified", "oauth_claim_unverified"} {
		t.Run(claim, func(t *testing.T) {
			f := newAccountAuditFixture(t, false)
			f.setFactor(f.uid, 0, secret)
			if err := claimUnverifiedAccountAs(f.app, f.uid, accountAuditEmail, claim); err != nil {
				t.Fatal(err)
			}
			if r := f.one("mfa_removed", "_benmore_users", f.uidText()); r.old != `{"factor":"totp"}` || r.new != `{"reason":"`+claim+`"}` {
				t.Fatalf("mfa_removed values = %s / %s", r.old, r.new)
			}
			if rows := f.rows(claim); len(rows) != 1 {
				t.Fatalf("%d %s rows, want 1", len(rows), claim)
			}
			f.noSecret(secret)
		})
	}
	// An account with no factor loses none.
	f := newAccountAuditFixture(t, false)
	f.setFactor(f.uid, 0, "")
	if err := claimUnverifiedAccountAs(f.app, f.uid, accountAuditEmail, "email_claim_unverified"); err != nil {
		t.Fatal(err)
	}
	f.none("mfa_removed", "there was no factor to remove")
}

// adminEvents performs every role, support-session and act-as change once
// and returns the support session's token.
func (f *adminAuditFixture) adminEvents() (support string) {
	t := f.t
	t.Helper()
	roles := "/api/_auth/users/" + f.memberText() + "/roles"
	if code := f.setRole("editor"); code != http.StatusSeeOther {
		t.Fatalf("set-role editor: %d", code)
	}
	if code := f.setRole("user"); code != http.StatusSeeOther {
		t.Fatalf("set-role user: %d", code)
	}
	if code, out := f.call("POST", roles, f.sid, map[string]string{"role": "editor"}); code != http.StatusOK {
		t.Fatalf("grant: %d %v", code, out)
	}
	if code, out := f.call("PATCH", roles+"/editor", f.sid, map[string]string{"expires_at": "2999-01-01T00:00:00Z"}); code != http.StatusOK {
		t.Fatalf("expiry: %d %v", code, out)
	}
	if code, out := f.call("DELETE", roles+"/editor", f.sid, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_user_roles (user_id, role, granted_by, expires_at) VALUES (?, 'user', ?, '2001-01-01 00:00:00')`, f.member, f.uid); err != nil {
		t.Fatal(err)
	}
	sweepExpiredRoles(f.app)
	if n := f.count(`SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ?`, f.member); n != 0 {
		t.Fatalf("%d grants left after revoke and the expiry sweep", n)
	}
	code, out := f.call("POST", "/api/_auth/impersonate", f.sid, map[string]any{"user_id": f.member, "password": accountAuditPassword})
	support, _ = out["token"].(string)
	if code != http.StatusOK || support == "" {
		t.Fatalf("impersonate: %d %v", code, out)
	}
	if code, out := f.call("POST", "/api/_auth/act_as", f.sid, map[string]string{"group_id": "7", "password": accountAuditPassword}); code != http.StatusOK {
		t.Fatalf("act_as: %d %v", code, out)
	}
	if code, out := f.call("DELETE", "/api/_auth/act_as", f.sid, nil); code != http.StatusOK || out["status"] != "cleared" {
		t.Fatalf("act_as end: %d %v", code, out)
	}
	return support
}

// Role changes, grants, a support session and act-as each write the row they
// always wrote: same action, table, row and values.
func TestAdminAccountEventRowsKeepTheirShape(t *testing.T) {
	f := newAdminAuditFixture(t, false)
	support := f.adminEvents()
	member, admin, sessionKey := f.memberText(), f.uidText(), sessionStorageKey(f.sid)

	changed := f.rows("role_changed")
	if len(changed) != 2 || changed[0].old != `{"role":"user"}` || changed[0].new != `{"role":"editor"}` || changed[1].new != `{"role":"user"}` ||
		changed[0].table != "_benmore_users" || changed[0].rowID != member || changed[0].userID != f.uid {
		t.Fatalf("role_changed rows = %+v", changed)
	}
	if r := f.one("role_granted", "_benmore_user_roles", member); r.old != "" ||
		r.new != `{"expires_at":null,"granted_by":`+admin+`,"group_id":null,"role":"editor","user_id":`+member+`}` {
		t.Fatalf("role_granted values = %s / %s", r.old, r.new)
	}
	if r := f.one("role_expiry_updated", "_benmore_user_roles", member); r.new != `{"expires_at":"2999-01-01 00:00:00","role":"editor","user_id":`+member+`}` {
		t.Fatalf("role_expiry_updated values = %s", r.new)
	}
	if r := f.one("role_revoked", "_benmore_user_roles", member); r.old != `{"group_id":"","role":"editor","user_id":`+member+`}` ||
		r.new != `{"group_id":"","revoked_by":`+admin+`,"role":"editor","user_id":`+member+`}` {
		t.Fatalf("role_revoked values = %s / %s", r.old, r.new)
	}
	expired := f.rows("role_expired")
	if len(expired) != 1 || expired[0].table != "_benmore_user_roles" || expired[0].rowID != member || expired[0].userID != 0 || expired[0].email != "" ||
		expired[0].old != `{"role":"user","user_id":`+member+`}` || expired[0].new != "" {
		t.Fatalf("role_expired rows = %+v", expired)
	}
	if r := f.one("impersonate", "_benmore_users", member); r.new != `{"impersonated_by":"`+accountAuditEmail+`","target_user":"`+adminAuditMemberEmail+`"}` {
		t.Fatalf("impersonate values = %s", r.new)
	}
	if r := f.one("act_as_start", "_benmore_sessions", sessionKey); r.new != `{"admin_email":"`+accountAuditEmail+`","target_group_id":"7"}` {
		t.Fatalf("act_as_start values = %s", r.new)
	}
	if r := f.one("act_as_end", "_benmore_sessions", sessionKey); r.new != `{"prior_group_id":"7","user_email":"`+accountAuditEmail+`"}` {
		t.Fatalf("act_as_end values = %s", r.new)
	}
	// The support session carries its marker and the admin behind it.
	if n := f.count(`SELECT COUNT(*) FROM _benmore_sessions WHERE id = ? AND is_impersonation = 1 AND impersonator_user_id = ? AND started_by_session_id = ?`,
		sessionStorageKey(support), f.uid, sessionKey); n != 1 {
		t.Fatal("the support session row does not carry its marker")
	}
	f.noSecret(support, f.sid)
}

// Under compliance: hipaa the audit tables are append-only; each of these
// events still writes its row once, through the change's transaction.
func TestAdminAccountEventsUnderHIPAAAppendOnly(t *testing.T) {
	f := newAdminAuditFixture(t, true)
	f.enroll(f.sid) // the role requires a second factor before the session is of other use
	f.setFactor(f.member, 1, "JBSWY3DPEHPK3PXP")
	f.connectProvider("google", "ya29."+generateToken(12))
	f.adminEvents()
	if code, out := f.call("DELETE", "/api/_auth/oauth-tokens/google", f.sid, nil); code != http.StatusOK {
		t.Fatalf("disconnect: %d %v", code, out)
	}
	// A claim of the member's account, unverified again and holding a factor.
	f.setFactor(f.member, 0, "JBSWY3DPEHPK3PXP")
	if err := claimUnverifiedAccountAs(f.app, f.member, adminAuditMemberEmail, "email_claim_unverified"); err != nil {
		t.Fatal(err)
	}
	removed := f.rows("mfa_removed")
	if len(removed) != 1 || removed[0].userID != f.member || removed[0].new != `{"reason":"email_claim_unverified"}` {
		t.Errorf("mfa_removed rows under hipaa = %+v", removed)
	}
	want := map[string]int{"role_changed": 2, "role_granted": 1, "role_expiry_updated": 1, "role_revoked": 1, "role_expired": 1,
		"impersonate": 1, "act_as_start": 1, "act_as_end": 1, "oauth_provider_disconnected": 1}
	for action, n := range want {
		if rows := f.rows(action); len(rows) != n {
			t.Errorf("%d %s audit rows under hipaa, want %d: %+v", len(rows), action, n, rows)
		}
	}
	if _, err := f.app.DB.Exec(`DELETE FROM _benmore_audit_log WHERE action = 'impersonate'`); err == nil {
		t.Error("an audit row of a support session was deleted under hipaa")
	}
}

// Each of these changes is refused when its audit row cannot be written, and
// nothing of it stays behind: no role, no grant, no support session, no
// step-in, and the connected provider and an expired grant stay as they were.
func TestAdminAccountEventIsRefusedWhenItsAuditRowCannotBeWritten(t *testing.T) {
	f := newAdminAuditFixture(t, false)
	f.connectProvider("google", "ya29."+generateToken(12))
	roles := "/api/_auth/users/" + f.memberText() + "/roles"
	// A grant to change and revoke, an expired grant to sweep, a step-in to end.
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_user_roles (user_id, role, granted_by) VALUES (?, 'editor', ?)`, f.member, f.uid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(`INSERT INTO _benmore_user_roles (user_id, role, granted_by, expires_at) VALUES (?, 'user', ?, '2001-01-01 00:00:00')`, f.member, f.uid); err != nil {
		t.Fatal(err)
	}
	stepped := f.session()
	if _, err := f.app.DB.Exec(`UPDATE _benmore_sessions SET acting_as_group = '7' WHERE id = ?`, sessionStorageKey(stepped)); err != nil {
		t.Fatal(err)
	}
	f.refuseAuditRows()

	if code := f.setRole("editor"); code == http.StatusSeeOther {
		t.Error("a role was changed with no audit row")
	}
	if role := f.text(`SELECT COALESCE(role, 'user') FROM _benmore_users WHERE id = ?`, f.member); role != "user" {
		t.Errorf("the role is %q although its audit row was refused", role)
	}
	if code, out := f.call("POST", roles, f.sid, map[string]string{"role": "viewer"}); code == http.StatusOK {
		t.Errorf("a role was granted with no audit row: %v", out)
	}
	if code, _ := f.call("PATCH", roles+"/editor", f.sid, map[string]string{"expires_at": "2999-01-01T00:00:00Z"}); code == http.StatusOK {
		t.Error("a grant's expiry was changed with no audit row")
	}
	if code, _ := f.call("DELETE", roles+"/editor", f.sid, nil); code == http.StatusOK {
		t.Error("a grant was revoked with no audit row")
	}
	sweepExpiredRoles(f.app)
	if n := f.count(`SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ? AND
		((role = 'editor' AND expires_at IS NULL) OR (role = 'user' AND expires_at = '2001-01-01 00:00:00'))`, f.member); n != 2 {
		t.Errorf("the member's grants changed although no audit row could be written: %d of 2 unchanged", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = ?`, f.member); n != 2 {
		t.Errorf("%d grants, want the 2 the member had", n)
	}
	if code, out := f.call("POST", "/api/_auth/impersonate", f.sid, map[string]any{"user_id": f.member, "password": accountAuditPassword}); code == http.StatusOK {
		t.Errorf("a support session started with no audit row: %v", out)
	}
	if n := f.count(`SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?`, f.member); n != 0 {
		t.Errorf("%d sessions as the member although the support session's audit row was refused", n)
	}
	if code, out := f.call("POST", "/api/_auth/act_as", f.sid, map[string]string{"group_id": "7", "password": accountAuditPassword}); code == http.StatusOK {
		t.Errorf("a step-in started with no audit row: %v", out)
	}
	if got := f.text(`SELECT COALESCE(acting_as_group, '') FROM _benmore_sessions WHERE id = ?`, sessionStorageKey(f.sid)); got != "" {
		t.Errorf("the session is stepped into %q although its audit row was refused", got)
	}
	if code, out := f.call("DELETE", "/api/_auth/act_as", stepped, nil); code == http.StatusOK {
		t.Errorf("a step-in ended with no audit row: %v", out)
	}
	if got := f.text(`SELECT COALESCE(acting_as_group, '') FROM _benmore_sessions WHERE id = ?`, sessionStorageKey(stepped)); got != "7" {
		t.Errorf("the step-in ended (%q) although its audit row was refused", got)
	}
	if code, out := f.call("DELETE", "/api/_auth/oauth-tokens/google", f.sid, nil); code == http.StatusOK {
		t.Errorf("a provider was disconnected with no audit row: %v", out)
	}
	if n := f.count(`SELECT COUNT(*) FROM _benmore_oauth_tokens WHERE user_id = ?`, f.uid); n != 1 {
		t.Error("the provider's tokens were removed although the audit row was refused")
	}
	if n := f.count(`SELECT COUNT(*) FROM _benmore_audit_log`); n != 0 {
		t.Errorf("fixture: %d audit rows were written through the refusing trigger", n)
	}
}

// An unverified account keeps its second factor when the reset that would
// take it cannot record the removal: the reset is refused whole.
func TestMFARemovalByResetIsRefusedWhenItsAuditRowCannotBeWritten(t *testing.T) {
	f := newAccountAuditFixture(t, false)
	f.setFactor(f.uid, 0, "JBSWY3DPEHPK3PXP")
	before := ""
	f.app.DB.QueryRow(`SELECT password_hash FROM _benmore_users WHERE id = ?`, f.uid).Scan(&before)
	f.refuseAuditRows()
	if code := f.resetWithLink(accountAuditEmail); code == http.StatusSeeOther {
		t.Fatal("the reset went through with no audit row")
	}
	var secret, hash string
	f.app.DB.QueryRow(`SELECT COALESCE(totp_secret, ''), password_hash FROM _benmore_users WHERE id = ?`, f.uid).Scan(&secret, &hash)
	if secret == "" || hash != before {
		t.Fatal("the factor or the password changed although the audit rows were refused")
	}
}
