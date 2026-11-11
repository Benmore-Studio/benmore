//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The admin panel runs generic create and update on _benmore_users. It wrote
// another account's TOTP secret and backup codes (one admin could replace a
// second admin's factor with one they hold, or clear it), seeded a factor on
// a new row, and changed another admin's sign-in address with every session
// and reset link of the account left working.

const (
	userColsAda = 10 // admin, the caller
	userColsBea = 11 // admin, enrolled in MFA
	userColsCy  = 12 // ordinary user
	userColsDee = 13 // role user, admin by a global grant

	userColsSecret = "JBSWY3DPEHPK3PXP"
	userColsBackup = `["stored-backup"]`
)

// newUserColumnsFixture is the last-admin fixture with every column the
// framework adds to _benmore_users, the credential tables an address change
// revokes, and the MFA routes.
func newUserColumnsFixture(t *testing.T) *lastAdminFixture {
	t.Helper()
	f := newLastAdminFixture(t)
	EnsureMFAColumns(f.db)
	if err := ensureMFASetupNonce(f.db); err != nil {
		t.Fatal(err)
	}
	ensureEmailGrandfathering(f.db)
	EnsureAPITokensTable(f.db)
	EnsurePasswordResetsTable(f.db)
	EnsureLoginAttemptsTable(f.db)
	ensureEmailChangesTable(f.db)
	RegisterMFARoutes(f.mux, f.app)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		id          int
		name, role  string
		secret, bak any
	}{
		{userColsAda, "ada", "admin", nil, nil},
		{userColsBea, "bea", "admin", userColsSecret, userColsBackup},
		{userColsCy, "cy", "user", userColsSecret, userColsBackup},
		{userColsDee, "dee", "user", nil, nil},
	} {
		mustExecArgs(t, f.db, `INSERT INTO _benmore_users (id, username, email, phone, password_hash, role, verified, totp_secret, backup_codes)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`, u.id, u.name, u.name+"@example.com", "+1555000"+u.name, string(hash), u.role, u.secret, u.bak)
	}
	mustExecArgs(t, f.db, `INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'admin')`, userColsDee)
	cols, err := GetTableColumns(f.db, "_benmore_users")
	if err != nil {
		t.Fatal(err)
	}
	f.app.Tables = append(f.app.Tables, Table{Name: "_benmore_users", Columns: cols})
	return f
}

// user reads one column of an account as text ("" for NULL).
func (f *lastAdminFixture) user(id int, col string) string {
	f.t.Helper()
	var v string
	if err := f.db.QueryRow("SELECT COALESCE(CAST("+col+" AS TEXT), '') FROM _benmore_users WHERE id = ?", id).Scan(&v); err != nil {
		f.t.Fatalf("read %s of account %d: %v", col, id, err)
	}
	return v
}

func (f *lastAdminFixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(query, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (f *lastAdminFixture) page(sid, path string) string {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

// An update through the panel never reaches another account's (or the
// caller's own) sign-in factor or the framework's account state, whether the
// request names only those columns or hides them beside an ordinary one.
func TestAdminPanelUpdateNeverWritesSignInFactors(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	const mine = "KRSXG5CTMVRXEZLUKRSXG5CT"

	// Replace the factor with one the caller holds, then clear it.
	for _, change := range []url.Values{
		{"totp_secret": {mine}, "backup_codes": {`["mine"]`}},
		{"totp_secret": {""}, "backup_codes": {""}},
	} {
		w := f.form(ada, "/_admin/api/_benmore_users/update/11", change)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "No fields to update") {
			t.Fatalf("update of only the factor columns %v: %d %s", change, w.Code, w.Body.String())
		}
		// The answer says where these change and points at the rule, not
		// at "change it in a flow".
		if body := w.Body.String(); !strings.Contains(body, `"docs":"auth.admin_panel_accounts"`) || strings.Contains(body, "in a flow") {
			t.Errorf("the refusal does not point at the admin panel's account rule: %s", body)
		}
		for _, col := range []string{"totp_secret", "backup_codes"} {
			if !strings.Contains(w.Header().Get("X-Stripped-Fields"), col) {
				t.Errorf("X-Stripped-Fields %q does not name %s", w.Header().Get("X-Stripped-Fields"), col)
			}
		}
		if got := f.user(userColsBea, "totp_secret"); got != userColsSecret {
			t.Fatalf("the panel wrote another admin's totp_secret: %q", got)
		}
		if got := f.user(userColsBea, "backup_codes"); got != userColsBackup {
			t.Fatalf("the panel wrote another admin's backup_codes: %q", got)
		}
	}

	// Beside an ordinary field: the field is saved, nothing else moves.
	before := map[string]string{}
	state := []string{"totp_secret", "backup_codes", "mfa_last_totp", "mfa_last_totp_at", "mfa_setup_nonce", "email_grandfathered", "password_hash", "password_change_required", "role"}
	for _, col := range state {
		before[col] = f.user(userColsCy, col)
	}
	w := f.form(ada, "/_admin/api/_benmore_users/update/12", url.Values{
		"first_name": {"Cyrus"}, "totp_secret": {mine}, "backup_codes": {"[]"},
		"mfa_last_totp": {"s:9999999999"}, "mfa_last_totp_at": {"2030-01-01T00:00:00Z"}, "mfa_setup_nonce": {"chosen"},
		"email_grandfathered": {"1"}, "password_hash": {"x"}, "password_change_required": {"1"}, "role": {"admin"},
	})
	if w.Code != http.StatusOK || f.user(userColsCy, "first_name") != "Cyrus" {
		t.Fatalf("ordinary edit beside framework columns: %d %s", w.Code, w.Body.String())
	}
	for _, col := range state {
		if got := f.user(userColsCy, col); got != before[col] {
			t.Errorf("the panel changed %s of account %d: %q -> %q", col, userColsCy, before[col], got)
		}
		if !strings.Contains(w.Header().Get("X-Stripped-Fields"), col) {
			t.Errorf("X-Stripped-Fields %q does not name %s", w.Header().Get("X-Stripped-Fields"), col)
		}
	}
	// The stored factor still signs the account in; the caller's does not.
	if ValidateMFACode(f.db, userColsCy, GenerateTOTP(mine)) {
		t.Fatal("a code from the caller's secret passed for the other account")
	}
	if !ValidateMFACode(f.db, userColsCy, GenerateTOTP(userColsSecret)) {
		t.Fatal("the account's own factor stopped working")
	}
}

// A row created through the panel starts with no factor and no framework
// account state, whatever the request seeds.
func TestAdminPanelCreateNeverSeedsSignInFactors(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	w := f.form(ada, "/_admin/api/_benmore_users/create", url.Values{
		"username": {"seeded"}, "email": {"seeded@example.com"}, "first_name": {"Seed"}, "verified": {"1"},
		"totp_secret": {"KRSXG5CTMVRXEZLUKRSXG5CT"}, "backup_codes": {`["mine"]`},
		"mfa_last_totp": {"s:1"}, "mfa_last_totp_at": {"2030-01-01T00:00:00Z"}, "mfa_setup_nonce": {"chosen"},
		"email_grandfathered": {"1"}, "password_hash": {"x"}, "password_change_required": {"1"}, "role": {"admin"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var id int
	if err := f.db.QueryRow("SELECT id FROM _benmore_users WHERE username = 'seeded'").Scan(&id); err != nil {
		t.Fatalf("the ordinary columns of the new row were not saved: %v", err)
	}
	if f.user(id, "email") != "seeded@example.com" || f.user(id, "first_name") != "Seed" || f.user(id, "verified") != "1" {
		t.Fatalf("the new row lost an ordinary column: email=%q first_name=%q verified=%q", f.user(id, "email"), f.user(id, "first_name"), f.user(id, "verified"))
	}
	for col, want := range map[string]string{
		"totp_secret": "", "backup_codes": "", "mfa_last_totp": "", "mfa_last_totp_at": "",
		"email_grandfathered": "0", "password_hash": "", "password_change_required": "0", "role": "user",
	} {
		if got := f.user(id, col); got != want {
			t.Errorf("the panel seeded %s = %q on a new account (want %q)", col, got, want)
		}
		if !strings.Contains(w.Header().Get("X-Stripped-Fields"), col) {
			t.Errorf("X-Stripped-Fields %q does not name %s", w.Header().Get("X-Stripped-Fields"), col)
		}
	}
	if f.user(id, "mfa_setup_nonce") == "chosen" {
		t.Error("the panel seeded mfa_setup_nonce")
	}
	if CheckMFA(f.db, int64(id)) {
		t.Fatal("the new account has a factor nobody enrolled")
	}
}

// Every column the framework puts on _benmore_users is either one no generic
// write takes, or one named here as writable. A new column fails this test
// until someone decides which it is.
func TestUserTableColumnsAreClassifiedForGenericWrites(t *testing.T) {
	f := newUserColumnsFixture(t)
	writable := []string{
		// email, and whichever of username / phone auth.identifier names, are
		// guarded by userIdentifierUpdate; the other is an ordinary field.
		"username", "email", "phone",
		"first_name", "last_name", "avatar_url", // profile
		"verified", "deactivated_at", // account state the panel manages (last-admin guard applies)
		"last_login_at", // sign-in bookkeeping, read only for display
	}
	create, update := protectedCreateFields(f.app, "_benmore_users"), protectedFields(protectedUpdateFields(f.app, "_benmore_users"))
	cols, err := GetTableColumns(f.db, "_benmore_users")
	if err != nil || len(cols) < 15 {
		t.Fatalf("columns: %d %v", len(cols), err)
	}
	for _, c := range cols {
		open := slices.Contains(writable, c.Name)
		if open == update.has(c.Name) {
			t.Errorf("_benmore_users.%s: writable-by-design=%v, protected on update=%v", c.Name, open, update.has(c.Name))
		}
		if !c.PK && open == create.has(c.Name) {
			t.Errorf("_benmore_users.%s: writable-by-design=%v, protected on create=%v", c.Name, open, create.has(c.Name))
		}
	}
	// Only this table: an app's own totp_secret column is the app's.
	if protectedCreateFields(f.app, "devices").has("totp_secret") {
		t.Error("totp_secret is protected on an app table")
	}
	// A URL naming the table in another case is the same table.
	if !protectedCreateFields(f.app, "_BENMORE_USERS").has("TOTP_SECRET") {
		t.Error("the protected set is case-sensitive")
	}
}

// Changing another admin's sign-in identifier through the panel is refused:
// with the address goes the reset link, the emailed sign-in code and the
// OAuth match, which is the whole account.
func TestAdminPanelRefusesAnotherAdminsIdentifier(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	bea := f.session(userColsBea, "bea@example.com")
	refused := func(id int, col, value string) {
		t.Helper()
		was := f.user(id, col)
		w := f.form(ada, "/_admin/api/_benmore_users/update/"+strconv.Itoa(id), url.Values{col: {value}, "first_name": {"Changed"}})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"error":"admin_identifier_protected"`) ||
			!strings.Contains(w.Body.String(), `"docs":"auth.admin_panel_accounts"`) || !strings.Contains(w.Body.String(), "another admin's "+col) {
			t.Fatalf("%s of admin %d through the panel: %d %s", col, id, w.Code, w.Body.String())
		}
		if got := f.user(id, col); got != was {
			t.Fatalf("%s of admin %d changed: %q -> %q", col, id, was, got)
		}
		if f.user(id, "first_name") == "Changed" {
			t.Fatalf("the refused update still wrote the other fields of admin %d", id)
		}
	}
	refused(userColsBea, "email", "ada+bea@example.com")
	refused(userColsBea, "email", "") // clearing it is a change too
	refused(userColsDee, "email", "ada+dee@example.com")
	if n := f.count("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", userColsBea); n != 1 || GetSessionFromDB(f.db, bea) == nil {
		t.Fatalf("a refused change ended the other admin's session (%d rows)", n)
	}

	// The configured identifier is guarded with the address.
	f.app.Design.Auth["identifier"] = "phone"
	refused(userColsBea, "phone", "+15550009999")
	f.app.Design.Auth["identifier"] = "username"
	refused(userColsBea, "username", "bea2")
	// A column that does not sign anyone in here is an ordinary field.
	if w := f.form(ada, "/_admin/api/_benmore_users/update/11", url.Values{"phone": {"+15550001234"}}); w.Code != http.StatusOK || f.user(userColsBea, "phone") != "+15550001234" {
		t.Fatalf("phone of an admin where phone is not the identifier: %d %s", w.Code, w.Body.String())
	}
	delete(f.app.Design.Auth, "identifier")

	// The edit form sends every field back: an unchanged address is no change.
	w := f.form(ada, "/_admin/api/_benmore_users/update/11", url.Values{"email": {"bea@example.com"}, "username": {"bea"}, "last_name": {"Admin"}})
	if w.Code != http.StatusOK || f.user(userColsBea, "last_name") != "Admin" {
		t.Fatalf("edit of another admin that echoes the address: %d %s", w.Code, w.Body.String())
	}
	if GetSessionFromDB(f.db, bea) == nil {
		t.Fatal("an edit that changed no identifier ended the account's session")
	}
}

// Changing an ordinary user's address through the panel still works, and
// ends what the email-change flow ends: sessions, API tokens, unused reset
// links for the old address and a pending email change.
func TestAdminPanelIdentifierChangeRevokesCredentials(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	seed := func(id int, email string) string {
		t.Helper()
		sid := f.session(int64(id), email)
		mustExecArgs(t, f.db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'ci', ?, '*')`, id, "hash-"+email)
		mustExecArgs(t, f.db, `INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'reset')`, "reset-"+email, email, soon(time.Hour))
		mustExecArgs(t, f.db, `INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, ?, ?, ?)`, id, "next-"+email, "change-"+email, soon(time.Hour))
		return sid
	}
	live := func(id int, email string) (sessions, tokens, resets, changes int) {
		return f.count("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", id),
			f.count("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?", id),
			f.count("SELECT COUNT(*) FROM _benmore_password_resets WHERE email = ? AND used = 0", email),
			f.count("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", id)
	}
	cy := seed(userColsCy, "cy@example.com")
	other := seed(6, "staff@example.com") // another account: untouched throughout

	// An edit that changes no identifier revokes nothing.
	if w := f.form(ada, "/_admin/api/_benmore_users/update/12", url.Values{"email": {"cy@example.com"}, "first_name": {"Cy"}}); w.Code != http.StatusOK {
		t.Fatalf("plain edit: %d %s", w.Code, w.Body.String())
	}
	if s, k, r, c := live(userColsCy, "cy@example.com"); s != 1 || k != 1 || r != 1 || c != 1 {
		t.Fatalf("a plain edit revoked credentials: sessions=%d tokens=%d resets=%d changes=%d", s, k, r, c)
	}

	w := f.form(ada, "/_admin/api/_benmore_users/update/12", url.Values{"email": {"cy@example.org"}, "first_name": {"Cy"}})
	if w.Code != http.StatusOK || f.user(userColsCy, "email") != "cy@example.org" {
		t.Fatalf("address change of an ordinary user: %d %s (email %q)", w.Code, w.Body.String(), f.user(userColsCy, "email"))
	}
	if s, k, r, c := live(userColsCy, "cy@example.com"); s != 0 || k != 0 || r != 0 || c != 0 {
		t.Fatalf("after the address change the account keeps sessions=%d tokens=%d reset links=%d pending changes=%d", s, k, r, c)
	}
	if GetSessionFromDB(f.db, cy) != nil {
		t.Fatal("the session of the old address still resolves")
	}
	// The factor and the password are the account's: an address change by
	// someone else does not touch them.
	if f.user(userColsCy, "totp_secret") != userColsSecret || f.user(userColsCy, "password_hash") == "" {
		t.Fatal("the address change touched the account's factor or password")
	}
	if s, k, r, c := live(6, "staff@example.com"); s != 1 || k != 1 || r != 1 || c != 1 || GetSessionFromDB(f.db, other) == nil {
		t.Fatalf("another account lost credentials: sessions=%d tokens=%d resets=%d changes=%d", s, k, r, c)
	}
	if n := f.count("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'update' AND table_name = '_benmore_users' AND row_id = '12' AND user_id = ? AND new_values LIKE '%cy@example.org%'", userColsAda); n != 1 {
		t.Fatalf("the address change has %d audit rows naming the admin and the new address", n)
	}

	// An admin's own address: allowed, and every session of the account
	// ends with it, the one that made the change included.
	second := f.session(userColsAda, "ada@example.com")
	if w := f.form(ada, "/_admin/api/_benmore_users/update/10", url.Values{"email": {"ada@example.org"}}); w.Code != http.StatusOK || f.user(userColsAda, "email") != "ada@example.org" {
		t.Fatalf("an admin's own address: %d %s", w.Code, w.Body.String())
	}
	if GetSessionFromDB(f.db, ada) != nil || GetSessionFromDB(f.db, second) != nil {
		t.Fatal("the admin's sessions outlived their own address change")
	}
}

// The user forms offer no input for a column the panel never writes.
func TestAdminPanelUserFormsOmitFrameworkColumns(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	list := f.page(ada, "/_admin/_benmore_users")
	_, create, ok := strings.Cut(list, `action="/_admin/api/_benmore_users/create"`)
	if !ok {
		t.Fatal("no create form on the users page")
	}
	detail := f.page(ada, "/_admin/_benmore_users/12")
	_, edit, ok := strings.Cut(detail, `action="/_admin/api/_benmore_users/update/12"`)
	if !ok {
		t.Fatal("no edit form on the user page")
	}
	edit, _, _ = strings.Cut(edit, `action="/_admin/set-role"`)
	for _, col := range []string{"totp_secret", "backup_codes", "mfa_last_totp", "mfa_last_totp_at", "mfa_setup_nonce", "email_grandfathered", "password_hash", "password_change_required", "role", "created_at"} {
		if strings.Contains(create, `name="`+col+`"`) {
			t.Errorf("the create form offers an input for %s", col)
		}
		if strings.Contains(edit, `name="`+col+`"`) {
			t.Errorf("the edit form offers an input for %s", col)
		}
	}
	for _, col := range []string{"email", "username", "first_name", "verified", "deactivated_at"} {
		if !strings.Contains(create, `name="`+col+`"`) {
			t.Errorf("the create form lost its input for %s", col)
		}
		if !strings.Contains(edit, `name="`+col+`"`) {
			t.Errorf("the edit form lost its input for %s", col)
		}
	}
	if strings.Contains(list+detail, userColsSecret) || strings.Contains(list+detail, "stored-backup") {
		t.Error("a user page prints a factor")
	}
}

// The endpoints that own these columns still write them.
func TestFactorAndPasswordEndpointsStillWriteUserColumns(t *testing.T) {
	f := newUserColumnsFixture(t)
	cy := f.session(userColsCy, "cy@example.com")
	// MFA disable removes the factor with a code from it.
	w := mfaFactorAction(t, f.mux, cy, "disable", GenerateTOTP(userColsSecret))
	if w.Code != http.StatusOK || CheckMFA(f.db, userColsCy) || f.user(userColsCy, "totp_secret") != "" {
		t.Fatalf("MFA disable: %d %s (secret %q)", w.Code, w.Body.String(), f.user(userColsCy, "totp_secret"))
	}
	// The password form replaces the hash.
	old := f.user(userColsCy, "password_hash")
	w = f.form(cy, "/settings/password", url.Values{"current_password": {fixturePassword}, "new_password": {"Replaced!456-abc"}, "confirm_password": {"Replaced!456-abc"}})
	now := f.user(userColsCy, "password_hash")
	if now == old || bcrypt.CompareHashAndPassword([]byte(now), []byte("Replaced!456-abc")) != nil {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}
}
