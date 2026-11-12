//go:build !cli

package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The admin panel's edit form writes deactivated_at on a _benmore_users row.
// Emptying the field stored the empty string, which the session and token
// lookups refuse like a timestamp, so an account could be deactivated there
// and never reactivated; the form posts every field, so saving an ACTIVE
// account's row (blank field) stored the empty string too.

// deactivationStored is how deactivated_at of account id is stored: "null",
// or the SQLite type and quoted value.
func deactivationStored(f *lastAdminFixture, id int) string {
	f.t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT CASE WHEN deactivated_at IS NULL THEN 'null'
		ELSE typeof(deactivated_at) || ':' || quote(deactivated_at) END FROM _benmore_users WHERE id = ?`, id).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// userColsEve is a plain password account with no second factor (a sign-in
// of an enrolled account stops at the code step and sets no session).
const userColsEve = 30

func newDeactivationFixture(t *testing.T) *lastAdminFixture {
	t.Helper()
	f := newUserColumnsFixture(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, f.db, `INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (?, 'eve', 'eve@example.com', ?, 'user', 1)`, userColsEve, string(hash))
	return f
}

// sessionAnswers reports the status of GET /api/_auth/profile for a session.
func sessionAnswers(f *lastAdminFixture, sid string) int {
	f.t.Helper()
	return f.api(sid, http.MethodGet, "/api/_auth/profile", "").Code
}

// signsIn posts the account's password to the sign-in form and returns the
// session it was given ("" when refused).
func signsIn(f *lastAdminFixture, email string) string {
	f.t.Helper()
	return accountStateSessionCookie(accountStateLogin(f.app, email, fixturePassword, false))
}

func TestAdminPanelEmptiedDeactivatedAtReactivatesTheAccount(t *testing.T) {
	f := newDeactivationFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	eve := f.session(userColsEve, "eve@example.com")
	const row = "/_admin/api/_benmore_users/update/30"

	deactivate := func() {
		t.Helper()
		if w := f.form(ada, row, url.Values{"deactivated_at": {"2026-01-01 00:00:00"}}); w.Code != http.StatusOK {
			t.Fatalf("deactivate in the panel: %d %s", w.Code, w.Body.String())
		}
		if code := sessionAnswers(f, eve); code != http.StatusUnauthorized {
			t.Fatalf("deactivated account's session answered %d, want 401", code)
		}
		if sid := signsIn(f, "eve@example.com"); sid != "" {
			t.Fatal("a deactivated account signed in")
		}
	}
	reactivated := func(how string) {
		t.Helper()
		if got := deactivationStored(f, userColsEve); got != "null" {
			t.Fatalf("%s stored deactivated_at as %s, want NULL", how, got)
		}
		if code := sessionAnswers(f, eve); code != http.StatusOK {
			t.Fatalf("%s: the account's existing session answered %d, want 200", how, code)
		}
		sid := signsIn(f, "eve@example.com")
		if sid == "" {
			t.Fatalf("%s: the account could not sign in", how)
		}
		if code := sessionAnswers(f, sid); code != http.StatusOK {
			t.Fatalf("%s: the new sign-in's session answered %d, want 200", how, code)
		}
	}

	// The edit form's field, emptied or left as spaces.
	for _, empty := range []string{"", "   "} {
		deactivate()
		if w := f.form(ada, row, url.Values{"deactivated_at": {empty}}); w.Code != http.StatusOK {
			t.Fatalf("empty the field (%q): %d %s", empty, w.Code, w.Body.String())
		}
		reactivated("an emptied field")
	}
	// The same route with a JSON body: an empty string, and null.
	for _, body := range []string{`{"deactivated_at":""}`, `{"deactivated_at":null}`} {
		deactivate()
		if w := f.api(ada, http.MethodPost, row, body); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
		reactivated(body)
	}
	// A timestamp is still stored as written.
	deactivate()
	if got := deactivationStored(f, userColsEve); got != "text:'2026-01-01 00:00:00'" {
		t.Fatalf("a timestamp was stored as %s", got)
	}
}

// adminEditFormValues are the fields the panel's edit form for a row would
// post back unchanged.
func adminEditFormValues(f *lastAdminFixture, sid, path string) url.Values {
	f.t.Helper()
	values := url.Values{}
	input := regexp.MustCompile(`<input type="[^"]*" name="([^"]+)" value="([^"]*)"`)
	for _, m := range input.FindAllStringSubmatch(f.page(sid, path), -1) {
		if m[1] != "_csrf" {
			values.Set(m[1], html.UnescapeString(m[2]))
		}
	}
	return values
}

// Saving the edit form of an active account, with nothing changed, leaves it
// active: its blank Deactivated At field is not a value.
func TestAdminPanelSavingAnActiveAccountKeepsItActive(t *testing.T) {
	f := newDeactivationFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	eve := f.session(userColsEve, "eve@example.com")

	for _, tc := range []struct {
		id  int
		sid string
	}{{userColsEve, eve}, {userColsAda, ada}} {
		path := "/_admin/_benmore_users/" + strconv.Itoa(tc.id)
		values := adminEditFormValues(f, ada, path)
		if _, shown := values["deactivated_at"]; !shown {
			t.Fatalf("the edit form of account %d has no deactivated_at field: %v", tc.id, values)
		}
		if values.Get("deactivated_at") != "" {
			t.Fatalf("an active account's field is %q", values.Get("deactivated_at"))
		}
		values.Set("first_name", "Renamed")
		if w := f.form(ada, "/_admin/api/_benmore_users/update/"+strconv.Itoa(tc.id), values); w.Code != http.StatusOK {
			t.Fatalf("save the form of account %d: %d %s", tc.id, w.Code, w.Body.String())
		}
		if got := f.user(tc.id, "first_name"); got != "Renamed" {
			t.Fatalf("the save did not write first_name: %q", got)
		}
		if got := deactivationStored(f, tc.id); got != "null" {
			t.Fatalf("saving the form of active account %d stored deactivated_at as %s", tc.id, got)
		}
		if code := sessionAnswers(f, tc.sid); code != http.StatusOK {
			t.Fatalf("after its row was saved, account %d's session answered %d", tc.id, code)
		}
	}
}

// A row that already holds the empty string is read as before: refused. It
// is reactivated by writing the row again (emptying the field in the panel).
func TestStoredEmptyDeactivatedAtIsStillRefused(t *testing.T) {
	f := newDeactivationFixture(t)
	ada := f.session(userColsAda, "ada@example.com")
	eve := f.session(userColsEve, "eve@example.com")
	mustExecArgs(t, f.db, `UPDATE _benmore_users SET deactivated_at = '' WHERE id = ?`, userColsEve)

	if code := sessionAnswers(f, eve); code != http.StatusUnauthorized {
		t.Fatalf("a session of an account stored with '' answered %d, want 401 as before", code)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+eve)
	if getSession(f.app, r) != nil {
		t.Fatal("a stored '' resolved a session")
	}

	if w := f.form(ada, "/_admin/api/_benmore_users/update/30", url.Values{"deactivated_at": {""}}); w.Code != http.StatusOK {
		t.Fatalf("empty the field again: %d %s", w.Code, w.Body.String())
	}
	if got := deactivationStored(f, userColsEve); got != "null" {
		t.Fatalf("emptying the field of a row stored with '' left %s", got)
	}
	if code := sessionAnswers(f, eve); code != http.StatusOK {
		t.Fatalf("after the field was emptied again the session answered %d", code)
	}
}

// The panel's guards are unchanged: the last usable admin is not deactivated
// there, and an emptied field on that admin's own row keeps them signed in.
func TestAdminPanelDeactivationKeepsTheLastAdminGuard(t *testing.T) {
	f := newLastAdminFixture(t)
	cols, err := GetTableColumns(f.db, "_benmore_users")
	if err != nil {
		t.Fatal(err)
	}
	f.app.Tables = append(f.app.Tables, Table{Name: "_benmore_users", Columns: cols})
	boss := f.session(1, "boss@example.com")

	w := f.form(boss, "/_admin/api/_benmore_users/update/1", url.Values{"deactivated_at": {"2026-01-01 00:00:00"}})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "last active admin") || !f.live(1) {
		t.Fatalf("the panel deactivated the last admin: %d %s", w.Code, w.Body.String())
	}
	if w := f.form(boss, "/_admin/api/_benmore_users/update/1", url.Values{"first_name": {"Boss"}, "deactivated_at": {""}}); w.Code != http.StatusOK {
		t.Fatalf("save the last admin's own row: %d %s", w.Code, w.Body.String())
	}
	if !f.live(1) {
		t.Fatal("saving the last admin's row with an empty field did not leave deactivated_at NULL")
	}
	if code := sessionAnswers(f, boss); code != http.StatusOK {
		t.Fatalf("the last admin's session answered %d after saving their own row", code)
	}
	// Reactivating the deactivated admin (2) by emptying its field works.
	if w := f.form(boss, "/_admin/api/_benmore_users/update/2", url.Values{"deactivated_at": {""}}); w.Code != http.StatusOK || !f.live(2) {
		t.Fatalf("reactivate another admin in the panel: %d %s, live=%v", w.Code, w.Body.String(), f.live(2))
	}
}
