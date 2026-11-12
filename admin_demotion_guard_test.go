//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// One admin could take over another's account in three requests: take their
// admin away (set-role, the role API, or a hand-written grant row in the
// panel), change their address now that it was no longer an admin's, and send
// a reset link to it. No admin demotes another, so the address stays theirs.

func TestNoAdminDemotesAnotherAdmin(t *testing.T) {
	f := newUserColumnsFixture(t)
	ada := f.session(userColsAda, "ada@example.com")

	protected := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"error":"`+adminDemotionProtectedCode+`"`) ||
			!strings.Contains(w.Body.String(), `"docs":"auth.admin_panel_accounts"`) {
			t.Fatalf("%s: %d %s", what, w.Code, w.Body.String())
		}
	}
	addressKept := func(id int) {
		t.Helper()
		was := f.user(id, "email")
		w := f.form(ada, "/_admin/api/_benmore_users/update/"+strconv.Itoa(id), url.Values{"email": {"ada+taken@example.com"}})
		if w.Code != http.StatusForbidden || f.user(id, "email") != was {
			t.Fatalf("address of admin %d after the demotion attempt: %d %s, now %q", id, w.Code, w.Body.String(), f.user(id, "email"))
		}
	}

	// The primary role (bea is an admin by the role column).
	protected("set-role on another admin", f.form(ada, "/_admin/set-role", url.Values{"user_id": {strconv.Itoa(userColsBea)}, "role": {"user"}}))
	if f.role(userColsBea) != "admin" {
		t.Fatalf("bea demoted: role %q", f.role(userColsBea))
	}
	addressKept(userColsBea)

	// The global grant (dee is an admin by a grant), through every role-API write.
	dee := "/api/_auth/users/" + strconv.Itoa(userColsDee) + "/roles"
	protected("revoke", f.api(ada, http.MethodDelete, dee+"/admin", ""))
	protected("revoke group_id=all", f.api(ada, http.MethodDelete, dee+"/admin?group_id=all", ""))
	protected("past expiry", f.api(ada, http.MethodPatch, dee+"/admin", `{"expires_at":"2020-01-01T00:00:00Z"}`))
	protected("future expiry", f.api(ada, http.MethodPatch, dee+"/admin", `{"expires_at":"`+soon(3600e9)+`"}`))
	protected("re-grant with expiry", f.api(ada, http.MethodPost, dee, `{"role":"admin","expires_at":"`+soon(3600e9)+`"}`))
	if f.adminGrant(userColsDee) != "durable" {
		t.Fatalf("dee's grant changed: %q", f.adminGrant(userColsDee))
	}

	// The panel writes no grant row at all: a hand-written one skipped every check above.
	var grant string
	f.db.QueryRow("SELECT id FROM _benmore_user_roles WHERE user_id = ?", userColsDee).Scan(&grant)
	for _, path := range []string{"delete/" + grant, "update/" + grant, "create"} {
		w := f.form(ada, "/_admin/api/_benmore_user_roles/"+path, url.Values{"expires_at": {"2020-01-01 00:00:00"}, "user_id": {"12"}, "role": {"admin"}})
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "holds role grants") {
			t.Fatalf("panel %s on a grant: %d %s", path, w.Code, w.Body.String())
		}
	}
	if f.adminGrant(userColsDee) != "durable" || f.count("SELECT COUNT(*) FROM _benmore_user_roles WHERE user_id = 12") != 0 {
		t.Fatalf("a panel write reached the grants: dee %q", f.adminGrant(userColsDee))
	}
	addressKept(userColsDee)

	// What stays allowed. Deactivation cuts another admin off, and their address stays protected.
	f.form(ada, "/_admin/api/_benmore_users/update/"+strconv.Itoa(userColsBea), url.Values{"deactivated_at": {"2026-01-01 00:00:00"}})
	if f.user(userColsBea, "deactivated_at") == "" {
		t.Fatal("deactivating another admin was refused")
	}
	addressKept(userColsBea)
	// A redundant grant goes: dee stays an admin by the role column.
	mustExecArgs(t, f.db, "UPDATE _benmore_users SET role = 'admin' WHERE id = ?", userColsDee)
	if w := f.api(ada, http.MethodDelete, dee+"/admin", ""); w.Code != http.StatusOK {
		t.Fatalf("revoking a redundant grant: %d %s", w.Code, w.Body.String())
	}
	// Granting admin, and stepping down from your own account.
	if w := f.api(ada, http.MethodPost, "/api/_auth/users/"+strconv.Itoa(userColsCy)+"/roles", `{"role":"admin"}`); w.Code != http.StatusOK {
		t.Fatalf("granting admin: %d %s", w.Code, w.Body.String())
	}
	if w := f.form(ada, "/_admin/set-role", url.Values{"user_id": {strconv.Itoa(userColsAda)}, "role": {"user"}}); w.Code != http.StatusSeeOther || f.role(userColsAda) != "user" {
		t.Fatalf("stepping down: %d %s, role %q", w.Code, w.Body.String(), f.role(userColsAda))
	}
}
