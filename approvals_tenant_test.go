//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// approvalsTenantApp is a two-tenant app: `members` is the groups: membership
// table, purchase_requests is tenant-wide (the implicit default), claims is
// declared owner-only (`self`), plans is scoped by membership (`member-of:`)
// and notes carries no tenant key.
//
//	areq, aappr  members of org-a
//	bappr        member of org-b
//	boss         global admin, no tenant
//	loner        no tenant
func approvalsTenantApp(t *testing.T) (*App, *http.ServeMux, map[string]string) {
	t.Helper()
	return approvalsTenantFixture(t, nil)
}

// approvalsTenantFixture is approvalsTenantApp with configure applied to the
// app before its routes are built (more tables, rules or groups: settings).
func approvalsTenantFixture(t *testing.T, configure func(app *App)) (*App, *http.ServeMux, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER)`,
		`CREATE TABLE purchase_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE claims (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	scoped := []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "title"}}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"claims": {"all": "self"},
			"plans":  {"all": "member-of:members(org_id, user_id)"},
		}},
		Tables: []Table{
			{Name: "members", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}}},
			{Name: "purchase_requests", Columns: scoped},
			{Name: "claims", Columns: scoped},
			{Name: "plans", Columns: scoped},
			{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "title"}}},
		},
	}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureNotificationsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	tokens := map[string]string{}
	for i, u := range []struct{ name, role, org string }{
		{"areq", "user", "org-a"}, {"aappr", "user", "org-a"}, {"bappr", "user", "org-b"}, {"boss", "admin", ""}, {"loner", "user", ""},
	} {
		email := u.name + "@example.com"
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)", u.name, email, u.role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		if id != int64(i+1) {
			t.Fatalf("fixture: %s got user id %d", u.name, id)
		}
		if u.org != "" {
			crudScopeMustExec(t, db, fmt.Sprintf(`INSERT INTO members (org_id, user_id) VALUES ('%s', %d)`, u.org, id))
		}
		// No tenant on the session row: each request resolves it from the
		// live membership, as after a sign-in.
		tokens[u.name] = CreateSession(app.DB, id, email, "", time.Hour)
	}
	crudScopeMustExec(t, db, `INSERT INTO purchase_requests (org_id, user_id, title) VALUES ('org-a', 1, 'forklift'), (NULL, 5, 'personal desk')`)
	crudScopeMustExec(t, db, `INSERT INTO claims (org_id, user_id, title) VALUES ('org-a', 1, 'taxi')`)
	crudScopeMustExec(t, db, `INSERT INTO plans (org_id, user_id, title) VALUES ('org-a', 1, 'roadmap')`)
	crudScopeMustExec(t, db, `INSERT INTO notes (user_id, title) VALUES (1, 'memo')`)
	if configure != nil {
		configure(app)
	}
	return app, buildAppMux(app, true, "http://localhost"), tokens
}

// approvalRequest posts an approval request and returns the status, the body
// with the id cut out (so two answers can be compared) and the id.
func approvalRequest(t *testing.T, mux *http.ServeMux, token, table, rowID, approver, title string) (int, string, int64) {
	t.Helper()
	rec := approvalPost(t, mux, "/api/_approvals", token, map[string]any{"table": table, "row_id": rowID, "approver_email": approver, "title": title})
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("approval request: %d %s", rec.Code, rec.Body.String())
	}
	id, _ := body["id"].(float64)
	delete(body, "id")
	shape, _ := json.Marshal(body)
	return rec.Code, string(shape), int64(id)
}

func approvalDecide(t *testing.T, mux *http.ServeMux, token string, id int64, decision string) *httptest.ResponseRecorder {
	t.Helper()
	return approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), token, map[string]any{"decision": decision})
}

func approvalStatus(t *testing.T, app *App, id int64) string {
	t.Helper()
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_approvals WHERE id = ?", id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func approvalList(t *testing.T, mux *http.ServeMux, token, path string) string {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// A member of tenant A named an account of tenant B as approver of a tenant A
// record: that account was notified with the requester's text, read the
// requester's email, the table and the row id under ?mine=1, and its decision
// was stored in the record's approval history that tenant A's readers see.
func TestApprovalApproverMustBelongToTheRecordTenant(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)

	// The answer for an approver outside the tenant is the answer for an
	// address nobody holds: nothing in it says the account exists.
	unknownCode, unknownShape, _ := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "nobody@example.com", "Unknown ask")
	code, shape, crossID := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "bappr@example.com", "Cross tenant ask DINGO")
	if code != unknownCode || shape != unknownShape {
		t.Fatalf("outside-tenant approver answered %d %s, an unknown address %d %s", code, shape, unknownCode, unknownShape)
	}
	if n := approvalNotifications(t, app, "bappr@example.com"); n != 0 {
		t.Errorf("an account of another tenant got %d notification(s) with the requester's text", n)
	}
	var boundTo sql.NullInt64
	if err := app.DB.QueryRow("SELECT approver_id FROM _benmore_approvals WHERE id = ?", crossID).Scan(&boundTo); err != nil {
		t.Fatal(err)
	}
	if boundTo.Valid {
		t.Errorf("the request was bound to account %d of another tenant", boundTo.Int64)
	}
	for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals", "/api/_approvals?table=purchase_requests&row_id=1"} {
		if body := approvalList(t, mux, tok["bappr"], path); strings.Contains(body, "DINGO") || strings.Contains(body, "areq@example.com") {
			t.Errorf("tenant B's account reads tenant A's approval via %s: %s", path, body)
		}
	}
	// Refused like an approval it was never named on.
	missing := approvalDecide(t, mux, tok["bappr"], 987654, "approved")
	rec := approvalDecide(t, mux, tok["bappr"], crossID, "approved")
	if rec.Code != missing.Code || rec.Body.String() != missing.Body.String() {
		t.Errorf("decide from another tenant: %d %s (an unknown approval answers %d %s)", rec.Code, rec.Body.String(), missing.Code, missing.Body.String())
	}
	if got := approvalStatus(t, app, crossID); got != "pending" {
		t.Fatalf("an account of another tenant decided a tenant A record's approval: %s", got)
	}
	// An account with no tenant is outside the record's tenant too.
	_, _, lonerID := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "loner@example.com", "Tenantless ask")
	if n := approvalNotifications(t, app, "loner@example.com"); n != 0 {
		t.Errorf("an account with no tenant got %d notification(s)", n)
	}
	if rec := approvalDecide(t, mux, tok["loner"], lonerID, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, lonerID) != "pending" {
		t.Errorf("an account with no tenant decided a tenant A record's approval: %d %s", rec.Code, rec.Body.String())
	}

	// A member of the record's tenant is asked, lists and decides as before.
	_, _, okID := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", "Buy the forklift")
	if n := approvalNotifications(t, app, "aappr@example.com"); n != 1 {
		t.Fatalf("in-tenant approver has %d notifications, want 1", n)
	}
	if body := approvalList(t, mux, tok["aappr"], "/api/_approvals?mine=1"); !strings.Contains(body, "Buy the forklift") {
		t.Fatalf("in-tenant approver does not list the request: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], okID, "approved"); rec.Code != http.StatusOK || approvalStatus(t, app, okID) != "approved" {
		t.Fatalf("in-tenant approver decide: %d %s", rec.Code, rec.Body.String())
	}

	// The approver need not be able to read the record: claims is owner-only,
	// so aappr gets 404 for the row and still decides the request on it.
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/claims/1", tok["aappr"], nil); rec.Code != http.StatusNotFound {
		t.Fatalf("fixture: aappr reads areq's owner-only claim: %d", rec.Code)
	}
	_, _, claimID := approvalRequest(t, mux, tok["areq"], "claims", "1", "aappr@example.com", "Taxi claim")
	if n := approvalNotifications(t, app, "aappr@example.com"); n != 2 {
		t.Errorf("approver of an owner-only record in their tenant has %d notifications, want 2", n)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], claimID, "rejected"); rec.Code != http.StatusOK {
		t.Errorf("approver of an owner-only record in their tenant: %d %s", rec.Code, rec.Body.String())
	}
	_, _, claimCross := approvalRequest(t, mux, tok["areq"], "claims", "1", "bappr@example.com", "Taxi claim for B")
	if rec := approvalDecide(t, mux, tok["bappr"], claimCross, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, claimCross) != "pending" {
		t.Errorf("another tenant's account decided an owner-only record's approval: %d %s", rec.Code, rec.Body.String())
	}

	// The same on a table scoped by membership (`member-of:`).
	_, _, planID := approvalRequest(t, mux, tok["areq"], "plans", "1", "aappr@example.com", "Roadmap")
	_, _, planCross := approvalRequest(t, mux, tok["areq"], "plans", "1", "bappr@example.com", "Roadmap for B")
	if rec := approvalDecide(t, mux, tok["bappr"], planCross, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, planCross) != "pending" {
		t.Errorf("another tenant's account decided a membership-scoped record's approval: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalDecide(t, mux, tok["aappr"], planID, "approved"); rec.Code != http.StatusOK {
		t.Errorf("in-tenant approver of a membership-scoped record: %d %s", rec.Code, rec.Body.String())
	}

	// A global admin reads every tenant's records and stays a valid approver.
	_, _, bossID := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "boss@example.com", "Ask the admin")
	if n := approvalNotifications(t, app, "boss@example.com"); n != 1 {
		t.Errorf("global admin approver has %d notifications, want 1", n)
	}
	if body := approvalList(t, mux, tok["boss"], "/api/_approvals?mine=1"); !strings.Contains(body, "Ask the admin") {
		t.Errorf("global admin does not list the request assigned to it: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["boss"], bossID, "approved"); rec.Code != http.StatusOK {
		t.Errorf("global admin approver decide: %d %s", rec.Code, rec.Body.String())
	}
	if n := approvalNotifications(t, app, "bappr@example.com"); n != 0 {
		t.Errorf("tenant B's account ended with %d notification(s) from tenant A records", n)
	}
}

// Where no tenant is involved an approval reaches any account, as before: a
// record with no tenant value and a table with neither the tenant key nor a
// membership rule. (A free-form label takes the requester's tenant:
// TestApprovalOnALabelStaysInTheRequestersTenant.)
func TestApprovalsWithoutATenantReachAnyAccount(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)
	for i, c := range []struct{ requester, table, rowID string }{
		{"loner", "purchase_requests", "2"}, // a record that carries no tenant
		{"areq", "notes", "1"},              // a table without the tenant key
	} {
		title := fmt.Sprintf("No tenant %d", i)
		code, _, id := approvalRequest(t, mux, tok[c.requester], c.table, c.rowID, "bappr@example.com", title)
		if code != http.StatusOK {
			t.Fatalf("%s/%s request: %d", c.table, c.rowID, code)
		}
		if n := approvalNotifications(t, app, "bappr@example.com"); n != i+1 {
			t.Errorf("%s/%s: approver has %d notifications, want %d", c.table, c.rowID, n, i+1)
		}
		if body := approvalList(t, mux, tok["bappr"], "/api/_approvals?mine=1"); !strings.Contains(body, title) {
			t.Errorf("%s/%s: approver does not list the request: %s", c.table, c.rowID, body)
		}
		if rec := approvalDecide(t, mux, tok["bappr"], id, "approved"); rec.Code != http.StatusOK {
			t.Errorf("%s/%s: approver decide: %d %s", c.table, c.rowID, rec.Code, rec.Body.String())
		}
	}
}

// The tenant is checked when the request is listed and decided, not only when
// it is made: an approver removed from the record's tenant (or moved to
// another one) neither lists nor decides it, and one who joins later does.
func TestApprovalFollowsTheApproversLiveTenant(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)
	_, _, id := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", "Buy the forklift")
	if body := approvalList(t, mux, tok["aappr"], "/api/_approvals?mine=1"); !strings.Contains(body, "Buy the forklift") {
		t.Fatalf("fixture: in-tenant approver does not list the request: %s", body)
	}
	refused := func(when string) {
		t.Helper()
		for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals"} {
			if body := approvalList(t, mux, tok["aappr"], path); strings.Contains(body, "Buy the forklift") {
				t.Errorf("%s: the approver still lists the request via %s: %s", when, path, body)
			}
		}
		if rec := approvalDecide(t, mux, tok["aappr"], id, "approved"); rec.Code != http.StatusForbidden {
			t.Errorf("%s: decide answered %d %s", when, rec.Code, rec.Body.String())
		}
		if got := approvalStatus(t, app, id); got != "pending" {
			t.Fatalf("%s: the approval was decided: %s", when, got)
		}
	}
	crudScopeMustExec(t, app.DB, `DELETE FROM members WHERE user_id = 2`)
	refused("removed from the tenant")
	crudScopeMustExec(t, app.DB, `INSERT INTO members (org_id, user_id) VALUES ('org-b', 2)`)
	refused("moved to another tenant")

	// The requester and the record's readers keep the request in its history.
	if body := approvalList(t, mux, tok["areq"], "/api/_approvals?table=purchase_requests&row_id=1"); !strings.Contains(body, "Buy the forklift") {
		t.Errorf("the requester lost the request: %s", body)
	}

	// A request made while the named account was outside the tenant becomes
	// that account's once it is a member.
	_, _, later := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "bappr@example.com", "For a future member")
	crudScopeMustExec(t, app.DB, `UPDATE members SET org_id = 'org-a' WHERE user_id = 3`)
	if body := approvalList(t, mux, tok["bappr"], "/api/_approvals?mine=1"); !strings.Contains(body, "For a future member") {
		t.Errorf("a new member does not list the request addressed to it: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["bappr"], later, "approved"); rec.Code != http.StatusOK {
		t.Errorf("a new member decide: %d %s", rec.Code, rec.Body.String())
	}
}

// A record that has been removed has no tenant left to check. The request it
// carried is not handed to the outside account it named; an admin still
// decides it.
func TestApprovalOnARemovedRecordAdmitsNoOutsider(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)
	_, _, cross := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "bappr@example.com", "Ask, then delete")
	_, _, inside := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", "Ask a colleague")
	crudScopeMustExec(t, app.DB, `DELETE FROM purchase_requests WHERE id = 1`)

	if body := approvalList(t, mux, tok["bappr"], "/api/_approvals?mine=1"); strings.Contains(body, "Ask, then delete") {
		t.Errorf("deleting the record handed its request to another tenant's account: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["bappr"], cross, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, cross) != "pending" {
		t.Errorf("another tenant's account decided the request of a removed record: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalDecide(t, mux, tok["aappr"], inside, "approved"); rec.Code != http.StatusForbidden {
		t.Errorf("decide on a removed record by its former approver: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalDecide(t, mux, tok["boss"], inside, "rejected"); rec.Code != http.StatusOK || approvalStatus(t, app, inside) != "rejected" {
		t.Errorf("admin decide on a removed record: %d %s", rec.Code, rec.Body.String())
	}
}
