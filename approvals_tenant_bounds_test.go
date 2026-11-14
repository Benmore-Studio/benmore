//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// approvalsBoundsApp is approvalsTenantApp plus the tables whose tenant is
// not a groups: key column:
//
//	orgs      the groups.bootstrap org_table (its row id IS the tenant),
//	          readable by every signed-in account
//	rooms,    scoped by `member-of:room_members(room_id, user_id)`, with no
//	messages  tenant key; areq and aappr are in room 1
func approvalsBoundsApp(t *testing.T) (*App, *http.ServeMux, map[string]string) {
	t.Helper()
	return approvalsTenantFixture(t, func(app *App) {
		for _, stmt := range []string{
			`CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT)`,
			`CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
			`CREATE TABLE room_members (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, user_id INTEGER)`,
			`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, user_id INTEGER, title TEXT)`,
			`INSERT INTO orgs (id, name) VALUES ('org-a', 'A'), ('org-b', 'B')`,
			`INSERT INTO rooms (title) VALUES ('planning')`,
			`INSERT INTO room_members (room_id, user_id) VALUES (1, 1), (1, 2)`,
			`INSERT INTO messages (room_id, user_id, title) VALUES (1, 1, 'draft')`,
			`INSERT INTO purchase_requests (org_id, user_id, title) VALUES ('org-a', 2, 'crane')`, // id 3, a colleague's
		} {
			crudScopeMustExec(t, app.DB, stmt)
		}
		app.Group.Bootstrap = &GroupBootstrapConfig{OrgTable: "orgs"}
		app.Access.rules["orgs"] = map[AccessOp]string{OpRead: "everyone"}
		app.Access.rules["rooms"] = map[AccessOp]string{"all": "member-of:room_members(room_id, user_id)"}
		app.Access.rules["messages"] = map[AccessOp]string{"all": "member-of:room_members(room_id, user_id)"}
		app.Tables = append(app.Tables,
			Table{Name: "orgs", Columns: []Column{{Name: "id", Type: "TEXT"}, {Name: "name"}}},
			Table{Name: "rooms", Columns: []Column{{Name: "id"}, {Name: "title"}}},
			Table{Name: "room_members", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "user_id"}}},
			Table{Name: "messages", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "user_id"}, {Name: "title"}}},
		)
	})
}

// approvalOutsider asserts that naming `approver` on table/rowID is answered
// like naming an address nobody holds, and that the account is not notified,
// lists nothing of the request and cannot decide it.
func approvalOutsider(t *testing.T, app *App, mux *http.ServeMux, tok map[string]string, requester, table, rowID, approver, marker string) {
	t.Helper()
	before := approvalNotifications(t, app, approver+"@example.com")
	unknownCode, unknownShape, _ := approvalRequest(t, mux, tok[requester], table, rowID, "nobody@example.com", "Unknown ask "+marker)
	code, shape, id := approvalRequest(t, mux, tok[requester], table, rowID, approver+"@example.com", "Outside ask "+marker)
	if code != unknownCode || shape != unknownShape {
		t.Fatalf("%s/%s: outside approver answered %d %s, an unknown address %d %s", table, rowID, code, shape, unknownCode, unknownShape)
	}
	if n := approvalNotifications(t, app, approver+"@example.com"); n != before {
		t.Errorf("%s/%s: %s got %d notification(s) with the requester's text", table, rowID, approver, n-before)
	}
	for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals"} {
		if body := approvalList(t, mux, tok[approver], path); strings.Contains(body, marker) {
			t.Errorf("%s/%s: %s reads the request via %s: %s", table, rowID, approver, path, body)
		}
	}
	missing := approvalDecide(t, mux, tok[approver], 987654, "approved")
	rec := approvalDecide(t, mux, tok[approver], id, "approved")
	if rec.Code != missing.Code || rec.Body.String() != missing.Body.String() {
		t.Errorf("%s/%s: decide by %s: %d %s (an unknown approval answers %d %s)", table, rowID, approver, rec.Code, rec.Body.String(), missing.Code, missing.Body.String())
	}
	if got := approvalStatus(t, app, id); got != "pending" {
		t.Errorf("%s/%s: %s decided the request: %s", table, rowID, approver, got)
	}
}

// approvalInsider asserts that `approver` is notified of, lists and decides
// a request on table/rowID.
func approvalInsider(t *testing.T, app *App, mux *http.ServeMux, tok map[string]string, requester, table, rowID, approver, title string) {
	t.Helper()
	before := approvalNotifications(t, app, approver+"@example.com")
	_, _, id := approvalRequest(t, mux, tok[requester], table, rowID, approver+"@example.com", title)
	if n := approvalNotifications(t, app, approver+"@example.com"); n != before+1 {
		t.Errorf("%s/%s: %s has %d new notification(s), want 1", table, rowID, approver, n-before)
	}
	if body := approvalList(t, mux, tok[approver], "/api/_approvals?mine=1"); !strings.Contains(body, title) {
		t.Errorf("%s/%s: %s does not list the request: %s", table, rowID, approver, body)
	}
	if rec := approvalDecide(t, mux, tok[approver], id, "approved"); rec.Code != http.StatusOK || approvalStatus(t, app, id) != "approved" {
		t.Errorf("%s/%s: decide by %s: %d %s", table, rowID, approver, rec.Code, rec.Body.String())
	}
}

// A requester who has left the record's tenant kept listing the request
// (with the approver's address, the decision and its note, all written after
// they left) and was notified of the decision.
func TestApprovalRequesterOutsideTheTenantNeitherListsNorIsNotified(t *testing.T) {
	app, mux, tok := approvalsBoundsApp(t)
	// While a member: listed, and notified of the decision.
	_, _, first := approvalRequest(t, mux, tok["areq"], "purchase_requests", "3", "aappr@example.com", "Crane ask EMU")
	if rec := approvalDecide(t, mux, tok["aappr"], first, "approved"); rec.Code != http.StatusOK {
		t.Fatalf("fixture: decide: %d %s", rec.Code, rec.Body.String())
	}
	if n := approvalNotifications(t, app, "areq@example.com"); n != 1 {
		t.Fatalf("a requester in the tenant has %d decision notification(s), want 1", n)
	}
	_, _, second := approvalRequest(t, mux, tok["areq"], "purchase_requests", "3", "aappr@example.com", "Crane ask KOALA")
	paths := []string{"/api/_approvals", "/api/_approvals?table=purchase_requests&row_id=3", "/api/_approvals?table=purchase_requests"}
	for _, path := range paths {
		if body := approvalList(t, mux, tok["areq"], path); !strings.Contains(body, "KOALA") {
			t.Fatalf("fixture: the requester does not list the request via %s: %s", path, body)
		}
	}

	crudScopeMustExec(t, app.DB, `DELETE FROM members WHERE user_id = 1`)
	for _, path := range paths {
		if body := approvalList(t, mux, tok["areq"], path); strings.Contains(body, "KOALA") || strings.Contains(body, "EMU") {
			t.Errorf("a requester who left the tenant still lists its approvals via %s: %s", path, body)
		}
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", second), tok["aappr"], map[string]any{"decision": "rejected", "note": "over budget WOMBAT"}); rec.Code != http.StatusOK {
		t.Fatalf("decide after the requester left: %d %s", rec.Code, rec.Body.String())
	}
	if n := approvalNotifications(t, app, "areq@example.com"); n != 1 {
		t.Errorf("a requester who left the tenant has %d notification(s), want the 1 from before", n)
	}

	// Back in the tenant, the requests are theirs to list again.
	crudScopeMustExec(t, app.DB, `INSERT INTO members (org_id, user_id) VALUES ('org-a', 1)`)
	if body := approvalList(t, mux, tok["areq"], "/api/_approvals"); !strings.Contains(body, "KOALA") || !strings.Contains(body, "WOMBAT") {
		t.Errorf("a requester back in the tenant does not list the request and its decision: %s", body)
	}

	// An admin requester has no tenant and is unchanged.
	_, _, byAdmin := approvalRequest(t, mux, tok["boss"], "purchase_requests", "3", "aappr@example.com", "Admin ask")
	if rec := approvalDecide(t, mux, tok["aappr"], byAdmin, "approved"); rec.Code != http.StatusOK {
		t.Fatalf("decide an admin's request: %d %s", rec.Code, rec.Body.String())
	}
	if n := approvalNotifications(t, app, "boss@example.com"); n != 1 {
		t.Errorf("an admin requester has %d decision notification(s), want 1", n)
	}
	if body := approvalList(t, mux, tok["boss"], "/api/_approvals"); !strings.Contains(body, "Admin ask") {
		t.Errorf("an admin does not list their request: %s", body)
	}

	// A record that has been removed has no tenant left to check: its
	// requester keeps the request in their list.
	crudScopeMustExec(t, app.DB, `DELETE FROM purchase_requests WHERE id = 3`)
	if body := approvalList(t, mux, tok["areq"], "/api/_approvals"); !strings.Contains(body, "KOALA") {
		t.Errorf("the requester lost the request of a removed record: %s", body)
	}
}

// The groups.bootstrap org table has no tenant key column (its row id is the
// tenant), and a `member-of:` table need not have one: an approval on their
// records accepted any account as approver.
func TestApprovalOnAnOrgOrMembershipRecordStaysInsideIt(t *testing.T) {
	app, mux, tok := approvalsBoundsApp(t)

	// The tenant's own row: only its members (and a global admin).
	approvalOutsider(t, app, mux, tok, "areq", "orgs", "org-a", "bappr", "QUOKKA")
	approvalOutsider(t, app, mux, tok, "areq", "orgs", "org-a", "loner", "NUMBAT")
	approvalInsider(t, app, mux, tok, "areq", "orgs", "org-a", "aappr", "Rename the company")
	approvalInsider(t, app, mux, tok, "areq", "orgs", "org-a", "boss", "Ask the admin about the company")

	// A record scoped by membership: only members of what it belongs to.
	for _, c := range []struct{ table, rowID string }{{"messages", "1"}, {"rooms", "1"}} {
		approvalOutsider(t, app, mux, tok, "areq", c.table, c.rowID, "bappr", "BILBY"+c.table)
		approvalOutsider(t, app, mux, tok, "areq", c.table, c.rowID, "loner", "POTOROO"+c.table)
		approvalInsider(t, app, mux, tok, "areq", c.table, c.rowID, "aappr", "Publish "+c.table)
		approvalInsider(t, app, mux, tok, "areq", c.table, c.rowID, "boss", "Admin, publish "+c.table)
	}

	// Checked when listed and decided: a member removed from the room stops,
	// one who joins picks the request up.
	_, _, leaving := approvalRequest(t, mux, tok["areq"], "messages", "1", "aappr@example.com", "For a leaving member")
	_, _, joining := approvalRequest(t, mux, tok["areq"], "messages", "1", "bappr@example.com", "For a joining member")
	crudScopeMustExec(t, app.DB, `DELETE FROM room_members WHERE user_id = 2`)
	crudScopeMustExec(t, app.DB, `INSERT INTO room_members (room_id, user_id) VALUES (1, 3)`)
	if body := approvalList(t, mux, tok["aappr"], "/api/_approvals?mine=1"); strings.Contains(body, "For a leaving member") {
		t.Errorf("a removed room member still lists the request: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], leaving, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, leaving) != "pending" {
		t.Errorf("a removed room member decided: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalDecide(t, mux, tok["bappr"], joining, "approved"); rec.Code != http.StatusOK {
		t.Errorf("a new room member decide: %d %s", rec.Code, rec.Body.String())
	}

	// A table with neither a tenant key nor a membership rule is not bounded.
	approvalInsider(t, app, mux, tok, "areq", "notes", "1", "bappr", "Unbounded note")
}

// A free-form label (a `table` that names no app table) reached any account
// in any tenant with text the requester chose. In an app with groups: the
// approver of a label is in a tenant the requester belongs to, or is a
// global admin.
func TestApprovalOnALabelStaysInTheRequestersTenant(t *testing.T) {
	app, mux, tok := approvalsBoundsApp(t)
	approvalOutsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "bappr", "TAIPAN")
	approvalOutsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "loner", "GOANNA")
	approvalInsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "aappr", "Travel claim")
	approvalInsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "boss", "Travel claim for the admin")

	// A requester with no tenant names only a global admin.
	approvalOutsider(t, app, mux, tok, "loner", "expense-claim", "Q3-18", "aappr", "SKINK")
	approvalInsider(t, app, mux, tok, "loner", "expense-claim", "Q3-18", "boss", "Loner asks the admin")

	// A global admin's request reaches any account, as before.
	approvalInsider(t, app, mux, tok, "boss", "expense-claim", "Q3-19", "bappr", "Admin asks tenant B")

	// Checked when listed and decided, against the requester's live
	// membership: the approver who leaves the tenant stops, and so does every
	// approver once the requester has left.
	_, _, id := approvalRequest(t, mux, tok["areq"], "expense-claim", "Q3-20", "aappr@example.com", "Hotel claim")
	crudScopeMustExec(t, app.DB, `UPDATE members SET org_id = 'org-b' WHERE user_id = 2`)
	if body := approvalList(t, mux, tok["aappr"], "/api/_approvals?mine=1"); strings.Contains(body, "Hotel claim") {
		t.Errorf("an approver who moved to another tenant still lists the label request: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], id, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, id) != "pending" {
		t.Errorf("an approver who moved to another tenant decided: %d %s", rec.Code, rec.Body.String())
	}
	crudScopeMustExec(t, app.DB, `UPDATE members SET org_id = 'org-b' WHERE user_id = 1`)
	if rec := approvalDecide(t, mux, tok["aappr"], id, "approved"); rec.Code != http.StatusOK {
		t.Errorf("approver and requester in one tenant again: %d %s", rec.Code, rec.Body.String())
	}
	// The requester keeps their own label requests wherever they are.
	if body := approvalList(t, mux, tok["areq"], "/api/_approvals"); !strings.Contains(body, "Hotel claim") || !strings.Contains(body, "TAIPAN") {
		t.Errorf("the requester does not list their label requests: %s", body)
	}
}

// The same bound when the groups: membership table names its members by
// address: the requester's membership is read from their proven address.
func TestApprovalOnALabelWithEmailKeyedMembership(t *testing.T) {
	app, mux, tok := approvalsTenantFixture(t, func(app *App) {
		crudScopeMustExec(t, app.DB, `ALTER TABLE members ADD COLUMN member_email TEXT`)
		crudScopeMustExec(t, app.DB, `UPDATE members SET member_email = (SELECT email FROM _benmore_users WHERE id = members.user_id), user_id = NULL`)
		app.Group.UserField = "member_email"
		app.Tables[0].Columns = append(app.Tables[0].Columns, Column{Name: "member_email"})
	})
	approvalOutsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "bappr", "TAIPAN")
	approvalInsider(t, app, mux, tok, "areq", "expense-claim", "Q3-17", "aappr", "Travel claim")
	// An address the requester has not proven places them in no tenant.
	_, _, id := approvalRequest(t, mux, tok["areq"], "expense-claim", "Q3-18", "aappr@example.com", "Hotel claim")
	crudScopeMustExec(t, app.DB, `UPDATE _benmore_users SET verified = 0, email_grandfathered = 0 WHERE id = 1`)
	if rec := approvalDecide(t, mux, tok["aappr"], id, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, id) != "pending" {
		t.Errorf("decide a label request of a requester with an unproven address: %d %s", rec.Code, rec.Body.String())
	}
}

// The approval's title is the text of the notification: a requester could
// put a megabyte into another account's notification list, 30 times per ten
// minutes. The notification carries a bounded copy; the approval keeps the
// title as written.
func TestApprovalNotificationTextIsCapped(t *testing.T) {
	app, mux, tok := approvalsBoundsApp(t)
	long := strings.Repeat("é<b>x</b> ", 20000)
	_, _, id := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", long)
	var body, stored string
	if err := app.DB.QueryRow("SELECT body FROM _benmore_notifications WHERE user_id = 2 ORDER BY id DESC LIMIT 1").Scan(&body); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(body); n > approvalNotificationTextMax+1 || !utf8.ValidString(body) || !strings.HasPrefix(long, strings.TrimSuffix(body, "…")) {
		t.Errorf("the approver's notification carries %d characters of the title (valid UTF-8: %v), want at most %d", n, utf8.ValidString(body), approvalNotificationTextMax)
	}
	if err := app.DB.QueryRow("SELECT title FROM _benmore_approvals WHERE id = ?", id).Scan(&stored); err != nil || stored != long {
		t.Errorf("the approval's own title was changed (%d bytes stored, %d sent): %v", len(stored), len(long), err)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], id, "approved"); rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}
	if err := app.DB.QueryRow("SELECT body FROM _benmore_notifications WHERE user_id = 1 ORDER BY id DESC LIMIT 1").Scan(&body); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(body); n > approvalNotificationTextMax+1 {
		t.Errorf("the requester's decision notification carries %d characters, want at most %d", n, approvalNotificationTextMax)
	}
	// A short title is the notification's text unchanged.
	approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", "Buy <the> forklift")
	if err := app.DB.QueryRow("SELECT body FROM _benmore_notifications WHERE user_id = 2 ORDER BY id DESC LIMIT 1").Scan(&body); err != nil || body != "Buy <the> forklift" {
		t.Errorf("a short title arrived as %q: %v", body, err)
	}
}
