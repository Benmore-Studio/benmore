//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
)

// SQLite resolves a table name in any ASCII letter case, and the approval
// request matched it exactly: `PURCHASE_REQUESTS` was stored as a free-form
// label, so the requester's read check on the record and the tenant bound on
// its approver were both skipped, while the stored row read as an approval on
// that table. The name is resolved to the schema's spelling first.

func approvalStoredTable(t *testing.T, app *App, id int64) string {
	t.Helper()
	var name string
	if err := app.DB.QueryRow("SELECT table_name FROM _benmore_approvals WHERE id = ?", id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestApprovalTableNameInAnotherCaseKeepsTheTenantBound(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)
	unknownCode, unknownShape, _ := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "nobody@example.com", "Unknown ask")
	code, shape, crossID := approvalRequest(t, mux, tok["areq"], "PURCHASE_REQUESTS", "1", "bappr@example.com", "Upper case ask DINGO")
	if code != unknownCode || shape != unknownShape {
		t.Fatalf("outside-tenant approver answered %d %s, an unknown address %d %s", code, shape, unknownCode, unknownShape)
	}
	if got := approvalStoredTable(t, app, crossID); got != "purchase_requests" {
		t.Errorf("stored table_name = %q, want the schema spelling purchase_requests", got)
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
	for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals", "/api/_approvals?table=PURCHASE_REQUESTS&row_id=1", "/api/_approvals?table=purchase_requests&row_id=1"} {
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

	// The same request under either spelling is one request, in the record's
	// history under either spelling, and a member of the tenant decides it.
	_, _, okID := approvalRequest(t, mux, tok["areq"], "Purchase_Requests", "1", "aappr@example.com", "Buy the forklift")
	if _, _, again := approvalRequest(t, mux, tok["areq"], "purchase_requests", "1", "aappr@example.com", "Buy the forklift"); again != okID {
		t.Errorf("the schema spelling stored a second request %d beside %d", again, okID)
	}
	for _, path := range []string{"/api/_approvals?table=Purchase_Requests&row_id=1", "/api/_approvals?table=purchase_requests&row_id=1"} {
		if body := approvalList(t, mux, tok["aappr"], path); !strings.Contains(body, "Buy the forklift") {
			t.Errorf("a reader of the record does not see its request via %s: %s", path, body)
		}
	}
	if rec := approvalDecide(t, mux, tok["aappr"], okID, "approved"); rec.Code != http.StatusOK || approvalNotifications(t, app, "aappr@example.com") != 1 {
		t.Fatalf("in-tenant approver decide: %d %s", rec.Code, rec.Body.String())
	}
	// A name that matches no table in any case stays a label, stored as
	// written, for an approver in the requester's tenant.
	_, _, labelID := approvalRequest(t, mux, tok["areq"], "Expense-Claim", "Q3-17", "aappr@example.com", "Travel")
	if rec := approvalDecide(t, mux, tok["aappr"], labelID, "approved"); rec.Code != http.StatusOK || approvalStoredTable(t, app, labelID) != "Expense-Claim" {
		t.Errorf("approver of a label: %d %s", rec.Code, rec.Body.String())
	}
}

// A request stored under another spelling before the name was resolved is
// bounded like one on the table when it is listed and decided, and stays out
// of the history the record's readers see.
func TestApprovalStoredUnderAnotherCaseIsBoundedWhenDecided(t *testing.T) {
	app, mux, tok := approvalsTenantApp(t)
	res, err := app.DB.Exec(`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_email, approver_id, title)
		VALUES ('PURCHASE_REQUESTS', '1', 1, 'areq@example.com', 'bappr@example.com', 3, 'Stored earlier EMU'),
		       ('PURCHASE_REQUESTS', '1', 1, 'areq@example.com', 'aappr@example.com', 2, 'Stored earlier, colleague')`)
	if err != nil {
		t.Fatal(err)
	}
	last, _ := res.LastInsertId()
	cross, inside := last-1, last
	for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals", "/api/_approvals?table=PURCHASE_REQUESTS&row_id=1"} {
		if body := approvalList(t, mux, tok["bappr"], path); strings.Contains(body, "EMU") {
			t.Errorf("tenant B's account reads the stored request via %s: %s", path, body)
		}
	}
	if rec := approvalDecide(t, mux, tok["bappr"], cross, "approved"); rec.Code != http.StatusForbidden || approvalStatus(t, app, cross) != "pending" {
		t.Errorf("another tenant's account decided the stored request: %d %s", rec.Code, rec.Body.String())
	}
	// Its requester and its in-tenant approver still find it under the name
	// it was written with; a reader of the record who is neither does not (it
	// was stored without the requester's read check).
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_users (username, email, role, verified) VALUES ('areader', 'areader@example.com', 'user', 1)`)
	crudScopeMustExec(t, app.DB, `INSERT INTO members (org_id, user_id) VALUES ('org-a', 6)`)
	tok["areader"] = CreateSession(app.DB, 6, "areader@example.com", "", app.SessionDuration)
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/purchase_requests/1", tok["areader"], nil); rec.Code != http.StatusOK {
		t.Fatalf("fixture: a tenant member reads the record: %d", rec.Code)
	}
	for who, want := range map[string]bool{"areq": true, "aappr": true, "areader": false} {
		if body := approvalList(t, mux, tok[who], "/api/_approvals?table=PURCHASE_REQUESTS&row_id=1"); strings.Contains(body, "Stored earlier, colleague") != want {
			t.Errorf("%s listing the stored request under its written name (want %v): %s", who, want, body)
		}
	}
	if body := approvalList(t, mux, tok["areader"], "/api/_approvals?table=purchase_requests&row_id=1"); strings.Contains(body, "Stored earlier") {
		t.Errorf("the stored request joined the record's history: %s", body)
	}
	if rec := approvalDecide(t, mux, tok["aappr"], inside, "approved"); rec.Code != http.StatusOK || approvalStatus(t, app, inside) != "approved" {
		t.Errorf("in-tenant approver of the stored request: %d %s", rec.Code, rec.Body.String())
	}
}

// The requester must be able to read the record whatever case the table name
// is written in.
func TestApprovalTableNameInAnotherCaseNeedsReadAccessToTheRecord(t *testing.T) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (org_id, user_id, title) VALUES (NULL, 1, 'alice-invoice')`,
	)
	EnsureNotificationsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	mallory := createCrudScopeSession(t, app, "mallory@example.com", "user", "", "")
	body := map[string]any{"table": "records", "row_id": "1", "approver_email": "boss@example.com", "title": "Approved by finance"}
	want := approvalPost(t, mux, "/api/_approvals", mallory, body)
	if want.Code != http.StatusNotFound {
		t.Fatalf("fixture: the schema spelling answered %d %s", want.Code, want.Body.String())
	}
	for _, name := range []string{"RECORDS", "Records"} {
		body["table"] = name
		if rec := approvalPost(t, mux, "/api/_approvals", mallory, body); rec.Code != want.Code || rec.Body.String() != want.Body.String() {
			t.Errorf("table %q on a record the requester cannot read: %d %s, want %d %s", name, rec.Code, rec.Body.String(), want.Code, want.Body.String())
		}
	}
	if n := countRows(t, app, "_benmore_approvals"); n != 0 {
		t.Fatalf("refused requests stored %d approvals", n)
	}
	// The record's owner requests under either spelling.
	body["table"] = "RECORDS"
	if rec := approvalPost(t, mux, "/api/_approvals", alice, body); rec.Code != http.StatusOK {
		t.Fatalf("owner request: %d %s", rec.Code, rec.Body.String())
	}
	var stored string
	if err := app.DB.QueryRow("SELECT table_name FROM _benmore_approvals").Scan(&stored); err != nil || stored != "records" {
		t.Fatalf("stored table_name = %q (%v), want records", stored, err)
	}
}
