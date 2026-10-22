//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// An approval request on an app record shows up in that record's approval
// history (GET /api/_approvals?table=&row_id=, the Approval component) for
// everyone who can read the record. Any signed-in user could attach one to a
// record they cannot read - another owner's or tenant's - name themselves as
// approver, approve it, and the record then showed "Last decision: approved"
// (or a pending request that hides the real request form). Requests on an app
// table now need read access to the row; free-form labels are unchanged.
func TestApprovalRequestNeedsReadAccessToTheRecord(t *testing.T) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (org_id, user_id, title) VALUES (NULL, 1, 'alice-invoice')`,
	)
	EnsureNotificationsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	mallory := createCrudScopeSession(t, app, "mallory@example.com", "user", "", "")

	rec := approvalPost(t, mux, "/api/_approvals", mallory, map[string]any{"table": "records", "row_id": "1", "approver_email": "mallory@example.com", "title": "Approved by finance"})
	if rec.Code == http.StatusOK {
		var id int64
		app.DB.QueryRow("SELECT id FROM _benmore_approvals WHERE requested_email = 'mallory@example.com'").Scan(&id)
		approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), mallory, map[string]any{"decision": "approved"})
		history := crudScopeRequest(t, mux, http.MethodGet, "/api/_approvals?table=records&row_id=1", alice, nil)
		t.Fatalf("an outsider attached an approval to a record they cannot read (owner now sees: %s)", history.Body.String())
	}
	if n := countRows(t, app, "_benmore_approvals"); n != 0 {
		t.Fatalf("refused request stored %d approvals", n)
	}

	// The record's owner still requests approvals on it, and a free-form
	// label that names no table keeps working for anyone.
	if rec := approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "records", "row_id": "1", "approver_email": "boss@example.com", "title": "Pay invoice"}); rec.Code != http.StatusOK {
		t.Fatalf("owner request: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalPost(t, mux, "/api/_approvals", mallory, map[string]any{"table": "expense-claim", "row_id": "Q3-17", "approver_email": "boss@example.com", "title": "Travel"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pending") {
		t.Fatalf("free-form approval label: %d %s", rec.Code, rec.Body.String())
	}
}
