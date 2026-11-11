//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// approverIdentityApp is the scheduling API over a users table that has the
// email-trust columns, with a fresh request limiter.
func approverIdentityApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	old := approvalRequestLimiter
	approvalRequestLimiter = NewRateLimiter(approvalRequestBurst, approvalRequestWindow)
	t.Cleanup(func() { approvalRequestLimiter = old })

	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureNotificationsTable(app.DB)
	EnsureSchedulingTables(app.DB)
	mux := http.NewServeMux()
	registerSchedulingAPI(mux, app)
	return app, mux
}

// approverIdentityUser stores an account with the given email trust and
// signs it in. The address is stored exactly as given.
func approverIdentityUser(t *testing.T, app *App, email string, verified, grandfathered bool) (string, int64) {
	t.Helper()
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified, email_grandfathered) VALUES (?, ?, 'user', ?, ?)",
		strings.ToLower(strings.NewReplacer("@", "-", ".", "-").Replace(email)), email, verified, grandfathered)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return CreateSession(app.DB, id, email, "", time.Hour), id
}

func approvalRowText(t *testing.T, app *App, id int64) string {
	t.Helper()
	var approver sql.NullInt64
	var email, status string
	if err := app.DB.QueryRow("SELECT approver_id, approver_email, status FROM _benmore_approvals WHERE id = ?", id).Scan(&approver, &email, &status); err != nil {
		t.Fatal(err)
	}
	who := "none"
	if approver.Valid {
		who = fmt.Sprint(approver.Int64)
	}
	return fmt.Sprintf("approver_id=%s approver_email=%q status=%s", who, email, status)
}

func approvalListBody(t *testing.T, mux *http.ServeMux, token, path string) string {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// An approval addressed by email was bound (approver_id) to whichever account
// held that address, proven or not. Someone who signed up as the approver's
// address ahead of the request, without proving it, then read the request
// (title, requester email) and approved it. The request is now bound only to
// an account that has proven the address, and reaches an unproven account
// once it does.
func TestApprovalByEmailIsNotBoundToAnUnprovenAccount(t *testing.T) {
	app, mux := approverIdentityApp(t)
	alice, _ := approverIdentityUser(t, app, "alice@example.com", true, false)
	// Registered before the request, never verified, not grandfathered.
	squatter, squatterID := approverIdentityUser(t, app, "cfo@corp.example", false, false)

	rec := approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "1", "approver_email": "cfo@corp.example", "title": "Wire 40k to Acme"})
	if rec.Code != http.StatusOK {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	id := responseID(t, rec)
	if got, want := approvalRowText(t, app, id), `approver_id=none approver_email="cfo@corp.example" status=pending`; got != want {
		t.Errorf("request bound to an account that never proved the address:\n got %s\nwant %s", got, want)
	}
	if n := approvalNotifications(t, app, "cfo@corp.example"); n != 0 {
		t.Errorf("the unproven account got %d notifications naming the request", n)
	}
	for _, path := range []string{"/api/_approvals?mine=1", "/api/_approvals"} {
		if body := approvalListBody(t, mux, squatter, path); strings.Contains(body, "Wire 40k") || strings.Contains(body, "alice@example.com") {
			t.Errorf("the unproven account reads the request via %s: %s", path, body)
		}
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), squatter, map[string]any{"decision": "approved", "note": "ok by cfo"}); rec.Code != http.StatusForbidden {
		t.Errorf("the unproven account decided the request: %d %s", rec.Code, rec.Body.String())
	}
	if got := approvalRowText(t, app, id); !strings.HasSuffix(got, "status=pending") {
		t.Fatalf("request no longer pending: %s", got)
	}

	// The address is proven (verification link, emailed code, OAuth claim):
	// the request addressed to it now reaches that account.
	mustExecArgs(t, app.DB, "UPDATE _benmore_users SET verified = 1 WHERE id = ?", squatterID)
	if body := approvalListBody(t, mux, squatter, "/api/_approvals?mine=1"); !strings.Contains(body, "Wire 40k") {
		t.Errorf("the proven address does not see its request: %s", body)
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), squatter, map[string]any{"decision": "approved"}); rec.Code != http.StatusOK {
		t.Errorf("the proven address cannot decide: %d %s", rec.Code, rec.Body.String())
	}
	if got := approvalRowText(t, app, id); !strings.HasSuffix(got, "status=approved") {
		t.Errorf("decision by the proven address not stored: %s", got)
	}
}

// Rows stored before the lookup required a proven address carry approver_id
// next to approver_email. The stored id counts only while that account holds
// the address in proven form; an approver named by id alone is unchanged.
func TestApprovalStoredApproverNeedsTheProvenAddress(t *testing.T) {
	app, mux := approverIdentityApp(t)
	_, aliceID := approverIdentityUser(t, app, "alice@example.com", true, false)
	squatter, squatterID := approverIdentityUser(t, app, "cfo@corp.example", false, false)
	veteran, veteranID := approverIdentityUser(t, app, "ops@corp.example", false, true) // grandfathered
	direct, directID := approverIdentityUser(t, app, "temp@corp.example", false, false)

	insert := func(approver int64, email, title string) int64 {
		t.Helper()
		res, err := app.DB.Exec(`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, approver_email, title)
			VALUES ('wire', '1', ?, 'alice@example.com', ?, ?, ?)`, aliceID, approver, email, title)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	decide := func(token string, id int64) int {
		t.Helper()
		return approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), token, map[string]any{"decision": "approved"}).Code
	}

	legacy := insert(squatterID, "cfo@corp.example", "Legacy wire")
	if body := approvalListBody(t, mux, squatter, "/api/_approvals?mine=1"); strings.Contains(body, "Legacy wire") {
		t.Errorf("unproven account lists a request stored under its id: %s", body)
	}
	if body := approvalListBody(t, mux, squatter, "/api/_approvals"); strings.Contains(body, "Legacy wire") {
		t.Errorf("unproven account reads a request stored under its id: %s", body)
	}
	if code := decide(squatter, legacy); code != http.StatusForbidden {
		t.Errorf("unproven account decided a request stored under its id: %d", code)
	}
	// Proving a different address does not make the stored id count: the
	// request was addressed to cfo@corp.example.
	mustExecArgs(t, app.DB, "UPDATE _benmore_users SET email = 'eve@elsewhere.example', verified = 1 WHERE id = ?", squatterID)
	if body := approvalListBody(t, mux, squatter, "/api/_approvals?mine=1"); strings.Contains(body, "Legacy wire") {
		t.Errorf("account lists a request addressed to an address it no longer holds: %s", body)
	}
	if code := decide(squatter, legacy); code != http.StatusForbidden {
		t.Errorf("account decided a request addressed to an address it never proved: %d", code)
	}
	if got := approvalRowText(t, app, legacy); !strings.HasSuffix(got, "status=pending") {
		t.Fatalf("legacy request no longer pending: %s", got)
	}

	// A grandfathered account keeps its email-keyed grants, this one too.
	kept := insert(veteranID, "ops@corp.example", "Grandfathered wire")
	if body := approvalListBody(t, mux, veteran, "/api/_approvals?mine=1"); !strings.Contains(body, "Grandfathered wire") {
		t.Errorf("grandfathered approver lost its request: %s", body)
	}
	if code := decide(veteran, kept); code != http.StatusOK {
		t.Errorf("grandfathered approver cannot decide: %d", code)
	}

	// Named by id with no address: no email is involved, so nothing to prove.
	byID := insert(directID, "", "Named by id")
	if body := approvalListBody(t, mux, direct, "/api/_approvals?mine=1"); !strings.Contains(body, "Named by id") {
		t.Errorf("approver named by id lost its request: %s", body)
	}
	if code := decide(direct, byID); code != http.StatusOK {
		t.Errorf("approver named by id cannot decide: %d", code)
	}
}

// approver_email in another letter case was stored as typed, matched no
// account and compared exactly afterwards: the request was accepted but the
// approver never saw it and could not decide it. The address is normalized
// when stored and matched in any case when read.
func TestApproverEmailMatchesInAnyLetterCase(t *testing.T) {
	app, mux := approverIdentityApp(t)
	alice, aliceID := approverIdentityUser(t, app, "alice@example.com", true, false)
	bob, bobID := approverIdentityUser(t, app, "bob@example.com", true, false)
	// An account whose stored address kept its capitals (created before
	// addresses were normalized).
	carol, _ := approverIdentityUser(t, app, "Carol@Example.com", true, false)

	rec := approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "1", "approver_email": "  Bob@Example.COM ", "title": "Case test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	id := responseID(t, rec)
	if got, want := approvalRowText(t, app, id), fmt.Sprintf(`approver_id=%d approver_email="bob@example.com" status=pending`, bobID); got != want {
		t.Errorf("stored request:\n got %s\nwant %s", got, want)
	}
	if n := approvalNotifications(t, app, "bob@example.com"); n != 1 {
		t.Errorf("approver notifications = %d, want 1", n)
	}
	// The same request in yet another case is the same pending request.
	rec = approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "1", "approver_email": "BOB@example.com", "title": "Case test"})
	if rec.Code != http.StatusOK || responseID(t, rec) != id {
		t.Errorf("repeat in another case: %d %s, want the pending request %d", rec.Code, rec.Body.String(), id)
	}
	if n := approvalNotifications(t, app, "bob@example.com"); n != 1 {
		t.Errorf("approver notifications after the repeat = %d, want 1", n)
	}
	if body := approvalListBody(t, mux, bob, "/api/_approvals?mine=1"); !strings.Contains(body, "Case test") {
		t.Errorf("approver does not see the request: %s", body)
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), bob, map[string]any{"decision": "approved"}); rec.Code != http.StatusOK {
		t.Errorf("approver cannot decide: %d %s", rec.Code, rec.Body.String())
	}

	// A row stored as typed before this change reaches the approver too, and
	// asking again returns it instead of storing a second pending request.
	res, err := app.DB.Exec(`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_email, title)
		VALUES ('wire', '2', ?, 'alice@example.com', 'Bob@Example.com', 'Stored as typed')`, aliceID)
	if err != nil {
		t.Fatal(err)
	}
	typed, _ := res.LastInsertId()
	rec = approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "2", "approver_email": "bob@example.com", "title": "Stored as typed"})
	if rec.Code != http.StatusOK || responseID(t, rec) != typed {
		t.Errorf("repeat of a request stored as typed: %d %s, want the pending request %d", rec.Code, rec.Body.String(), typed)
	}
	if body := approvalListBody(t, mux, bob, "/api/_approvals?mine=1"); !strings.Contains(body, "Stored as typed") {
		t.Errorf("approver does not see the request stored as typed: %s", body)
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", typed), bob, map[string]any{"decision": "rejected"}); rec.Code != http.StatusOK {
		t.Errorf("approver cannot decide the request stored as typed: %d %s", rec.Code, rec.Body.String())
	}

	// The account's own stored case does not matter either.
	rec = approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "3", "approver_email": "carol@example.com", "title": "For Carol"})
	if rec.Code != http.StatusOK {
		t.Fatalf("request for carol: %d %s", rec.Code, rec.Body.String())
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", responseID(t, rec)), carol, map[string]any{"decision": "approved"}); rec.Code != http.StatusOK {
		t.Errorf("approver whose stored address has capitals cannot decide: %d %s", rec.Code, rec.Body.String())
	}

	// Naming yourself stays refused in any case or padding.
	if rec := approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "4", "approver_email": " ALICE@Example.com", "title": "Mine"}); rec.Code != http.StatusForbidden {
		t.Errorf("self-approval request in another case: %d %s", rec.Code, rec.Body.String())
	}
}

// The account purge blanks approver_email on requests addressed to the erased
// address. A request stored before approvals required a proven address can
// still carry the id of another account that had registered the address
// earlier; with the address blanked the row reads as "approver named by id",
// so the purge clears that stale id with it.
func TestAccountPurgeClearsAStaleApproverIDWithTheAddress(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	EnsureSchedulingTables(app.DB)
	insertPurgeUser(t, app, 1, "alice@example.com")     // requester
	insertPurgeUser(t, app, 2, "eve@elsewhere.example") // registered cfo@corp.example once, then moved to this address
	insertPurgeUser(t, app, 3, "cfo@corp.example")      // holds the address now and erases the account
	mustExec(t, app.DB, `INSERT INTO _benmore_approvals (id, table_name, row_id, requested_by, requested_email, approver_id, approver_email, title) VALUES
		(1, 'wire', '1', 1, 'alice@example.com', 2, 'CFO@corp.example', 'stale id on the erased address'),
		(2, 'wire', '2', 1, 'alice@example.com', 3, 'cfo@corp.example', 'the erased account itself'),
		(3, 'wire', '3', 1, 'alice@example.com', 2, '', 'named by id'),
		(4, 'wire', '4', 1, 'alice@example.com', 2, 'eve@elsewhere.example', 'another address'),
		(5, 'wire', '5', 1, 'alice@example.com', 3, 'treasurer@corp.example', 'bound to the erased id, addressed elsewhere')`)

	flow := &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+CreateSession(app.DB, 3, "cfo@corp.example", "", time.Hour))
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rr.Code, rr.Body.String())
	}

	for id, want := range map[int64]string{
		1: `approver_id=none approver_email="" status=pending`,
		2: `approver_id=3 approver_email="" status=pending`,
		3: `approver_id=2 approver_email="" status=pending`,
		4: `approver_id=2 approver_email="eve@elsewhere.example" status=pending`,
		// Whoever proves treasurer@ owns it, not the tombstone.
		5: `approver_id=none approver_email="treasurer@corp.example" status=pending`,
	} {
		if got := approvalRowText(t, app, id); got != want {
			t.Errorf("approval %d after the purge:\n got %s\nwant %s", id, got, want)
		}
	}

	// What the stale id would have bought: the request addressed to the
	// erased address is not this account's to decide; its own still are.
	mux := http.NewServeMux()
	registerSchedulingAPI(mux, app)
	eve := CreateSession(app.DB, 2, "eve@elsewhere.example", "", time.Hour)
	if rec := approvalPost(t, mux, "/api/_approvals/1/decide", eve, map[string]any{"decision": "approved"}); rec.Code != http.StatusForbidden {
		t.Errorf("account decided a request addressed to the erased address: %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range []int{3, 4} {
		if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), eve, map[string]any{"decision": "approved"}); rec.Code != http.StatusOK {
			t.Errorf("account cannot decide its own approval %d: %d %s", id, rec.Code, rec.Body.String())
		}
	}
}

// OAuth sign-up stores a provider's address as given, and the lookups compare
// with COLLATE NOCASE, which folds ASCII only. Lowercasing all of Unicode
// turned a request for "Élise@Example.com" into "élise@example.com", which
// no lookup matched: no one was notified and Élise could not see or decide it.
func TestApproverEmailKeepsNonASCIICase(t *testing.T) {
	app, mux := approverIdentityApp(t)
	alice, _ := approverIdentityUser(t, app, "alice@example.com", true, false)
	elise, eliseID := approverIdentityUser(t, app, "Élise@Example.com", true, false)

	rec := approvalPost(t, mux, "/api/_approvals", alice, map[string]any{"table": "wire", "row_id": "1", "approver_email": " Élise@EXAMPLE.com ", "title": "Unicode case"})
	if rec.Code != http.StatusOK {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	id := responseID(t, rec)
	if got, want := approvalRowText(t, app, id), fmt.Sprintf(`approver_id=%d approver_email="Élise@example.com" status=pending`, eliseID); got != want {
		t.Errorf("stored request:\n got %s\nwant %s", got, want)
	}
	if body := approvalListBody(t, mux, elise, "/api/_approvals?mine=1"); !strings.Contains(body, "Unicode case") {
		t.Errorf("approver does not see the request: %s", body)
	}
	if rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), elise, map[string]any{"decision": "approved"}); rec.Code != http.StatusOK {
		t.Errorf("approver cannot decide: %d %s", rec.Code, rec.Body.String())
	}
}
