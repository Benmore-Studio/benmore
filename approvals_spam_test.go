//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func approvalPost(t *testing.T, mux *http.ServeMux, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func approvalsSpamApp(t *testing.T) (*App, *http.ServeMux, map[string]string) {
	t.Helper()
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
	tokens := map[string]string{}
	for _, name := range []string{"requester", "approver"} {
		email := name + "@example.com"
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)", name, email)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		tokens[name] = CreateSession(app.DB, id, email, "", time.Hour)
	}
	mux := http.NewServeMux()
	registerSchedulingAPI(mux, app)
	return app, mux, tokens
}

func approvalNotifications(t *testing.T, app *App, email string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_notifications WHERE user_id = (SELECT id FROM _benmore_users WHERE email = ?)", email).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// POST /api/_approvals let any signed-in account name any user as approver
// and notify them on every call: repeating one request, or cycling row ids,
// flooded the approver's notifications (and evicted their real ones at the
// per-user cap). A repeated pending request now returns the existing
// approval without a second notification, requests per account are capped,
// and re-deciding a decided approval does not notify the requester again.
func TestApprovalRequestsCannotFloodNotifications(t *testing.T) {
	old := approvalRequestLimiter
	approvalRequestLimiter = NewRateLimiter(approvalRequestBurst, approvalRequestWindow)
	t.Cleanup(func() { approvalRequestLimiter = old })
	app, mux, tok := approvalsSpamApp(t)
	request := func(row string) int {
		return approvalPost(t, mux, "/api/_approvals", tok["requester"], map[string]any{
			"table": "docs", "row_id": row, "approver_email": "approver@example.com", "title": "Please approve",
		}).Code
	}

	for i := 0; i < 5; i++ {
		if code := request("1"); code != http.StatusOK {
			t.Fatalf("repeat request %d: %d", i, code)
		}
	}
	if n := approvalNotifications(t, app, "approver@example.com"); n != 1 {
		t.Fatalf("one pending approval notified the approver %d times", n)
	}
	var rows int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_approvals").Scan(&rows)
	if rows != 1 {
		t.Fatalf("a repeated pending request stored %d approvals", rows)
	}

	refused := 0
	for i := 2; i < 2+approvalRequestBurst+10; i++ {
		if request(fmt.Sprint(i)) == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("one account could request approvals without limit")
	}
	if n := approvalNotifications(t, app, "approver@example.com"); n > approvalRequestBurst {
		t.Fatalf("approver got %d notifications from one account, cap %d", n, approvalRequestBurst)
	}

	var id int64
	app.DB.QueryRow("SELECT id FROM _benmore_approvals WHERE row_id = '1'").Scan(&id)
	for i := 0; i < 3; i++ {
		rec := approvalPost(t, mux, fmt.Sprintf("/api/_approvals/%d/decide", id), tok["approver"], map[string]any{"decision": "rejected"})
		if rec.Code != http.StatusOK {
			t.Fatalf("decide %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if n := approvalNotifications(t, app, "requester@example.com"); n != 1 {
		t.Fatalf("one decision notified the requester %d times", n)
	}
}
