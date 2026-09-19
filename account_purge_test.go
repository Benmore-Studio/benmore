//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const validPurgeFlowYAML = `on:
  request:
    method: POST
    path: /api/account-delete
    auth: required
    transaction: true
jobs:
  delete:
    steps:
      - id: app_cleanup
        run: sql
        query: SELECT 1 AS ok
      - id: purge
        run: purge_current_user
        with:
          confirm: "${{ params.confirm }}"
      - run: respond
        with:
          status: 200
          body: { deleted: true }
`

func TestPurgeCurrentUserFlowContractValidation(t *testing.T) {
	if msg := validateFlowsYAML(validPurgeFlowYAML); msg != "" {
		t.Fatalf("valid purge flow rejected: %s", msg)
	}

	cases := map[string]string{
		"auth required":            strings.Replace(validPurgeFlowYAML, "    auth: required\n", "", 1),
		"transaction required":     strings.Replace(validPurgeFlowYAML, "    transaction: true\n", "", 1),
		"mutating method":          strings.Replace(validPurgeFlowYAML, "method: POST", "method: GET", 1),
		"request confirmation":     strings.Replace(validPurgeFlowYAML, `"${{ params.confirm }}"`, `"DELETE"`, 1),
		"only confirm input":       strings.Replace(validPurgeFlowYAML, "          confirm: \"${{ params.confirm }}\"\n", "          confirm: \"${{ params.confirm }}\"\n          user_id: \"${{ params.user_id }}\"\n", 1),
		"no on-error branch":       strings.Replace(validPurgeFlowYAML, "          confirm: \"${{ params.confirm }}\"\n", "          confirm: \"${{ params.confirm }}\"\n        on_error:\n          - run: respond\n            with: { status: 200, body: { deleted: true } }\n", 1),
		"terminal-safe steps only": strings.Replace(validPurgeFlowYAML, "      - run: respond\n", "      - run: email\n        with: { to: x@example.com, subject: x, template: x }\n      - run: respond\n", 1),
		"not nested": strings.Replace(validPurgeFlowYAML,
			"      - id: purge\n        run: purge_current_user\n        with:\n          confirm: \"${{ params.confirm }}\"\n",
			"      - if: ${{ params.confirm == 'DELETE' }}\n        steps:\n          - id: purge\n            run: purge_current_user\n            with:\n              confirm: \"${{ params.confirm }}\"\n", 1),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if msg := validateFlowsYAML(source); msg == "" {
				t.Fatal("unsafe purge flow unexpectedly passed validation")
			}
		})
	}
}

func TestPurgeCurrentUserParser(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := osWriteFileForTest(app.Dir+"/flows.yaml", validPurgeFlowYAML); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 || len(flows[0].Steps) != 3 {
		t.Fatalf("parsed flows = %#v", flows)
	}
	got := flows[0].Steps[1]
	if got.Type != "purge_current_user" || got.PurgeCurrentUserConfirm != "{{confirm}}" {
		t.Fatalf("parsed purge step = %#v", got)
	}
}

func osWriteFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestPurgeCurrentUserRejectsNonSessionAndImpersonation(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)

	step := FlowStep{Type: "purge_current_user", PurgeCurrentUserConfirm: "DELETE"}
	cases := []struct {
		name    string
		session *Session
		prepare func()
	}{
		{name: "nil session"},
		{name: "persistent api token", session: &Session{ID: "apitoken:1", UserID: 1, Email: "owner@example.com"}},
		{name: "edge bridge", session: &Session{ID: "edge:1", UserID: 1, Email: "owner@example.com"}},
		{name: "not live", session: &Session{ID: "missing", UserID: 1, Email: "owner@example.com"}},
		{name: "impersonation", session: &Session{ID: sessionID, UserID: 1, Email: "owner@example.com"}, prepare: func() {
			mustExec(t, app.DB, "UPDATE _benmore_sessions SET is_impersonation=1 WHERE id='"+sessionID+"'")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prepare != nil {
				tc.prepare()
			}
			tx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			ctx := &FlowContext{App: app, Session: tc.session, Data: map[string]any{}, Params: map[string]string{}, Tx: tx}
			if err := execStepPurgeCurrentUser(ctx, &step); err == nil {
				t.Fatal("unsafe caller unexpectedly purged account")
			}
			_ = tx.Rollback()
		})
	}
}

func TestPurgeCurrentUserUsesImmutableSessionAndScrubsFrameworkIdentity(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	insertPurgeUser(t, app, 2, "victim@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)
	mustExec(t, app.DB, `INSERT INTO _benmore_api_tokens(user_id,name,token_hash,scopes) VALUES(1,'phone','h','*')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_oauth_tokens(user_id,provider,access_token) VALUES(1,'google','secret')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_devices(user_id,token,platform) VALUES(1,'device','ios')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_notifications(user_id,title) VALUES(1,'private')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_login_attempts(email) VALUES('OWNER@example.com')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_password_resets(token,email,expires_at) VALUES('reset','owner@example.com',datetime('now','+1 day'))`)
	mustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission,granted_by) VALUES('doc','1','user','OWNER@example.com','read',1)`)
	mustExec(t, app.DB, `INSERT INTO _benmore_rate_limits(key,count) VALUES('u:1',3),('user:1',4),('e:owner@example.com',5),('u:10',6),('ip:1',7)`)
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_jobs(flow_name,payload,status) VALUES('mine-pending','{"user_id":1,"email":"owner@example.com"}','pending'),('mine-complete','{"user_id":"1","email":"owner@example.com"}','complete'),('theirs','{"user_id":2,"email":"victim@example.com"}','pending')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email,old_values,new_values) VALUES('update','_benmore_users','1',1,'owner@example.com','{"email":"owner@example.com"}','{"email":"new@example.com"}')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_read_audit(table_name,query_type,user_id,user_email) VALUES('docs','read',1,'owner@example.com')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_subscriptions(user_id,status) VALUES(1,'active')`)

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
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE","user_id":2}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rr.Code, rr.Body.String())
	}

	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || response["deleted"] != true {
		t.Fatalf("response = %s (%v)", rr.Body.String(), err)
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=1", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id=1", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_oauth_tokens WHERE user_id=1", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_devices WHERE user_id=1", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_notifications WHERE user_id=1", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE lower(email)='owner@example.com'", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_password_resets WHERE lower(email)='owner@example.com'", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_permissions WHERE lower(grantee_id)='owner@example.com'", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_rate_limits WHERE key IN ('u:1','user:1','e:owner@example.com')", 0)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_rate_limits WHERE key IN ('u:10','ip:1')", 2)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_jobs WHERE flow_name='mine-pending' AND status='failed' AND payload='{}' AND error='cancelled: account deleted'", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_jobs WHERE flow_name='mine-complete' AND status='complete' AND payload='{}'", 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_jobs WHERE flow_name='theirs' AND status='pending' AND payload='{"user_id":2,"email":"victim@example.com"}'`, 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_subscriptions WHERE user_id=1", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=2 AND email='victim@example.com'", 1)

	var username string
	var email, phone, passwordHash *string
	var firstName, role string
	var verified int
	if err := app.DB.QueryRow(`SELECT username,email,phone,password_hash,first_name,role,verified FROM _benmore_users WHERE id=1`).Scan(&username, &email, &phone, &passwordHash, &firstName, &role, &verified); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(username, "deleted-user-1-") || email != nil || phone != nil || passwordHash != nil || firstName != "Deleted" || role != "user" || verified != 0 {
		t.Fatalf("bad tombstone: username=%q email=%v phone=%v password=%v first=%q role=%q verified=%d", username, email, phone, passwordHash, firstName, role, verified)
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action='update' AND user_id=1 AND user_email='' AND old_values IS NULL AND new_values IS NULL", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE action='account_purge' AND row_id='1'", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_read_audit WHERE user_id=1 AND user_email=''", 1)

	// The released identifier may create a genuinely new account, but it must
	// never reconnect that identity to the retained tombstone/history.
	insertPurgeUser(t, app, 3, "owner@example.com")
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=3 AND email='owner@example.com'", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email IS NULL AND username LIKE 'deleted-user-1-%'", 1)
}

func TestPurgeCurrentUserRequiresExactRuntimeConfirmation(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)

	for _, confirm := range []string{"", "delete", "DELETE ", " DELETE"} {
		t.Run(strconv.Quote(confirm), func(t *testing.T) {
			tx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			ctx := &FlowContext{App: app, Session: &Session{ID: sessionID, UserID: 1, Email: "owner@example.com"}, Request: httptest.NewRequest(http.MethodPost, "/api/account-delete", nil), Data: map[string]any{}, Params: map[string]string{}, Tx: tx}
			if err := execStepPurgeCurrentUser(ctx, &FlowStep{Type: "purge_current_user", PurgeCurrentUserConfirm: confirm}); err == nil {
				t.Fatalf("confirmation %q unexpectedly accepted", confirm)
			}
			_ = tx.Rollback()
		})
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email='owner@example.com' AND deactivated_at IS NULL", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE id='"+sessionID+"'", 1)
}

func TestPurgeCurrentUserConcurrentRequestsHaveOneWinner(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessions := []string{
		CreateSession(app.DB, 1, "owner@example.com", "", time.Hour),
		CreateSession(app.DB, 1, "owner@example.com", "", time.Hour),
	}
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

	start := make(chan struct{})
	codes := make(chan int, len(sessions))
	var wg sync.WaitGroup
	for _, sessionID := range sessions {
		wg.Add(1)
		go func(sessionID string) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+sessionID)
			rr := httptest.NewRecorder()
			executeFlowHTTP(app, flow, rr, req)
			codes <- rr.Code
		}(sessionID)
	}
	close(start)
	wg.Wait()
	close(codes)

	ok, failed := 0, 0
	for code := range codes {
		if code == http.StatusOK {
			ok++
		} else if code == http.StatusUnauthorized || code >= http.StatusInternalServerError {
			// The losing request can reach auth after the winner has revoked
			// both sessions. It is then rejected before entering the flow.
			failed++
		} else {
			t.Fatalf("unexpected concurrent purge status %d", code)
		}
	}
	if ok != 1 || failed != 1 {
		t.Fatalf("concurrent purge results ok=%d failed=%d, want one of each", ok, failed)
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email IS NULL AND username LIKE 'deleted-user-1-%'", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=1", 0)
}

func TestPurgeCurrentUserRollsBackWhenOptionalIdentityTableIsIncompatible(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)
	mustExec(t, app.DB, `DROP TABLE _benmore_devices`)
	mustExec(t, app.DB, `CREATE TABLE _benmore_devices(id INTEGER PRIMARY KEY, token TEXT)`)

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx := &FlowContext{App: app, Session: &Session{ID: sessionID, UserID: 1, Email: "owner@example.com"}, Data: map[string]any{}, Params: map[string]string{}, Tx: tx}
	step := FlowStep{Type: "purge_current_user", PurgeCurrentUserConfirm: "DELETE"}
	if err := execStepPurgeCurrentUser(ctx, &step); err == nil {
		t.Fatal("incompatible identity table unexpectedly accepted")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email='owner@example.com' AND deactivated_at IS NULL", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE id='"+sessionID+"'", 1)
}

func TestPurgeCurrentUserDoesNotSendSuccessBeforeTransactionCommit(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	mustExec(t, app.DB, `PRAGMA foreign_keys=ON`)
	mustExec(t, app.DB, `CREATE TABLE purge_parent(id INTEGER PRIMARY KEY)`)
	mustExec(t, app.DB, `CREATE TABLE purge_child(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES purge_parent(id) DEFERRABLE INITIALLY DEFERRED)`)
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)

	flow := &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Name: "deferred_failure", Type: "sql", SQL: `INSERT INTO purge_child(parent_id) VALUES(999)`},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("commit failure status=%d body=%s, want 500", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"deleted":true`) {
		t.Fatalf("commit failure leaked buffered success: %s", rr.Body.String())
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email='owner@example.com' AND deactivated_at IS NULL", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_sessions WHERE id='"+sessionID+"'", 1)
}

func TestPurgeCurrentUserWithNoEmailDoesNotEraseOtherBlankEmailRows(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	_, err := app.DB.Exec(`INSERT INTO _benmore_users(id,username,email,phone,password_hash,first_name,role) VALUES(1,'phone-user',NULL,'+15550000001','hash','Phone','user')`)
	if err != nil {
		t.Fatal(err)
	}
	insertPurgeUser(t, app, 2, "other@example.com")
	sessionID := CreateSession(app.DB, 1, "", "", time.Hour)
	mustExec(t, app.DB, `INSERT INTO _benmore_login_attempts(email) VALUES('')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_password_resets(token,email,expires_at) VALUES('blank','',datetime('now','+1 day'))`)
	mustExec(t, app.DB, `INSERT INTO _benmore_permissions(resource_type,resource_id,grant_type,grantee_id,permission,granted_by) VALUES('doc','2','user','','read',2)`)
	mustExec(t, app.DB, `INSERT INTO _benmore_locks(table_name,row_id,user_id,user_email,expires_at) VALUES('docs','2',2,'',datetime('now','+1 day'))`)

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
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_login_attempts WHERE email=''", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_password_resets WHERE email=''", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_permissions WHERE grantee_id=''", 1)
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_locks WHERE user_id=2 AND user_email=''", 1)
}

func newPurgeTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	if err := EnsureUsersTable(app.DB); err != nil {
		cleanup()
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureOAuthTokensTable(app.DB)
	EnsureDevicesTable(app.DB)
	EnsureNotificationsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsurePermissionsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsureReadAuditTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsureRateLimitsTable(app.DB)
	mustExec(t, app.DB, `CREATE TABLE _benmore_subscriptions(id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT)`)
	return app, cleanup
}

func insertPurgeUser(t *testing.T, app *App, id int64, email string) {
	t.Helper()
	_, err := app.DB.Exec(`INSERT INTO _benmore_users(id,username,email,phone,password_hash,first_name,last_name,avatar_url,role,verified) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, "user-"+email, email, "+1555000000"+strconv.FormatInt(id, 10), "hash", "Owner", "Person", "/avatar.png", "admin", 1)
	if err != nil {
		t.Fatal(err)
	}
}

func assertCount(t *testing.T, app *App, query string, want int) {
	t.Helper()
	var got int
	if err := app.DB.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	if got != want {
		t.Fatalf("query %q count=%d want=%d", query, got, want)
	}
}
