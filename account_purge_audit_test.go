//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// purgeAuditTestFlow is the documented purge flow shape: app clean-up SQL
// first, then the purge step, then the success answer. The probe insert
// shows whether a refused purge left any write behind.
func purgeAuditTestFlow() *Flow {
	return &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "app_cleanup", Type: "sql", SQL: `INSERT INTO purge_probe(x) VALUES(1)`},
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
}

// F8 (round 2026-11-05): a purge erased the email from audit rows the
// account wrote itself, but rows other actors wrote about it (the operator's
// app_user_created / superuser_password_reset, an admin's impersonate, a
// share naming it) kept the address. After a purge no framework audit row may
// carry it; the rows themselves, their actors and other people's identities
// stay.
func TestPurgeCurrentUserScrubsAccountEmailFromAuditRowsOthersWrote(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	const owner = "owner@example.com"
	const victim = "victim@example.com"
	const third = "third@example.com"
	const operator = "editor@test.com" // the platform account

	// The operator's rows about the account, in the shape the platform data
	// channel writes them (app_data_ops_users.go: LogAuditDB with the
	// platform account as a user_id-0 session and the address in
	// new_values). The platform edition's
	// TestPurgeCurrentUserScrubsDataChannelAuditRows makes them for real.
	const uid, vid = int64(1), int64(2)
	insertPurgeUser(t, app, uid, owner)
	insertPurgeUser(t, app, vid, victim)
	ownerRow, victimRow := itoa64(uid), itoa64(vid)
	LogAuditDB(app.DB, "app_user_created", "_benmore_users", ownerRow, &Session{Email: operator}, nil, map[string]any{"email": owner, "role": "user", "source": "platform create_app_user"})
	LogAuditDB(app.DB, "superuser_password_reset", "_benmore_users", ownerRow, &Session{Email: operator}, nil, map[string]any{"email": owner, "password": "reset", "source": "platform create_superuser"})

	ownerSess := &Session{UserID: uid, Email: owner}
	victimSess := &Session{UserID: vid, Email: victim}
	// Shapes written by auth.go (impersonate, act_as_*), admin.go
	// (role_changed), permissions.go (share, revoke_share), import_run.go
	// (import with a chosen owner) and app_mcp_connector_control.go.
	LogAudit(app, "impersonate", "_benmore_users", ownerRow, victimSess, nil, map[string]any{"impersonated_by": victim, "target_user": owner})
	LogAudit(app, "impersonate", "_benmore_users", victimRow, ownerSess, nil, map[string]any{"impersonated_by": owner, "target_user": victim})
	LogAudit(app, "act_as_start", "_benmore_sessions", "s1", ownerSess, nil, map[string]any{"target_group_id": "g1", "admin_email": owner})
	LogAudit(app, "act_as_end", "_benmore_sessions", "s1", ownerSess, nil, map[string]any{"prior_group_id": "g1", "user_email": owner})
	LogAudit(app, "role_changed", "_benmore_users", victimRow, ownerSess, map[string]any{"role": "user"}, map[string]any{"role": "admin"})
	LogAudit(app, "share", "docs", "5", victimSess, nil, map[string]any{"shared_with": "Owner@Example.com", "permission": "read"})
	LogAudit(app, "share", "docs", "5", victimSess, nil, map[string]any{"shared_with": third, "permission": "read"})
	LogAudit(app, "revoke_share", "docs", "5", victimSess, nil, map[string]any{"shared_with": owner})
	LogAudit(app, "import", "docs", "", &Session{Email: operator}, nil, map[string]any{"rows": 3, "owner_user_id": uid, "owner_email": owner})
	if err := insertAuditRowChecked(app.DB, "mcp_connector_switch", "mcp_connector", "", &Session{Email: owner}, `{"exposed":false}`, `{"exposed":true}`); err != nil {
		t.Fatal(err)
	}
	insertAuditRow(app.DB, "update", "docs", "5", &Session{UserID: vid, Email: victim, ImpersonatorUserID: uid, ImpersonatorEmail: owner}, `{"title":"a"}`, `{"title":"b"}`)
	// An app table's own row snapshot is the app's data: the documented
	// contract leaves app tables (and so their audit snapshots) to the app.
	LogAudit(app, "insert", "contacts", "9", victimSess, nil, map[string]any{"email": owner, "name": "Owner"})

	var before int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `CREATE TABLE purge_probe(x INTEGER)`)
	sessionID := CreateSession(app.DB, uid, owner, "", time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, purgeAuditTestFlow(), rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Nothing the framework wrote still names the address, in any column.
	leftover := `SELECT COUNT(*) FROM _benmore_audit_log WHERE NOT (action='insert' AND table_name='contacts') AND instr(lower(COALESCE(user_email,'')||' '||COALESCE(old_values,'')||' '||COALESCE(new_values,'')||' '||COALESCE(impersonator_email,'')), '` + owner + `')>0`
	assertCount(t, app, leftover, 0)
	// Governance rows are kept (plus the purge marker), with their actors
	// and stable ids.
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log`, before+1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action IN ('app_user_created','superuser_password_reset') AND user_id=0 AND user_email='`+operator+`' AND row_id='`+ownerRow+`' AND old_values IS NULL AND new_values IS NULL`, 2)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='impersonate' AND row_id='`+ownerRow+`' AND user_id=`+victimRow+` AND user_email='`+victim+`' AND new_values IS NULL`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='import' AND user_email='`+operator+`' AND json_extract(new_values,'$.owner_email')='' AND json_extract(new_values,'$.owner_user_id')=`+ownerRow, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='mcp_connector_switch' AND user_email='' AND new_values='{"exposed":true}'`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='update' AND table_name='docs' AND user_email='`+victim+`' AND impersonator_user_id=`+ownerRow+` AND impersonator_email=''`, 1)
	// Other people's identities in the same rows are untouched.
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='impersonate' AND row_id='`+victimRow+`' AND user_id=`+ownerRow+` AND user_email='' AND json_extract(new_values,'$.impersonated_by')='' AND json_extract(new_values,'$.target_user')='`+victim+`'`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='role_changed' AND row_id='`+victimRow+`' AND user_email='' AND json_extract(new_values,'$.role')='admin'`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='share' AND user_email='`+victim+`' AND json_extract(new_values,'$.shared_with')='`+third+`'`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action IN ('share','revoke_share') AND json_extract(new_values,'$.shared_with')='' AND json_extract(new_values,'$.permission') IS NOT 'x'`, 2)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action IN ('act_as_start','act_as_end') AND user_id=`+ownerRow+` AND user_email='' AND COALESCE(json_extract(new_values,'$.admin_email'),json_extract(new_values,'$.user_email'))='' AND json_extract(new_values,'$.target_group_id') IS NOT 'x'`, 2)
	// The app's own row snapshot is left to the app.
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='insert' AND table_name='contacts' AND json_extract(new_values,'$.email')='`+owner+`'`, 1)
}

// F10 (round 2026-11-05): a refused purge answered 500 flow_no_response
// "Internal error", so a client could not tell a typo from an outage. Each
// refusal now answers 400 (confirmation) or 403 (credential) with the reason,
// and leaves no write behind: the app clean-up step before it rolls back too.
func TestPurgeCurrentUserRefusalsAnswerClientErrorsWithoutSideEffects(t *testing.T) {
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	const owner = "owner@example.com"
	insertPurgeUser(t, app, 1, owner)
	mustExec(t, app.DB, `CREATE TABLE purge_probe(x INTEGER)`)

	mustExec(t, app.DB, `INSERT INTO _benmore_api_tokens(user_id,name,token_hash,scopes) VALUES(1,'cli','`+hashToken("bmr_purge_refusal_token")+`','*')`)
	cookieSID := CreateSession(app.DB, 1, owner, "", time.Hour)
	bearerSID := CreateSession(app.DB, 1, owner, "", time.Hour)
	scopedSID := CreateSession(app.DB, 1, owner, "", time.Hour, "notes:read")
	actAsSID := CreateSession(app.DB, 1, owner, "", time.Hour)
	mustExec(t, app.DB, `UPDATE _benmore_sessions SET acting_as_group='7' WHERE id='`+sessionStorageKey(actAsSID)+`'`)
	delegatedSID := createDelegatedSession(app.DB, 1, owner, "", time.Hour)
	if delegatedSID == "" {
		t.Fatal("no delegated session")
	}

	cases := []struct {
		name    string
		body    string
		auth    func(*http.Request)
		status  int
		code    string
		message string
	}{
		{name: "api token", body: `{"confirm":"DELETE"}`, auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer bmr_purge_refusal_token") },
			status: http.StatusForbidden, code: "credential_not_allowed", message: "not an API token"},
		{name: "wrong confirmation", body: `{"confirm":"yes"}`, auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+bearerSID) },
			status: http.StatusBadRequest, code: "confirmation_required", message: "exactly equal DELETE"},
		{name: "missing confirmation (cookie)", body: `{}`, auth: func(r *http.Request) {
			r.AddCookie(sessionCookie(cookieSID, true, time.Hour))
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(cookieSID))
		}, status: http.StatusBadRequest, code: "confirmation_required", message: "exactly equal DELETE"},
		{name: "scoped bearer session", body: `{"confirm":"DELETE"}`, auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+scopedSID) },
			status: http.StatusForbidden, code: "credential_not_allowed", message: "not a scoped credential"},
		{name: "admin stepped into a tenant", body: `{"confirm":"DELETE"}`, auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+actAsSID) },
			status: http.StatusForbidden, code: "credential_not_allowed", message: "act-as"},
		{name: "impersonation session", body: `{"confirm":"DELETE"}`, auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+delegatedSID) },
			status: http.StatusForbidden, code: "credential_not_allowed", message: "impersonation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			tc.auth(req)
			rr := httptest.NewRecorder()
			executeFlowHTTP(app, purgeAuditTestFlow(), rr, req)
			if rr.Code != tc.status {
				t.Fatalf("status=%d body=%s, want %d", rr.Code, rr.Body.String(), tc.status)
			}
			var body map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not one JSON object: %q (%v)", rr.Body.String(), err)
			}
			msg, _ := body["message"].(string)
			if body["error"] != tc.code || !strings.Contains(msg, tc.message) {
				t.Fatalf("body=%s, want error %q and a message containing %q", rr.Body.String(), tc.code, tc.message)
			}
			if body["request_id"] == "" || rr.Header().Get(requestIDHeader) == "" {
				t.Fatalf("refusal carries no request id: %s", rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "deleted") {
				t.Fatalf("refusal leaked the success body: %s", rr.Body.String())
			}
			// No side effect: the account, its credentials and the app step
			// before the purge are all as they were.
			assertCount(t, app, `SELECT COUNT(*) FROM purge_probe`, 0)
			assertCount(t, app, `SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email='`+owner+`' AND deactivated_at IS NULL AND password_hash='hash'`, 1)
			assertCount(t, app, `SELECT COUNT(*) FROM _benmore_sessions WHERE user_id=1`, 5)
			assertCount(t, app, `SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id=1`, 1)
			assertCount(t, app, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action='account_purge'`, 0)
		})
	}

	// The same flow with the account's own session and DELETE still purges.
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerSID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, purgeAuditTestFlow(), rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid purge status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertCount(t, app, `SELECT COUNT(*) FROM purge_probe`, 1)
	assertCount(t, app, `SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email IS NULL`, 1)
}
