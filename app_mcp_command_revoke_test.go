//go:build !cli && !windows

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// revokeFlow is the task command with a member removal and a
// `run: revoke_user_sessions` step. The prepare phase looks the member up by a
// literal address (no tenant filter, so a test can point it at anyone) and
// captures the id as prepared argument member_id.
func revokeFlow(victimEmail, applySteps string) string {
	flow := commandTaskFlowFixture
	flow = strings.Replace(flow, "required: [id, project_id]", "required: [id, project_id, member_id]", 1)
	flow = strings.Replace(flow, "      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n  preview_schema", "      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n      member_id: {type: integer, minimum: 1, maximum: 9007199254740991}\n  preview_schema", 1)
	flow = strings.Replace(flow, "writes: [tasks, activities]", "writes: [tasks, activities, members]", 1)
	flow = strings.Replace(flow, "      - run: respond\n        with:\n          status: 200\n          json:\n            arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}",
		"      - id: victim\n        run: sql\n        with:\n          query: SELECT user_id AS member FROM members WHERE email = '"+victimEmail+"'\n      - run: respond\n        with:\n          status: 200\n          json:\n            arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}', member_id: '${{ steps.victim.outputs.first.member }}'}", 1)
	flow = strings.Replace(flow, "      - run: respond\n        with: {status: 200, json: {ok: true}}", applySteps+"      - run: respond\n        with: {status: 200, json: {ok: true}}", 1)
	return flow
}

const (
	revokeDeleteMember = `      - id: remove_member
        run: sql
        expect_rows: '>=0'
        with:
          query: DELETE FROM members WHERE user_id = :member AND org_id = :tenant
          params: {member: '${{ params.member_id }}', tenant: '${{ user.group_id }}'}
`
	revokeStep = `      - id: revoke
        run: revoke_user_sessions
        with:
          user_id: ${{ params.member_id }}
`
	revokeFailAfter = `      - id: fail_after
        run: sql
        expect_rows: '=1'
        with:
          query: UPDATE tasks SET title = title WHERE id = 999
`
)

var revokeCompileTables = map[string]bool{"tasks": true, "activities": true, "members": true, "projects": true}

type revokeVictim struct {
	id      int64
	session string
	grantID string
}

// addVictim creates a signed-in member with an API token and a connector grant.
func addVictim(t *testing.T, h *exposureHarness, email, role, org string) revokeVictim {
	t.Helper()
	EnsureAPITokensTable(h.app.DB)
	session := createCrudScopeSession(t, h.app, email, role, org, "")
	u := GetSessionFromDB(h.app.DB, session)
	if u == nil {
		t.Fatal("victim session missing")
	}
	if _, err := h.app.DB.Exec(`INSERT INTO members(org_id,email,user_id) VALUES(?,?,?)`, org, email, u.UserID); err != nil {
		t.Fatal(err)
	}
	if ok, err := insertAPITokenWithinCap(h.app.DB, u.UserID, "t", "hash-"+email, "*", nil); err != nil || !ok {
		t.Fatalf("token: %v %v", ok, err)
	}
	v := revokeVictim{id: u.UserID, session: session}
	// A connector grant is never minted for an admin.
	if role != "admin" {
		pair, err := createAppMCPNativeGrantFor(context.Background(), h.app, u.UserID, org, "client-v", h.resource, "complete_item", time.Now())
		if err != nil {
			t.Fatalf("victim grant: %v", err)
		}
		v.grantID = pair.GrantID
	}
	return v
}

func (h *exposureHarness) sessionLive(id string) bool {
	h.t.Helper()
	r, _ := http.NewRequest("GET", "/api/_auth/sessions", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	return getSession(h.app, r) != nil
}

func (h *exposureHarness) victimIntact(v revokeVictim) bool {
	h.t.Helper()
	return h.sessionLive(v.session) &&
		h.count("SELECT count(*) FROM _benmore_api_tokens WHERE user_id=?", v.id) == 1 &&
		(v.grantID == "" || h.count("SELECT count(*) FROM _benmore_mcp_grants WHERE user_id=? AND revoked=0", v.id) == 1) &&
		h.count("SELECT count(*) FROM members WHERE user_id=?", v.id) == 1
}

func TestAppMCPRevokeSessionsEndsRemovedMembersCredentialsAfterCommit(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("victim@example.com", revokeDeleteMember+revokeStep), "")
	v := addVictim(t, h, "victim@example.com", "editor", "17")
	if !h.victimIntact(v) {
		t.Fatal("fixture victim is not signed in")
	}
	id := h.prepare()
	_, body, _ := h.review(h.cookie, id)
	if !strings.Contains(body, "End every sign-in, API token and connector grant") {
		t.Fatalf("review page does not disclose the revocation: %s", body)
	}
	h.approveOK(id)
	if _, code := h.commit(id); code != "" {
		t.Fatalf("commit failed: %s", code)
	}
	if h.sessionLive(v.session) {
		t.Fatal("removed member's session still resolves after commit")
	}
	if h.count("SELECT count(*) FROM _benmore_sessions WHERE user_id=?", v.id) != 0 ||
		h.count("SELECT count(*) FROM _benmore_api_tokens WHERE user_id=?", v.id) != 0 ||
		h.count("SELECT count(*) FROM _benmore_mcp_grants WHERE user_id=? AND revoked=0", v.id) != 0 ||
		h.count("SELECT count(*) FROM members WHERE user_id=?", v.id) != 0 {
		t.Fatal("removed member kept a credential or the membership")
	}
	if !h.sessionLive(h.cookie) || h.count("SELECT count(*) FROM _benmore_mcp_grants WHERE user_id=? AND revoked=0", h.actorID) != 1 {
		t.Fatal("the actor's own credentials must be untouched")
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action=? AND table_name='_benmore_users' AND row_id=? AND user_id=?", appMCPCommandRevokeAudit, v.id, h.actorID) != 1 {
		t.Fatal("revocation was not audited")
	}
	var details string
	h.app.DB.QueryRow("SELECT new_values FROM _benmore_audit_log WHERE action=?", appMCPCommandRevokeAudit).Scan(&details)
	if strings.Contains(details, "victim@example.com") {
		t.Fatalf("audit row names the member's address: %s", details)
	}
}

// The step may come before the statement that removes the membership.
func TestAppMCPRevokeSessionsBeforeMembershipDelete(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("victim@example.com", revokeStep+revokeDeleteMember), "")
	v := addVictim(t, h, "victim@example.com", "editor", "17")
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "" {
		t.Fatalf("commit failed: %s", code)
	}
	if h.sessionLive(v.session) || h.count("SELECT count(*) FROM members WHERE user_id=?", v.id) != 0 {
		t.Fatal("member was not removed and signed out")
	}
}

func TestAppMCPRevokeSessionsRefusesTargetsOutsideTheActorsTenant(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("elsewhere@example.com", revokeStep), "")
	v := addVictim(t, h, "elsewhere@example.com", "editor", "99")
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "denied" {
		t.Fatalf("cross-tenant target code = %q, want denied", code)
	}
	if !h.victimIntact(v) || h.taskDone() {
		t.Fatal("a refused revocation changed something")
	}
}

func TestAppMCPRevokeSessionsRefusesFormerMember(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("gone@example.com", revokeStep), "")
	v := addVictim(t, h, "gone@example.com", "editor", "17")
	if _, err := h.app.DB.Exec("UPDATE members SET org_id='old' WHERE user_id=?", v.id); err != nil {
		t.Fatal(err)
	}
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "denied" {
		t.Fatalf("former member code = %q, want denied", code)
	}
	if !h.sessionLive(v.session) {
		t.Fatal("a former member's session was revoked")
	}
}

func TestAppMCPRevokeSessionsRefusesTheActor(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("task-actor@example.com", revokeStep), "")
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code != "denied" {
		t.Fatalf("self target code = %q, want denied", code)
	}
	if !h.sessionLive(h.cookie) || h.taskDone() {
		t.Fatal("a refused self revocation changed something")
	}
}

func TestAppMCPRevokeSessionsRefusesFrameworkAdmins(t *testing.T) {
	for name, demote := range map[string]bool{"role column": false, "global grant": true} {
		t.Run(name, func(t *testing.T) {
			h := newExposureHarnessWithFlow(t, revokeFlow("boss@example.com", revokeStep), "")
			v := addVictim(t, h, "boss@example.com", "admin", "17")
			if demote {
				if _, err := h.app.DB.Exec("UPDATE _benmore_users SET role='user' WHERE id=?", v.id); err != nil {
					t.Fatal(err)
				}
				if _, err := h.app.DB.Exec("INSERT INTO _benmore_user_roles(user_id, role) VALUES(?, 'admin')", v.id); err != nil {
					t.Fatal(err)
				}
			}
			id := h.prepare()
			h.approveOK(id)
			if _, code := h.commit(id); code != "denied" {
				t.Fatalf("admin target code = %q, want denied", code)
			}
			if !h.victimIntact(v) {
				t.Fatal("an admin's credentials were revoked")
			}
		})
	}
}

func TestAppMCPRevokeSessionsRollsBackWithTheApply(t *testing.T) {
	h := newExposureHarnessWithFlow(t, revokeFlow("victim@example.com", revokeStep+revokeDeleteMember+revokeFailAfter), "")
	v := addVictim(t, h, "victim@example.com", "editor", "17")
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code == "" {
		t.Fatal("commit succeeded although a later step failed")
	}
	if !h.victimIntact(v) || h.taskDone() {
		t.Fatal("a rolled-back apply revoked credentials or left rows")
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action=?", appMCPCommandRevokeAudit) != 0 {
		t.Fatal("a rolled-back apply left an audit row")
	}
}

func TestAppMCPRevokeSessionsCompileGates(t *testing.T) {
	good := revokeFlow("victim@example.com", revokeDeleteMember+revokeStep)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(good), revokeCompileTables); err != nil {
		t.Fatalf("well-formed revoke command refused: %v", err)
	}
	const ref = "user_id: ${{ params.member_id }}"
	for name, mutate := range map[string]func(string) string{
		"literal id": func(s string) string { return strings.Replace(s, ref, "user_id: 5", 1) },
		"actor id":   func(s string) string { return strings.Replace(s, ref, "user_id: ${{ user.id }}", 1) },
		"step output": func(s string) string {
			return strings.Replace(s, ref, "user_id: ${{ steps.remove_member.outputs.first.id }}", 1)
		},
		"extra with key": func(s string) string { return strings.Replace(s, ref, ref+"\n          all: true", 1) },
		"expect_rows on it": func(s string) string {
			return strings.Replace(s, "        run: revoke_user_sessions\n", "        run: revoke_user_sessions\n        expect_rows: '=1'\n", 1)
		},
	} {
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(mutate(good)), revokeCompileTables); err == nil {
			t.Errorf("%s: compile accepted the step", name)
		}
	}
	inPrepare := strings.Replace(good, "      - id: victim\n", revokeStep+"      - id: victim\n", 1)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(inPrepare), revokeCompileTables); err == nil {
		t.Error("revoke_user_sessions compiled in the prepare phase")
	}
	loop := strings.Replace(good, revokeStep, "      - for_each: ${{ params.ids }}\n        as: item\n        steps:\n          - id: revoke\n            run: revoke_user_sessions\n            with:\n              user_id: ${{ params.member_id }}\n", 1)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(loop), revokeCompileTables); err == nil {
		t.Error("revoke_user_sessions compiled inside a loop")
	}
}

func TestAppMCPRevokeSessionsNeedsAnIntegerPreparedValue(t *testing.T) {
	good := revokeFlow("victim@example.com", revokeStep)
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(good), revokeCompileTables)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPCommandIntentBindings(flow.Command.Apply.Steps, flow.Command.PreparedSchema, "apply"); err != nil {
		t.Fatalf("integer user id refused: %v", err)
	}
	flow.Command.PreparedSchema.Properties["member_id"].Type = "string"
	if err := validateAppMCPCommandIntentBindings(flow.Command.Apply.Steps, flow.Command.PreparedSchema, "apply"); err == nil {
		t.Fatal("a string-typed user id was accepted for revoke_user_sessions")
	}
}

func TestRevokeUserSessionsIsRefusedInOrdinaryFlows(t *testing.T) {
	flow := "on:\n  request:\n    method: POST\n    path: /api/kick\n    auth: required\njobs:\n  kick:\n    steps:\n      - run: revoke_user_sessions\n        with: { user_id: '${{ params.id }}' }\n      - run: respond\n        with: { json: { ok: true } }\n"
	if msg := validateFlowsYAML(flow); !strings.Contains(msg, "revoke_user_sessions") {
		t.Fatalf("ordinary flow accepted run: revoke_user_sessions: %q", msg)
	}
	if err := executeStep(&FlowContext{}, &FlowStep{Type: "revoke_user_sessions"}); err == nil {
		t.Fatal("executeStep ran revoke_user_sessions outside a command")
	}
}

func TestAuthorizeCommandRevokeAdmitsOnlyTheCredentialDeletes(t *testing.T) {
	const ok, deny = sqlite3.SQLITE_OK, sqlite3.SQLITE_DENY
	for _, tc := range []struct {
		action                  int
		table, column, database string
		want                    int
	}{
		{sqlite3.SQLITE_DELETE, "_benmore_sessions", "", "main", ok},
		{sqlite3.SQLITE_DELETE, "_benmore_api_tokens", "", "main", ok},
		{sqlite3.SQLITE_DELETE, "_benmore_oauth_codes", "", "main", ok},
		{sqlite3.SQLITE_DELETE, "_benmore_mcp_authorizations", "", "main", ok},
		{sqlite3.SQLITE_UPDATE, "_benmore_mcp_grants", "revoked", "main", ok},
		{sqlite3.SQLITE_INSERT, "_benmore_audit_log", "", "main", ok},
		{sqlite3.SQLITE_DELETE, "_benmore_users", "", "main", deny},
		{sqlite3.SQLITE_DELETE, "_benmore_user_roles", "", "main", deny},
		{sqlite3.SQLITE_DELETE, "members", "", "main", deny},
		{sqlite3.SQLITE_DELETE, "_benmore_sessions", "", "temp", deny},
		{sqlite3.SQLITE_UPDATE, "_benmore_mcp_grants", "scopes", "main", deny},
		{sqlite3.SQLITE_UPDATE, "_benmore_users", "role", "main", deny},
		{sqlite3.SQLITE_INSERT, "_benmore_sessions", "", "main", deny},
		{sqlite3.SQLITE_INSERT, "_benmore_jobs", "", "main", deny},
		{sqlite3.SQLITE_READ, "_benmore_mcp_credentials", "token_hash", "main", deny},
		{sqlite3.SQLITE_READ, "_benmore_users", "role", "main", ok},
	} {
		if got := authorizeCommandRevoke(tc.action, tc.table, tc.column, tc.database); got != tc.want {
			t.Errorf("authorizeCommandRevoke(%d,%q,%q,%q) = %d, want %d", tc.action, tc.table, tc.column, tc.database, got, tc.want)
		}
	}
}
