//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func auditPost(mux *http.ServeMux, sid, path, key, body string, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if csrf {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	} else {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	if key != "" {
		r.Header.Set("X-Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestAuditFetchOldPagesRefreshWithoutDispatch(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "refresh@example.com", "user", "", "")
	mux := http.NewServeMux()
	registerFetchRoutes(mux, app, &http.Client{Transport: auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("old or invalid descriptors dispatched a fetch")
		return nil, nil
	})})
	for _, path := range []string{"/_internal/fetch?url=https://example.com&headers=unsafe", "/_internal/fetch?d=invalid"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		r.Header.Set("HX-Request", "true")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("HX-Refresh") != "true" {
			t.Fatalf("old page was not told to refresh safely: status=%d headers=%v", w.Code, w.Header())
		}
	}
}

func TestAuditIdempotencyAtomicReplayAndConflict(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "retry@example.com", "user", "", "")
	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = auditPost(mux, sid, "/api/notes", "retry", `{"title":"once"}`, false)
		}(i)
	}
	wg.Wait()
	for _, w := range results {
		if w.Code != 200 || w.Body.String() != results[0].Body.String() {
			t.Fatalf("retry differed: HTTP %d %s", w.Code, w.Body.String())
		}
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n)
	if n != 1 {
		t.Fatalf("retries inserted %d rows", n)
	}
	w := auditPost(mux, sid, "/api/notes", "retry", `{"title":"different"}`, false)
	if w.Code != 409 {
		t.Fatalf("changed body returned %d: %s", w.Code, w.Body.String())
	}
	// A cached response must never bypass the current CSRF or scope gate.
	r := httptest.NewRequest("POST", "/api/notes", strings.NewReader(`{"title":"once"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Idempotency-Key", "retry")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("CSRF replay: %d", w.Code)
	}
	auditExec(t, app.DB, "UPDATE _benmore_sessions SET scopes='notes:read' WHERE id=?", sid)
	w = auditPost(mux, sid, "/api/notes", "retry", `{"title":"once"}`, false)
	if w.Code != 403 {
		t.Fatalf("scoped replay: %d", w.Code)
	}
}

func TestAuditTransactionRollbackAndCommittedEvents(t *testing.T) {
	app, mux := auditApp(t)
	EnsureJobsTable(app.DB)
	sid := createCrudScopeSession(t, app, "atomic@example.com", "user", "", "")
	app.DB.SetMaxOpenConns(1) // hooks and schema reads must use the active tx connection
	app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"notes": {{SQL: "SELECT 'limit reached' AS error WHERE (SELECT COUNT(*) FROM notes)>0"}}}, OnInsert: map[string][]Hook{"notes": {{SQL: "SELECT 1"}}}, OnDelete: map[string][]Hook{"notes": {{SQL: "SELECT 1"}}}}
	w := auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"insert","data":{"title":"first"}},{"table":"notes","action":"insert","data":{"title":"second"}}]}`, false)
	if w.Code == 200 {
		t.Fatal("hook failed to see prior operation")
	}
	for _, table := range []string{"notes", "_benmore_jobs", "_benmore_audit_log"} {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Fatalf("rollback leaked %s: %d", table, n)
		}
	}
	w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"insert","data":{"title":"committed"}}]}`, false)
	if w.Code != 200 {
		t.Fatalf("valid transaction: %d %s", w.Code, w.Body.String())
	}
	w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"delete","id":1}]}`, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"action":"delete"`) {
		t.Fatalf("delete result: %d %s", w.Code, w.Body.String())
	}
	for _, table := range []string{"_benmore_jobs", "_benmore_audit_log"} {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 2 {
			t.Fatalf("missing insert/delete effects in %s: %d", table, n)
		}
	}
}

func TestAuditTransactionValidators(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "validated@example.com", "user", "", "")
	app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"notes": {{Rule: "title != 'blocked'", Error: "blocked title"}}}}
	w := auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"insert","data":{"title":"blocked"}}]}`, false)
	if w.Code == 200 {
		t.Fatal("transaction bypassed validator")
	}
}

func TestAuditSchedulerTrustedIdentityAndRevocation(t *testing.T) {
	for _, mode := range []string{"valid", "logged_out", "expired", "promoted", "deactivated", "dynamic"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := auditApp(t)
			sid := createCrudScopeSession(t, app, "scheduled@example.com", "user", "", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			step := FlowStep{Type: "sql", SQL: "INSERT INTO notes(user_id,title) VALUES (:user_id,:user_role)"}
			if mode == "dynamic" {
				step = FlowStep{Type: "sql_dynamic", SQL: "{{input}}"}
			}
			app.Flows = []Flow{{Name: "safe", Auth: "required", Transaction: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/safe"}, Steps: []FlowStep{step, {Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"ok": true}}}}}}
			w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"safe","body":{"user_id":999,"user_role":"admin","user":{"id":999},"user.id":999,"input":"INSERT INTO notes(title) VALUES ('injected')"},"run_at":"2000-01-01T00:00:00Z"}`, true)
			if w.Code != 200 {
				t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
			}
			if mode == "logged_out" {
				auditExec(t, app.DB, "DELETE FROM _benmore_sessions WHERE id=?", sid)
			}
			if mode == "expired" {
				auditExec(t, app.DB, "UPDATE _benmore_sessions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?", sid)
			}
			if mode == "deactivated" {
				auditExec(t, app.DB, "UPDATE _benmore_users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?", uid)
			}
			if mode == "promoted" {
				auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
			}
			sweepScheduledTasks(app)
			var n int
			app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n)
			var status string
			app.DB.QueryRow("SELECT status FROM _benmore_scheduled_tasks").Scan(&status)
			if mode != "dynamic" && mode != "deactivated" {
				var owner int64
				var role string
				app.DB.QueryRow("SELECT user_id,title FROM notes").Scan(&owner, &role)
				if n != 1 || owner != uid || role != "user" || status != "done" {
					t.Fatalf("untrusted identity: n=%d uid=%d role=%s status=%s", n, owner, role, status)
				}
			} else if n != 0 || (mode == "dynamic" && status != "failed") || (mode == "deactivated" && status != "blocked") {
				t.Fatalf("unsafe schedule executed: n=%d status=%s", n, status)
			}
		})
	}
}

func TestAuditTokenScopeAttenuation(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "mint@example.com", "user", "", "")
	auditExec(t, app.DB, "UPDATE _benmore_sessions SET scopes='notes:write' WHERE id=?", sid)
	for _, scopes := range []string{"*", "*:read", "notes:delete", "rooms:read"} {
		w := auditPost(mux, sid, "/api/_auth/api-tokens", "", fmt.Sprintf(`{"name":"test","scopes":%q}`, scopes), false)
		if w.Code != 403 {
			t.Fatalf("overbroad mint %s: %d", scopes, w.Code)
		}
	}
	w := auditPost(mux, sid, "/api/_auth/api-tokens", "", `{"name":"test","scopes":"notes:read"}`, false)
	if w.Code != 200 {
		t.Fatalf("legitimate scoped mint: %d %s", w.Code, w.Body.String())
	}
	var token map[string]any
	json.Unmarshal(w.Body.Bytes(), &token)
	if tok, _ := token["token"].(string); tok == "" {
		t.Fatal("missing token")
	}
	for _, tc := range []struct {
		granted, requested string
		want               bool
	}{{"*:write", "notes:read", true}, {"*:read", "notes:write", false}, {"notes:*", "*:read", false}, {"notes:write rooms:read", "notes:read rooms:read", true}} {
		if got := scopesWithin(tc.granted, tc.requested); got != tc.want {
			t.Errorf("subset %s / %s = %v", tc.granted, tc.requested, got)
		}
	}
	for _, role := range []string{"user", "admin"} {
		if HasPermission(&Session{Role: role, Scopes: "*:read"}, "notes:write") {
			t.Fatalf("wildcard scope bypass with role %s", role)
		}
	}
}

func TestAuditMFAActiveSessionCannotReplaceFactor(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "factor@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "UPDATE _benmore_users SET totp_secret='JBSWY3DPEHPK3PXP' WHERE id=?", uid)
	w := auditPost(mux, sid, "/api/_auth/mfa/setup", "", "{}", false)
	if w.Code != 403 || !CheckMFA(app.DB, uid) {
		t.Fatalf("active factor replaced: HTTP %d", w.Code)
	}
}

func TestAuditQueryRejectsMaskedFieldInference(t *testing.T) {
	app, mux, cleanup := encIncludeApp(t)
	defer cleanup()
	sid := createCrudScopeSession(t, app, "inference@example.com", "user", "", "")
	for _, body := range []string{`{"table":"accounts","aggregates":[{"fn":"max","col":"secret_note","as":"unmasked"}]}`, `{"table":"accounts","group_by":["secret_note"]}`, `{"table":"accounts","where":{"secret_note":"guess"}}`, `{"table":"accounts","order_by":[{"col":"secret_note"}]}`} {
		w := auditPost(mux, sid, "/api/_query", "", body, false)
		if w.Code != 400 {
			t.Fatalf("masked-field inference: %d %s", w.Code, w.Body.String())
		}
	}
	admin := createCrudScopeSession(t, app, "authorized@example.com", "admin", "", "")
	w := auditPost(mux, admin, "/api/_query", "", `{"table":"accounts","select":["secret_note"]}`, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "TOPSECRETvalue9999") {
		t.Fatalf("authorized unmask: %d %s", w.Code, w.Body.String())
	}
}

func TestAuditCursorProjectionKeepsCursor(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "projection@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "INSERT INTO notes(user_id,title) VALUES (?, 'wanted'), (?, 'other')", uid, uid)
	w := crudScopeRequest(t, mux, "GET", "/api/notes?cursor=0&where[title]=wanted&fields=title&limit=1", sid, nil)
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 200 || body["next_cursor"] != float64(1) || strings.Contains(w.Body.String(), "other") || strings.Contains(w.Body.String(), `"id":`) {
		t.Fatalf("cursor projection: %d %s", w.Code, w.Body.String())
	}
}

func auditExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestAuditTokenCannotBypassRoleLimits(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "bounded@example.com", "user", "", "")
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"user": {Scopes: "notes:read"}}}
	token := auditToken(t, app, sid, "*")
	w := auditPost(mux, token, "/api/notes", "", `{"title":"denied"}`, false)
	if w.Code != 403 {
		t.Fatalf("explicit token bypasses roles: %d %s", w.Code, w.Body.String())
	}
	w = crudScopeRequest(t, mux, "GET", "/api/notes", token, nil)
	if w.Code != 200 {
		t.Fatalf("permitted read refused: %d %s", w.Code, w.Body.String())
	}
}

func TestAuditLegacyIdempotencyRefusesUnverifiableReplay(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "legacy@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "DROP TABLE _benmore_idempotency")
	auditExec(t, app.DB, "CREATE TABLE _benmore_idempotency (key TEXT PRIMARY KEY, response TEXT NOT NULL, status_code INTEGER NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
	auditExec(t, app.DB, "INSERT INTO _benmore_idempotency(key,response,status_code) VALUES ('legacy','{\"private\":\"unverified-old-response\"}',200)")
	EnsureIdempotencyTable(app.DB)
	w := auditPost(mux, sid, "/api/notes", "legacy", `{"title":"retry"}`, false)
	if w.Code != 409 || strings.Contains(w.Body.String(), "unverified-old-response") {
		t.Fatalf("legacy replay: %d %s", w.Code, w.Body.String())
	}
	w = auditPost(mux, sid, "/api/notes", "new", `{"title":"new operation"}`, false)
	if w.Code != 200 {
		t.Fatalf("upgraded legacy table cannot accept new keys: %d %s", w.Code, w.Body.String())
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE user_id=?", uid).Scan(&n)
	if n != 1 {
		t.Fatalf("legacy/new key created %d rows", n)
	}
}

func TestAuditTransactionReferencesDoNotGrantMembership(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "references@example.com", "user", "", "")
	auditExec(t, app.DB, "CREATE TABLE messages (id INTEGER PRIMARY KEY, room_id INTEGER, text TEXT)")
	app.Tables = append(app.Tables, Table{Name: "messages", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "text"}}})
	app.Access.rules["messages"] = map[AccessOp]string{"all": "member-of:room_members(room_id, member_id)"}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	// The first note has id=1, but that coincidence doesn't confer membership
	// in the existing private room with id=1.
	w := auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"insert","data":{"title":"unrelated"}},{"table":"messages","action":"insert","ref":"room_id","ref_op":0,"data":{"text":"denied"}}]}`, false)
	if w.Code == 200 {
		t.Fatal("unrelated ref ID granted room membership")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&n)
	if n != 0 {
		t.Fatal("rejected ref did not roll back first operation")
	}
	// A real parent create autojoins within the same transaction, so its
	// child is authorized and readable immediately.
	w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"rooms","action":"insert","data":{"title":"new room"}},{"table":"messages","action":"insert","ref":"room_id","ref_op":0,"data":{"text":"allowed"}}]}`, false)
	if w.Code != 200 {
		t.Fatalf("legitimate parent-child create failed: %d %s", w.Code, w.Body.String())
	}
}

func TestAuditSyncFetchCacheAndRedirectPolicy(t *testing.T) {
	app, _ := auditApp(t)
	other, _ := auditApp(t)
	calls := 0
	client := &http.Client{Transport: auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"name":"ok"}`)), Request: r}, nil
	})}
	content := `<fetch url="https://93.184.216.34/sync" as="data" cache="1m">{{data.name}}</fetch>`
	for _, a := range []*App{app, app, other} {
		ctx := &RenderContext{Data: map[string]any{}}
		if out := expandFetchTagsWithClient(content, a, ctx, client); out != "ok" {
			t.Fatalf("sync render: %s", out)
		}
	}
	if calls != 2 {
		t.Fatalf("cache app isolation/reuse: %d", calls)
	}
	for range 2 {
		ctx := &RenderContext{User: &Session{ID: "session"}, Data: map[string]any{}}
		expandFetchTagsWithClient(content, app, ctx, client)
	}
	if calls != 4 {
		t.Fatalf("authenticated sync fetch cached: %d", calls)
	}
	original, _ := http.NewRequest("GET", "https://93.184.216.34/start", nil)
	for _, dest := range []string{"https://1.1.1.1/end", "http://93.184.216.34/end"} {
		next, _ := http.NewRequest("GET", dest, nil)
		if fetchHTTPClient(time.Second).CheckRedirect(next, []*http.Request{original}) == nil {
			t.Fatalf("credential-leaking redirect accepted: %s", dest)
		}
	}
}

func TestAuditSchedulerReportsCommitFailure(t *testing.T) {
	app, mux := auditApp(t)
	app.DB.SetMaxOpenConns(1)
	sid := createCrudScopeSession(t, app, "commitfail@example.com", "user", "", "")
	auditExec(t, app.DB, "PRAGMA foreign_keys=ON")
	auditExec(t, app.DB, "CREATE TABLE deferred_child (room_id INTEGER REFERENCES rooms(id) DEFERRABLE INITIALLY DEFERRED)")
	app.Flows = []Flow{{Name: "commit-failure", Auth: "required", Transaction: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/commit-failure"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO deferred_child(room_id) VALUES (999)"}, {Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"ok": true}}}}}}
	w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"commit-failure","run_at":"2000-01-01T00:00:00Z"}`, true)
	if w.Code != 200 {
		t.Fatalf("schedule: %d %s", w.Code, w.Body.String())
	}
	sweepScheduledTasks(app)
	var status string
	if err := app.DB.QueryRow("SELECT status FROM _benmore_scheduled_tasks").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("failed commit reported %s", status)
	}
}
