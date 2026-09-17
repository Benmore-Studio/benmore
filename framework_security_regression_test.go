//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for the framework security review. All fixtures and secrets
// are synthetic; outbound fetch tests use an injected transport.
func auditApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE orgdocs (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, title TEXT)`,
		`CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
		`CREATE TABLE room_members (id INTEGER PRIMARY KEY, room_id INTEGER, member_id INTEGER)`,
		`CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT)`,
		`INSERT INTO orgdocs VALUES (1, 'tenant-a', 'private-a'), (2, 'tenant-b', 'private-b')`,
		`INSERT INTO rooms VALUES (1, 'private-room')`,
	} {
		mustExec(t, db, stmt)
	}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Group: &GroupConfig{Table: "members", Key: "org_id", UserField: "email"},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"notes": {"all": "self"}, "orgdocs": {"all": "group"},
			"rooms": {"all": "member-of:room_members(room_id, member_id)"},
		}},
	}
	t.Cleanup(func() { close(app.Stop) })
	names, err := GetTableNames(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	RegisterQueryAPI(mux, app)
	RegisterSchedulingAPI(mux, app)
	RegisterMFARoutes(mux, app)
	mux.HandleFunc("POST /api/_auth/api-tokens", func(w http.ResponseWriter, r *http.Request) { handleCreateAPIToken(w, r, app) })
	return app, mux
}

func auditToken(t *testing.T, app *App, sid, scopes string) string {
	t.Helper()
	s := GetSessionFromDB(app.DB, sid)
	if s == nil {
		t.Fatal("missing test session")
	}
	tok := "bmr_" + generateToken(32)
	_, err := app.DB.Exec("INSERT INTO _benmore_api_tokens (user_id,name,token_hash,scopes) VALUES (?, ?, ?, ?)", s.UserID, "audit", hashToken(tok), scopes)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAuditRestrictedTokenCannotMintFullToken(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	tok := auditToken(t, app, sid, "notes:read")
	denied := crudScopeRequest(t, mux, "POST", "/api/notes", tok, map[string]any{"title": "before"})
	if denied.Code != 403 {
		t.Fatalf("control: restricted write returned %d", denied.Code)
	}
	mint := crudScopeRequest(t, mux, "POST", "/api/_auth/api-tokens", tok, map[string]any{"name": "escalated", "scopes": "*"})
	var payload map[string]any
	if err := json.Unmarshal(mint.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if minted, ok := payload["token"].(string); ok {
		write := crudScopeRequest(t, mux, "POST", "/api/notes", minted, map[string]any{"title": "after"})
		t.Fatalf("restricted token minted scopes=%v (HTTP %d); new token write HTTP %d", payload["scopes"], mint.Code, write.Code)
	}
	if mint.Code != 403 {
		t.Fatalf("expected 403, got %d", mint.Code)
	}
}

func TestAuditWildcardReadCannotWriteOrDelete(t *testing.T) {
	for _, action := range []string{"write", "delete", "approve"} {
		if hasScope(&Session{Scopes: "*:read"}, "notes", action) {
			t.Errorf("*:read authorizes notes:%s", action)
		}
	}
}

func TestAuditGrouplessUserCannotReadTenantRows(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "groupless@example.com", "user", "", "")
	for _, path := range []string{"/api/orgdocs", "/api/orgdocs/1", "/api/orgdocs?count=true"} {
		rec := crudScopeRequest(t, mux, "GET", path, sid, nil)
		if strings.Contains(rec.Body.String(), "private-") || strings.Contains(rec.Body.String(), `"count":2`) {
			t.Errorf("%s leaked tenant data: HTTP %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestAuditQueryEnforcesReadPolicies(t *testing.T) {
	t.Run("token scopes", func(t *testing.T) {
		app, mux := auditApp(t)
		sid := createCrudScopeSession(t, app, "queryreader@example.com", "user", "tenant-a", "")
		if _, err := app.DB.Exec("INSERT INTO members(org_id,email) VALUES (?,?)", "tenant-a", "queryreader@example.com"); err != nil {
			t.Fatal(err)
		}
		tok := auditToken(t, app, sid, "notes:read")
		control := crudScopeRequest(t, mux, "GET", "/api/orgdocs", tok, nil)
		if control.Code != 403 {
			t.Fatalf("control: %d %s", control.Code, control.Body.String())
		}
		rec := crudScopeRequest(t, mux, "POST", "/api/_query", tok, map[string]any{"table": "orgdocs"})
		if rec.Code != 403 {
			t.Fatalf("query bypassed token scope: HTTP %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("member-of", func(t *testing.T) {
		app, mux := auditApp(t)
		sid := createCrudScopeSession(t, app, "nonmember@example.com", "user", "", "")
		control := crudScopeRequest(t, mux, "GET", "/api/rooms", sid, nil)
		if control.Code != 200 || strings.Contains(control.Body.String(), "private-room") {
			t.Fatalf("control failed: %s", control.Body.String())
		}
		rec := crudScopeRequest(t, mux, "POST", "/api/_query", sid, map[string]any{"table": "rooms"})
		if strings.Contains(rec.Body.String(), "private-room") {
			t.Fatalf("query bypassed membership: HTTP %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("encrypted column", func(t *testing.T) {
		app, mux, cleanup := encIncludeApp(t)
		defer cleanup()
		sid := createCrudScopeSession(t, app, "masked@example.com", "user", "", "")
		control := crudScopeRequest(t, mux, "GET", "/api/accounts", sid, nil)
		if strings.Contains(control.Body.String(), "TOPSECRETvalue9999") {
			t.Fatal("control leaked plaintext")
		}
		rec := crudScopeRequest(t, mux, "POST", "/api/_query", sid, map[string]any{"table": "accounts"})
		if strings.Contains(rec.Body.String(), "TOPSECRETvalue9999") {
			t.Fatalf("query bypassed field masking: HTTP %d %s", rec.Code, rec.Body.String())
		}
	})
}

func TestAuditTransactionEnforcesBeforeHooks(t *testing.T) {
	for _, action := range []string{"insert", "update", "delete"} {
		t.Run(action, func(t *testing.T) {
			app, mux := auditApp(t)
			sid := createCrudScopeSession(t, app, "hooked@example.com", "user", "", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			if _, err := app.DB.Exec("INSERT INTO notes(id,user_id,title) VALUES(1,?,'original')", uid); err != nil {
				t.Fatal(err)
			}
			deny := map[string][]Hook{"notes": {{SQL: "SELECT 'denied by policy' AS error"}}}
			app.Hooks = &HookConfig{BeforeInsert: deny, BeforeUpdate: deny, BeforeDelete: deny}
			method, path := "POST", "/api/notes"
			if action == "update" {
				method, path = "PATCH", "/api/notes/1"
			}
			if action == "delete" {
				method, path = "DELETE", "/api/notes/1"
			}
			control := crudScopeRequest(t, mux, method, path, sid, map[string]any{"title": "blocked"})
			if control.Code != 422 {
				t.Fatalf("control: HTTP %d %s", control.Code, control.Body.String())
			}
			rec := crudScopeRequest(t, mux, "POST", "/api/_transaction", sid, map[string]any{"operations": []any{map[string]any{"table": "notes", "action": action, "id": 1, "data": map[string]any{"title": "bypass"}}}})
			var count int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if rec.Code == 200 {
				t.Fatalf("transaction bypassed %s hook; rows=%d HTTP %d %s", action, count, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuditSchedulerCannotInvokeAdminFlow(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "scheduler@example.com", "user", "", "")
	app.Flows = []Flow{{Name: "admin-action", Auth: "required", Role: "admin", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/admin-action"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO rooms(title) VALUES (:user_role)"}}}}
	RegisterFlows(mux, app, app.Flows)
	control := crudScopeRequest(t, mux, "POST", "/api/admin-action", sid, map[string]any{"user_role": "admin"})
	if control.Code != 403 {
		t.Fatalf("control: HTTP %d %s", control.Code, control.Body.String())
	}
	body := `{"kind":"flow","flow":"admin-action","body":{"user_role":"forged-admin-context"},"run_at":"2000-01-01T00:00:00Z"}`
	r := httptest.NewRequest("POST", "/api/_scheduled", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	sweepScheduledTasks(app)
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM rooms WHERE title='forged-admin-context'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("ordinary user scheduled and executed admin flow with forged context; schedule HTTP %d, effect count=%d", w.Code, n)
	}
}

type auditRoundTripFunc func(*http.Request) (*http.Response, error)

func (f auditRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuditFetchDoesNotExpandVisitorControlledSecrets(t *testing.T) {
	app, _ := auditApp(t)
	SetAppEnv(app.Dir, "AUDIT_SECRET", "synthetic-secret-only")
	var captured string
	transport := auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		captured = r.Header.Get("X-Audit-Secret")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})
	mux := http.NewServeMux()
	registerFetchRoutes(mux, app, &http.Client{Transport: transport})
	q := url.Values{"url": {"https://93.184.216.34/audit-capture"}, "headers": {"X-Audit-Secret: {{env.AUDIT_SECRET}}"}}
	r := httptest.NewRequest("GET", "/_internal/fetch?"+q.Encode(), nil)
	r.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if captured != "" {
		t.Fatalf("unauthenticated request exported synthetic app secret to chosen public URL: HTTP %d header=%q", w.Code, captured)
	}
}

func auditFetchPath(t *testing.T, app *App, session *Session, headers string) string {
	t.Helper()
	token, err := sealFetchDescriptor(app, fetchDescriptor{URL: "https://93.184.216.34/audit", Headers: headers, Cache: "1m", Audience: sessionSecurityFingerprint(session), Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return "/_internal/fetch?d=" + url.QueryEscape(token)
}

func TestAuditFetchCacheSeparatesUsersAndApps(t *testing.T) {
	victim, _ := auditApp(t)
	otherApp, _ := auditApp(t)
	sid := createCrudScopeSession(t, victim, "cachevictim@example.com", "user", "", "")
	calls := 0
	client := &http.Client{Transport: auditRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"call":%d}`, calls))), Request: r}, nil
	})}
	request := func(app *App, sid string, headers string) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		registerFetchRoutes(mux, app, client)
		r := httptest.NewRequest("GET", "/", nil)
		if sid != "" {
			r.Header.Set("Authorization", "Bearer "+sid)
		} else {
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(""))
		}
		r.URL, _ = url.Parse(auditFetchPath(t, app, getSession(app, r), headers))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("fetch HTTP %d: %s", w.Code, w.Body.String())
		}
		return w
	}
	request(victim, sid, "")
	request(victim, sid, "")
	if calls != 2 {
		t.Fatal("authenticated response was cached")
	}
	request(victim, "", "X-API-Key: synthetic")
	request(victim, "", "X-API-Key: synthetic")
	if calls != 4 {
		t.Fatal("credentialed response was cached")
	}
	request(victim, "", "")
	request(victim, "", "")
	if calls != 5 {
		t.Fatal("public fetch did not reuse its cache")
	}
	request(otherApp, "", "")
	if calls != 6 {
		t.Fatal("fetch cache crossed apps")
	}
}

func TestAuditFetchDescriptorBinding(t *testing.T) {
	app, _ := auditApp(t)
	other, _ := auditApp(t)
	session := &Session{ID: "synthetic-session", UserID: 1, Scopes: "notes:read"}
	desc := fetchDescriptor{URL: "https://93.184.216.34/", Headers: "X-Key: synthetic-secret", Audience: sessionSecurityFingerprint(session), Expires: time.Now().Add(time.Minute).Unix()}
	token, err := sealFetchDescriptor(app, desc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, "synthetic-secret") {
		t.Fatal("descriptor exposes secret")
	}
	if _, err := openFetchDescriptor(app, token, session); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		app     *App
		token   string
		session *Session
	}{{other, token, session}, {app, token, nil}, {app, "x" + token, session}, {app, token, &Session{ID: "synthetic-session", UserID: 1, Scopes: "notes:write"}}} {
		if _, err := openFetchDescriptor(tc.app, tc.token, tc.session); err == nil {
			t.Fatal("accepted a modified descriptor or wrong audience/app")
		}
	}
	desc.Expires = time.Now().Add(-time.Minute).Unix()
	token, _ = sealFetchDescriptor(app, desc)
	if _, err := openFetchDescriptor(app, token, session); err == nil {
		t.Fatal("accepted expired descriptor")
	}
}

func TestAuditMFASetupCannotReplaceActiveFactor(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "mfauser@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if _, err := app.DB.Exec("UPDATE _benmore_users SET totp_secret=? WHERE id=?", "JBSWY3DPEHPK3PXP", uid); err != nil {
		t.Fatal(err)
	}
	tok := auditToken(t, app, sid, "notes:read")
	if !CheckMFA(app.DB, uid) {
		t.Fatal("control: MFA not active")
	}
	w := crudScopeRequest(t, mux, "POST", "/api/_auth/mfa/setup", tok, map[string]any{})
	if !CheckMFA(app.DB, uid) {
		t.Fatalf("read-only API token disabled active MFA through setup without existing factor: HTTP %d", w.Code)
	}
}

func TestAuditCursorKeepsWhereFilters(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "cursoruser@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES(?,'wanted'),(?,'other')", uid, uid); err != nil {
		t.Fatal(err)
	}
	w := crudScopeRequest(t, mux, "GET", "/api/notes?cursor=0&where[title]=wanted", sid, nil)
	if strings.Contains(w.Body.String(), "other") {
		t.Fatalf("cursor pagination ignored where filter: HTTP %d %s", w.Code, w.Body.String())
	}
}

func TestAuditIdempotencyIsBoundToRoute(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "dedupeuser@example.com", "admin", "", "")
	post := func(path, title string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(fmt.Sprintf(`{"title":%q}`, title)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		r.Header.Set("X-Idempotency-Key", "same-key")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	first := post("/api/notes", "note-created")
	if first.Code != 200 {
		t.Fatalf("control: %d %s", first.Code, first.Body.String())
	}
	second := post("/api/rooms", "room-requested")
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM rooms WHERE title='room-requested'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 && second.Code == 200 {
		t.Fatalf("different route returned unrelated cached success without inserting: %s", second.Body.String())
	}
}
