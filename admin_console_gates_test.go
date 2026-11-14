//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// An admin can hand a narrowly scoped credential (an API token or a Bearer
// session minted with scopes) to an integration. Row visibility follows the
// admin role on purpose, so that credential still reads every row its scope
// names. The handlers below are not row reads: they let an admin read the
// app's feedback inbox and health report, or act on another user's stream,
// lock or approval, and no scope names them. They were gated on IsAdmin, so a
// notes:read credential did all of it. Like the other admin-only management
// surfaces (security rule 15b) they need IsAdminConsole: an admin on an
// unscoped credential. A scoped admin credential gets what the same account
// would get without the admin role.

const consoleGateScopes = "notes:read notes:write"

type consoleGateFixture struct {
	app *App
	mux *http.ServeMux
	// Three credentials of one admin account, and the ids of the account, of
	// an ordinary user whose objects the admin acts on, and of a third user.
	allowed   map[string]string // credential name -> Bearer value that keeps admin management
	delegated map[string]string // credential name -> scoped Bearer value
	adminID   int64
	otherID   int64
	thirdID   int64
}

func newConsoleGateFixture(t *testing.T) *consoleGateFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsureAuditLogTable(db)
	EnsureNotificationsTable(db)
	EnsureLocksTable(db)
	EnsureFeedbackTables(db)
	EnsureSchedulingTables(db)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)

	feedbackOn := true
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		// A published app: the feedback widget is on, testing mode is off.
		Design: &DesignConfig{Auth: map[string]string{"enabled": "true"}, SEO: map[string]string{},
			Features: &FeaturesConfig{Feedback: &feedbackOn}},
		Access: accessFromYAML(t, "access:\n  notes: self\n")}
	t.Cleanup(app.Shutdown)
	cols, err := GetTableColumns(db, "notes")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = []Table{{Name: "notes", Columns: cols}}

	mux := http.NewServeMux()
	RegisterFeedbackAPI(mux, app)
	mux.HandleFunc("GET /health", healthHandler(app))
	RegisterBroadcastRoutes(mux, app)
	RegisterLockRoutes(mux, app)
	registerSchedulingAPI(mux, app)

	f := &consoleGateFixture{app: app, mux: mux}
	sid := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	f.adminID = GetSessionFromDB(db, sid).UserID
	other := createCrudScopeSession(t, app, "other@example.com", "user", "", "")
	f.otherID = GetSessionFromDB(db, other).UserID
	third := createCrudScopeSession(t, app, "third@example.com", "user", "", "")
	f.thirdID = GetSessionFromDB(db, third).UserID
	f.allowed = map[string]string{
		"admin session":        sid,
		"unscoped admin token": auditToken(t, app, sid, "*"),
	}
	f.delegated = map[string]string{
		"scoped admin token":   auditToken(t, app, sid, consoleGateScopes),
		"scoped admin session": CreateSession(db, f.adminID, "admin@example.com", "", time.Hour, consoleGateScopes),
	}
	// Fixture check: every credential is the admin, and the scoped ones keep
	// the row-visibility bypass that rule 15b leaves on IsAdmin.
	for name, tok := range f.delegated {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		s := getSession(app, r)
		if s == nil || !s.IsAdmin() || !s.IsAdminBypass() || s.IsAdminConsole() {
			t.Fatalf("fixture: %s should be an admin with row bypass and no console: %+v", name, s)
		}
	}
	return f
}

func (f *consoleGateFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Published-app feedback carries every visitor's comment and email.
func TestScopedAdminCredentialCannotReadPublishedFeedback(t *testing.T) {
	f := newConsoleGateFixture(t)
	crudScopeMustExec(t, f.app.DB, `INSERT INTO _benmore_feedback (page_url, origin_host, body, visitor_email)
		VALUES ('/', 'live.example.com', 'checkout is broken', 'visitor@example.com')`)

	for name, tok := range f.allowed {
		list := crudScopeRequest(t, f.mux, http.MethodGet, "/api/_feedback", tok, nil)
		if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "visitor@example.com") {
			t.Fatalf("%s GET /api/_feedback = %d, want the inbox: %.200s", name, list.Code, list.Body.String())
		}
		detail := crudScopeRequest(t, f.mux, http.MethodGet, "/api/_feedback/1", tok, nil)
		if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "checkout is broken") {
			t.Fatalf("%s GET /api/_feedback/1 = %d, want the item: %.200s", name, detail.Code, detail.Body.String())
		}
	}
	for name, tok := range f.delegated {
		// The list answers an empty array to anyone who may not read it (the
		// widget polls it), the detail answers 403: the non-admin shapes.
		list := crudScopeRequest(t, f.mux, http.MethodGet, "/api/_feedback", tok, nil)
		if list.Code != http.StatusOK || strings.TrimSpace(list.Body.String()) != "[]" {
			t.Errorf("%s GET /api/_feedback = %d %.200s, want 200 []", name, list.Code, list.Body.String())
		}
		detail := crudScopeRequest(t, f.mux, http.MethodGet, "/api/_feedback/1", tok, nil)
		if detail.Code != http.StatusForbidden || strings.Contains(detail.Body.String(), "visitor@example.com") || strings.Contains(detail.Body.String(), "checkout is broken") {
			t.Errorf("%s GET /api/_feedback/1 = %d %.200s, want 403 without the item", name, detail.Code, detail.Body.String())
		}
	}
}

// The detailed health report (uptime, per-subsystem checks) is the admin's
// view; everyone else gets the status line.
func TestScopedAdminCredentialGetsBasicHealthOnly(t *testing.T) {
	f := newConsoleGateFixture(t)
	health := func(tok string) (int, map[string]any) {
		rec := crudScopeRequest(t, f.mux, http.MethodGet, "/health", tok, nil)
		var out map[string]any
		mustDecodeBody(t, rec, &out)
		return rec.Code, out
	}
	for name, tok := range f.allowed {
		code, out := health(tok)
		if code != http.StatusOK || out["checks"] == nil || out["uptime"] == nil {
			t.Fatalf("%s GET /health = %d %v, want the detailed report", name, code, out)
		}
	}
	for name, tok := range f.delegated {
		code, out := health(tok)
		if code != http.StatusOK || out["status"] != "healthy" {
			t.Fatalf("%s GET /health = %d %v, want 200 healthy", name, code, out)
		}
		if out["checks"] != nil || out["uptime"] != nil {
			t.Errorf("%s GET /health exposed the admin-only detail: %v", name, out)
		}
	}
}

// Stopping a stream deletes the publisher's record. The publisher may; an
// admin may stop anyone's.
func TestScopedAdminCredentialCannotStopAnotherUsersBroadcast(t *testing.T) {
	f := newConsoleGateFixture(t)
	publish := func(slug string, publisher int64) {
		t.Helper()
		if _, err := f.app.DB.Exec(`INSERT INTO _benmore_broadcasts (slug, publisher_session_id, publisher_user_id) VALUES (?, 'sfu-session', ?)`, slug, publisher); err != nil {
			t.Fatal(err)
		}
	}
	live := func(slug string) bool {
		return f.count(t, `SELECT COUNT(*) FROM _benmore_broadcasts WHERE slug = ?`, slug) == 1
	}
	stop := func(tok, slug string) int {
		return crudScopeRequest(t, f.mux, http.MethodPost, "/api/_broadcast/stop", tok, map[string]any{"slug": slug}).Code
	}
	// The slugs here match no ws_rooms pattern, so a scoped credential reaches
	// them only with a wildcard write scope (scoped_credential_routes.go).
	// With one, the admin-console rule is what decides.
	anyRoom := map[string]string{
		"admin token *:write":   auditToken(t, f.app, f.allowed["admin session"], "*:write"),
		"admin session *:write": CreateSession(f.app.DB, f.adminID, "admin@example.com", "", time.Hour, "*:write"),
	}
	n := 0
	for name, tok := range f.allowed {
		n++
		slug := fmt.Sprintf("theirs-%d", n)
		publish(slug, f.otherID)
		if code := stop(tok, slug); code != http.StatusOK || live(slug) {
			t.Fatalf("%s stop of another user's stream = %d, still live = %v; want it stopped", name, code, live(slug))
		}
	}
	for name, tok := range anyRoom {
		n++
		slug := fmt.Sprintf("theirs-%d", n)
		publish(slug, f.otherID)
		if code := stop(tok, slug); code != http.StatusForbidden || !live(slug) {
			t.Errorf("%s stop of another user's stream = %d, still live = %v; want 403 and the stream kept", name, code, live(slug))
		}
		// Its own stream is not an admin action.
		mine := fmt.Sprintf("mine-%d", n)
		publish(mine, f.adminID)
		if code := stop(tok, mine); code != http.StatusOK || live(mine) {
			t.Errorf("%s stop of its own stream = %d, still live = %v; want it stopped", name, code, live(mine))
		}
	}
	// Scopes that name only a table stop no stream in a room they do not
	// cover, the account's own included.
	for name, tok := range f.delegated {
		n++
		for _, c := range []struct {
			slug      string
			publisher int64
		}{{fmt.Sprintf("theirs-%d", n), f.otherID}, {fmt.Sprintf("mine-%d", n), f.adminID}} {
			publish(c.slug, c.publisher)
			if code := stop(tok, c.slug); code != http.StatusForbidden || !live(c.slug) {
				t.Errorf("%s stop of %s = %d, still live = %v; want 403 and the stream kept", name, c.slug, code, live(c.slug))
			}
		}
	}
}

// A lock blocks other editors until its holder releases it or it expires. An
// admin may release anyone's.
func TestScopedAdminCredentialCannotReleaseAnotherUsersLock(t *testing.T) {
	f := newConsoleGateFixture(t)
	crudScopeMustExec(t, f.app.DB, fmt.Sprintf(`INSERT INTO notes (user_id, title) VALUES (%d, 'theirs')`, f.otherID)) // id 1
	lock := func(holder int64) {
		t.Helper()
		if _, err := f.app.DB.Exec(`INSERT OR REPLACE INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
			VALUES ('notes', '1', ?, 'holder@example.com', datetime('now', '+1 hour'))`, holder); err != nil {
			t.Fatal(err)
		}
	}
	held := func() bool {
		return f.count(t, `SELECT COUNT(*) FROM _benmore_locks WHERE table_name = 'notes' AND row_id = '1'`) == 1
	}
	release := func(tok string) int {
		return crudScopeRequest(t, f.mux, http.MethodDelete, "/api/notes/1/lock", tok, nil).Code
	}
	for name, tok := range f.allowed {
		lock(f.otherID)
		if code := release(tok); code != http.StatusOK || held() {
			t.Fatalf("%s release of another user's lock = %d, still held = %v; want it released", name, code, held())
		}
	}
	for name, tok := range f.delegated {
		lock(f.otherID)
		if code := release(tok); code != http.StatusForbidden || !held() {
			t.Errorf("%s release of another user's lock = %d, still held = %v; want 403 and the lock kept", name, code, held())
		}
		// Its own lock is not an admin action.
		lock(f.adminID)
		if code := release(tok); code != http.StatusOK || held() {
			t.Errorf("%s release of its own lock = %d, still held = %v; want it released", name, code, held())
		}
	}
}

// An approved row is evidence that the assigned approver (or an admin
// stepping in for them) decided.
func TestScopedAdminCredentialCannotDecideAnotherUsersApproval(t *testing.T) {
	f := newConsoleGateFixture(t)
	request := func(approver int64) int64 {
		t.Helper()
		res, err := f.app.DB.Exec(`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, title)
			VALUES ('notes', '1', ?, 'third@example.com', ?, 'Publish the note')`, f.thirdID, approver)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	status := func(id int64) string {
		var s string
		if err := f.app.DB.QueryRow(`SELECT status FROM _benmore_approvals WHERE id = ?`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	decide := func(tok string, id int64) (int, string) {
		rec := crudScopeRequest(t, f.mux, http.MethodPost, fmt.Sprintf("/api/_approvals/%d/decide", id), tok, map[string]any{"decision": "approved"})
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		msg, _ := out["error"].(string)
		return rec.Code, msg
	}
	for name, tok := range f.allowed {
		id := request(f.otherID)
		if code, msg := decide(tok, id); code != http.StatusOK || status(id) != "approved" {
			t.Fatalf("%s decide of another user's approval = %d %q, stored %q; want approved", name, code, msg, status(id))
		}
	}
	for name, tok := range f.delegated {
		id := request(f.otherID)
		if code, msg := decide(tok, id); code != http.StatusForbidden || msg != "not the assigned approver" || status(id) != "pending" {
			t.Errorf("%s decide of another user's approval = %d %q, stored %q; want 403 not the assigned approver, still pending", name, code, msg, status(id))
		}
		// An id that does not exist answers the same 403, so the refusal
		// tells a scoped credential nothing about which approvals exist.
		if code, msg := decide(tok, 999999); code != http.StatusForbidden || msg != "not the assigned approver" {
			t.Errorf("%s decide of a missing approval = %d %q, want the same 403", name, code, msg)
		}
		// An approval assigned to the account itself is not an admin action.
		own := request(f.adminID)
		if code, msg := decide(tok, own); code != http.StatusOK || status(own) != "approved" {
			t.Errorf("%s decide of its own approval = %d %q, stored %q; want approved", name, code, msg, status(own))
		}
	}
}

// Two listed sites stay on IsAdmin: POST /api/_auth/act_as (step-in) and the
// "an admin may switch to any group" branch of POST /api/_switch_group. Both
// only choose which tenant the caller's own session is scoped to, which is
// row visibility (rule 15b keeps that on IsAdmin): a scoped admin session
// already reads every tenant's rows inside its scopes, step-in narrows that
// to one tenant, and a switch only records a tenant on a session that keeps
// the bypass. Neither reaches a table its scopes do not name. Refusing
// step-in would leave a scoped admin session with no way to confine itself
// to a single tenant.
func TestScopedAdminSessionStepInAndSwitchOnlyChooseTheTenant(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureLoginAttemptsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	for _, stmt := range []string{
		`CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)`,
		`CREATE TABLE records (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE payroll (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, salary_cents INTEGER)`,
		`INSERT INTO members (org_id, user_id) VALUES ('org-a', 900), ('org-b', 901)`,
		`INSERT INTO records (org_id, user_id, title) VALUES ('org-a', 900, 'a-row'), ('org-b', 901, 'b-row')`,
		`INSERT INTO payroll (org_id, salary_cents) VALUES ('org-a', 1), ('org-b', 2)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Group:  &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"},
		Design: &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}},
		Access: accessFromYAML(t, "access:\n  records: group\n  payroll: group\n")}
	app.Paths = DiscoverAuthPaths(nil)
	t.Cleanup(app.Shutdown)
	for _, name := range []string{"members", "records", "payroll"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	mux := http.NewServeMux()
	registerAuthRoutes(mux, app)
	RegisterCRUD(mux, app)

	hash, err := generateBcryptHash([]byte("Admin!Pass1"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('boss', 'boss@example.com', ?, 'admin', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	// The admin is a member of neither tenant.
	scoped := CreateSession(db, adminID, "boss@example.com", "", time.Hour, "records:read records:write")

	titles := func() string {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/records", scoped, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/records = %d %s", rec.Code, rec.Body.String())
		}
		var rows []map[string]any
		mustDecodeBody(t, rec, &rows)
		var got []string
		for _, row := range rows {
			got = append(got, fmt.Sprint(row["org_id"], "/", row["title"]))
		}
		sort.Strings(got)
		return strings.Join(got, " ")
	}
	outsideScope := func(when string) {
		t.Helper()
		if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/payroll", scoped, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: GET /api/payroll = %d %s, want 403: the session's scopes do not name the table", when, rec.Code, rec.Body.String())
		}
	}
	create := func(title string) string {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/records", scoped, map[string]any{"title": title})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("POST /api/records = %d %s", rec.Code, rec.Body.String())
		}
		var org sql.NullString
		if err := db.QueryRow(`SELECT org_id FROM records WHERE title = ?`, title).Scan(&org); err != nil {
			t.Fatal(err)
		}
		return org.String
	}

	// Before: the row-visibility bypass, inside the session's scopes.
	if got := titles(); got != "org-a/a-row org-b/b-row" {
		t.Fatalf("before step-in the scoped admin session reads %q, want both tenants' rows", got)
	}
	outsideScope("before step-in")

	// Step-in narrows the same session to one tenant.
	stepIn := crudScopeRequest(t, mux, http.MethodPost, "/api/_auth/act_as", scoped, map[string]any{"group_id": "org-a", "password": "Admin!Pass1"})
	if stepIn.Code != http.StatusOK {
		t.Fatalf("scoped admin session step-in = %d %s, want 200", stepIn.Code, stepIn.Body.String())
	}
	if got := titles(); got != "org-a/a-row" {
		t.Fatalf("stepped into org-a the session reads %q, want only that tenant's rows", got)
	}
	outsideScope("stepped in")
	if org := create("made stepped in"); org != "org-a" {
		t.Fatalf("a row created while stepped into org-a landed in %q", org)
	}
	if out := crudScopeRequest(t, mux, http.MethodDelete, "/api/_auth/act_as", scoped, nil); out.Code != http.StatusOK {
		t.Fatalf("step out = %d %s", out.Code, out.Body.String())
	}

	// A switch records the tenant on the session. An admin outside step-in
	// keeps the bypass, so what the session reads and where it may write are
	// exactly what they were before the switch.
	sw := crudScopeRequest(t, mux, http.MethodPost, "/api/_switch_group", scoped, map[string]any{"group_id": "org-b"})
	if sw.Code != http.StatusOK {
		t.Fatalf("scoped admin session switch to a tenant it is not a member of = %d %s, want 200", sw.Code, sw.Body.String())
	}
	var state map[string]any
	mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, "/api/_auth/act_as", scoped, nil), &state)
	if state["group_id"] != "org-b" || state["bypass"] != true {
		t.Fatalf("after the switch the session reports %v, want group_id org-b with the bypass on", state)
	}
	if got := titles(); got != "org-a/a-row org-a/made stepped in org-b/b-row" {
		t.Fatalf("after the switch the session reads %q, want the same rows as before it", got)
	}
	outsideScope("after the switch")
}
