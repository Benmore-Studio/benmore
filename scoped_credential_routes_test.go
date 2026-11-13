//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A credential minted with scopes (an API token, a scoped Bearer session) is
// narrowed table by table on the generated API. The routes beside it that
// are about one table's rows answered it as the whole account. The fixture
// is an app with a table the "without" credentials are not scoped to
// (ledger), a room bound to a membership table, and billing configured.
type scopedRoutesFixture struct {
	app *App
	mux *http.ServeMux
	// Credentials of the owner (user 1), by name.
	owner map[string]string
	// Credentials of the approver (user 2), by name.
	approver map[string]string
}

const scopedRoutesApproverEmail = "approver@example.com"

func newScopedRoutesFixture(t *testing.T) *scopedRoutesFixture {
	t.Helper()
	return newScopedRoutesFixtureWith(t, nil)
}

func newScopedRoutesFixtureWith(t *testing.T, roles *RolesConfig) *scopedRoutesFixture {
	t.Helper()
	return newScopedRoutesFixtureConfigured(t, roles, nil)
}

// newScopedRoutesFixtureConfigured lets a test finish configuring the app
// (features, a tenant key) before the mux and its workers exist.
func newScopedRoutesFixtureConfigured(t *testing.T, roles *RolesConfig, configure func(*App)) *scopedRoutesFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, entry TEXT, file TEXT)`,
		`CREATE TABLE room_members (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, member_id INTEGER)`,
		`INSERT INTO ledger (user_id, entry, file) VALUES (1, 'rent', '/uploads/private/receipt.png')`,
		`INSERT INTO room_members (room_id, member_id) VALUES (7, 1)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	if err := os.MkdirAll(filepath.Join(dir, "uploads", "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uploads", "private", "receipt.png"), []byte("not really a png"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Design: &DesignConfig{Auth: map[string]string{"enabled": "true", "billing_provider": "stripe"}, SEO: map[string]string{}},
		Access: accessFromYAML(t, "access:\n  notes: self\n  ledger: self\n"),
		Tables: []Table{
			{Name: "notes", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}}},
			{Name: "ledger", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "entry"}, {Name: "file"}}},
			{Name: "room_members", Columns: []Column{{Name: "id", PK: true}, {Name: "room_id"}, {Name: "member_id"}}},
		},
		WSRooms: []WSRoomRule{{Pattern: "huddle-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}},
	}
	t.Cleanup(app.Shutdown)
	app.Paths = DiscoverAuthPaths(nil)
	app.Roles = roles
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	f := &scopedRoutesFixture{app: app, owner: map[string]string{}, approver: map[string]string{}}
	for i, u := range []struct {
		email string
		creds map[string]string
	}{{"owner@example.com", f.owner}, {scopedRoutesApproverEmail, f.approver}} {
		res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)", strings.Split(u.email, "@")[0], u.email)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		if id != int64(i+1) {
			t.Fatalf("fixture: %s got user id %d", u.email, id)
		}
		u.creds["sign-in"] = CreateSession(db, id, u.email, "", time.Hour)
		u.creds["scoped session notes:read"] = CreateSession(db, id, u.email, "", time.Hour, "notes:read")
		for _, scopes := range []string{"*", "notes:read", "ledger:read", "ledger:write", "room_members:read", "room_members:write", "*:read", "*:write"} {
			secret := "bmr_" + generateToken(32)
			if _, err := db.Exec(`INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, ?, ?, ?)`, id, scopes, hashToken(secret), scopes); err != nil {
				t.Fatal(err)
			}
			u.creds["token "+scopes] = secret
		}
	}
	if configure != nil {
		configure(app)
	}
	// Everything is configured before the mux (and its workers) exists.
	f.mux = buildAppMux(app, false, "https://fixture.example.com")
	return f
}

// without are the owner's credentials whose scopes name only another table.
func (f *scopedRoutesFixture) without() map[string]string {
	return map[string]string{
		"API token notes:read":      f.owner["token notes:read"],
		"scoped session notes:read": f.owner["scoped session notes:read"],
	}
}

// unscoped are the owner's credentials that carry no scopes of their own.
func (f *scopedRoutesFixture) unscoped() map[string]string {
	return map[string]string{"sign-in session": f.owner["sign-in"], "API token *": f.owner["token *"]}
}

func (f *scopedRoutesFixture) call(t *testing.T, method, path, cred string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return crudScopeRequest(t, f.mux, method, path, cred, body)
}

func (f *scopedRoutesFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.app.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// assertScopeRefusal checks the standard scope refusal: 403, the sentence
// auto-CRUD answers for the same table and action, and its docs address.
func assertScopeRefusal(t *testing.T, label string, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Errorf("%s: status %d, want 403\n%s", label, rec.Code, rec.Body.String())
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Errorf("%s: the 403 body is not JSON: %v\n%s", label, err, rec.Body.String())
		return
	}
	message, _ := body["error"].(string)
	if !strings.HasPrefix(message, "scope denied: ") || !strings.Contains(message, want) {
		t.Errorf("%s: error = %q, want a scope refusal naming %q", label, message, want)
	}
	if body["docs"] != "rbac.gotchas" {
		t.Errorf("%s: docs = %v, want rbac.gotchas", label, body["docs"])
	}
}

func assertSideRouteStatus(t *testing.T, label string, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: status %d, want %d\n%s", label, rec.Code, want, rec.Body.String())
	}
}

// The refusal on these routes is the one GET or POST /api/<table> gives the
// same credential.
func TestScopedCredentialSideRouteRefusalMatchesAutoCRUD(t *testing.T) {
	f := newScopedRoutesFixture(t)
	tok := f.owner["token notes:read"]
	crud := f.call(t, http.MethodGet, "/api/ledger", tok, nil)
	side := f.call(t, http.MethodGet, "/api/_approvals?table=ledger&row_id=1", tok, nil)
	assertScopeRefusal(t, "GET /api/ledger", crud, "ledger:read")
	if crud.Body.String() != side.Body.String() {
		t.Errorf("the side route answers %s, auto-CRUD answers %s", side.Body.String(), crud.Body.String())
	}
}

func TestScopedCredentialApprovalsNeedTheRecordTableScope(t *testing.T) {
	f := newScopedRoutesFixture(t)
	request := map[string]any{"table": "ledger", "row_id": "1", "approver_email": scopedRoutesApproverEmail, "title": "approve-rent-marker"}

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" POST /api/_approvals", f.call(t, http.MethodPost, "/api/_approvals", cred, request), "ledger:write")
	}
	assertScopeRefusal(t, "ledger:read POST /api/_approvals", f.call(t, http.MethodPost, "/api/_approvals", f.owner["token ledger:read"], request), "ledger:write")
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_approvals"); n != 0 {
		t.Fatalf("refused requests stored %d approvals", n)
	}
	created := f.call(t, http.MethodPost, "/api/_approvals", f.owner["token ledger:write"], request)
	assertSideRouteStatus(t, "ledger:write POST /api/_approvals", created, http.StatusOK)
	id := responseID(t, created)

	// A label that is no table has no scope a narrowed token could carry.
	label := map[string]any{"table": "petty cash", "row_id": "x", "approver_email": scopedRoutesApproverEmail, "title": "label-marker"}
	assertScopeRefusal(t, "ledger:write POST a label", f.call(t, http.MethodPost, "/api/_approvals", f.owner["token ledger:write"], label), "petty cash:write")
	for name, cred := range f.unscoped() {
		assertSideRouteStatus(t, name+" POST a label", f.call(t, http.MethodPost, "/api/_approvals", cred, label), http.StatusOK)
	}

	// Reading: the named table's read scope, and a list that names no table
	// holds only the tables the credential reads.
	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" GET ?table=ledger", f.call(t, http.MethodGet, "/api/_approvals?table=ledger&row_id=1", cred, nil), "ledger:read")
		all := f.call(t, http.MethodGet, "/api/_approvals", cred, nil)
		assertSideRouteStatus(t, name+" GET /api/_approvals", all, http.StatusOK)
		if strings.Contains(all.Body.String(), "marker") {
			t.Errorf("%s lists approvals of tables outside its scopes: %s", name, all.Body.String())
		}
	}
	for _, path := range []string{"/api/_approvals?table=ledger&row_id=1", "/api/_approvals"} {
		rec := f.call(t, http.MethodGet, path, f.owner["token ledger:read"], nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "approve-rent-marker") || strings.Contains(rec.Body.String(), "label-marker") {
			t.Errorf("ledger:read GET %s = %d %s, want the ledger approval alone", path, rec.Code, rec.Body.String())
		}
	}
	for name, cred := range f.unscoped() {
		rec := f.call(t, http.MethodGet, "/api/_approvals", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "approve-rent-marker") || !strings.Contains(rec.Body.String(), "label-marker") {
			t.Errorf("%s GET /api/_approvals = %d %s, want both approvals", name, rec.Code, rec.Body.String())
		}
	}

	// Deciding is a change to the record's approval: the assigned approver's
	// narrowed credential needs the table's write scope.
	decide := fmt.Sprintf("/api/_approvals/%d/decide", id)
	for _, name := range []string{"token notes:read", "scoped session notes:read", "token ledger:read"} {
		assertScopeRefusal(t, "approver "+name+" decide", f.call(t, http.MethodPost, decide, f.approver[name], map[string]any{"decision": "approved"}), "ledger:write")
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_approvals WHERE id = ? AND status = 'pending'", id); n != 1 {
		t.Fatal("a refused decision changed the approval")
	}
	assertSideRouteStatus(t, "approver ledger:write decide", f.call(t, http.MethodPost, decide, f.approver["token ledger:write"], map[string]any{"decision": "approved"}), http.StatusOK)
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_approvals WHERE id = ? AND status = 'approved'", id); n != 1 {
		t.Fatal("the approver's ledger:write token did not decide the approval")
	}
}

func TestScopedCredentialScheduledTasksNeedTheTableScope(t *testing.T) {
	f := newScopedRoutesFixture(t)
	onRecord := map[string]any{"kind": "reminder", "title": "chase-rent-marker", "table": "ledger", "row_id": "1", "run_at": "2h"}
	personal := map[string]any{"kind": "reminder", "title": "personal-marker", "run_at": "2h"}

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" POST /api/_scheduled", f.call(t, http.MethodPost, "/api/_scheduled", cred, onRecord), "ledger:write")
		assertScopeRefusal(t, name+" POST a reminder naming no table", f.call(t, http.MethodPost, "/api/_scheduled", cred, personal), "names no table")
	}
	assertScopeRefusal(t, "ledger:read POST /api/_scheduled", f.call(t, http.MethodPost, "/api/_scheduled", f.owner["token ledger:read"], onRecord), "ledger:write")
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_scheduled_tasks"); n != 0 {
		t.Fatalf("refused requests stored %d tasks", n)
	}
	created := f.call(t, http.MethodPost, "/api/_scheduled", f.owner["token ledger:write"], onRecord)
	assertSideRouteStatus(t, "ledger:write POST /api/_scheduled", created, http.StatusOK)
	recordTask := responseID(t, created)
	created = f.call(t, http.MethodPost, "/api/_scheduled", f.owner["sign-in"], personal)
	assertSideRouteStatus(t, "sign-in POST a reminder naming no table", created, http.StatusOK)
	personalTask := responseID(t, created)
	assertSideRouteStatus(t, "API token * POST a reminder naming no table", f.call(t, http.MethodPost, "/api/_scheduled", f.owner["token *"], personal), http.StatusOK)

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" GET ?table=ledger", f.call(t, http.MethodGet, "/api/_scheduled?table=ledger", cred, nil), "ledger:read")
		all := f.call(t, http.MethodGet, "/api/_scheduled", cred, nil)
		assertSideRouteStatus(t, name+" GET /api/_scheduled", all, http.StatusOK)
		if strings.Contains(all.Body.String(), "marker") {
			t.Errorf("%s lists tasks outside its scopes: %s", name, all.Body.String())
		}
		assertScopeRefusal(t, name+" DELETE the ledger task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", recordTask), cred, nil), "ledger:write")
		assertScopeRefusal(t, name+" DELETE the personal task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", personalTask), cred, nil), "names no table")
		// An id that is not the caller's task answers as before.
		assertSideRouteStatus(t, name+" DELETE an unknown task", f.call(t, http.MethodDelete, "/api/_scheduled/99999", cred, nil), http.StatusNotFound)
	}
	for _, path := range []string{"/api/_scheduled?table=ledger", "/api/_scheduled"} {
		rec := f.call(t, http.MethodGet, path, f.owner["token ledger:read"], nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "chase-rent-marker") || strings.Contains(rec.Body.String(), "personal-marker") {
			t.Errorf("ledger:read GET %s = %d %s, want the ledger task alone", path, rec.Code, rec.Body.String())
		}
	}
	for name, cred := range f.unscoped() {
		rec := f.call(t, http.MethodGet, "/api/_scheduled", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "chase-rent-marker") || !strings.Contains(rec.Body.String(), "personal-marker") {
			t.Errorf("%s GET /api/_scheduled = %d %s, want both tasks", name, rec.Code, rec.Body.String())
		}
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE id IN (?, ?) AND status = 'pending'", recordTask, personalTask); n != 2 {
		t.Fatal("a refused cancel changed a task")
	}
	assertScopeRefusal(t, "ledger:read DELETE the ledger task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", recordTask), f.owner["token ledger:read"], nil), "ledger:write")
	assertSideRouteStatus(t, "ledger:write DELETE the ledger task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", recordTask), f.owner["token ledger:write"], nil), http.StatusOK)
	assertSideRouteStatus(t, "sign-in DELETE the personal task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", personalTask), f.owner["sign-in"], nil), http.StatusOK)
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE id IN (?, ?) AND status = 'cancelled'", recordTask, personalTask); n != 2 {
		t.Fatal("the allowed cancels did not cancel both tasks")
	}
}

func TestScopedCredentialSavedViewsNeedTheViewTableScope(t *testing.T) {
	f := newScopedRoutesFixture(t)
	ledgerView := map[string]any{"name": "ledger-view-marker", "spec": map[string]any{"table": "ledger"}}

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" POST /api/_query/views", f.call(t, http.MethodPost, "/api/_query/views", cred, ledgerView), "ledger:write")
		assertScopeRefusal(t, name+" POST a view naming no table", f.call(t, http.MethodPost, "/api/_query/views", cred, map[string]any{"name": "blank", "spec": map[string]any{}}), "names no table")
	}
	assertScopeRefusal(t, "ledger:read POST /api/_query/views", f.call(t, http.MethodPost, "/api/_query/views", f.owner["token ledger:read"], ledgerView), "ledger:write")
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_saved_views"); n != 0 {
		t.Fatalf("refused requests stored %d views", n)
	}
	created := f.call(t, http.MethodPost, "/api/_query/views", f.owner["token ledger:write"], ledgerView)
	assertSideRouteStatus(t, "ledger:write POST /api/_query/views", created, http.StatusOK)
	view := responseID(t, created)
	for name, cred := range f.unscoped() {
		assertSideRouteStatus(t, name+" POST a notes view", f.call(t, http.MethodPost, "/api/_query/views", cred, map[string]any{"name": "notes-view-marker", "spec": map[string]any{"table": "notes"}}), http.StatusOK)
		assertSideRouteStatus(t, name+" POST a view naming no table", f.call(t, http.MethodPost, "/api/_query/views", cred, map[string]any{"name": "blank-view-marker", "spec": map[string]any{}}), http.StatusOK)
	}

	lists := func(cred string) string {
		rec := f.call(t, http.MethodGet, "/api/_query/views", cred, nil)
		assertSideRouteStatus(t, "GET /api/_query/views", rec, http.StatusOK)
		return rec.Body.String()
	}
	for name, cred := range f.without() {
		if got := lists(cred); !strings.Contains(got, "notes-view-marker") || strings.Contains(got, "ledger-view-marker") || strings.Contains(got, "blank-view-marker") {
			t.Errorf("%s lists %s, want the notes views alone", name, got)
		}
		assertScopeRefusal(t, name+" DELETE the ledger view", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_query/views/%d", view), cred, nil), "ledger:write")
	}
	if got := lists(f.owner["token ledger:read"]); !strings.Contains(got, "ledger-view-marker") || strings.Contains(got, "notes-view-marker") {
		t.Errorf("ledger:read lists %s, want the ledger view alone", got)
	}
	for name, cred := range f.unscoped() {
		if got := lists(cred); !strings.Contains(got, "ledger-view-marker") || !strings.Contains(got, "notes-view-marker") || !strings.Contains(got, "blank-view-marker") {
			t.Errorf("%s lists %s, want every view", name, got)
		}
	}
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_saved_views WHERE id = ?", view); n != 1 {
		t.Fatal("a refused delete removed the view")
	}
	assertSideRouteStatus(t, "ledger:write DELETE the ledger view", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_query/views/%d", view), f.owner["token ledger:write"], nil), http.StatusOK)
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_saved_views WHERE id = ?", view); n != 0 {
		t.Fatal("the ledger:write token did not delete the view")
	}
}

func TestScopedCredentialPresenceNeedsTheRoomTableScope(t *testing.T) {
	f := newScopedRoutesFixture(t)
	join := func(slug string) map[string]any { return map[string]any{"slug": slug, "action": "join"} }

	for name, cred := range f.without() {
		assertScopeRefusal(t, name+" GET a declared room", f.call(t, http.MethodGet, "/api/_presence?slug=huddle-7", cred, nil), "room_members:read")
		assertScopeRefusal(t, name+" join a declared room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", cred, join("huddle-7")), "room_members:write")
		assertScopeRefusal(t, name+" GET an undeclared room", f.call(t, http.MethodGet, "/api/_presence?slug=lobby", cred, nil), "names no table")
		assertScopeRefusal(t, name+" join an undeclared room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", cred, join("lobby")), "names no table")
		assertScopeRefusal(t, name+" leave a declared room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", cred, map[string]any{"slug": "huddle-7", "action": "leave"}), "room_members:write")
	}
	assertScopeRefusal(t, "room_members:read join", f.call(t, http.MethodPost, "/api/_presence/heartbeat", f.owner["token room_members:read"], join("huddle-7")), "room_members:write")
	assertScopeRefusal(t, "room_members:write GET an undeclared room", f.call(t, http.MethodGet, "/api/_presence?slug=lobby", f.owner["token room_members:write"], nil), "names no table")
	if n := f.count(t, "SELECT COUNT(*) FROM _benmore_presence"); n != 0 {
		t.Fatalf("refused heartbeats stored %d presence rows", n)
	}

	assertSideRouteStatus(t, "room_members:write join", f.call(t, http.MethodPost, "/api/_presence/heartbeat", f.owner["token room_members:write"], join("huddle-7")), http.StatusOK)
	rec := f.call(t, http.MethodGet, "/api/_presence?slug=huddle-7", f.owner["token room_members:read"], nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Errorf("room_members:read GET the room = %d %s, want its one member", rec.Code, rec.Body.String())
	}
	for name, cred := range f.unscoped() {
		assertSideRouteStatus(t, name+" join an undeclared room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", cred, join("lobby")), http.StatusOK)
		rec := f.call(t, http.MethodGet, "/api/_presence?slug=lobby", cred, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
			t.Errorf("%s GET an undeclared room = %d %s, want its one member", name, rec.Code, rec.Body.String())
		}
		assertSideRouteStatus(t, name+" GET a declared room", f.call(t, http.MethodGet, "/api/_presence?slug=huddle-7", cred, nil), http.StatusOK)
	}
}

// Billing and the passkey list are the account's own, like its sessions and
// tokens: no scope names them, so a narrowed credential is refused whatever
// its scopes.
func TestScopedCredentialCannotReadBillingOrPasskeys(t *testing.T) {
	f := newScopedRoutesFixture(t)
	crudScopeMustExec(t, f.app.DB, `INSERT INTO _benmore_subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, plan) VALUES (1, 'customer-marker', 'subscription-marker', 'active', 'pro-plan-marker')`)
	crudScopeMustExec(t, f.app.DB, `INSERT INTO _benmore_passkeys (user_id, credential_id, public_key, alg, name) VALUES (1, 'cred-marker', x'00', -7, 'laptop-key-marker')`)
	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/_billing/me"},
		{http.MethodPost, "/api/_billing/portal"},
		{http.MethodGet, "/api/_auth/passkeys"},
	}
	scoped := f.without()
	scoped["API token ledger:write"] = f.owner["token ledger:write"]
	for name, cred := range scoped {
		for _, route := range routes {
			rec := f.call(t, route.method, route.path, cred, nil)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "account management requires a full-access sign-in") || strings.Contains(rec.Body.String(), "marker") {
				t.Errorf("%s %s %s = %d %s, want the account-management refusal", name, route.method, route.path, rec.Code, rec.Body.String())
			}
		}
	}
	for name, cred := range f.unscoped() {
		if rec := f.call(t, http.MethodGet, "/api/_billing/me", cred, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pro-plan-marker") {
			t.Errorf("%s GET /api/_billing/me = %d %s, want the subscription", name, rec.Code, rec.Body.String())
		}
		if rec := f.call(t, http.MethodGet, "/api/_auth/passkeys", cred, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "laptop-key-marker") {
			t.Errorf("%s GET /api/_auth/passkeys = %d %s, want the passkey", name, rec.Code, rec.Body.String())
		}
		// No Stripe key in the fixture: the request gets as far as it did.
		if rec := f.call(t, http.MethodPost, "/api/_billing/portal", cred, nil); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s POST /api/_billing/portal = %d %s, want the 503 for the missing key", name, rec.Code, rec.Body.String())
		}
	}
}

// Private upload serving and image transforms take no session at all: the
// signed link is the credential, and signing one already asks the owning
// record's read scope. Pinned here so the three stay that way.
func TestPrivateUploadRoutesDoNotAnswerToASessionAlone(t *testing.T) {
	f := newScopedRoutesFixture(t)
	const file = "/uploads/private/receipt.png"
	every := map[string]string{"API token ledger:read": f.owner["token ledger:read"]}
	for name, cred := range f.without() {
		every[name] = cred
	}
	for name, cred := range f.unscoped() {
		every[name] = cred
	}
	for name, cred := range every {
		assertSideRouteStatus(t, name+" GET "+file, f.call(t, http.MethodGet, file, cred, nil), http.StatusForbidden)
		assertSideRouteStatus(t, name+" transform "+file, f.call(t, http.MethodGet, "/api/_images/transform?src="+file, cred, nil), http.StatusForbidden)
	}
	sign := "/api/_signed_url?path=private/receipt.png&record_table=ledger&record_id=1"
	for name, cred := range f.without() {
		assertSideRouteStatus(t, name+" sign the ledger row's file", f.call(t, http.MethodGet, sign, cred, nil), http.StatusForbidden)
	}
	rec := f.call(t, http.MethodGet, sign, f.owner["token ledger:read"], nil)
	assertSideRouteStatus(t, "ledger:read sign the ledger row's file", rec, http.StatusOK)
	var signed struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &signed); err != nil || signed.Path == "" {
		t.Fatalf("no signed path in %s", rec.Body.String())
	}
	out := f.call(t, http.MethodGet, signed.Path, "", nil)
	if out.Code != http.StatusOK || out.Body.String() != "not really a png" {
		t.Errorf("the signed link, with no credential, = %d %q; want the file", out.Code, out.Body.String())
	}
}

// A wildcard resource (*:read, *:write) covers every name, the entries that
// name no table included, and still holds its action limit.
func TestScopedCredentialWildcardResourceCoversUnnamedEntries(t *testing.T) {
	f := newScopedRoutesFixture(t)
	read, write := f.owner["token *:read"], f.owner["token *:write"]
	personal := map[string]any{"kind": "reminder", "title": "personal-marker", "run_at": "2h"}
	blank := map[string]any{"name": "blank-view-marker", "spec": map[string]any{}}

	assertScopeRefusal(t, "*:read POST a reminder", f.call(t, http.MethodPost, "/api/_scheduled", read, personal), "names no table")
	assertScopeRefusal(t, "*:read POST a view", f.call(t, http.MethodPost, "/api/_query/views", read, blank), "names no table")
	assertScopeRefusal(t, "*:read join a room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", read, map[string]any{"slug": "lobby", "action": "join"}), "names no table")
	assertSideRouteStatus(t, "*:write POST a reminder", f.call(t, http.MethodPost, "/api/_scheduled", write, personal), http.StatusOK)
	assertSideRouteStatus(t, "*:write POST a view", f.call(t, http.MethodPost, "/api/_query/views", write, blank), http.StatusOK)
	assertSideRouteStatus(t, "*:write join a room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", write, map[string]any{"slug": "lobby", "action": "join"}), http.StatusOK)
	for path, want := range map[string]string{
		"/api/_scheduled":           "personal-marker",
		"/api/_query/views":         "blank-view-marker",
		"/api/_presence?slug=lobby": `"count":1`,
	} {
		rec := f.call(t, http.MethodGet, path, read, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("*:read GET %s = %d %s, want %s", path, rec.Code, rec.Body.String(), want)
		}
	}
	// Still no account route: no scope names one.
	if rec := f.call(t, http.MethodGet, "/api/_auth/passkeys", f.owner["token *:read"], nil); rec.Code != http.StatusForbidden {
		t.Errorf("*:read GET /api/_auth/passkeys = %d, want 403", rec.Code)
	}
}

// Role scopes narrow the generated API for every session of an app with a
// roles: block. They decide nothing on these routes: the new check is for
// scoped credentials only, or a capability-only roles: block (no table
// named) would have cut every signed-in user off them.
func TestRoleScopesDoNotGateSideRoutesForSignIns(t *testing.T) {
	f := newScopedRoutesFixtureWith(t, &RolesConfig{Roles: map[string]RoleDef{"user": {Scopes: "app:use"}}})
	signIn := f.owner["sign-in"]
	assertScopeRefusal(t, "control: sign-in GET /api/ledger", f.call(t, http.MethodGet, "/api/ledger", signIn, nil), "ledger:read")
	created := f.call(t, http.MethodPost, "/api/_scheduled", signIn, map[string]any{"kind": "reminder", "title": "chase-rent-marker", "table": "ledger", "row_id": "1", "run_at": "2h"})
	assertSideRouteStatus(t, "sign-in POST /api/_scheduled", created, http.StatusOK)
	for path, want := range map[string]string{
		"/api/_scheduled?table=ledger":          "chase-rent-marker",
		"/api/_scheduled":                       "chase-rent-marker",
		"/api/_approvals?table=ledger&row_id=1": `"approvals"`,
		"/api/_approvals":                       `"approvals"`,
		"/api/_query/views":                     `"views"`,
		"/api/_presence?slug=lobby":             `"count":0`,
		"/api/_billing/me":                      `"status":"none"`,
		"/api/_auth/passkeys":                   `"passkeys"`,
	} {
		rec := f.call(t, http.MethodGet, path, signIn, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("sign-in GET %s = %d %s, want 200 with %s", path, rec.Code, rec.Body.String(), want)
		}
	}
	assertSideRouteStatus(t, "sign-in POST /api/_query/views", f.call(t, http.MethodPost, "/api/_query/views", signIn, map[string]any{"name": "v", "spec": map[string]any{"table": "ledger"}}), http.StatusOK)
	assertSideRouteStatus(t, "sign-in join a room", f.call(t, http.MethodPost, "/api/_presence/heartbeat", signIn, map[string]any{"slug": "huddle-7", "action": "join"}), http.StatusOK)
	assertSideRouteStatus(t, "sign-in DELETE the task", f.call(t, http.MethodDelete, fmt.Sprintf("/api/_scheduled/%d", responseID(t, created)), signIn, nil), http.StatusOK)
}
