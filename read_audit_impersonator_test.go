//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// supportReadFixture is an app with read audit on, an admin, a member who owns
// one note, and a support (impersonation) session of the admin as the member.
type supportReadFixture struct {
	app                *App
	mux                *http.ServeMux
	adminID, memberID  int64
	adminSID, support  string
	memberSID, noteID  string
	adminEmail, member string
}

func newSupportReadFixture(t *testing.T) *supportReadFixture {
	t.Helper()
	app := newCrudScopeApp(t)
	f := &supportReadFixture{app: app, adminEmail: "admin@example.com", member: "member@example.com", noteID: "50"}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "*"}}
	// An app with an auth section has its sign-in routes, as a loaded app does.
	app.Paths = DiscoverAuthPaths(nil)
	f.mux = buildAppMux(app, true, "http://localhost")
	InitReadAudit(app, true)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	seed := func(email, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	// The fixture's notes belong to user ids 1 and 2: keep both accounts
	// clear of them, so the only note either can read is the one added here.
	mustExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, role, verified) VALUES (1, 'one', 'one@example.com', 'user', 1), (2, 'two', 'two@example.com', 'user', 1)")
	f.adminID, f.memberID = seed(f.adminEmail, "admin"), seed(f.member, "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (%s, %d, 'chart')", f.noteID, f.memberID))
	f.adminSID = CreateSession(app.DB, f.adminID, f.adminEmail, "", time.Hour)
	f.memberSID = CreateSession(app.DB, f.memberID, f.member, "", time.Hour)

	auth := http.NewServeMux()
	RegisterAuthRoutes(auth, app)
	body, _ := json.Marshal(map[string]any{"user_id": f.memberID, "password": fixturePassword})
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(f.adminSID))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: f.adminSID})
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, r)
	var started map[string]any
	json.Unmarshal(w.Body.Bytes(), &started)
	f.support, _ = started["token"].(string)
	if w.Code != http.StatusOK || f.support == "" {
		t.Fatalf("start support session: %d %s", w.Code, w.Body.String())
	}
	return f
}

func (f *supportReadFixture) get(t *testing.T, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	return crudScopeRequest(t, f.mux, http.MethodGet, path, token, nil)
}

// A read made through a support session is recorded as the impersonated
// user's (whose records were read) and names the admin who read them, on
// every read path, as a mutation's audit row does. The read audit had no
// impersonator columns, so an admin's reads of a customer's records looked
// like the customer's own.
func TestReadAuditNamesTheImpersonatingAdmin(t *testing.T) {
	f := newSupportReadFixture(t)
	app := f.app

	// list, read, /api/_query: over HTTP with the support session's token.
	if w := f.get(t, f.support, "/api/notes"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "chart") {
		t.Fatalf("list through the support session: %d %s", w.Code, w.Body.String())
	}
	if w := f.get(t, f.support, "/api/notes/"+f.noteID); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "chart") {
		t.Fatalf("read through the support session: %d %s", w.Code, w.Body.String())
	}
	if w := crudScopeRequest(t, f.mux, http.MethodPost, "/api/_query", f.support, map[string]any{"table": "notes"}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "chart") {
		t.Fatalf("query through the support session: %d %s", w.Code, w.Body.String())
	}
	// versions, include, flow SQL and page queries: the handlers and helpers
	// those paths run, with the session the support token resolves to.
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/notes/"+f.noteID+"/versions", nil)
		r.Header.Set("Authorization", "Bearer "+f.support)
		r.SetPathValue("id", f.noteID)
		return r
	}
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}}); err != nil {
		t.Fatal(err)
	}
	vw := httptest.NewRecorder()
	handleListVersions(vw, req(), app, "notes")
	if vw.Code != http.StatusOK {
		t.Fatalf("versions through the support session: %d %s", vw.Code, vw.Body.String())
	}
	support := getSession(app, req())
	if support == nil || support.UserID != f.memberID || support.ImpersonatorUserID != f.adminID {
		t.Fatalf("support session resolved to %+v", support)
	}
	app.JoinMap = JoinMap{"notes": {"user_id": {Table: "records", Column: "id"}}}
	if err := ResolveIncludes(app, req(), "records", []map[string]any{{"id": f.memberID}}, "notes", support); err != nil {
		t.Fatal(err)
	}
	app.JoinMap = nil
	if err := auditFlowSQLRead(&FlowContext{App: app, Request: req(), Session: support}, "SELECT title FROM notes"); err != nil {
		t.Fatal(err)
	}
	if err := logPageQueryTables(app, req(), []string{"notes"}, support); err != nil {
		t.Fatal(err)
	}
	// A data export is not a read a support session can make at all.
	if w := f.get(t, f.support, "/api/_my-data"); w.Code != http.StatusForbidden {
		t.Fatalf("data export through a support session: %d %s", w.Code, w.Body.String())
	}

	for _, queryType := range []string{"list", "read", "query", "versions", "include", "flow_sql", "page_query"} {
		var n int
		err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_read_audit WHERE table_name = 'notes' AND query_type = ?
			AND user_id = ? AND user_email = ? AND impersonator_user_id = ? AND impersonator_email = ?`,
			queryType, f.memberID, f.member, f.adminID, f.adminEmail).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("%s through the support session: no read-audit row names the admin", queryType)
		}
	}
	var unnamed int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_read_audit WHERE user_id = ? AND COALESCE(impersonator_user_id, 0) = 0`, f.memberID).Scan(&unnamed); err != nil {
		t.Fatal(err)
	}
	if unnamed != 0 {
		t.Fatalf("%d support-session reads recorded as the member's own", unnamed)
	}

	// The member's own read names no one else.
	if w := f.get(t, f.memberSID, "/api/notes/"+f.noteID); w.Code != http.StatusOK {
		t.Fatalf("member's own read: %d %s", w.Code, w.Body.String())
	}
	var ownID int64
	var ownEmail string
	if err := app.DB.QueryRow(`SELECT impersonator_user_id, impersonator_email FROM _benmore_read_audit WHERE user_id = ? ORDER BY id DESC LIMIT 1`, f.memberID).Scan(&ownID, &ownEmail); err != nil {
		t.Fatal(err)
	}
	if ownID != 0 || ownEmail != "" {
		t.Fatalf("the member's own read recorded impersonator %d %q", ownID, ownEmail)
	}

	// GET /api/_audit/reads: an admin sees who read; the account itself sees
	// which events were support reads, without the admin's address or client
	// address.
	history := func(token, query string) []map[string]any {
		w := f.get(t, token, "/api/_audit/reads?"+query)
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != http.StatusOK {
			t.Fatalf("read history: %d %s", w.Code, w.Body.String())
		}
		return rows
	}
	adminView := history(f.adminSID, "table=notes&user_id="+fmt.Sprint(f.memberID))
	if len(adminView) != 8 {
		t.Fatalf("admin's view of the member's read history: %d rows, want 8: %v", len(adminView), adminView)
	}
	named := 0
	for _, row := range adminView {
		if row["impersonator_user_id"] == float64(f.adminID) && row["impersonator_email"] == f.adminEmail && row["user_email"] == f.member {
			named++
		}
	}
	if named != 7 {
		t.Fatalf("admin's view names the impersonator on %d rows, want 7: %v", named, adminView)
	}
	ownView := history(f.memberSID, "table=notes")
	if len(ownView) != 8 {
		t.Fatalf("member's own read history: %d rows, want 8", len(ownView))
	}
	for _, row := range ownView {
		supportRead := row["impersonator_user_id"] == float64(f.adminID)
		switch {
		case supportRead && (row["impersonator_email"] != "" || row["client_ip"] != nil):
			t.Fatalf("the member's own history shows the support admin's address: %v", row)
		case !supportRead && (row["impersonator_user_id"] != float64(0) || row["client_ip"] == nil):
			t.Fatalf("the member's own read lost its client address or gained an impersonator: %v", row)
		}
	}
}

// The impersonator columns reach a database from before them by ADD COLUMN,
// which leaves the append-only triggers of a compliance: hipaa app as they
// were: rows from before keep reading 0 and the empty string, new rows carry the admin, and
// no existing row can be changed.
func TestReadAuditImpersonatorColumnsKeepAppendOnlyTriggers(t *testing.T) {
	db := appendOnlyAuditTestDB(t) // the table as an older runtime made it, triggers installed
	mustExec(t, db, `INSERT INTO _benmore_read_audit (table_name, row_id, query_type, user_id, user_email) VALUES ('notes', '1', 'read', 7, 'old@example.com')`)
	for pass := 0; pass < 2; pass++ { // the second start changes nothing
		EnsureReadAuditTable(db)
	}
	cols, err := GetTableColumns(db, "_benmore_read_audit")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"client_ip", "impersonator_user_id", "impersonator_email"} {
		if !hasColumnInList(cols, name) {
			t.Fatalf("column %s was not added", name)
		}
	}
	for _, kind := range auditAppendOnlyKinds {
		var stored string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?`, auditTriggerName("_benmore_read_audit", kind)).Scan(&stored); err != nil {
			t.Fatalf("append-only trigger %s is gone after the migration: %v", kind, err)
		}
		if stored != auditTriggerSQL("_benmore_read_audit", kind) {
			t.Fatalf("append-only trigger %s changed: %q", kind, stored)
		}
	}
	buffer := &readAuditBuffer{db: db}
	if err := buffer.write([]readAuditEntry{{Table: "notes", RowID: "1", QueryType: "read", UserID: 7, Email: "old@example.com", ImpersonatorID: 3, ImpersonatorEmail: "admin@example.com"}}); err != nil {
		t.Fatal(err)
	}
	var oldID, newID int64
	var oldEmail, newEmail string
	if err := db.QueryRow(`SELECT impersonator_user_id, impersonator_email FROM _benmore_read_audit WHERE id = 1`).Scan(&oldID, &oldEmail); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT impersonator_user_id, impersonator_email FROM _benmore_read_audit WHERE id = 2`).Scan(&newID, &newEmail); err != nil {
		t.Fatal(err)
	}
	if oldID != 0 || oldEmail != "" || newID != 3 || newEmail != "admin@example.com" {
		t.Fatalf("old row impersonator %d %q, new row %d %q", oldID, oldEmail, newID, newEmail)
	}
	for _, stmt := range []string{
		`UPDATE _benmore_read_audit SET impersonator_user_id = 0, impersonator_email = '' WHERE id = 2`,
		`DELETE FROM _benmore_read_audit WHERE id = 2`,
	} {
		if _, err := db.Exec(stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v, want the append-only refusal", stmt, err)
		}
	}
}

// The admin panel shows the audit tables and the credential tables and never
// writes them. Its create route stored hand-made audit rows (someone else's
// delete, a read that never happened) and session rows; its pages offered
// Create, Edit and Delete on them.
func TestAdminPanelNeverWritesAuditOrCredentialTables(t *testing.T) {
	f := newSupportReadFixture(t)
	app := f.app
	EnsureAPITokensTable(app.DB)
	if !app.FeatureEnabled("admin") {
		t.Fatal("fixture has no admin panel")
	}
	LogAudit(app, "insert", "notes", f.noteID, GetSessionFromDB(app.DB, f.memberSID), nil, map[string]any{"title": "chart"})
	f.get(t, f.memberSID, "/api/notes/"+f.noteID) // one read-audit row
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+f.adminSID)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	count := func(table string) (n int) {
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(table)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	forged := map[string]url.Values{
		"_benmore_audit_log":  {"action": {"delete"}, "table_name": {"notes"}, "row_id": {f.noteID}, "user_email": {f.member}},
		"_benmore_read_audit": {"table_name": {"notes"}, "row_id": {f.noteID}, "query_type": {"read"}, "user_email": {f.member}},
		"_benmore_sessions":   {"email": {f.member}},
		"_benmore_api_tokens": {"name": {"mine"}, "token_hash": {"abc"}, "scopes": {"*"}},
		// SQLite reads this as the same table.
		"_BENMORE_AUDIT_LOG": {"action": {"delete"}, "table_name": {"notes"}, "row_id": {f.noteID}, "user_email": {f.member}},
	}
	for table, form := range forged {
		before := count(table)
		for _, action := range []string{"create", "update/1", "delete/1"} {
			w := post("/_admin/api/"+table+"/"+action, form)
			var body map[string]any
			json.Unmarshal(w.Body.Bytes(), &body)
			msg, _ := body["message"].(string)
			docs := "auth.credential_limits"
			if strings.Contains(strings.ToLower(table), "audit") {
				docs = "audit.append_only"
			}
			if w.Code != http.StatusForbidden || body["error"] != "admin_table_read_only" || body["docs"] != docs || !strings.Contains(msg, table) || !strings.Contains(msg, "never writes it") {
				t.Errorf("POST /_admin/api/%s/%s: %d %s, want a 403 admin_table_read_only (docs %s) that says the panel never writes the table", table, action, w.Code, w.Body.String(), docs)
			}
		}
		if after := count(table); after != before {
			t.Errorf("%s: %d rows after the refused writes, was %d", table, after, before)
		}
		for _, page := range []string{"/_admin/" + table, "/_admin/" + table + "/1"} {
			w := f.get(t, f.adminSID, page)
			if w.Code == http.StatusNotFound && page != "/_admin/"+table && !strings.Contains(strings.ToLower(table), "audit") {
				continue // no row 1: session ids are hashes, the fixture holds no API token
			}
			html := w.Body.String()
			if w.Code != http.StatusOK || !strings.Contains(html, "never writes it") {
				t.Errorf("GET %s: %d, want the page with its read-only note", page, w.Code)
			}
			for _, control := range []string{"/_admin/api/", "admin-create", "<form method=\"POST\"", "hx-post", "Save Changes"} {
				if strings.Contains(html, control) {
					t.Errorf("GET %s still renders a write control (%s)", page, control)
				}
			}
		}
	}
	// The stored audit trail is what the framework wrote, nothing else.
	var forgedRows int
	app.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'delete') + (SELECT COUNT(*) FROM _benmore_sessions WHERE id IS NULL)`).Scan(&forgedRows)
	if forgedRows != 0 {
		t.Fatalf("%d hand-made audit or session rows were stored", forgedRows)
	}

	// An app table keeps its controls, and the panel still writes it.
	page := f.get(t, f.adminSID, "/_admin/notes").Body.String()
	for _, control := range []string{"/_admin/api/notes/create", "admin-create", "/_admin/api/notes/delete/" + f.noteID} {
		if !strings.Contains(page, control) {
			t.Errorf("/_admin/notes lost its %s control", control)
		}
	}
	if w := post("/_admin/api/notes/create", url.Values{"title": {"made in the panel"}}); w.Code != http.StatusOK {
		t.Fatalf("panel create on an app table: %d %s", w.Code, w.Body.String())
	}
	if w := post("/_admin/api/notes/update/"+f.noteID, url.Values{"title": {"edited in the panel"}}); w.Code != http.StatusOK {
		t.Fatalf("panel update on an app table: %d %s", w.Code, w.Body.String())
	}
	var title string
	app.DB.QueryRow("SELECT title FROM notes WHERE id = ?", f.noteID).Scan(&title)
	if title != "edited in the panel" {
		t.Fatalf("panel update did not reach the app table: %q", title)
	}
}
