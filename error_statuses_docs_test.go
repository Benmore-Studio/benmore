//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Refusals whose status or body differed from the one the reference states.
// Each test names the documented answer it holds the route to.

func statusBody(w *httptest.ResponseRecorder) (int, map[string]any) {
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// newUnscopedParentApp is an app whose `vendors` table has no owner or tenant
// column (any caller may reference any vendor), whose `projects` are owned,
// and whose `requests` point at both. Foreign keys are enforced, as in a
// served app.
func newUnscopedParentApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	EnsureSessionsTable(db)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureAuditLogTable(db)
	EnsureLocksTable(db)
	EnsurePermissionsTable(db)
	for _, q := range []string{
		"CREATE TABLE vendors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)",
		"CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)",
		"CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, vendor_id INTEGER REFERENCES vendors(id), project_id INTEGER REFERENCES projects(id), title TEXT)",
		"INSERT INTO vendors (id, name) VALUES (1, 'acme')",
	} {
		mustExec(t, db, q)
	}
	reloadGateSchema(t, app)
	return app
}

// scoping.foreign_keys: "A missing and a forbidden parent both answer 422
// `<column> references a record that does not exist or is not accessible`".
// A parent table with no row scope skipped the visibility check, so a missing
// parent there reached SQLite's constraint and came back as 400 "Insert
// failed: a referenced record does not exist or is not accessible", without
// the column. Every create and update path now answers the documented 422.
func TestMissingParentInUnscopedTableAnswers422(t *testing.T) {
	app := newUnscopedParentApp(t)
	uidA, _ := gateUser(t, app, "a@example.com")
	uidB, sidB := gateUser(t, app, "b@example.com")
	mustExec(t, app.DB, "INSERT INTO projects (id, user_id, name) VALUES (1, "+strconv.FormatInt(uidA, 10)+", 'A'), (2, "+strconv.FormatInt(uidB, 10)+", 'B')")
	mustExec(t, app.DB, "INSERT INTO requests (id, user_id, vendor_id, project_id, title) VALUES (10, "+strconv.FormatInt(uidB, 10)+", 1, 2, 'mine')")
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('root', 'root@example.com', 'admin', 1)")
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	adminSID := CreateSession(app.DB, adminID, "root@example.com", "", time.Hour)

	const vendorRefusal = "vendor_id references a record that does not exist or is not accessible"
	const projectRefusal = "project_id references a record that does not exist or is not accessible"
	transaction := func(sid, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://app.example.com/api/_transaction", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handleTransaction(w, r, app)
		return w
	}

	// The forbidden and the missing parent of a scoped table: the documented
	// answer, which the unscoped table must match.
	for name, body := range map[string]string{"forbidden": `{"project_id":1,"title":"x"}`, "missing": `{"project_id":9999,"title":"x"}`} {
		code, got := statusBody(gateCall(app, handleCreate, "requests", "POST", "/api/requests", "application/json", body, sidB))
		if code != http.StatusUnprocessableEntity || got["error"] != projectRefusal {
			t.Fatalf("control, %s scoped parent: %d %v", name, code, got)
		}
	}

	calls := map[string]*httptest.ResponseRecorder{
		"create":             gateCall(app, handleCreate, "requests", "POST", "/api/requests", "application/json", `{"vendor_id":999,"title":"lost"}`, sidB),
		"create as admin":    gateCall(app, handleCreate, "requests", "POST", "/api/requests", "application/json", `{"vendor_id":999,"title":"lost"}`, adminSID),
		"batch create":       gateCall(app, handleBatchCreate, "requests", "POST", "/api/requests/batch", "application/json", `[{"vendor_id":999,"title":"lost"}]`, sidB),
		"update":             gateCall(app, handleUpdate, "requests", "PATCH", "/api/requests/10", "application/json", `{"vendor_id":999}`, sidB),
		"batch update":       gateCall(app, handleBatchUpdate, "requests", "PATCH", "/api/requests/batch", "application/json", `{"ids":[10],"fields":{"vendor_id":"999"}}`, sidB),
		"transaction insert": transaction(sidB, `{"operations":[{"table":"requests","action":"insert","data":{"vendor_id":999,"title":"lost"}}]}`),
		"transaction update": transaction(sidB, `{"operations":[{"table":"requests","action":"update","id":10,"data":{"vendor_id":999}}]}`),
	}
	for name, w := range calls {
		code, got := statusBody(w)
		text, _ := got["error"].(string)
		if code != http.StatusUnprocessableEntity || !strings.HasSuffix(text, vendorRefusal) || strings.Contains(text, "FOREIGN KEY") {
			t.Errorf("%s naming a missing vendor: %d %s, want 422 %q", name, code, w.Body.String(), vendorRefusal)
		}
	}
	// The single-row paths answer exactly the documented sentence.
	for _, name := range []string{"create", "create as admin", "update", "batch update"} {
		if _, got := statusBody(calls[name]); got["error"] != vendorRefusal {
			t.Errorf("%s: error = %v, want %q", name, got["error"], vendorRefusal)
		}
	}
	// NDJSON ingest counts the row as an error and stores nothing.
	ingest := gateCall(app, handleStreamingIngest, "requests", "POST", "/api/requests/ingest", "application/x-ndjson", `{"vendor_id":999,"title":"lost"}`+"\n", sidB)
	if _, got := statusBody(ingest); got["ingested"] != float64(0) || got["errors"] != float64(1) {
		t.Errorf("ingest of a row naming a missing vendor: %d %s, want ingested 0, errors 1", ingest.Code, ingest.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM requests WHERE vendor_id = 999 OR title = 'lost'"); n != "0" {
		t.Fatalf("%s rows were written with a missing vendor", n)
	}
	if got := gateScalar(t, app, "SELECT vendor_id FROM requests WHERE id = 10"); got != "1" {
		t.Fatalf("re-point to a missing vendor applied: vendor_id = %s", got)
	}

	// An existing vendor is accepted, by create and by re-point.
	mustExec(t, app.DB, "INSERT INTO vendors (id, name) VALUES (2, 'globex')")
	if w := gateCall(app, handleCreate, "requests", "POST", "/api/requests", "application/json", `{"vendor_id":1,"project_id":2,"title":"kept"}`, sidB); w.Code != http.StatusOK {
		t.Fatalf("create naming an existing vendor: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleUpdate, "requests", "PATCH", "/api/requests/10", "application/json", `{"vendor_id":2}`, sidB); w.Code != http.StatusOK {
		t.Fatalf("re-point to an existing vendor: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT vendor_id FROM requests WHERE id = 10"); got != "2" {
		t.Fatalf("re-point to an existing vendor not applied: vendor_id = %s", got)
	}
}

// locks.not_found: "PATCH, DELETE, batch update/delete and /api/_transaction
// answer 409 for a locked row only when the caller may edit/delete it; a
// locked row outside the caller's scope is 404 ..., like an unlocked one".
// The transaction answered 400 for the row PATCH and DELETE answer 404 for.
func TestTransactionRowOutsideScopeAnswers404LikePatch(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	groupA := createCrudScopeSession(t, app, "group-a@example.com", "user", "org-a", "")

	patch := crudScopeRequest(t, mux, http.MethodPatch, "/api/records/2", groupA, map[string]any{"title": "leak"})
	patchCode, patchBody := statusBody(patch)
	if patchCode != http.StatusNotFound || patchBody["error"] != "not found or not authorized" {
		t.Fatalf("control, PATCH of another tenant's row: %d %s", patch.Code, patch.Body.String())
	}
	for _, op := range []map[string]any{
		{"table": "records", "action": "update", "id": 2, "data": map[string]any{"title": "leak"}},
		{"table": "records", "action": "delete", "id": 2},
		{"table": "records", "action": "update", "id": 9999, "data": map[string]any{"title": "leak"}},
	} {
		w := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", groupA, map[string]any{"operations": []any{op}})
		code, body := statusBody(w)
		if code != patchCode || body["error"] != patchBody["error"] {
			t.Errorf("transaction %v on row %v: %d %s, want %d %v as PATCH answers", op["action"], op["id"], w.Code, w.Body.String(), patchCode, patchBody)
		}
	}
	// A refused operation rolls back the ones before it.
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", groupA, map[string]any{"operations": []any{
		map[string]any{"table": "records", "action": "update", "id": 1, "data": map[string]any{"title": "half"}},
		map[string]any{"table": "records", "action": "update", "id": 2, "data": map[string]any{"title": "leak"}},
	}})
	if w.Code != http.StatusNotFound {
		t.Fatalf("transaction with one refused row: %d %s", w.Code, w.Body.String())
	}
	assertRecordTitle(t, app.DB, 1, "a")
	assertRecordTitle(t, app.DB, 2, "b")
	assertRowExists(t, app.DB, "records", 2, true)
}

// auth.credential_limits lists the admin-only management surfaces; a caller
// with no valid credential (signed out, an expired session, a revoked token)
// is unauthenticated there as on every other route (401), and only a
// signed-in caller who is not an admin console is forbidden (403). They
// answered 403 `admin required` to both.
func TestAdminManagementRoutesAnswer401WithoutACredential(t *testing.T) {
	app, _ := newCrudScopeTestApp(t)
	EnsureAuditLogTable(app.DB)
	EnsureAPITokensTable(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureJobsTable(app.DB)
	EnsureFeedbackTables(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuditAPI(mux, app)
	RegisterJobsAPI(mux, app)
	registerCustomFieldRoutes(mux, app)
	EnsureAnalyticsTables(app.DB)
	registerAnalyticsRoutes(mux, app)
	RegisterUsageAPI(mux, app)
	registerDemoRoutes(mux, app, "demo-"+generateToken(6))
	RegisterAuthRoutes(mux, app)
	RegisterBlindIndexRoutes(mux, app)
	RegisterEncryptionRotationRoute(mux, app)
	RegisterRoleRoutes(mux, app)
	registerAppMCPTelemetryRoute(mux, app)

	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	expired := createCrudScopeSession(t, app, "gone@example.com", "admin", "", "")
	crudScopeMustExec(t, app.DB, "UPDATE _benmore_sessions SET expires_at = datetime('now', '-1 hour') WHERE id = '"+sessionStorageKey(expired)+"'")
	revoked := auditToken(t, app, admin, "*")
	crudScopeMustExec(t, app.DB, "DELETE FROM _benmore_api_tokens WHERE token_hash = '"+hashToken(revoked)+"'")

	routes := []struct{ method, path string }{
		{"GET", "/api/_audit"},
		{"GET", "/api/_jobs"},
		{"GET", "/api/_jobs/1"},
		{"POST", "/api/_jobs/1/retry"},
		{"DELETE", "/api/_jobs/1"},
		{"GET", "/api/_schema/notes/fields"},
		{"POST", "/api/_schema/notes/fields"},
		{"DELETE", "/api/_schema/notes/fields/extra"},
		{"GET", "/api/_analytics/summary"},
		{"GET", "/api/_analytics/funnels"},
		{"POST", "/api/_analytics/funnel"},
		{"DELETE", "/api/_analytics/funnel"},
		{"GET", "/api/_usage/history"},
		{"GET", "/api/_feedback"},
		{"GET", "/api/_feedback/1"},
		{"PATCH", "/api/_feedback/1"},
		{"POST", "/api/_feedback/1/comment"},
		{"POST", "/api/_testing/reset"},
		{"POST", "/api/_internal/blind/backfill"},
		{"POST", "/api/_internal/encryption/rotate"},
		{"GET", "/api/_mcp/telemetry"},
		{"GET", "/api/_auth/roles"},
		{"POST", "/api/_auth/users/1/roles"},
		{"PATCH", "/api/_auth/users/1/roles/editor"},
		{"DELETE", "/api/_auth/users/1/roles/editor"},
		{"POST", "/api/_auth/impersonate"},
		{"POST", "/api/_auth/act_as"},
	}
	for _, route := range routes {
		name := route.method + " " + route.path
		for who, token := range map[string]string{"signed out": "", "expired session": expired, "revoked token": revoked} {
			w := crudScopeRequest(t, mux, route.method, route.path, token, nil)
			code, body := statusBody(w)
			if code != http.StatusUnauthorized || body["error"] != "authentication required" {
				t.Errorf("%s, %s: %d %s, want 401 authentication required", name, who, w.Code, w.Body.String())
			}
		}
		w := crudScopeRequest(t, mux, route.method, route.path, member, nil)
		code, body := statusBody(w)
		text, _ := body["error"].(string)
		if code != http.StatusForbidden || !strings.Contains(text, "admin") {
			t.Errorf("%s, signed-in member: %d %s, want 403 naming the admin requirement", name, w.Code, w.Body.String())
		}
		if w := crudScopeRequest(t, mux, route.method, route.path, admin, nil); w.Code == http.StatusUnauthorized || strings.Contains(w.Body.String(), "admin required") {
			t.Errorf("%s, admin session: %d %s", name, w.Code, w.Body.String())
		}
	}
}

// heldStreamFixture is mfaGateFixture with the realtime handshakes behind the
// account-hold gates, as the server chain puts them.
func heldStreamFixture(t *testing.T) (app *App, handler http.Handler, uid int64, sid, tok string) {
	t.Helper()
	app, _, uid, sid, _, tok = mfaGateFixture(t)
	mux := http.NewServeMux()
	RegisterSSERoutes(mux, app)
	RegisterWebSocketRoutes(mux, app)
	RegisterMFARoutes(mux, app)
	RegisterCRUD(mux, app)
	return app, requestSessionCacheMiddleware(accountHoldMiddleware(mux, app)), uid, sid, tok
}

// mfa.existing_credentials: a held session or token gets 403
// {error: "mfa_enrollment_required", message, redirect} "on every route";
// auth.required_password_change: "APIs return 403 password_change_required".
// GET /sse/events and GET /ws answered 401 `authentication required`, which
// tells a client to sign in again (it is signed in). The handshake now gives
// the documented answer and still opens no stream.
func TestHeldCredentialOnStreamHandshakeGetsTheDocumentedRefusal(t *testing.T) {
	app, handler, uid, sid, tok := heldStreamFixture(t)
	streams := []string{"/sse/events", "/ws"}

	for _, path := range streams {
		w := mfaGateCall{method: "GET", path: path}.serve(handler)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "authentication required") {
			t.Fatalf("control, signed-out %s: %d %s", path, w.Code, w.Body.String())
		}
	}

	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'manager')", uid)
	for _, path := range streams {
		for name, call := range map[string]mfaGateCall{
			"cookie session": {method: "GET", path: path, cookie: sid},
			"api token":      {method: "GET", path: path, bearer: tok},
		} {
			w := call.serve(handler)
			code, body := statusBody(w)
			if code != http.StatusForbidden || body["error"] != "mfa_enrollment_required" || body["redirect"] != "/mfa-setup" || body["message"] == nil {
				t.Errorf("%s of an unenrolled manager on %s: %d %s, want 403 mfa_enrollment_required", name, path, w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "text/event-stream") || w.Code == http.StatusSwitchingProtocols {
				t.Errorf("%s on %s opened a stream for a held credential (%d, %s)", name, path, w.Code, ct)
			}
		}
	}

	// A temporary password holds the account the same way.
	passwordChangeExec(t, app.DB, "DELETE FROM _benmore_user_roles WHERE user_id = ?", uid)
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_change_required = 1 WHERE id = ?", uid)
	for _, path := range streams {
		w := mfaGateCall{method: "GET", path: path, cookie: sid}.serve(handler)
		code, body := statusBody(w)
		if code != http.StatusForbidden || body["error"] != "password_change_required" || body["redirect"] != passwordChangePagePath {
			t.Errorf("temporary-password session on %s: %d %s, want 403 password_change_required", path, w.Code, w.Body.String())
		}
	}
}

// A held API token was told "POST /api/_auth/mfa/setup with your current
// password", and that call answers a token "MFA enrollment requires a
// full-access login session": the advice could not be followed. The refusal
// now tells a token to sign in, and the setup route answers a credential that
// may not enroll 403 (auth.credential_limits: "MFA setup/verify/disable ...
// return 403 for scoped tokens"), keeping 401 for no credential at all.
func TestHeldAPITokenIsToldToSignInAndSetupAnswers403(t *testing.T) {
	app, handler, uid, sid, tok := heldStreamFixture(t)
	scoped := auditToken(t, app, sid, "notes:read")
	setup := `{"password":"` + fixturePassword + `"}`

	// Not held yet: a scoped token is a valid credential that may not enroll.
	for name, bearer := range map[string]string{"scoped token": scoped, "unscoped token": tok} {
		w := mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", bearer: bearer, body: setup}.serve(handler)
		code, body := statusBody(w)
		text, _ := body["error"].(string)
		if code != http.StatusForbidden || !strings.Contains(text, "full-access login session") {
			t.Errorf("MFA setup with a %s: %d %s, want 403", name, w.Code, w.Body.String())
		}
	}
	if w := (mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", body: setup}).serve(handler); w.Code != http.StatusUnauthorized {
		t.Errorf("MFA setup with no credential: %d %s, want 401", w.Code, w.Body.String())
	}

	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'manager')", uid)
	message := func(call mfaGateCall) string {
		w := call.serve(handler)
		code, body := statusBody(w)
		if code != http.StatusForbidden || body["error"] != "mfa_enrollment_required" {
			t.Fatalf("held credential on %s: %d %s", call.path, w.Code, w.Body.String())
		}
		text, _ := body["message"].(string)
		return text
	}
	tokenMessage := message(mfaGateCall{method: "GET", path: "/api/notes", bearer: tok})
	if !strings.Contains(tokenMessage, "API token cannot enroll") || !strings.Contains(strings.ToLower(tokenMessage), "sign in") {
		t.Errorf("held API token is not told to sign in: %q", tokenMessage)
	}
	sessionMessage := message(mfaGateCall{method: "GET", path: "/api/notes", cookie: sid})
	if !strings.Contains(sessionMessage, "POST /api/_auth/mfa/setup with your current password") || strings.Contains(sessionMessage, "API token cannot enroll") {
		t.Errorf("held session lost its enrollment instructions: %q", sessionMessage)
	}
	// The held token still cannot enroll, and is told why with a 403.
	w := mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", bearer: tok, body: setup}.serve(handler)
	if code, body := statusBody(w); code != http.StatusForbidden || !strings.Contains(w.Body.String(), "full-access login session") || body["secret"] != nil {
		t.Errorf("MFA setup with a held API token: %d %s, want 403", w.Code, w.Body.String())
	}
	var secret sql.NullString
	if err := app.DB.QueryRow("SELECT totp_secret FROM _benmore_users WHERE id = ?", uid).Scan(&secret); err != nil || secret.String != "" {
		t.Fatalf("an API token started an enrollment: %q %v", secret.String, err)
	}
	// The held session enrolls as before.
	if w := (mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", cookie: sid, body: setup}).serve(handler); w.Code != http.StatusOK {
		t.Fatalf("held session could not start enrollment: %d %s", w.Code, w.Body.String())
	}
}

// audit.read_coverage: reads of an audited table are recorded on every app
// read surface, the /_admin table pages included. GET /api/_audit returns the
// old and new values of those tables' rows and recorded nothing. It now
// records one event (query_type `audit_log`) per audited table whose rows it
// returned, and under compliance: hipaa refuses the read when the event
// cannot be written.
func TestAuditLogReadIsRecordedInTheReadAudit(t *testing.T) {
	app, _ := newCrudScopeTestApp(t)
	EnsureAuditLogTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "notes"}}
	InitReadAudit(app, true)
	mux := http.NewServeMux()
	RegisterAuditAPI(mux, app)
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	adminID := GetSessionFromDB(app.DB, admin).UserID
	for _, q := range []string{
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES ('update', 'notes', '1', 1, 'a@example.com', '{"title":"before"}', '{"title":"diagnosis"}')`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES ('update', 'notes', '2', 1, 'a@example.com', '{"title":"x"}', '{"title":"y"}')`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email, old_values, new_values) VALUES ('update', 'records', '1', 1, 'a@example.com', '{"title":"a"}', '{"title":"b"}')`,
	} {
		crudScopeMustExec(t, app.DB, q)
	}
	events := func(where string) int {
		t.Helper()
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_read_audit WHERE query_type = 'audit_log' AND "+where, adminID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Only `records` rows come back: that table is not read-audited.
	if w := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit?table=records", admin, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"records"`) {
		t.Fatalf("audit read of an unaudited table: %d %s", w.Code, w.Body.String())
	}
	if n := events("user_id = ?"); n != 0 {
		t.Fatalf("audit read of an unaudited table recorded %d read events", n)
	}

	w := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit", admin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "diagnosis") {
		t.Fatalf("audit read: %d %s", w.Code, w.Body.String())
	}
	if n := events("user_id = ? AND table_name = 'notes' AND user_email = 'admin@example.com'"); n != 1 {
		t.Fatalf("audit read returning notes values recorded %d read events for notes, want 1", n)
	}
	if n := events("user_id = ? AND table_name <> 'notes'"); n != 0 {
		t.Fatalf("audit read recorded %d events for tables that are not read-audited", n)
	}
	// A row filter is kept on the event.
	if w := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit?table=notes&row_id=2", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("filtered audit read: %d %s", w.Code, w.Body.String())
	}
	if n := events("user_id = ? AND table_name = 'notes' AND row_id = '2'"); n != 1 {
		t.Fatalf("filtered audit read recorded %d events for notes row 2, want 1", n)
	}

	// compliance: hipaa fails closed: with no read audit to write to, the
	// values are not returned.
	hipaa := &App{Dir: app.Dir, DB: app.DB, SessionDuration: time.Hour, Tables: app.Tables,
		Design: &DesignConfig{Compliance: complianceHIPAA, Auth: map[string]string{"require_mfa_for_roles": "nobody"}}}
	hipaaMux := http.NewServeMux()
	RegisterAuditAPI(hipaaMux, hipaa)
	w = crudScopeRequest(t, hipaaMux, http.MethodGet, "/api/_audit", admin, nil)
	if w.Code < 500 || strings.Contains(w.Body.String(), "diagnosis") {
		t.Fatalf("hipaa audit read with no read audit to record it: %d %s, want 5xx without values", w.Code, w.Body.String())
	}
}

// auth.password_change documents POST /settings/password {current_password,
// new_password, confirm_password, _csrf}; /login and /signup read the same
// fields from a JSON body and `bm.api.post` always sends JSON. The settings
// forms read form encodings only, so a JSON body answered 400 "All password
// fields are required". The checks are unchanged: CSRF and the current
// password.
func TestSettingsPasswordAcceptsAJSONBody(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	appOAuthEnsureTables(app)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET password_hash = ? WHERE id = ?", string(hash), uid)
	next := "Changed!" + generateToken(6)
	post := func(current, csrf string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"current_password": current, "new_password": next, "confirm_password": next})
		r := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	stored := func() string {
		var h string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", uid).Scan(&h)
		return h
	}

	if w := post(fixturePassword, ""); w.Code != http.StatusForbidden || stored() != string(hash) {
		t.Fatalf("JSON password change without a CSRF token: %d %s", w.Code, w.Body.String())
	}
	w := post("not-the-password", authMintCSRFToken(sid))
	if code, body := statusBody(w); code != http.StatusBadRequest || body["error"] != "Current password is incorrect" || stored() != string(hash) {
		t.Fatalf("JSON password change with a wrong current password: %d %s", w.Code, w.Body.String())
	}
	w = post(fixturePassword, authMintCSRFToken(sid))
	if code, body := statusBody(w); code != http.StatusOK || body["ok"] != true || body["message"] != "Password updated successfully" {
		t.Fatalf("JSON password change: %d %s, want 200 {ok:true}", w.Code, w.Body.String())
	}
	if bcrypt.CompareHashAndPassword([]byte(stored()), []byte(next)) != nil {
		t.Fatal("the new password was not stored")
	}
}

// A JSON body is read into the form only when the request's media type is
// application/json. The Content-Type used to be matched by substring, so
// `text/plain; x=application/json` (a type a cross-site page may send with
// no CORS preflight) was parsed as JSON too.
func TestJSONBodyIsMergedOnlyForTheJSONMediaType(t *testing.T) {
	for contentType, merged := range map[string]bool{
		"application/json":                  true,
		"application/json; charset=utf-8":   true,
		"Application/JSON":                  true,
		"text/plain; x=application/json":    false,
		"text/plain;application/json":       false,
		"application/jsonx":                 false,
		"application/x-www-form-urlencoded": false,
		"":                                  false,
	} {
		r := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(`{"current_password":"from-json"}`))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		mergeJSONBodyIntoForm(r)
		if got := r.FormValue("current_password") == "from-json"; got != merged {
			t.Errorf("Content-Type %q: JSON body merged = %v, want %v", contentType, got, merged)
		}
	}
}
