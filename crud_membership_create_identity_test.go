//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newMemberIdentityApp serves a tenant app whose membership table is keyed by
// userField. notes is an ordinary owned table.
func newMemberIdentityApp(t *testing.T, userField, access string) (*App, *http.ServeMux) {
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
	EnsureAuditLogTable(db)
	for _, stmt := range []string{
		`CREATE TABLE orgs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user_id INTEGER)`,
		`CREATE TABLE org_members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER, user_id INTEGER, email TEXT, member_role TEXT, note TEXT)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
		`INSERT INTO orgs (id, name) VALUES (1, 'acme')`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group: &GroupConfig{Table: "org_members", Key: "org_id", UserField: userField, RoleField: "member_role",
			Bootstrap: &GroupBootstrapConfig{OrgTable: "orgs", FoundingRole: "org_admin"}},
		Access: accessFromYAML(t, access),
	}
	for _, name := range []string{"orgs", "org_members", "notes"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

// memberIdentityAdmin creates the org's admin and a second user, returning the
// admin's session and both ids.
func memberIdentityAdmin(t *testing.T, app *App) (sid string, adminID, bobID int64) {
	t.Helper()
	sid = createCrudScopeSession(t, app, "admin@example.com", "user", "1", "")
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'admin@example.com'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'bob@example.com'").Scan(&bobID); err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, app.DB, "INSERT INTO org_members (org_id, user_id, member_role) VALUES (1, ?, 'org_admin')", adminID)
	return sid, adminID, bobID
}

func memberRowCount(t *testing.T, app *App) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM org_members").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// assertMemberRefused checks the refusal is a clear 4xx that names the field
// and the way to add a member, and that it created nothing.
func assertMemberRefused(t *testing.T, app *App, rec *httptest.ResponseRecorder, before int) {
	t.Helper()
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"user_id", "invitation", "flow", "scoping"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("refusal %s does not mention %q", rec.Body.String(), want)
		}
	}
	if after := memberRowCount(t, app); after != before {
		t.Fatalf("membership rows went from %d to %d on a refused create", before, after)
	}
}

// An org admin adding bob with POST {"user_id":bob} used to answer 200 with
// X-Stripped-Fields: user_id and create a second membership row for the ADMIN:
// user_id is protected and filled from the session. The app reads that as bob
// having joined. Every create path refuses it; naming yourself or leaving the
// field out behaves as before.
func TestMembershipCreateNamingAnotherMemberIsRefused(t *testing.T) {
	app, mux := newMemberIdentityApp(t, "user_id", "access:\n  notes:\n    write: everyone\n")
	admin, adminID, bobID := memberIdentityAdmin(t, app)
	other := map[string]any{"user_id": bobID}
	self := map[string]any{"user_id": adminID, "note": "self"}

	t.Run("single", func(t *testing.T) {
		before := memberRowCount(t, app)
		assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/org_members", admin, other), before)
		assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/org_members", admin, map[string]any{"USER_ID": bobID}), before)

		form := httptest.NewRequest(http.MethodPost, "/api/org_members", strings.NewReader(fmt.Sprintf("user_id=%d", bobID)))
		form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		form.Header.Set("Authorization", "Bearer "+admin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, form)
		assertMemberRefused(t, app, rec, before)

		assertStatus(t, mux, http.MethodPost, "/api/org_members", admin, self, http.StatusOK)
		assertStatus(t, mux, http.MethodPost, "/api/org_members", admin, map[string]any{"note": "omitted"}, http.StatusOK)
		assertStatus(t, mux, http.MethodPost, "/api/org_members", admin, map[string]any{"user_id": nil, "note": "null"}, http.StatusOK)
		var named int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM org_members WHERE user_id = ?", bobID).Scan(&named); err != nil || named != 0 {
			t.Fatalf("bob membership rows = %d err=%v", named, err)
		}
	})

	t.Run("batch", func(t *testing.T) {
		before := memberRowCount(t, app)
		// One bad item rolls the whole batch back.
		assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/org_members/batch", admin, []map[string]any{{"note": "fine"}, other}), before)
		assertStatus(t, mux, http.MethodPost, "/api/org_members/batch", admin, []map[string]any{self, {"note": "omitted"}}, http.StatusOK)
	})

	t.Run("transaction", func(t *testing.T) {
		before := memberRowCount(t, app)
		assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", admin, map[string]any{"operations": []any{
			map[string]any{"table": "org_members", "action": "insert", "data": map[string]any{"note": "fine"}},
			map[string]any{"table": "org_members", "action": "insert", "data": other},
		}}), before)
		assertStatus(t, mux, http.MethodPost, "/api/_transaction", admin, map[string]any{"operations": []any{
			map[string]any{"table": "org_members", "action": "insert", "data": self},
		}}, http.StatusOK)
	})

	t.Run("ingest", func(t *testing.T) {
		ingest := func(lines ...string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/api/org_members/ingest", strings.NewReader(strings.Join(lines, "\n")+"\n"))
			req.Header.Set("Content-Type", "application/x-ndjson")
			req.Header.Set("Authorization", "Bearer "+admin)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			return rec
		}
		before := memberRowCount(t, app)
		assertMemberRefused(t, app, ingest(`{"note":"fine"}`, fmt.Sprintf(`{"user_id":%d}`, bobID)), before)
		if rec := ingest(fmt.Sprintf(`{"user_id":%d,"note":"self"}`, adminID), `{"note":"omitted"}`); rec.Code != http.StatusOK {
			t.Fatalf("ingest naming the caller = %d %s", rec.Code, rec.Body.String())
		}
		if after := memberRowCount(t, app); after != before+2 {
			t.Fatalf("ingest created %d rows, want 2", after-before)
		}
	})

	t.Run("global admin", func(t *testing.T) {
		global := createCrudScopeSession(t, app, "global@example.com", "admin", "", "")
		before := memberRowCount(t, app)
		assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/org_members", global, map[string]any{"user_id": bobID, "org_id": 1}), before)
	})

	// The founding row is built from the session, so a body naming someone
	// else cannot put them in the new tenant.
	t.Run("bootstrap", func(t *testing.T) {
		founder := createCrudScopeSession(t, app, "founder@example.com", "user", "", "")
		var founderID int64
		if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'founder@example.com'").Scan(&founderID); err != nil {
			t.Fatal(err)
		}
		assertStatus(t, mux, http.MethodPost, "/api/_groups/create", founder, map[string]any{"name": "new", "user_id": bobID}, http.StatusOK)
		var member, org int64
		if err := app.DB.QueryRow("SELECT m.user_id, o.user_id FROM org_members m JOIN orgs o ON o.id = m.org_id WHERE o.name = 'new'").Scan(&member, &org); err != nil {
			t.Fatal(err)
		}
		if member != founderID || org != founderID {
			t.Fatalf("founding member = %d, org owner = %d, want the caller %d", member, org, founderID)
		}
	})

	// Other tables keep the documented strip: the row belongs to the caller.
	t.Run("other tables", func(t *testing.T) {
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", admin, map[string]any{"user_id": bobID, "title": "mine"})
		if rec.Code != http.StatusOK || rec.Header().Get("X-Stripped-Fields") != "user_id" {
			t.Fatalf("notes create = %d stripped=%q body=%s", rec.Code, rec.Header().Get("X-Stripped-Fields"), rec.Body.String())
		}
	})
}

// A declared access rule decides who may create, not whose row it is: the
// member a declared rule lets through gets the same refusal.
func TestMembershipCreateNamingAnotherMemberRefusedUnderDeclaredRule(t *testing.T) {
	app, mux := newMemberIdentityApp(t, "user_id", "access:\n  org_members:\n    write: group\n")
	_, _, bobID := memberIdentityAdmin(t, app)
	member := createCrudScopeSession(t, app, "member@example.com", "user", "1", "")
	var memberID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'member@example.com'").Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, app.DB, "INSERT INTO org_members (org_id, user_id, member_role) VALUES (1, ?, 'viewer')", memberID)
	before := memberRowCount(t, app)
	assertMemberRefused(t, app, crudScopeRequest(t, mux, http.MethodPost, "/api/org_members", member, map[string]any{"user_id": bobID}), before)
}

// An email-keyed membership table takes its identity from the request, which
// is how an invite row names someone else; its user_id is only the row's owner
// and is stripped as before.
func TestMembershipCreateWritableIdentityStillNamesAnyone(t *testing.T) {
	app, mux := newMemberIdentityApp(t, "email", "access:\n  notes:\n    write: everyone\n")
	admin := createCrudScopeSession(t, app, "admin@example.com", "user", "1", "")
	mustExecArgs(t, app.DB, "INSERT INTO org_members (org_id, email, member_role) VALUES (1, ?, 'org_admin')", "admin@example.com")
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/org_members", admin, map[string]any{"email": "invitee@example.com", "user_id": 999})
	if rec.Code != http.StatusOK || rec.Header().Get("X-Stripped-Fields") != "user_id" {
		t.Fatalf("email-keyed create = %d stripped=%q body=%s", rec.Code, rec.Header().Get("X-Stripped-Fields"), rec.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM org_members WHERE email = 'invitee@example.com'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("invite rows = %d err=%v", n, err)
	}
}

// Import Mode A: NDJSON ignores keys that are not importable, so a file naming
// other members used to load one row per line under the importing admin. CSV
// and a declared column list already refuse the protected column.
func TestImportMembershipRowNamingAnotherMemberIsRefused(t *testing.T) {
	load := func(t *testing.T, id, format, content string) (error, int) {
		t.Helper()
		app, cleanup := newImportTestApp(t)
		t.Cleanup(cleanup)
		mustExec(t, app.DB, `CREATE TABLE org_members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER, user_id INTEGER, note TEXT)`)
		app.Group = &GroupConfig{Table: "org_members", Key: "org_id", UserField: "user_id"}
		sum := stageString(t, app, id, content)
		mustExecArgs(t, app.DB, `INSERT INTO _benmore_imports (id, table_name, format, bytes_total, sha256, state, created_by)
			VALUES (?, 'org_members', ?, ?, ?, 'running', 7)`, id, format, len(content), sum)
		sess, err := loadImportSession(app.DB, id)
		if err != nil {
			t.Fatal(err)
		}
		runErr := runImport(app, sess)
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM org_members").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return runErr, n
	}
	for name, content := range map[string]string{
		"first object": `{"org_id":1,"user_id":9}` + "\n",
		"later object": `{"org_id":1}` + "\n" + `{"org_id":1,"user_id":9}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			err, n := load(t, "member0001", "ndjson", content)
			if err == nil || !strings.Contains(err.Error(), "user_id") || !strings.Contains(err.Error(), "invitation") {
				t.Fatalf("runImport = %v; want the membership identity refusal", err)
			}
			if n != 0 {
				t.Fatalf("%d rows loaded by a refused import", n)
			}
		})
	}
	t.Run("the importer", func(t *testing.T) {
		if err, n := load(t, "member0002", "ndjson", `{"org_id":1,"user_id":7}`+"\n"+`{"org_id":1}`+"\n"); err != nil || n != 2 {
			t.Fatalf("runImport = %v, %d rows; want both rows", err, n)
		}
	})
	t.Run("csv header", func(t *testing.T) {
		if err, n := load(t, "member0003", "csv", "org_id,user_id\n1,9\n"); err == nil || !strings.Contains(err.Error(), "user_id") || n != 0 {
			t.Fatalf("runImport = %v, %d rows; want the protected column refused", err, n)
		}
	})
}
