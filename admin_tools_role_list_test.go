//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Tools page listed, and its runner ran, only a flow whose role text was
// exactly "admin". A role gate is an any-of list and `admin` in any letter
// case means the app's global admin, so `role: [admin, finance]` and
// `role: Admin` are admin flows too: the flow's own route admits a global
// admin by that name, and the Tools page left them out.
func TestAdminToolsListsFlowsWhoseRoleListNamesAdmin(t *testing.T) {
	flow := func(name, role, method, path string) Flow {
		return Flow{Name: name, Role: role, Trigger: FlowTrigger{Type: "http", Method: method, Path: path},
			Steps: []FlowStep{{Name: "s", Type: "sql", SQL: "INSERT INTO runs (flow) VALUES ('" + name + "')"}}}
	}
	// fixture serves an app with the given flows to a signed-in global admin.
	fixture := func(t *testing.T, flows ...Flow) (*sql.DB, *http.ServeMux, string) {
		t.Helper()
		dir := t.TempDir()
		db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		mustExec(t, db, `CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, flow TEXT)`)
		if err := EnsureUsersTable(db); err != nil {
			t.Fatal(err)
		}
		EnsureSessionsTable(db)
		res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('boss', 'boss@example.com', 'admin', 1)")
		if err != nil {
			t.Fatal(err)
		}
		uid, _ := res.LastInsertId()
		// Everything about the app is set before its routes are built.
		app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}), Flows: flows,
			Tables: []Table{{Name: "runs", Columns: []Column{{Name: "id"}, {Name: "flow"}}}}}
		t.Cleanup(app.Shutdown)
		mux := buildAppMux(app, true, "http://localhost")
		return db, mux, CreateSession(db, uid, "boss@example.com", "", time.Hour)
	}
	page := func(mux *http.ServeMux, sid, path string) string {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Body.String()
	}
	ran := func(db *sql.DB, name string) int {
		var n int
		db.QueryRow("SELECT COUNT(*) FROM runs WHERE flow = ?", name).Scan(&n)
		return n
	}

	db, mux, sid := fixture(t,
		flow("exact", "admin", "POST", "/api/tools/exact"),
		flow("listed", "admin,finance", "POST", "/api/tools/listed"),
		flow("listed_last", "finance,admin", "POST", "/api/tools/listed-last"),
		flow("capital", "Admin", "POST", "/api/tools/capital"),
		// Not admin flows: a global admin passes these gates too, but the
		// gate names other people, and the page is for the admin's own tools.
		flow("finance_only", "finance", "POST", "/api/tools/finance-only"),
		flow("no_gate", "", "POST", "/api/tools/no-gate"),
		// A name that only contains the word.
		flow("org_admin", "org_admin", "POST", "/api/tools/org-admin"),
		// Admin flows the page never listed: not a POST, or a record action.
		flow("reader", "admin,finance", "GET", "/api/tools/reader"),
		flow("per_record", "admin,finance", "POST", "/api/tools/record/:id"),
	)
	tools := page(mux, sid, "/_admin/tools")
	for _, name := range []string{"exact", "listed", "listed-last", "capital"} {
		if !strings.Contains(tools, `name="_flow_path" value="/api/tools/`+name+`"`) {
			t.Errorf("the Tools page does not list the admin flow /api/tools/%s", name)
		}
	}
	for _, name := range []string{"finance-only", "no-gate", "org-admin", "reader", "record/:id"} {
		if strings.Contains(tools, `value="/api/tools/`+name+`"`) {
			t.Errorf("the Tools page lists /api/tools/%s, which is not an admin POST tool", name)
		}
	}

	// The runner runs what the page lists and nothing else.
	for _, c := range []struct {
		name, path string
		runs       bool
	}{
		{"exact", "/api/tools/exact", true},
		{"listed", "/api/tools/listed", true},
		{"listed_last", "/api/tools/listed-last", true},
		{"capital", "/api/tools/capital", true},
		{"finance_only", "/api/tools/finance-only", false},
		{"no_gate", "/api/tools/no-gate", false},
		{"org_admin", "/api/tools/org-admin", false},
		{"reader", "/api/tools/reader", false},
		{"per_record", "/api/tools/record/:id", false},
	} {
		loc := adminToolsRun(mux, sid, url.Values{"_flow_path": {c.path}})
		if c.runs && (ran(db, c.name) != 1 || !strings.Contains(loc, "msg=")) {
			t.Errorf("running %s from the Tools page: %d runs, redirect %q", c.path, ran(db, c.name), loc)
		}
		if !c.runs && (ran(db, c.name) != 0 || !strings.Contains(loc, "error=")) {
			t.Errorf("the Tools runner ran %s (%d runs, redirect %q)", c.path, ran(db, c.name), loc)
		}
	}

	// The sidebar links to Tools when the only admin flow is gated by a list.
	_, mux, sid = fixture(t, flow("listed", "finance,admin", "POST", "/api/tools/listed"))
	if dash := page(mux, sid, "/_admin"); !strings.Contains(dash, `href="/_admin/tools"`) {
		t.Error("the sidebar has no Tools link though the app has an admin flow (role: [finance, admin])")
	}
	_, mux, sid = fixture(t, flow("finance_only", "finance", "POST", "/api/tools/finance-only"))
	if dash := page(mux, sid, "/_admin"); strings.Contains(dash, `href="/_admin/tools"`) {
		t.Error("the sidebar links to Tools though the app has no admin flow")
	}
}
