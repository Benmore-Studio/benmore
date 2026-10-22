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

func adminToolsRun(mux *http.ServeMux, sid string, form url.Values) string {
	form.Set("_csrf", authMintCSRFToken(sid))
	r := httptest.NewRequest(http.MethodPost, "/_admin/tools/run", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Header().Get("Location")
}

// The /_admin/tools runner executes an admin POST flow with the posted form
// as its input, but built the flow context by hand: it never marked those
// values as request input (so sql_dynamic, which refuses request-sourced
// text, ran them as raw SQL) and never dropped identity and reserved keys
// (user_group_id, user.*, env.*), which the HTTP entry point strips so a
// caller can't stand in for the session or the app environment. It now
// applies the same marking and stripping as the HTTP path.
func TestAdminToolsRunnerTreatsFormAsRequestInput(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
	mustExec(t, db, `INSERT INTO notes (title) VALUES ('keep')`)
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "title"}}}}}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('boss', 'boss@example.com', 'admin', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(db, uid, "boss@example.com", "", time.Hour)

	app.Flows = append(app.Flows,
		Flow{Name: "retitle", Role: "admin", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/admin/retitle"},
			Steps: []FlowStep{{Name: "q", Type: "sql_dynamic", SQL: "UPDATE notes SET title = '{{label}}'"}}},
		Flow{Name: "stamp", Role: "admin", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/admin/stamp"},
			Steps: []FlowStep{{Name: "s", Type: "sql", SQL: "INSERT INTO notes (title) VALUES ('group:' || COALESCE(:user_group_id, 'none'))"}}},
	)

	loc := adminToolsRun(mux, sid, url.Values{"_flow_path": {"/api/admin/retitle"}, "label": {"x' || (SELECT email FROM _benmore_users) || '"}})
	var titles []string
	rows, err := db.Query("SELECT title FROM notes ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		rows.Scan(&s)
		titles = append(titles, s)
	}
	rows.Close()
	if len(titles) != 1 || titles[0] != "keep" {
		t.Fatalf("sql_dynamic ran posted form text as SQL from the tools page (titles %q, redirect %q)", titles, loc)
	}
	if !strings.Contains(loc, "error=") {
		t.Fatalf("refused flow reported success: %q", loc)
	}

	adminToolsRun(mux, sid, url.Values{"_flow_path": {"/api/admin/stamp"}, "user_group_id": {"other-tenant"}})
	var forged int
	db.QueryRow("SELECT COUNT(*) FROM notes WHERE title = 'group:other-tenant'").Scan(&forged)
	if forged != 0 {
		t.Fatal("a posted user_group_id stood in for the session's tenant")
	}
}
