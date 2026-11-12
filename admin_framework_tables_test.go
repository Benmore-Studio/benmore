//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The admin panel's write routes ran generic create, update and delete on
// whatever table the URL named. For framework tables that reached record
// permissions (a grant that skips the share checks), jobs and scheduled tasks
// (a queued flow run with a payload and actor of the writer's choice), the
// migrations ledger, webhooks, approvals, locks and the rest. The panel now
// writes app tables and _benmore_users, and shows every other framework table.

type adminFrameworkFixture struct {
	t        *testing.T
	app      *App
	mux      *http.ServeMux
	adminSID string
	memberID int64
}

// newAdminFrameworkFixture is a scaffolded app loaded and routed the way the
// server does it, so its database holds the framework tables a real app has.
func newAdminFrameworkFixture(t *testing.T) *adminFrameworkFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "panel")
	if err := writeHTMLScaffoldFiles(dir, "Panel", false); err != nil {
		t.Fatal(err)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	f := &adminFrameworkFixture{t: t, app: app, mux: buildAppMux(app, false, "http://panel.example.test")}
	if !app.FeatureEnabled("admin") {
		t.Fatal("fixture has no admin panel")
	}
	seed := func(name, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)", name, name+"@example.com", role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	adminID := seed("root", "admin")
	f.memberID = seed("member", "user")
	f.adminSID = CreateSession(app.DB, adminID, "root@example.com", "", time.Hour)
	if f.adminSID == "" {
		t.Fatal("no admin session")
	}
	// A framework table nobody has listed anywhere: the rule reads the name.
	mustExec(t, app.DB, "CREATE TABLE _benmore_future_feature (id INTEGER PRIMARY KEY, name TEXT)")
	return f
}

func (f *adminFrameworkFixture) post(path string, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+f.adminSID)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func (f *adminFrameworkFixture) page(path string) (int, string) {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+f.adminSID)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// contents is every row of table as text, in rowid order.
func (f *adminFrameworkFixture) contents(table string) string {
	f.t.Helper()
	rows, err := f.app.DB.Query("SELECT * FROM " + quoteIdent(table) + " ORDER BY rowid")
	if err != nil {
		f.t.Fatalf("read %s: %v", table, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var sb strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			f.t.Fatalf("scan %s: %v", table, err)
		}
		for _, v := range vals {
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			fmt.Fprintf(&sb, "%v|", v)
		}
		sb.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("read %s: %v", table, err)
	}
	return sb.String()
}

// frameworkTables lists the database's own framework tables, so a table a
// later release adds is covered without anyone naming it here.
func (f *adminFrameworkFixture) frameworkTables() []string {
	f.t.Helper()
	rows, err := f.app.DB.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND lower(name) LIKE '\_benmore\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, name)
	}
	return out
}

// seedRowOne gives table a row with id 1 when a plain row fits its columns, so
// update/1 and delete/1 aim at something. It reports whether row 1 exists.
func (f *adminFrameworkFixture) seedRowOne(table string, cols []Column) bool {
	hasID := false
	var names, marks []string
	var args []any
	for _, c := range cols {
		names = append(names, quoteIdent(c.Name))
		marks = append(marks, "?")
		switch {
		case c.Name == "id":
			hasID = true
			args = append(args, 1)
		case strings.Contains(strings.ToUpper(c.Type), "INT"), strings.Contains(strings.ToUpper(c.Type), "REAL"):
			args = append(args, 1)
		default:
			args = append(args, "1")
		}
	}
	if !hasID {
		return false
	}
	f.app.DB.Exec("INSERT OR IGNORE INTO "+quoteIdent(table)+" ("+strings.Join(names, ", ")+") VALUES ("+strings.Join(marks, ", ")+")", args...)
	var n int
	f.app.DB.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(table) + " WHERE id = 1").Scan(&n)
	return n == 1
}

var adminWriteControls = []string{"/_admin/api/", "admin-create", `<form method="POST"`, "hx-post", "Save Changes"}

func TestAdminPanelWritesNoFrameworkTableButUsers(t *testing.T) {
	f := newAdminFrameworkFixture(t)
	tables := f.frameworkTables()
	// A scaffolded app has some forty of them; far fewer means the fixture
	// stopped creating them and this test would be checking nothing.
	if len(tables) < 30 {
		t.Fatalf("fixture database has %d framework tables: %v", len(tables), tables)
	}
	checked, withRow := 0, 0
	sawUsers, sawUnlisted := false, false
	for _, table := range tables {
		if table == "_benmore_users" {
			sawUsers = true
			continue
		}
		if table == "_benmore_future_feature" {
			sawUnlisted = true
		}
		cols, err := GetTableColumns(f.app.DB, table)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		hasRow := f.seedRowOne(table, cols)
		if hasRow {
			withRow++
		}
		form := url.Values{}
		for _, c := range cols {
			if !c.PK {
				form.Set(c.Name, "1")
			}
		}
		// The same table as SQLite reads the name, in another case.
		for _, name := range []string{table, strings.ToUpper(table)} {
			before := f.contents(table)
			for _, action := range []string{"create", "update/1", "delete/1"} {
				w, body := f.post("/_admin/api/"+name+"/"+action, form)
				msg, _ := body["message"].(string)
				docs, _ := body["docs"].(string)
				if w.Code != http.StatusForbidden || body["error"] != "admin_table_read_only" || body["table"] != name ||
					!strings.Contains(msg, name) || !strings.Contains(msg, "never writes it") || docs == "" {
					t.Errorf("POST /_admin/api/%s/%s: %d %s, want 403 admin_table_read_only naming the table with a docs pointer", name, action, w.Code, strings.TrimSpace(w.Body.String()))
				}
			}
			if after := f.contents(table); after != before {
				t.Errorf("%s changed through the admin panel:\nbefore:\n%safter:\n%s", table, before, after)
			}
		}
		pages := []string{"/_admin/" + table}
		if hasRow {
			pages = append(pages, "/_admin/"+table+"/1")
		}
		for _, path := range pages {
			code, html := f.page(path)
			if code != http.StatusOK || !strings.Contains(html, "never writes it") {
				t.Errorf("GET %s: %d, want the page with its read-only note", path, code)
				continue
			}
			for _, control := range adminWriteControls {
				if strings.Contains(html, control) {
					t.Errorf("GET %s renders a write control (%s)", path, control)
				}
			}
		}
		checked++
	}
	// A table with no message of its own points at the panel's reference key.
	if _, body := f.post("/_admin/api/_benmore_permissions/create", url.Values{"user_id": {"2"}}); body["docs"] != "auth.admin_panel_accounts" {
		t.Errorf("docs pointer for a framework table: %v", body["docs"])
	}
	if !sawUsers || !sawUnlisted {
		t.Fatalf("the table list is missing _benmore_users (%v) or the unlisted table (%v)", sawUsers, sawUnlisted)
	}
	// Most framework tables took a plain row 1, so update and delete were
	// refused on a row that exists and not only on a missing one.
	if withRow < checked/2 {
		t.Errorf("only %d of %d framework tables hold a row 1", withRow, checked)
	}
	t.Logf("%d framework tables refused every panel write (%d with a row 1 to aim at)", checked, withRow)
}

// The one framework table the panel writes keeps its ordinary edits, and the
// columns no generic write takes stay out of reach.
func TestAdminPanelStillWritesUsersTable(t *testing.T) {
	f := newAdminFrameworkFixture(t)
	read := func(id int64, col string) string {
		var v sql.NullString
		if err := f.app.DB.QueryRow("SELECT CAST("+col+" AS TEXT) FROM _benmore_users WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatalf("read %s of account %d: %v", col, id, err)
		}
		return v.String
	}
	member := fmt.Sprint(f.memberID)

	w, _ := f.post("/_admin/api/_benmore_users/update/"+member, url.Values{"first_name": {"Mia"}, "password_hash": {"forged"}, "role": {"admin"}})
	if w.Code != http.StatusOK || read(f.memberID, "first_name") != "Mia" {
		t.Fatalf("ordinary edit of a user: %d %s, first_name %q", w.Code, w.Body.String(), read(f.memberID, "first_name"))
	}
	if read(f.memberID, "password_hash") != "" || read(f.memberID, "role") != "user" {
		t.Errorf("the edit wrote a protected column: password_hash %q, role %q", read(f.memberID, "password_hash"), read(f.memberID, "role"))
	}

	w, _ = f.post("/_admin/api/_benmore_users/create", url.Values{"username": {"newbie"}, "email": {"newbie@example.com"}, "role": {"admin"}})
	var newID int64
	var role string
	if err := f.app.DB.QueryRow("SELECT id, role FROM _benmore_users WHERE email = 'newbie@example.com'").Scan(&newID, &role); err != nil || role != "user" {
		t.Fatalf("create a user: %d %s (row: %v, role %q)", w.Code, w.Body.String(), err, role)
	}
	w, _ = f.post("/_admin/api/_benmore_users/delete/"+fmt.Sprint(newID), url.Values{})
	var left int
	f.app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE id = ?", newID).Scan(&left)
	if left != 0 {
		t.Fatalf("delete a user: %d %s", w.Code, w.Body.String())
	}

	for _, path := range []string{"/_admin/_benmore_users", "/_admin/_benmore_users/" + member} {
		code, html := f.page(path)
		if code != http.StatusOK || strings.Contains(html, "never writes it") || !strings.Contains(html, "/_admin/api/_benmore_users/") {
			t.Errorf("GET %s: %d, want the page with its write controls and no read-only note", path, code)
		}
	}
}

// App tables are written through the panel as before.
func TestAdminPanelStillWritesAppTables(t *testing.T) {
	f := newAdminFrameworkFixture(t)
	title := func(id string) (v string) {
		f.app.DB.QueryRow("SELECT title FROM notes WHERE id = ?", id).Scan(&v)
		return v
	}
	w, body := f.post("/_admin/api/notes/create", url.Values{"title": {"panel note"}})
	id := fmt.Sprint(body["id"])
	if w.Code != http.StatusOK || title(id) != "panel note" {
		t.Fatalf("create a note: %d %s", w.Code, w.Body.String())
	}
	if w, _ = f.post("/_admin/api/notes/update/"+id, url.Values{"title": {"edited"}}); w.Code != http.StatusOK || title(id) != "edited" {
		t.Fatalf("edit a note: %d %s, title %q", w.Code, w.Body.String(), title(id))
	}
	for _, path := range []string{"/_admin/notes", "/_admin/notes/" + id} {
		code, html := f.page(path)
		if code != http.StatusOK || strings.Contains(html, "never writes it") || !strings.Contains(html, "/_admin/api/notes/") {
			t.Errorf("GET %s: %d, want the page with its write controls and no read-only note", path, code)
		}
	}
	if w, _ = f.post("/_admin/api/notes/delete/"+id, url.Values{}); w.Code != http.StatusOK {
		t.Fatalf("delete a note: %d %s", w.Code, w.Body.String())
	}
	var live int
	f.app.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ? AND deleted_at IS NULL", id).Scan(&live)
	if live != 0 {
		t.Errorf("the deleted note is still live")
	}
}

// The rule is the name: every _benmore_ table but the users table, in any
// letter case, and nothing an app can name.
func TestAdminReadOnlyKindIsDerivedFromTheName(t *testing.T) {
	for _, table := range []string{"_benmore_permissions", "_benmore_jobs", "_benmore_scheduled_tasks", "_benmore_migrations",
		"_benmore_not_written_yet", "_BENMORE_WEBHOOKS", "_Benmore_Locks", "_benmore_users_archive", "_benmore_"} {
		if adminReadOnlyKind(table) == "" {
			t.Errorf("%s is writable through the admin panel", table)
		}
	}
	for _, table := range []string{"_benmore_users", "_BENMORE_USERS", "notes", "benmore_notes", "my_benmore_table", "users", ""} {
		if kind := adminReadOnlyKind(table); kind != "" {
			t.Errorf("%s is read-only in the admin panel (%s)", table, kind)
		}
	}
	// The registries that choose a table's message add nothing to the rule:
	// every name in them carries the prefix and none is the users table.
	listed := append([]string{"_benmore_user_roles"}, auditAppendOnlyTables...)
	listed = append(listed, restoreMCPTables...)
	for _, spec := range restoreGrantTables {
		listed = append(listed, spec.name)
	}
	for _, name := range listed {
		if !strings.HasPrefix(name, frameworkTablePrefix) || name == adminPanelWritableFrameworkTable {
			t.Errorf("%s has a read-only message of its own and is not covered by the name rule", name)
		}
	}
	// The tables with a message of their own keep it.
	for table, kind := range map[string]string{
		"_benmore_audit_log": adminReadOnlyAudit, "_benmore_sessions": adminReadOnlyCredential,
		"_benmore_user_roles": adminReadOnlyGrants, "_benmore_permissions": adminReadOnlyFramework,
	} {
		if got := adminReadOnlyKind(table); got != kind {
			t.Errorf("%s: kind %q, want %q", table, got, kind)
		}
	}
}
