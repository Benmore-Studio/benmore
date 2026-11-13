//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A table admin.yaml hides was left out of the sidebar and its pages and
// write routes answered 404, while the rest of the panel kept reading it: the
// dashboard counted its rows, a record page of another table listed them
// under "Related", the activity list named them, and hiding a framework
// table (the users table, say) left its dashboard tiles, the recent-users
// list, the search index and the page header as they were.

const adminHiddenSchema = `model Client {
  id   Int    @id @default(autoincrement())
  name String

  @@map("clients")
}

model Invoice {
  id       Int    @id @default(autoincrement())
  clientId Int    @map("client_id")
  label    String

  @@map("invoices")
}

model Secret {
  id       Int    @id @default(autoincrement())
  clientId Int    @map("client_id")
  body     String

  @@map("secrets")
}
`

// adminHiddenFixture is an app with clients, their invoices and their
// secrets, served with the given admin.yaml (none when empty). It holds two
// clients, one invoice and three secrets, each written through the API so the
// audit log names them, plus a second account.
func adminHiddenFixture(t *testing.T, adminYAML string) (*App, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: \"hidden-reads\"\nfeatures:\n  testing: true\n")
	writeTestFile(t, dir, "schema.prisma", adminHiddenSchema)
	if adminYAML != "" {
		writeTestFile(t, dir, "admin.yaml", adminYAML)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "https://fixture.example")
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	mustExec(t, app.DB, `INSERT INTO _benmore_users (username, email, role, verified) VALUES ('second', 'second-account@example.com', 'user', 1)`)
	create := func(table string, body map[string]any) {
		t.Helper()
		if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/"+table, admin, body); rec.Code != http.StatusOK {
			t.Fatalf("create %s: %d %s", table, rec.Code, rec.Body.String())
		}
	}
	create("clients", map[string]any{"name": "first client"})
	create("clients", map[string]any{"name": "second client"})
	create("invoices", map[string]any{"client_id": 1, "label": "invoice-marker"})
	for i := 1; i <= 3; i++ {
		create("secrets", map[string]any{"client_id": 1, "body": fmt.Sprintf("secret-marker-%d", i)})
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_feedback (visitor_name, page_url, body, status) VALUES ('visitor', '/', 'feedback-marker', 'open')`)
	return app, mux, admin
}

func adminPage(t *testing.T, mux *http.ServeMux, token, path string) string {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

var adminTotalRecordsRe = regexp.MustCompile(`Total Records</div>\s*<div[^>]*>(\d+)</div>`)

func adminTotalRecords(t *testing.T, page string) string {
	t.Helper()
	m := adminTotalRecordsRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the dashboard has no Total Records tile")
	}
	return m[1]
}

func TestAdminPanelReadsNoHiddenAppTable(t *testing.T) {
	// With nothing hidden the panel shows all of it: what the assertions
	// below look for is really there to be hidden.
	_, mux, admin := adminHiddenFixture(t, "")
	dash := adminPage(t, mux, admin, "/_admin")
	if got := adminTotalRecords(t, dash); got != "6" {
		t.Fatalf("fixture: Total Records %s, want 6 (2 clients, 1 invoice, 3 secrets)", got)
	}
	if !strings.Contains(dash, "secrets #1") || !strings.Contains(dash, "clients #1") {
		t.Fatal("fixture: the activity list does not name the rows the API created")
	}
	record := adminPage(t, mux, admin, "/_admin/clients/1")
	if !strings.Contains(record, "Related Secrets (3)") || !strings.Contains(record, "secret-marker-2") || !strings.Contains(record, "Related Invoices (1)") {
		t.Fatal("fixture: the client page lists no related invoices and secrets")
	}

	// The name is matched as SQLite matches it.
	for _, name := range []string{"secrets", "SECRETS"} {
		_, mux, admin := adminHiddenFixture(t, "tables:\n  "+name+":\n    hidden: true\n")
		dash := adminPage(t, mux, admin, "/_admin")
		if got := adminTotalRecords(t, dash); got != "3" {
			t.Errorf("hidden as %s: Total Records %s counts the hidden table's rows, want 3", name, got)
		}
		if strings.Contains(dash, "secrets #") {
			t.Errorf("hidden as %s: the activity list names rows of the hidden table", name)
		}
		if !strings.Contains(dash, "clients #1") || !strings.Contains(dash, "invoices #1") {
			t.Errorf("hidden as %s: the activity list lost the rows of tables that are not hidden", name)
		}
		record := adminPage(t, mux, admin, "/_admin/clients/1")
		if strings.Contains(record, "Related Secrets") || strings.Contains(record, "secret-marker") {
			t.Errorf("hidden as %s: the client page lists the hidden table's rows", name)
		}
		if !strings.Contains(record, "Related Invoices (1)") || !strings.Contains(record, "invoice-marker") {
			t.Errorf("hidden as %s: the client page lost the related rows of a table that is not hidden", name)
		}
		for _, path := range []string{"/_admin", "/_admin/clients", "/_admin/clients/1", "/_admin/tools"} {
			if page := adminPage(t, mux, admin, path); strings.Contains(page, "secret-marker") || strings.Contains(page, `href="/_admin/secrets`) {
				t.Errorf("hidden as %s: GET %s shows the hidden table", name, path)
			}
		}
	}
}

func TestAdminPanelReadsNoHiddenFrameworkTable(t *testing.T) {
	_, mux, admin := adminHiddenFixture(t, "")
	dash := adminPage(t, mux, admin, "/_admin")
	for _, want := range []string{"second-account@example.com", ">Users<", ">Active Sessions<", ">Page Views<", ">API Requests<", ">Audit Trail<", "Recent Users", "Recent Activity", " users</span>", " sessions</span>", `href="/_admin/feedback"`} {
		if !strings.Contains(dash, want) {
			t.Fatalf("fixture: the dashboard has no %q to hide", want)
		}
	}
	if !strings.Contains(adminPage(t, mux, admin, "/_admin/feedback"), "feedback-marker") {
		t.Fatal("fixture: the feedback page does not list the feedback row")
	}

	cases := []struct {
		table string
		gone  []string // not in any panel page once the table is hidden
		kept  []string // still on the dashboard: other tables' tiles and lists
	}{
		{"_benmore_users", []string{"second-account@example.com", ">Users<", "Recent Users", " users</span>"}, []string{">Active Sessions<", "Recent Activity", ">Total Records<"}},
		{"_benmore_sessions", []string{">Active Sessions<", " sessions</span>"}, []string{">Users<", "Recent Users", "second-account@example.com"}},
		{"_benmore_usage", []string{">Page Views<", ">API Requests<"}, []string{">Users<", ">Active Sessions<"}},
		{"_benmore_audit_log", []string{">Audit Trail<", "Recent Activity", "clients #1"}, []string{">Users<", ">Total Records<", "Recent Users"}},
		{"_BENMORE_USERS", []string{"second-account@example.com", ">Users<", "Recent Users"}, []string{">Active Sessions<"}},
		{"_benmore_feedback", []string{`href="/_admin/feedback"`, "feedback-marker"}, []string{">Users<", "Recent Users"}},
	}
	for _, c := range cases {
		_, mux, admin := adminHiddenFixture(t, "tables:\n  "+c.table+":\n    hidden: true\n")
		dash := adminPage(t, mux, admin, "/_admin")
		for _, kept := range c.kept {
			if !strings.Contains(dash, kept) {
				t.Errorf("%s hidden: the dashboard lost %q, which reads another table", c.table, kept)
			}
		}
		for _, path := range []string{"/_admin", "/_admin/clients", "/_admin/clients/1", "/_admin/tools"} {
			page := adminPage(t, mux, admin, path)
			for _, gone := range c.gone {
				if strings.Contains(page, gone) {
					t.Errorf("%s hidden: GET %s still shows %q", c.table, path, gone)
				}
			}
		}
		if identIs(c.table, "_benmore_feedback") {
			// Answered as an unknown page is (this app has no page of its
			// own there), with none of the table's rows.
			rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/feedback", admin, nil)
			if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "feedback-marker") {
				t.Errorf("_benmore_feedback hidden: GET /_admin/feedback answered %d and shows the table", rec.Code)
			}
		}
	}
}

// The framework keeps rows about an app table in tables of its own: the audit
// log holds the old and new values of every change, and <table>_history its
// earlier versions. Their panel pages showed the hidden table's rows that way.
func TestAdminPanelShowsNoFrameworkRowsAboutAHiddenTable(t *testing.T) {
	audit := func(t *testing.T, app *App, table string) (id string) {
		t.Helper()
		if err := app.DB.QueryRow(`SELECT CAST(id AS TEXT) FROM _benmore_audit_log WHERE table_name = ? ORDER BY id LIMIT 1`, table).Scan(&id); err != nil {
			t.Fatalf("fixture: no audit row about %s: %v", table, err)
		}
		return id
	}

	// Nothing hidden: the audit log's pages show the rows about secrets.
	app, mux, admin := adminHiddenFixture(t, "")
	if list := adminPage(t, mux, admin, "/_admin/_benmore_audit_log"); !strings.Contains(list, "secret-marker") || !strings.Contains(list, "invoice-marker") {
		t.Fatal("fixture: the audit log page does not show the values of the rows the API created")
	}
	if strings.Contains(adminPage(t, mux, admin, "/_admin/_benmore_audit_log?q=secret-marker-2"), "No records found.") {
		t.Fatal("fixture: the audit log's search does not find the row by its values")
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_audit_log/"+audit(t, app, "secrets"), admin, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "secret-marker") {
		t.Fatalf("fixture: the audit row about secrets has no page: %d", rec.Code)
	}

	for _, name := range []string{"secrets", "Secrets"} {
		app, mux, admin := adminHiddenFixture(t, "tables:\n  "+name+":\n    hidden: true\n")
		var about, others int
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name = 'secrets'`).Scan(&about)
		app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name <> 'secrets'`).Scan(&others)
		if about != 3 || others == 0 {
			t.Fatalf("fixture: %d audit rows about secrets and %d about other tables", about, others)
		}
		for _, path := range []string{"/_admin/_benmore_audit_log", "/_admin/_benmore_audit_log?q=secret-marker-2", "/_admin/_benmore_audit_log?q=secrets"} {
			list := adminPage(t, mux, admin, path)
			if strings.Contains(path, "?") {
				// A search for the hidden rows finds none (the page repeats
				// the search text in its input, so the text says nothing).
				if !strings.Contains(list, "No records found.") {
					t.Errorf("hidden as %s: GET %s finds rows about the hidden table", name, path)
				}
				continue
			}
			if strings.Contains(list, "secret-marker") {
				t.Errorf("hidden as %s: GET %s shows the hidden table's rows", name, path)
			}
			// The rows about other tables stay, and the count is of what is listed.
			if !strings.Contains(list, "invoice-marker") || !strings.Contains(list, fmt.Sprintf("%d records &middot;", others)) {
				t.Errorf("hidden as %s: GET %s lost the rows about other tables, or counts the left-out rows (want %d records)", name, path, others)
			}
		}
		rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_audit_log/"+audit(t, app, "secrets"), admin, nil)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "secret-marker") {
			t.Errorf("hidden as %s: the audit row about the hidden table has a page (%d)", name, rec.Code)
		}
		if rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_audit_log/"+audit(t, app, "invoices"), admin, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invoice-marker") {
			t.Errorf("hidden as %s: the audit row about a table that is not hidden lost its page (%d)", name, rec.Code)
		}
	}
}

// The stored versions of a hidden table are hidden with it.
func TestAdminPanelHidesTheVersionHistoryOfAHiddenTable(t *testing.T) {
	f := newAdminHistoryFixture(t)
	id := f.noteWithTwoVersions("first-version-marker", "second-version-marker", "current")
	// notes is versioned and not hidden: its history has pages.
	if code, page := f.page("/_admin/notes_history"); code != http.StatusOK || !strings.Contains(page, "first-version-marker") {
		t.Fatalf("fixture: /_admin/notes_history: %d", code)
	}
	if _, page := f.page("/_admin/notes_history/" + id); !strings.Contains(page, "Back to list") {
		t.Fatal("fixture: a stored version has no page")
	}

	// The same app with notes hidden.
	if err := os.WriteFile(filepath.Join(f.app.Dir, "admin.yaml"), []byte("tables:\n  Notes:\n    hidden: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.app.mu.Lock()
	f.app.Admin = LoadAdminConfig(f.app.Dir)
	f.app.mu.Unlock()
	before := f.contents("notes_history")
	for _, name := range []string{"notes_history", "NOTES_HISTORY"} {
		for _, path := range []string{"/_admin/" + name, "/_admin/" + name + "/" + id} {
			if _, page := f.page(path); strings.Contains(page, "version-marker") || strings.Contains(page, "Back to list") || strings.Contains(page, "records &middot;") {
				t.Errorf("GET %s shows the stored versions of the hidden table", path)
			}
		}
		// A write answers as for the hidden table itself, and writes nothing.
		for _, action := range []string{"create", "update/" + id, "delete/" + id} {
			if w, _ := f.post("/_admin/api/"+name+"/"+action, url.Values{"title": {"forged"}}); w.Code != http.StatusNotFound {
				t.Errorf("POST /_admin/api/%s/%s: %d, want 404", name, action, w.Code)
			}
		}
	}
	if after := f.contents("notes_history"); after != before {
		t.Error("the hidden table's history changed through the panel")
	}
	// An app table whose name only ends in _history is not the history of
	// anything: it stays.
	if code, page := f.page("/_admin/visit_history"); code != http.StatusOK || !strings.Contains(page, "/_admin/api/visit_history/") {
		t.Errorf("/_admin/visit_history: %d, want its page", code)
	}
}
