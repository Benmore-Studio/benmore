//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A versioned table's earlier states live in <table>_history, a table with no
// _benmore_ prefix. The admin panel's write routes ran generic create, update
// and delete on it like on an app table, so an admin could forge a version,
// rewrite every stored version of a row at once (the route updates by id, and
// every version of a row carries the row's id) or delete them: the versions
// API then reported a history that never happened and a revert restored it.
// The panel shows version history and never writes it. The same routes also
// wrote a table admin.yaml hides, whose pages answer 404.

// newAdminHistoryFixture is a scaffolded app with notes versioned and three
// more tables: one whose name only looks like a version history, one that is
// the history kept from a table no longer versioned, and one admin.yaml hides.
func newAdminHistoryFixture(t *testing.T) *adminFrameworkFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "panel")
	if err := writeHTMLScaffoldFiles(dir, "Panel", false); err != nil {
		t.Fatal(err)
	}
	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(appYAML), "versioned:") {
		t.Fatal("the scaffold already declares versioned tables")
	}
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), append(appYAML, []byte("\nversioned:\n  - notes\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "admin.yaml"), []byte("tables:\n  vault:\n    hidden: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	f := &adminFrameworkFixture{t: t, app: app, mux: buildAppMux(app, false, "http://panel.example.test")}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('root', 'root@example.com', 'admin', 1)")
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	if f.adminSID = CreateSession(app.DB, adminID, "root@example.com", "", time.Hour); f.adminSID == "" {
		t.Fatal("no admin session")
	}
	for _, q := range []string{
		// An app table of its own: the suffix and one column name in common
		// with a version history do not make it one.
		`CREATE TABLE visit_history (id INTEGER PRIMARY KEY, place TEXT, _version INTEGER)`,
		// What a versioned table leaves behind when its app.yaml entry goes:
		// the stored versions stay, and come back into use if it returns.
		`CREATE TABLE drafts (id INTEGER PRIMARY KEY, title TEXT)`,
		`CREATE TABLE drafts_history (id INTEGER, title TEXT, _version INTEGER NOT NULL, _valid_from DATETIME NOT NULL,
			_valid_to DATETIME NOT NULL DEFAULT (datetime('now')), _changed_by INTEGER, _change_type TEXT NOT NULL)`,
		`INSERT INTO drafts_history (id, title, _version, _valid_from, _change_type) VALUES (1, 'first draft', 1, datetime('now'), 'update')`,
		`CREATE TABLE vault (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO vault (id, name) VALUES (1, 'kept')`,
	} {
		mustExec(t, app.DB, q)
	}
	return f
}

func (f *adminFrameworkFixture) getJSON(path string) (int, map[string]any) {
	f.t.Helper()
	code, text := f.page(path)
	var body map[string]any
	json.Unmarshal([]byte(text), &body)
	return code, body
}

// noteWithTwoVersions creates a note through the panel and edits it twice, so
// notes_history holds version 1 (first) and version 2 (second) of it.
func (f *adminFrameworkFixture) noteWithTwoVersions(first, second, current string) string {
	f.t.Helper()
	w, body := f.post("/_admin/api/notes/create", url.Values{"title": {first}})
	id := fmt.Sprint(body["id"])
	if w.Code != http.StatusOK || body["id"] == nil {
		f.t.Fatalf("create a note: %d %s", w.Code, w.Body.String())
	}
	for _, title := range []string{second, current} {
		if w, _ := f.post("/_admin/api/notes/update/"+id, url.Values{"title": {title}}); w.Code != http.StatusOK {
			f.t.Fatalf("edit the note: %d %s", w.Code, w.Body.String())
		}
	}
	var versions int
	f.app.DB.QueryRow("SELECT COUNT(*) FROM notes_history WHERE id = ?", id).Scan(&versions)
	if versions != 2 {
		f.t.Fatalf("fixture: the note has %d stored versions, want 2", versions)
	}
	return id
}

func TestAdminPanelWritesNoVersionHistory(t *testing.T) {
	f := newAdminHistoryFixture(t)
	id := f.noteWithTwoVersions("signed off by legal", "signed off by legal and finance", "published")

	forged := url.Values{"id": {id}, "title": {"never written"}, "body": {""}, "user_id": {"1"},
		"_version": {"9"}, "_valid_from": {"2020-01-01 00:00:00"}, "_valid_to": {"2020-01-02 00:00:00"}, "_changed_by": {"1"}, "_change_type": {"update"}}
	// notes_history is the history of a table app.yaml versions; drafts_history
	// is the history a table left behind. Each also in another letter case.
	for _, table := range []string{"notes_history", "drafts_history"} {
		rowID := id
		if table == "drafts_history" {
			rowID = "1"
		}
		for _, name := range []string{table, strings.ToUpper(table)} {
			before := f.contents(table)
			for _, action := range []string{"create", "update/" + rowID, "delete/" + rowID} {
				w, body := f.post("/_admin/api/"+name+"/"+action, forged)
				msg, _ := body["message"].(string)
				if w.Code != http.StatusForbidden || body["error"] != "admin_table_read_only" || body["table"] != name ||
					!strings.Contains(msg, name) || !strings.Contains(msg, "version history") || !strings.Contains(msg, "never writes it") ||
					body["docs"] != "versioning.history_table" {
					t.Errorf("POST /_admin/api/%s/%s: %d %s, want 403 admin_table_read_only naming the table with the versioning docs pointer", name, action, w.Code, strings.TrimSpace(w.Body.String()))
				}
			}
			if after := f.contents(table); after != before {
				t.Errorf("%s changed through the admin panel:\nbefore:\n%safter:\n%s", table, before, after)
			}
		}
		for _, path := range []string{"/_admin/" + table, "/_admin/" + table + "/" + rowID} {
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
	}
}

// What the history is for keeps working: the versions API lists and returns
// the stored versions, a revert restores one, and the edit a revert makes is
// itself recorded by the table's history trigger.
func TestVersionsAndRevertWorkWithReadOnlyHistoryInThePanel(t *testing.T) {
	f := newAdminHistoryFixture(t)
	id := f.noteWithTwoVersions("first wording", "second wording", "third wording")
	// The refused panel writes of the test above, on this row.
	f.post("/_admin/api/notes_history/update/"+id, url.Values{"title": {"rewritten"}})
	f.post("/_admin/api/notes_history/delete/"+id, url.Values{})

	code, body := f.getJSON("/api/notes/" + id + "/versions")
	versions, _ := body["versions"].([]any)
	if code != http.StatusOK || len(versions) != 2 {
		t.Fatalf("GET versions: %d %v, want the two stored versions", code, body)
	}
	if code, body = f.getJSON("/api/notes/" + id + "/versions/1"); code != http.StatusOK || !strings.Contains(fmt.Sprint(body), "first wording") {
		t.Fatalf("GET version 1: %d %v, want the first wording", code, body)
	}
	w, reverted := f.post("/api/notes/"+id+"/revert/1", url.Values{})
	if w.Code != http.StatusOK || reverted["status"] != "reverted" {
		t.Fatalf("revert to version 1: %d %s", w.Code, w.Body.String())
	}
	var title string
	f.app.DB.QueryRow("SELECT title FROM notes WHERE id = ?", id).Scan(&title)
	if title != "first wording" {
		t.Errorf("after the revert the note reads %q, want the first wording", title)
	}
	var stored int
	var latest string
	f.app.DB.QueryRow("SELECT COUNT(*) FROM notes_history WHERE id = ?", id).Scan(&stored)
	f.app.DB.QueryRow("SELECT title FROM notes_history WHERE id = ? ORDER BY _version DESC LIMIT 1", id).Scan(&latest)
	if stored != 3 || latest != "third wording" {
		t.Errorf("after the revert the note has %d stored versions, the latest %q; want 3 and the wording the revert replaced", stored, latest)
	}
}

// An app table that only has the suffix is the app's own and is written
// through the panel like any other.
func TestAdminPanelStillWritesAnAppTableNamedLikeHistory(t *testing.T) {
	f := newAdminHistoryFixture(t)
	if kind := adminPanelReadOnlyKind(f.app, "visit_history"); kind != "" {
		t.Fatalf("visit_history is read-only in the panel (%s)", kind)
	}
	place := func(id string) (v string) {
		f.app.DB.QueryRow("SELECT place FROM visit_history WHERE id = ?", id).Scan(&v)
		return v
	}
	w, body := f.post("/_admin/api/visit_history/create", url.Values{"place": {"harbour"}})
	id := fmt.Sprint(body["id"])
	if w.Code != http.StatusOK || place(id) != "harbour" {
		t.Fatalf("create a visit: %d %s", w.Code, w.Body.String())
	}
	if w, _ = f.post("/_admin/api/visit_history/update/"+id, url.Values{"place": {"lighthouse"}}); w.Code != http.StatusOK || place(id) != "lighthouse" {
		t.Fatalf("edit a visit: %d %s, place %q", w.Code, w.Body.String(), place(id))
	}
	for _, path := range []string{"/_admin/visit_history", "/_admin/visit_history/" + id} {
		code, html := f.page(path)
		if code != http.StatusOK || strings.Contains(html, "never writes it") || !strings.Contains(html, "/_admin/api/visit_history/") {
			t.Errorf("GET %s: %d, want the page with its write controls and no read-only note", path, code)
		}
	}
	if w, _ = f.post("/_admin/api/visit_history/delete/"+id, url.Values{}); w.Code != http.StatusOK {
		t.Fatalf("delete a visit: %d %s", w.Code, w.Body.String())
	}
	var left int
	f.app.DB.QueryRow("SELECT COUNT(*) FROM visit_history WHERE id = ?", id).Scan(&left)
	if left != 0 {
		t.Errorf("the deleted visit is still there")
	}
	// The versioned table itself stays writable too (its fixture rows were
	// written through the panel).
	if kind := adminPanelReadOnlyKind(f.app, "notes"); kind != "" {
		t.Errorf("notes is read-only in the panel (%s)", kind)
	}
}

// A table admin.yaml hides has no page in the panel, and its write routes
// answer 404, in any letter case, with nothing written.
func TestAdminPanelDoesNotWriteAHiddenTable(t *testing.T) {
	f := newAdminHistoryFixture(t)
	for _, name := range []string{"vault", "VAULT", "Vault"} {
		before := f.contents("vault")
		for _, action := range []string{"create", "update/1", "delete/1"} {
			r := httptest.NewRequest(http.MethodPost, "/_admin/api/"+name+"/"+action, strings.NewReader(url.Values{"name": {"written through the panel"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Authorization", "Bearer "+f.adminSID)
			w := httptest.NewRecorder()
			f.mux.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("POST /_admin/api/%s/%s: %d %s, want 404", name, action, w.Code, strings.TrimSpace(w.Body.String()))
			}
		}
		if after := f.contents("vault"); after != before {
			t.Errorf("the hidden table changed through POST /_admin/api/%s:\nbefore:\n%safter:\n%s", name, before, after)
		}
		// Its pages are not the panel's either (this app answers an unknown
		// page with its own front end, so the status says nothing).
		for _, path := range []string{"/_admin/" + name, "/_admin/" + name + "/1"} {
			if _, html := f.page(path); strings.Contains(html, "kept") || strings.Contains(html, "/_admin/api/") || strings.Contains(html, "Back to list") {
				t.Errorf("GET %s shows the hidden table", path)
			}
		}
	}
	// The pages of a table that is not hidden do carry what was looked for.
	if _, html := f.page("/_admin/visit_history"); !strings.Contains(html, "/_admin/api/visit_history/") {
		t.Fatalf("fixture: a table page has no write control to look for")
	}
	// A table admin.yaml does not hide is unaffected.
	if w, _ := f.post("/_admin/api/notes/create", url.Values{"title": {"visible"}}); w.Code != http.StatusOK {
		t.Errorf("create in a table that is not hidden: %d %s", w.Code, w.Body.String())
	}
}
