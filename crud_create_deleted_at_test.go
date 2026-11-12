//go:build !cli && !windows

package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// softDeleteCreateFixture is an app with soft-delete tables: notes (owner
// rows), drafts (the column declared Deleted_At, which SQLite and the
// soft-delete filter treat as deleted_at) and prefs (one row per user, the
// singleton upsert's shape).
//
// The database is opened as a served app opens it. The mux built here starts
// workers that write (the context graph rebuild, the job worker's lease
// sweep) while the test sends requests. On the bare driver a request that
// meets one of them is refused at once with "database is locked": a
// transaction that reads before it writes (PATCH, restore, a transaction
// batch) asks for a lock upgrade, which SQLite never waits for. The served
// settings take the write lock when the transaction begins, and wait for it.
func softDeleteCreateFixture(t *testing.T) (*App, *http.ServeMux, string, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	prepareGateApp(t, app,
		"CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, deleted_at DATETIME)",
		"CREATE TABLE drafts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, Deleted_At DATETIME)",
		"CREATE TABLE prefs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, title TEXT, deleted_at DATETIME)",
	)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	_, sid := gateUser(t, app, "writer@softdelete.invalid")
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	return app, buildAppMux(app, true, "http://localhost"), sid, admin
}

// A create that sent deleted_at stored it: the row was written already in the
// trash, absent from every list and present in the table. deleted_at belongs
// to DELETE and restore, so every create path drops it like created_at and
// updated_at, and the single-row create names it in X-Stripped-Fields.
func TestCreateNeverStoresDeletedAt(t *testing.T) {
	app, mux, sid, admin := softDeleteCreateFixture(t)
	const sent = "2020-02-02 02:02:02"
	send := func(token, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://app.example.com"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	row := func(title, column string) []byte {
		return []byte(fmt.Sprintf(`{"title":%q,%q:%q}`, title, column, sent))
	}
	var form bytes.Buffer
	parts := multipart.NewWriter(&form)
	parts.WriteField("title", "single-multipart")
	parts.WriteField("deleted_at", sent)
	parts.Close()

	cases := []struct {
		name, table string
		do          func() *httptest.ResponseRecorder
		header      bool // a single-row create names what it dropped
	}{
		{"single-json", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/notes", "application/json", row("single-json", "deleted_at"))
		}, true},
		{"single-form", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/notes", "application/x-www-form-urlencoded", []byte(url.Values{"title": {"single-form"}, "deleted_at": {sent}}.Encode()))
		}, true},
		{"single-multipart", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/notes", parts.FormDataContentType(), form.Bytes())
		}, true},
		{"single-declared-case", "drafts", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/drafts", "application/json", row("single-declared-case", "Deleted_At"))
		}, true},
		{"batch", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/notes/batch", "application/json", []byte("["+string(row("batch", "deleted_at"))+"]"))
		}, false},
		{"batch-declared-case", "drafts", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/drafts/batch", "application/json", []byte("["+string(row("batch-declared-case", "Deleted_At"))+"]"))
		}, false},
		{"ingest", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/notes/ingest", "application/x-ndjson", append(row("ingest", "deleted_at"), '\n'))
		}, false},
		{"transaction", "notes", func() *httptest.ResponseRecorder {
			return send(sid, "POST", "/api/_transaction", "application/json", []byte(`{"operations":[{"table":"notes","action":"insert","data":`+string(row("transaction", "deleted_at"))+`}]}`))
		}, false},
		{"singleton-upsert", "prefs", func() *httptest.ResponseRecorder {
			return send(sid, "PATCH", "/api/prefs", "application/json", row("singleton-upsert", "deleted_at"))
		}, true},
		{"admin-panel", "notes", func() *httptest.ResponseRecorder {
			return send(admin, "POST", "/_admin/api/notes/create", "application/x-www-form-urlencoded", []byte(url.Values{"title": {"admin-panel"}, "deleted_at": {sent}}.Encode()))
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := c.do()
			var deleted any
			if err := app.DB.QueryRow("SELECT CAST(deleted_at AS TEXT) FROM "+c.table+" WHERE title = ?", c.name).Scan(&deleted); err != nil {
				t.Fatalf("the created row: %v (%s)", err, w.Body.String())
			}
			if deleted != nil {
				t.Errorf("the create stored deleted_at %v: the row was created soft-deleted", deleted)
			}
			if c.header && !strings.Contains(strings.ToLower(w.Header().Get("X-Stripped-Fields")), "deleted_at") {
				t.Errorf("X-Stripped-Fields = %q, want it to name deleted_at", w.Header().Get("X-Stripped-Fields"))
			}
			// The row is live: its creator's list returns it.
			token := sid
			if c.name == "admin-panel" {
				token = admin
			}
			if list := send(token, "GET", "/api/"+c.table, "application/json", nil); !strings.Contains(list.Body.String(), `"`+c.name+`"`) {
				t.Errorf("the list does not return the created row: %s", list.Body.String())
			}
		})
	}

	// An object naming only deleted_at is an object naming only protected
	// keys: on a table with an owner column it inserts the caller's row with
	// the column defaults, live like any other.
	send(sid, "POST", "/api/notes/batch", "application/json", []byte(`[{"deleted_at":"`+sent+`"}]`))
	for _, table := range []string{"notes", "drafts", "prefs"} {
		if n := gateScalar(t, app, "SELECT COUNT(*) FROM "+table+" WHERE deleted_at IS NOT NULL"); n != "0" {
			t.Errorf("%s holds %s row(s) created soft-deleted", table, n)
		}
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM notes WHERE title IS NULL"); n != "1" {
		t.Errorf("a batch object of only deleted_at wrote %s row(s), want the caller's one default row", n)
	}

	// The admin panel's create form offers no input for the column.
	page := send(admin, "GET", "/_admin/notes", "text/html", nil).Body.String()
	fields := adminFormFields(t, page, "/_admin/api/notes/create")
	if _, offered := fields["deleted_at"]; offered {
		t.Errorf("the admin create form offers an input for deleted_at, whose value a create drops")
	}
	if _, offered := fields["title"]; !offered {
		t.Errorf("the admin create form lost the input for title")
	}
}

// Soft delete and restore still own the column: DELETE sets it, the restore
// route clears it, and a PATCH that sends it changes nothing about it (as
// before: no update writes deleted_at).
func TestDeleteAndRestoreStillOwnDeletedAt(t *testing.T) {
	app, mux, sid, _ := softDeleteCreateFixture(t)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	deletedAt := func(id string) any {
		t.Helper()
		var v any
		if err := app.DB.QueryRow("SELECT CAST(deleted_at AS TEXT) FROM notes WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	listed := func() bool {
		return strings.Contains(call("GET", "/api/notes", "").Body.String(), `"kept"`)
	}
	if w := call("POST", "/api/notes", `{"title":"kept"}`); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := gateScalar(t, app, "SELECT id FROM notes WHERE title = 'kept'")

	if w := call("DELETE", "/api/notes/"+id, ""); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if deletedAt(id) == nil || listed() {
		t.Fatalf("after DELETE: deleted_at %v, listed %v; want a soft-deleted row no list returns", deletedAt(id), listed())
	}
	if w := call("POST", "/api/notes/"+id+"/restore", ""); w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	if deletedAt(id) != nil || !listed() {
		t.Fatalf("after restore: deleted_at %v, listed %v; want the live row back", deletedAt(id), listed())
	}

	// A PATCH naming deleted_at saves the other fields and reports the drop.
	w := call("PATCH", "/api/notes/"+id, `{"title":"kept","deleted_at":"2020-02-02 02:02:02"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("X-Stripped-Fields"), "deleted_at") {
		t.Fatalf("patch: %d, X-Stripped-Fields %q, body %s", w.Code, w.Header().Get("X-Stripped-Fields"), w.Body.String())
	}
	if deletedAt(id) != nil || !listed() {
		t.Fatalf("a PATCH wrote deleted_at %v", deletedAt(id))
	}
}

// POST /api/_groups/create builds the organization row from the request with
// the same protected set, so a founder cannot create a soft-deleted tenant.
func TestGroupBootstrapNeverStoresDeletedAt(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	EnsureSessionsTable(db)
	EnsureAuditLogTable(db)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, user_id INTEGER, Deleted_At DATETIME)")
	mustExec(t, db, "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, user_id INTEGER)")
	app.Group = &GroupConfig{
		Table: "company_members", Key: "company_id", UserField: "user_id",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies"},
	}
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('founder', 'founder@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(db, uid, "founder@example.com", "", time.Hour)

	if w := bootstrapAs(app, sid, `{"name":"Acme","Deleted_At":"2020-02-02 02:02:02"}`); w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var deleted any
	if err := db.QueryRow("SELECT CAST(Deleted_At AS TEXT) FROM companies WHERE name = 'Acme'").Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != nil {
		t.Errorf("the organization was created with deleted_at %v", deleted)
	}
}
