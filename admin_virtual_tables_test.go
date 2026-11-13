//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The admin panel's write routes ran generic create, update and delete on a
// full-text index's own tables. `<table>_fts_data` and `<table>_fts_docsize`
// have an id column, so the writes went through: the index's records were
// replaced, and every later create on the indexed table failed. The panel
// shows a virtual table and its shadow tables and never writes them. Which
// tables those are is the engine's answer, not a name's.

// adminTableDump is every row of table as sorted text (an index table has no
// rowid to order by).
func adminTableDump(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.Query("SELECT * FROM " + quoteIdent(table))
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var lines []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}
		lines = append(lines, fmt.Sprintf("%x", fmt.Sprint(vals...)))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestAdminPanelWritesNoVirtualOrShadowTable(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: \"index-tables\"\n")
	writeTestFile(t, dir, "schema.prisma", "model Doc {\n  id    Int     @id @default(autoincrement())\n  title String\n  note  String?\n\n  @@fulltext([title, note])\n  @@map(\"docs\")\n}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "https://fixture.example")
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	// An app table of its own that is named like an index table and is none.
	mustExec(t, app.DB, `CREATE TABLE notes_fts_data (id INTEGER PRIMARY KEY, block TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes_fts_data (id, block) VALUES (1, 'app row')`)

	create := func(title string) *http.Response {
		t.Helper()
		return crudScopeRequest(t, mux, http.MethodPost, "/api/docs", admin, map[string]any{"title": title}).Result()
	}
	for i := 1; i <= 3; i++ {
		if res := create(fmt.Sprintf("searchable document %d", i)); res.StatusCode != http.StatusOK {
			t.Fatalf("fixture: create a doc: %d", res.StatusCode)
		}
	}
	search := func(term string) string {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/docs?q="+term, admin, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("search %s: %d %s", term, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	if !strings.Contains(search("searchable"), "searchable document 2") {
		t.Fatal("fixture: search does not find the docs")
	}

	// The index's tables, as the engine names them.
	rows, err := app.DB.Query(`SELECT name, type FROM pragma_table_list WHERE schema = 'main' AND type IN ('virtual', 'shadow') ORDER BY name`)
	if err != nil {
		t.Fatalf("PRAGMA table_list through the app's connection: %v", err)
	}
	kinds := map[string]string{}
	var names []string
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			t.Fatal(err)
		}
		kinds[name] = kind
		names = append(names, name)
	}
	rows.Close()
	if kinds["docs_fts"] != "virtual" || kinds["docs_fts_data"] != "shadow" || kinds["docs_fts_docsize"] != "shadow" || len(names) < 5 {
		t.Fatalf("fixture: the engine lists %v as virtual and shadow tables", kinds)
	}

	// Every field any of those tables has, so a create would have something
	// to store.
	form := url.Values{"block": {"x"}, "sz": {"x"}, "k": {"version"}, "v": {"9"}, "segid": {"1"}, "term": {"x"}, "pgno": {"1"}, "title": {"x"}, "note": {"x"}, "id": {"77"}}.Encode()
	for _, name := range names {
		before := adminTableDump(t, app.DB, name)
		for _, spelled := range []string{name, strings.ToUpper(name)} {
			for _, action := range []string{"create", "update/1", "delete/1"} {
				rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/"+spelled+"/"+action, admin, "application/x-www-form-urlencoded", form)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"admin_table_read_only"`) {
					t.Errorf("POST /_admin/api/%s/%s (%s table): %d %s, want 403 admin_table_read_only", spelled, action, kinds[name], rec.Code, strings.TrimSpace(rec.Body.String()))
				}
			}
		}
		if after := adminTableDump(t, app.DB, name); after != before {
			t.Errorf("%s changed through the admin panel", name)
		}
		// Its page is shown without a write control.
		page := crudScopeRequest(t, mux, http.MethodGet, "/_admin/"+name, admin, nil)
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), "/_admin/api/"+name+"/") || !strings.Contains(page.Body.String(), "never writes it") {
			t.Errorf("GET /_admin/%s: %d, want the table shown with the read-only note and no create, edit or delete control", name, page.Code)
		}
	}

	// The indexed table is as it was: creates work, search finds the new row,
	// and the index is consistent.
	if res := create("later zebra entry"); res.StatusCode != http.StatusOK {
		t.Errorf("a create on the indexed table after the panel requests: %d", res.StatusCode)
	}
	if !strings.Contains(search("zebra"), "later zebra entry") || !strings.Contains(search("searchable"), "searchable document 2") {
		t.Error("search no longer finds the indexed rows")
	}
	if _, err := app.DB.Exec(`INSERT INTO docs_fts(docs_fts) VALUES('integrity-check')`); err != nil {
		t.Errorf("the full-text index is inconsistent: %v", err)
	}
	// The indexed table itself stays the panel's to write.
	if rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/docs/create", admin, "application/x-www-form-urlencoded", url.Values{"title": {"made in the panel"}}.Encode()); rec.Code != http.StatusOK {
		t.Errorf("create on the indexed table through the panel: %d %s", rec.Code, rec.Body.String())
	}

	// The look-alike app table is written like any app table.
	if kind := adminPanelReadOnlyKind(app, "notes_fts_data"); kind != "" {
		t.Errorf("an app table named notes_fts_data is read-only in the panel (%s)", kind)
	}
	if rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/notes_fts_data/create", admin, "application/x-www-form-urlencoded", url.Values{"block": {"written"}}.Encode()); rec.Code != http.StatusOK {
		t.Errorf("create on the look-alike app table: %d %s", rec.Code, rec.Body.String())
	}
	if rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/notes_fts_data/update/1", admin, "application/x-www-form-urlencoded", url.Values{"block": {"edited"}}.Encode()); rec.Code != http.StatusOK {
		t.Errorf("update on the look-alike app table: %d %s", rec.Code, rec.Body.String())
	}
	var edited string
	var count int
	app.DB.QueryRow(`SELECT block FROM notes_fts_data WHERE id = 1`).Scan(&edited)
	app.DB.QueryRow(`SELECT COUNT(*) FROM notes_fts_data WHERE block = 'written'`).Scan(&count)
	if edited != "edited" || count != 1 {
		t.Errorf("the look-alike app table holds block %q for row 1 and %d created rows", edited, count)
	}
	if page := crudScopeRequest(t, mux, http.MethodGet, "/_admin/notes_fts_data", admin, nil); !strings.Contains(page.Body.String(), "/_admin/api/notes_fts_data/create") {
		t.Error("the look-alike app table's page lost its create form")
	}
}

// When the engine cannot be asked what a table is, the panel does not write it.
func TestAdminPanelReadOnlyKindFailsClosedWithoutTheTableList(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
	app := &App{Dir: dir, DB: db}
	if kind := adminPanelReadOnlyKind(app, "notes"); kind != "" {
		t.Fatalf("an app table is read-only (%s) while the table list can be read", kind)
	}
	_ = db.Close()
	if kind := adminPanelReadOnlyKind(app, "notes"); kind == "" {
		t.Fatal("with the table list unreadable, the panel still writes the table")
	}
}
