//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func legacyQueryPage(extra, query string) string {
	encoded, _ := json.Marshal(query)
	return "---\nengine: gotmpl\n" + extra + "queries:\n  rows: " + string(encoded) + "\n---\n<pre id=\"report\">{{ toJson .rows }}</pre>"
}

// legacyQueryRows renders a page through the real mux and returns .rows.
func legacyQueryRows(t *testing.T, mux *http.ServeMux, route, actor string) []map[string]any {
	t.Helper()
	return reportFixtureRows(t, ssrGet(mux, route, actor))
}

func legacyQueryFixture(t *testing.T, pages map[string]string) (*App, *http.ServeMux) {
	t.Helper()
	app, _ := newTenantEncryptionFixture(t)
	ssrLoadPages(t, app, pages)
	return app, buildAppMux(app, false, "https://report.example.invalid")
}

func assertMasked(t *testing.T, what string, value any, plaintext string) {
	t.Helper()
	text := fmt.Sprint(value)
	if !strings.Contains(text, "*") || strings.Contains(text, plaintext) {
		t.Fatalf("%s: got %q, want a mask of %q", what, text, plaintext)
	}
}

// The reported leak: a member with no unmask role read plaintext through
// queries: while /api/_query and sources: showed the mask.
func TestGotmplQueriesMaskLikeNativeQuery(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"legacy.html": legacyQueryPage("", "SELECT private_note FROM projects ORDER BY id"),
		"tenant.html": legacyQueryPage("", "SELECT company_id, private_note FROM projects ORDER BY id"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	reviewer, _ := tenantMember(t, app, "reviewer@example.com", "user", 1, "company_admin")
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")

	spec := map[string]any{"table": "projects", "select": []string{"company_id", "private_note"}, "order_by": []map[string]string{{"col": "id"}}}
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", viewer, spec)
	var native struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &native); err != nil || len(native.Rows) != 2 {
		t.Fatalf("native query: %d %s", w.Code, w.Body.String())
	}
	rows := legacyQueryRows(t, mux, "/tenant", viewer)
	for i := range rows {
		if rows[i]["private_note"] != native.Rows[i]["private_note"] {
			t.Fatalf("row %d: legacy %v differs from native %v", i, rows[i], native.Rows[i])
		}
	}
	assertMasked(t, "viewer", rows[0]["private_note"], "acme-private-note")

	// A tenant role unmasks only its own tenant, read from the source row.
	rows = legacyQueryRows(t, mux, "/tenant", reviewer)
	if rows[0]["private_note"] != "acme-private-note" {
		t.Fatalf("tenant role in its own tenant: %v", rows[0])
	}
	assertMasked(t, "tenant role in another tenant", rows[1]["private_note"], "globex-private-note")

	// Without the tenant column the row cannot prove its tenant: masked.
	rows = legacyQueryRows(t, mux, "/legacy", reviewer)
	assertMasked(t, "tenant role, tenant not selected", rows[0]["private_note"], "acme-private-note")

	// A global unmask decision needs no row identity.
	rows = legacyQueryRows(t, mux, "/legacy", admin)
	if rows[0]["private_note"] != "acme-private-note" || rows[1]["private_note"] != "globex-private-note" {
		t.Fatalf("global admin: %v", rows)
	}

	app.Encrypted.Fields["projects"][0].Roles = []string{"auditor"}
	auditor := createCrudScopeSession(t, app, "auditor@example.com", "auditor", "", "")
	rows = legacyQueryRows(t, mux, "/legacy", auditor)
	if rows[0]["private_note"] != "acme-private-note" {
		t.Fatalf("global unmask role: %v", rows[0])
	}
	rows = legacyQueryRows(t, mux, "/legacy", viewer)
	assertMasked(t, "no unmask role", rows[0]["private_note"], "acme-private-note")

	// A field declared without roles stays readable by every reader.
	app.Encrypted.Fields["projects"][0].Roles = nil
	if rows = legacyQueryRows(t, mux, "/legacy", viewer); rows[0]["private_note"] != "acme-private-note" {
		t.Fatalf("no unmask roles declared: %v", rows[0])
	}
}

// A result name is not provenance: every spelling of the read stays masked.
func TestGotmplQueriesMaskEveryShapeOfTheRead(t *testing.T) {
	queries := map[string]string{
		"alias":   "SELECT private_note AS contact FROM projects ORDER BY id",
		"qualify": "SELECT p.private_note AS contact FROM projects p ORDER BY p.id",
		"join":    "SELECT p.name, c.private_note FROM projects p JOIN companies c ON c.id = p.company_id ORDER BY p.id",
		"sub":     "SELECT name, (SELECT private_note FROM companies c WHERE c.id = p.company_id) AS contact FROM projects p ORDER BY p.id",
		"cte":     "WITH x AS (SELECT private_note AS contact, id FROM projects) SELECT contact FROM x ORDER BY id",
		"view":    "SELECT note FROM project_notes ORDER BY id",
		"union":   "SELECT private_note AS contact FROM projects UNION ALL SELECT private_note FROM companies",
		"expr":    "SELECT private_note || '' AS contact FROM projects ORDER BY id",
		"decrypt": "SELECT benmore_decrypt(private_note) AS private_note FROM projects ORDER BY id",
		"star":    "SELECT * FROM projects ORDER BY id",
		"max":     "SELECT MAX(private_note) AS contact FROM projects",
	}
	pages := map[string]string{}
	for name, query := range queries {
		pages[name+".html"] = legacyQueryPage("", query)
	}
	app, mux := legacyQueryFixture(t, pages)
	crudScopeMustExec(t, app.DB, "CREATE VIEW project_notes AS SELECT id, private_note AS note FROM projects")
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	for name := range queries {
		w := ssrGet(mux, "/"+name, viewer)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
		body := html.UnescapeString(w.Body.String())
		if strings.Contains(body, "acme-private-note") || strings.Contains(body, "globex-private-note") || strings.Contains(body, "enc:v") {
			t.Fatalf("%s leaked: %s", name, body)
		}
		if !strings.Contains(body, "***") {
			t.Fatalf("%s rendered no mask: %s", name, body)
		}
	}
}

// Ciphertext copied into an ordinary column keeps the policy it was sealed
// under, so a page cannot be used as a decrypt oracle; a column of the same
// name that the query did not read from an encrypted field is left alone.
func TestGotmplQueriesCiphertextProvenance(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"copied.html":  legacyQueryPage("", "SELECT name FROM brokers WHERE id = 1"),
		"context.html": legacyQueryPage("", "SELECT name FROM brokers WHERE id = 2"),
		"plain.html":   legacyQueryPage("", "SELECT private_note FROM memos"),
	})
	crudScopeMustExec(t, app.DB, "CREATE TABLE memos (id INTEGER PRIMARY KEY, private_note TEXT)")
	crudScopeMustExec(t, app.DB, "INSERT INTO memos (private_note) VALUES ('open memo')")
	var cipher string
	if err := app.DB.QueryRow("SELECT private_note FROM projects WHERE id = 1").Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("UPDATE brokers SET name = ? WHERE id = 1", cipher); err != nil {
		t.Fatal(err)
	}
	// Sealed with no field context, it matches no declared policy.
	if _, err := app.DB.Exec("UPDATE brokers SET name = benmore_encrypt('contextless') WHERE id = 2"); err != nil {
		t.Fatal(err)
	}
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	rows := legacyQueryRows(t, mux, "/copied", viewer)
	assertMasked(t, "copied ciphertext", rows[0]["name"], "acme-private-note")
	rows = legacyQueryRows(t, mux, "/context", viewer)
	assertMasked(t, "context-free ciphertext", rows[0]["name"], "contextless")
	if rows = legacyQueryRows(t, mux, "/plain", viewer); rows[0]["private_note"] != "open memo" {
		t.Fatalf("an unencrypted same-named column was masked: %v", rows)
	}
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	if rows = legacyQueryRows(t, mux, "/copied", admin); rows[0]["name"] != "acme-private-note" {
		t.Fatalf("entitled viewer of copied ciphertext: %v", rows)
	}
}

// Owner unmask needs a row the query proves is the viewer's. /api/_query adds
// user_id itself; authored SQL cannot be rewritten, so only provable shapes
// count and anything else stays masked.
func TestGotmplQueriesOwnerUnmaskNeedsProvenRowIdentity(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"projected.html": legacyQueryPage("", "SELECT user_id, private_note FROM projects ORDER BY id"),
		"star.html":      legacyQueryPage("", "SELECT * FROM projects ORDER BY id"),
		"qualified.html": legacyQueryPage("", "SELECT p.user_id, p.private_note FROM projects AS p ORDER BY p.id"),
		"scoped.html":    legacyQueryPage("scope: owner\nauth: required\n", "SELECT private_note FROM projects"),
		"where.html":     legacyQueryPage("", "SELECT private_note FROM projects WHERE user_id = :user_id ORDER BY id"),
		"whereand.html":  legacyQueryPage("", "SELECT p.private_note FROM projects p WHERE p.name IS NOT NULL AND p.user_id = :user_id"),
		"bare.html":      legacyQueryPage("", "SELECT private_note FROM projects ORDER BY id"),
		"forged.html":    legacyQueryPage("", "SELECT :user_id AS user_id, private_note FROM projects ORDER BY id"),
		"shadow.html":    legacyQueryPage("", "SELECT user_id, :user_id AS user_id, private_note FROM projects ORDER BY id"),
		"orwhere.html":   legacyQueryPage("", "SELECT private_note FROM projects WHERE user_id = :user_id OR 1=1 ORDER BY id"),
		"selfjoin.html":  legacyQueryPage("", "SELECT a.user_id, b.private_note FROM projects a JOIN projects b ON b.id <> a.id ORDER BY a.id"),
		"comma.html":     legacyQueryPage("", "SELECT a.user_id, b.private_note FROM projects a, projects b WHERE b.id <> a.id ORDER BY a.id"),
	})
	owner, ownerID := tenantMember(t, app, "owner@example.com", "user", 1, "viewer")
	peer, peerID := tenantMember(t, app, "peer@example.com", "user", 2, "viewer")
	app.Encrypted.Fields["projects"][0].Roles = []string{"owner"}
	for _, row := range []struct{ id, uid int64 }{{1, ownerID}, {2, peerID}} {
		if _, err := app.DB.Exec("UPDATE projects SET user_id=? WHERE id=?", row.uid, row.id); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []string{"/projected", "/star", "/qualified"} {
		rows := legacyQueryRows(t, mux, route, owner)
		if rows[0]["private_note"] != "acme-private-note" {
			t.Fatalf("%s: own row: %v", route, rows[0])
		}
		assertMasked(t, route+" other row", rows[1]["private_note"], "globex-private-note")
	}
	for _, route := range []string{"/scoped", "/where", "/whereand"} {
		rows := legacyQueryRows(t, mux, route, owner)
		if len(rows) != 1 || rows[0]["private_note"] != "acme-private-note" {
			t.Fatalf("%s: rows proven to be the viewer's: %v", route, rows)
		}
	}
	for _, route := range []string{"/bare", "/forged", "/shadow", "/orwhere"} {
		for _, row := range legacyQueryRows(t, mux, route, owner) {
			assertMasked(t, route, row["private_note"], "-private-note")
		}
	}
	for _, route := range []string{"/selfjoin", "/comma"} {
		// The peer's own user_id joined to the owner's note: the identity
		// in the row is not the note's.
		for _, row := range legacyQueryRows(t, mux, route, peer) {
			assertMasked(t, route, row["private_note"], "-private-note")
		}
	}
}

func TestGotmplQueriesStripHiddenColumns(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"star.html":  legacyQueryPage("", "SELECT * FROM companies ORDER BY id"),
		"named.html": legacyQueryPage("", "SELECT name, api_key, private_note_blind FROM companies ORDER BY id"),
		"where.html": legacyQueryPage("", "SELECT name FROM companies WHERE api_key = 'must-stay-hidden' ORDER BY id"),
	})
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN api_key TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE companies SET api_key='must-stay-hidden'")
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	for _, route := range []string{"/star", "/named"} {
		rows := legacyQueryRows(t, mux, route, viewer)
		if len(rows) != 2 {
			t.Fatalf("%s: %v", route, rows)
		}
		for _, row := range rows {
			if _, ok := row["api_key"]; ok {
				t.Fatalf("%s: credential column disclosed: %v", route, row)
			}
			if _, ok := row["private_note_blind"]; ok {
				t.Fatalf("%s: blind index disclosed: %v", route, row)
			}
			if row["name"] == nil {
				t.Fatalf("%s: ordinary column dropped: %v", route, row)
			}
		}
	}
	// Reading a hidden column to find a row is not returning it.
	if rows := legacyQueryRows(t, mux, "/where", viewer); len(rows) != 2 {
		t.Fatalf("hidden column in WHERE: %v", rows)
	}
}

func TestGotmplQueriesWriteReadAudit(t *testing.T) {
	app, _ := newTenantEncryptionFixture(t)
	ssrLoadPages(t, app, map[string]string{
		"join.html":   legacyQueryPage("", "SELECT p.name, c.name AS company FROM projects p JOIN companies c ON c.id = p.company_id"),
		"count.html":  legacyQueryPage("", "SELECT COUNT(*) AS n FROM projects"),
		"view.html":   legacyQueryPage("", "SELECT id FROM project_ids"),
		"other.html":  legacyQueryPage("", "SELECT name FROM brokers"),
		"broken.html": legacyQueryPage("", "SELECT nope FROM projects"),
	})
	crudScopeMustExec(t, app.DB, "CREATE VIEW project_ids AS SELECT id FROM projects")
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "projects,companies"}}
	InitReadAudit(app, false)
	mux := buildAppMux(app, false, "https://report.example.invalid")
	viewer, uid := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")

	count := func(table string) int {
		t.Helper()
		FlushReadAudit(app)
		var n int
		if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE table_name=? AND user_id=? AND query_type='page_query'", table, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	get := func(route string, want int) {
		t.Helper()
		if w := ssrGet(mux, route, viewer); w.Code != want {
			t.Fatalf("%s: %d %s", route, w.Code, w.Body.String())
		}
	}
	get("/join", http.StatusOK)
	if p, c := count("projects"), count("companies"); p != 1 || c != 1 {
		t.Fatalf("a join must audit both tables once: projects=%d companies=%d", p, c)
	}
	get("/count", http.StatusOK)
	if p := count("projects"); p != 2 {
		t.Fatalf("COUNT(*) reads the table: projects=%d", p)
	}
	get("/view", http.StatusOK)
	if p := count("projects"); p != 3 {
		t.Fatalf("a view is audited as the table it reads: projects=%d", p)
	}
	get("/other", http.StatusOK)
	if b := count("brokers"); b != 0 {
		t.Fatalf("an unlisted table was audited: %d", b)
	}
	get("/broken", http.StatusInternalServerError)
	if p := count("projects"); p != 3 {
		t.Fatalf("a failed query logged a read: projects=%d", p)
	}
	// The reported shape, end to end, through the read-audit API.
	w := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit/reads?table=projects", viewer, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "page_query") {
		t.Fatalf("/api/_audit/reads: %d %s", w.Code, w.Body.String())
	}
}

// A failed query must not look like an empty result. Bad SQL and the deadline
// both used to answer 200 with empty data outside dev mode.
func TestGotmplFailedQueryIsAVisibleError(t *testing.T) {
	const marker = "partial-render-marker"
	page := "---\nengine: gotmpl\nqueries:\n  rows: SELECT nope FROM projects\n---\n<h1>" + marker + "</h1>{{range .rows}}{{.nope}}{{end}}"
	single := "---\nengine: gotmpl\nqueries:\n  row: SELECT nope FROM projects LIMIT 1\n---\n<h1>" + marker + "</h1>{{.row.nope}}"
	slow := "---\nengine: gotmpl\nqueries:\n  rows: WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) AS n FROM c\n---\n<h1>" + marker + "</h1>{{range .rows}}{{.n}}{{end}}"
	app, mux := legacyQueryFixture(t, map[string]string{"bad.html": page, "single.html": single, "slow.html": slow})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")

	assertGeneric := func(w *httptest.ResponseRecorder) {
		t.Helper()
		body := w.Body.String()
		if w.Code != http.StatusInternalServerError || strings.Contains(body, marker) {
			t.Fatalf("failed query rendered: %d %s", w.Code, body)
		}
		id := w.Header().Get(requestIDHeader)
		if id == "" || !strings.Contains(body, id) {
			t.Fatalf("no request id in the answer: header %q body %s", id, body)
		}
		for _, secret := range []string{"nope", "no such column", "SELECT", "RECURSIVE", "deadline"} {
			if strings.Contains(body, secret) {
				t.Fatalf("production answer disclosed %q: %s", secret, body)
			}
		}
	}
	assertGeneric(ssrGet(mux, "/bad", viewer))
	assertGeneric(ssrGet(mux, "/single", viewer))

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Authorization", "Bearer "+viewer)
	deadline, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req.WithContext(deadline))
	assertGeneric(rec)

	// Dev keeps its detailed message.
	app.DevMode = true
	if w := ssrGet(buildAppMux(app, true, "http://localhost"), "/bad", viewer); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "nope") {
		t.Fatalf("dev answer lost its detail: %d %s", w.Code, w.Body.String())
	}
}

// The page query pins a connection, so it must not need a second one while it
// scans: on a one-connection pool that would hang.
func TestGotmplQueriesOnASingleConnectionPool(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"legacy.html": legacyQueryPage("", "SELECT private_note FROM projects ORDER BY id"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	app.DB.SetMaxOpenConns(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, actor := range []string{viewer, admin} {
			if w := ssrGet(mux, "/legacy", actor); w.Code != http.StatusOK {
				t.Errorf("status %d: %s", w.Code, w.Body.String())
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("page query deadlocked on a one-connection pool")
	}
}

// With a storage ceiling the connection's default authorizer stays in force
// during a page query and comes back after it: a page's SQL can no more lift
// the ceiling than any other app SQL, and a pooled connection must not keep
// the page's recording authorizer.
func TestGotmplQueriesKeepStorageCeilingAuthorizer(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"lift.html":   legacyQueryPage("", "PRAGMA max_page_count = 999999"),
		"legacy.html": legacyQueryPage("", "SELECT name FROM projects"),
	})
	path := filepath.Join(app.Dir, "data.db")
	setDBStorageLimit(path, 1<<30)
	t.Cleanup(func() { dbStorageLimits.Delete(canonicalDBPath(path)) })
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	app.DB.SetMaxOpenConns(1)
	if w := ssrGet(mux, "/lift", viewer); w.Code != http.StatusInternalServerError {
		t.Fatalf("a page query set a storage-ceiling pragma: %d %s", w.Code, w.Body.String())
	}
	if w := ssrGet(mux, "/legacy", viewer); w.Code != http.StatusOK {
		t.Fatalf("page after refusal: %d %s", w.Code, w.Body.String())
	}
	if _, err := app.DB.Exec("PRAGMA max_page_count = 999999"); err == nil {
		t.Fatal("pooled connection lost the storage ceiling authorizer")
	}
}

func TestParsePageQuerySource(t *testing.T) {
	for _, tc := range []struct {
		sql    string
		table  string
		owner  bool
		bare   []string
		denied []string
	}{
		{sql: "SELECT a, user_id FROM t", table: "t", bare: []string{"user_id", "a"}, denied: []string{"b"}},
		{sql: `SELECT "t"."user_id" FROM "t";`, table: "t", bare: []string{"user_id"}},
		{sql: "select * from t order by id", table: "t", bare: []string{"user_id", "anything"}},
		{sql: "SELECT x.* FROM t AS x WHERE x.id = 1", table: "t", bare: []string{"user_id"}},
		{sql: "SELECT a FROM t x LIMIT 1", table: "t", bare: []string{"a"}},
		{sql: "SELECT user_id AS user_id FROM t", table: "t", bare: []string{"user_id"}},
		{sql: "SELECT a AS user_id FROM t", table: "t", denied: []string{"user_id"}},
		{sql: "SELECT a user_id FROM t", table: "t", denied: []string{"user_id"}},
		{sql: "SELECT user_id, 1 AS user_id FROM t", table: "t", denied: []string{"user_id"}},
		{sql: "SELECT *, 1 AS user_id FROM t", table: "t", denied: []string{"user_id"}},
		{sql: "SELECT a FROM t WHERE user_id = :user_id", table: "t", owner: true},
		{sql: "SELECT a FROM t WHERE x = 1 AND t.user_id = :user_id AND y = 2 ORDER BY a", table: "t", owner: true},
		{sql: "SELECT a FROM t WHERE (user_id = :user_id)", table: "t"},
		{sql: "SELECT a FROM t WHERE user_id = :user_id OR x = 1", table: "t"},
		{sql: "SELECT a FROM t WHERE NOT user_id = :user_id", table: "t"},
		{sql: "SELECT a FROM t WHERE x BETWEEN 1 AND user_id = :user_id", table: "t"},
		{sql: "SELECT a FROM t WHERE CASE WHEN x THEN 1 ELSE 2 END AND user_id = :user_id", table: "t"},
		{sql: "SELECT a FROM t WHERE user_id = :user_id = 0", table: "t"},
		{sql: "SELECT a FROM t, u"},
		{sql: "SELECT a FROM t JOIN u ON 1"},
		{sql: "SELECT a FROM t NATURAL JOIN u"},
		{sql: "SELECT a FROM main.t"},
		{sql: "SELECT a FROM 't'"},
		{sql: "SELECT a FROM (SELECT a FROM t)"},
		{sql: "SELECT (SELECT 1 FROM u), a FROM t"},
		{sql: "SELECT a FROM t UNION SELECT a FROM t"},
		{sql: "WITH x AS (SELECT 1) SELECT a FROM t"},
		{sql: "SELECT 1"},
		{sql: "not sql at all"},
	} {
		got := parsePageQuerySource(tc.sql, gotmplViewerParam)
		if tc.table == "" {
			if got != nil {
				t.Errorf("%s: want no single source, got %+v", tc.sql, got)
			}
			continue
		}
		if got == nil || got.table != tc.table {
			t.Errorf("%s: source %+v, want table %s", tc.sql, got, tc.table)
			continue
		}
		if got.ownerRows != tc.owner {
			t.Errorf("%s: ownerRows=%v", tc.sql, got.ownerRows)
		}
		for _, col := range tc.bare {
			if !got.projects(col) {
				t.Errorf("%s: should project %s", tc.sql, col)
			}
		}
		for _, col := range tc.denied {
			if got.projects(col) {
				t.Errorf("%s: should not trust %s", tc.sql, col)
			}
		}
	}
}

// A signed-in user in no tenant binds :user_group_id as NULL, so a
// tenant-scoped page shows its empty state. The placeholder used to be left
// unbound ("not enough args to execute query: want 1 got 0"); once query
// failures stopped being swallowed that became a render error for every
// tenantless viewer (fleet impact on 2.7.323: three live dev apps' pages).
func TestGotmplIdentityBindWithoutValueIsNull(t *testing.T) {
	app, mux := legacyQueryFixture(t, map[string]string{
		"mine.html": legacyQueryPage("auth: required\n", "SELECT id, company_id FROM projects WHERE company_id = :user_group_id ORDER BY id"),
	})
	member, _ := tenantMember(t, app, "member@example.com", "user", 1, "viewer")
	if rows := legacyQueryRows(t, mux, "/mine", member); len(rows) != 1 || fmt.Sprint(rows[0]["company_id"]) != "1" {
		t.Fatalf("tenant member: %v", rows)
	}
	solo := createCrudScopeSession(t, app, "solo@example.com", "user", "", "")
	w := ssrGet(mux, "/mine", solo)
	if w.Code != http.StatusOK {
		t.Fatalf("tenantless viewer: %d %s", w.Code, w.Body.String())
	}
	if rows := reportFixtureRows(t, w); len(rows) != 0 {
		t.Fatalf("tenantless viewer saw rows: %v", rows)
	}
	// An unknown name is still left for SQLite to refuse, visibly.
	ctx := &RenderContext{}
	if _, ok := resolveBind(ctx, "totally_made_up"); ok {
		t.Fatal("an unknown bind resolved")
	}
	if v, ok := resolveBind(ctx, "user_group_id"); !ok || v != nil {
		t.Fatalf("user_group_id without a user: %v %v", v, ok)
	}
}
