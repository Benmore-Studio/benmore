//go:build !cli

package main

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mustache <query> tags get the read boundary of gotmpl queries: (masking,
// hidden columns, read audit, a failed query is a 5xx), and their cache=
// results are shared only between viewers who would get the same answer.

func queryTagFixture(t *testing.T, pages map[string]string) (*App, *http.ServeMux) {
	t.Helper()
	app, _ := newTenantEncryptionFixture(t)
	ssrLoadPages(t, app, pages)
	clearQueryCacheForTest(t)
	return app, buildAppMux(app, false, "https://report.example.invalid")
}

func clearQueryCacheForTest(t *testing.T) {
	t.Helper()
	reset := func() {
		queryCache.mu.Lock()
		queryCache.entries = map[string]*queryCacheEntry{}
		queryCache.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// queryTagList renders each row of rows as <li>col=value|...</li>.
func queryTagList(attrs string, cols ...string) string {
	var cells []string
	for _, col := range cols {
		cells = append(cells, col+"={{"+col+"}}")
	}
	return `<query ` + attrs + ` as="rows"><ul>{{#rows}}<li>` + strings.Join(cells, "|") + `</li>{{/rows}}</ul>{{^rows}}<p>no rows</p>{{/rows}}</query>`
}

func queryTagBody(t *testing.T, mux *http.ServeMux, route, actor string) string {
	t.Helper()
	w := ssrGet(mux, route, actor)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", route, w.Code, w.Body.String())
	}
	return html.UnescapeString(w.Body.String())
}

func assertQueryTagPlain(t *testing.T, what, body string, plain ...string) {
	t.Helper()
	for _, p := range plain {
		if !strings.Contains(body, "private_note="+p) {
			t.Fatalf("%s: want plaintext %q: %s", what, p, body)
		}
	}
}

// queryTagHasMaskCell reports a rendered cell holding exactly the constant
// mask, so a value-shaped mask ("*******note") does not count.
func queryTagHasMaskCell(body string) bool {
	return strings.Contains(body, "="+encryptedFieldMask+"|") || strings.Contains(body, "="+encryptedFieldMask+"<")
}

func assertQueryTagMasked(t *testing.T, what, body string, plain ...string) {
	t.Helper()
	for _, p := range plain {
		if strings.Contains(body, p) {
			t.Fatalf("%s: %q disclosed: %s", what, p, body)
		}
	}
	if strings.Contains(body, "enc:v") {
		t.Fatalf("%s: ciphertext disclosed: %s", what, body)
	}
	if !queryTagHasMaskCell(body) {
		t.Fatalf("%s: rendered no mask: %s", what, body)
	}
}

// Rows: every session value a page can bind lands in the statement text or
// its arguments, so it is part of the cache key. Two owners of different rows
// never share a cached result. This holds on main as well; it pins the key.
func TestQueryTagCacheNeverSharesRowsAcrossViewers(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"uid.html":    queryTagList(`sql="SELECT name FROM projects WHERE user_id = {{user_id}}" cache="5m"`, "name"),
		"cur.html":    queryTagList(`sql="SELECT name FROM projects WHERE user_id = :current_user" cache="5m"`, "name"),
		"owned.html":  queryTagList(`from="projects" pick="name" owned="true" cache="5m"`, "name"),
		"scoped.html": `<page scope="owner">` + queryTagList(`sql="SELECT name FROM projects" cache="5m"`, "name") + `</page>`,
	})
	alice, aliceID := tenantMember(t, app, "alice@example.com", "user", 1, "viewer")
	bob, bobID := tenantMember(t, app, "bob@example.com", "user", 2, "viewer")
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE projects SET user_id = CASE id WHEN 1 THEN %d ELSE %d END", aliceID, bobID))
	for _, route := range []string{"/uid", "/cur", "/owned", "/scoped"} {
		if body := queryTagBody(t, mux, route, alice); !strings.Contains(body, "name=acme-p") || strings.Contains(body, "globex-p") {
			t.Fatalf("%s as alice: %s", route, body)
		}
		if body := queryTagBody(t, mux, route, bob); !strings.Contains(body, "name=globex-p") || strings.Contains(body, "acme-p") {
			t.Fatalf("%s as bob after alice filled the cache: %s", route, body)
		}
		if body := queryTagBody(t, mux, route, ""); strings.Contains(body, "acme-p") || strings.Contains(body, "globex-p") || !strings.Contains(body, "no rows") {
			t.Fatalf("%s anonymous: %s", route, body)
		}
	}
}

// Masks: the same rows are masked differently per viewer, so a cached result
// is keyed by the viewer's unmask class. A plaintext result filled by an
// entitled viewer must never be served to another.
func TestQueryTagCacheIsKeyedByUnmaskClass(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"notes.html":  queryTagList(`sql="SELECT id, private_note FROM projects ORDER BY id" cache="5m"`, "id", "private_note"),
		"tenant.html": queryTagList(`sql="SELECT id, company_id, private_note FROM projects ORDER BY id" cache="5m"`, "id", "private_note"),
		"own.html":    queryTagList(`sql="SELECT id, user_id, private_note FROM projects ORDER BY id" cache="5m"`, "id", "private_note"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	acmeAdmin, acmeAdminID := tenantMember(t, app, "acme-admin@example.com", "user", 1, "company_admin")
	globexAdmin, globexAdminID := tenantMember(t, app, "globex-admin@example.com", "user", 2, "company_admin")
	root := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")

	// A global admin fills the entry; a viewer with no unmask role reads it.
	assertQueryTagPlain(t, "admin", queryTagBody(t, mux, "/notes", root), "acme-private-note", "globex-private-note")
	assertQueryTagMasked(t, "viewer after admin", queryTagBody(t, mux, "/notes", viewer), "acme-private-note", "globex-private-note")
	// And the other way round: a masked entry is not served to the admin.
	clearQueryCacheForTest(t)
	assertQueryTagMasked(t, "viewer first", queryTagBody(t, mux, "/notes", viewer), "acme-private-note", "globex-private-note")
	assertQueryTagPlain(t, "admin after viewer", queryTagBody(t, mux, "/notes", root), "acme-private-note", "globex-private-note")

	// A tenant role unmasks its own tenant's row only, so each tenant's
	// admin has its own entry.
	body := queryTagBody(t, mux, "/tenant", acmeAdmin)
	assertQueryTagPlain(t, "acme admin", body, "acme-private-note")
	assertQueryTagMasked(t, "acme admin, globex row", body, "globex-private-note")
	body = queryTagBody(t, mux, "/tenant", globexAdmin)
	assertQueryTagPlain(t, "globex admin after acme admin", body, "globex-private-note")
	assertQueryTagMasked(t, "globex admin, acme row", body, "acme-private-note")
	assertQueryTagMasked(t, "viewer after tenant admins", queryTagBody(t, mux, "/tenant", viewer), "acme-private-note", "globex-private-note")

	// An owner unmask carries the owner, so owners never share an entry.
	app.Encrypted.Fields["projects"][0].Roles = []string{"owner"}
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE projects SET user_id = CASE id WHEN 1 THEN %d ELSE %d END", acmeAdminID, globexAdminID))
	body = queryTagBody(t, mux, "/own", acmeAdmin)
	assertQueryTagPlain(t, "owner of row 1", body, "acme-private-note")
	assertQueryTagMasked(t, "owner of row 1, row 2", body, "globex-private-note")
	body = queryTagBody(t, mux, "/own", globexAdmin)
	assertQueryTagPlain(t, "owner of row 2 after owner of row 1", body, "globex-private-note")
	assertQueryTagMasked(t, "owner of row 2, row 1", body, "acme-private-note")
}

// The same masking as gotmpl queries: and /api/_query, on both tag forms.
func TestQueryTagMasksForTheViewer(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"plain.html": queryTagList(`sql="SELECT private_note FROM projects ORDER BY id"`, "private_note"),
		"alias.html": queryTagList(`sql="SELECT p.private_note AS note FROM projects p ORDER BY p.id"`, "note"),
		"join.html":  queryTagList(`sql="SELECT p.name, c.private_note FROM projects p JOIN companies c ON c.id = p.company_id ORDER BY p.id"`, "name", "private_note"),
		"star.html":  queryTagList(`sql="SELECT * FROM projects ORDER BY id"`, "name", "private_note", "private_note_blind"),
		"short.html": queryTagList(`from="projects" pick="name,private_note" sort="id asc"`, "name", "private_note"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	root := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
	for _, route := range []string{"/plain", "/alias", "/join", "/star", "/short"} {
		body := queryTagBody(t, mux, route, viewer)
		for _, plain := range []string{"acme-private-note", "globex-private-note", "enc:v"} {
			if strings.Contains(body, plain) {
				t.Fatalf("%s: viewer read %q: %s", route, plain, body)
			}
		}
		if !queryTagHasMaskCell(body) {
			t.Fatalf("%s: no mask: %s", route, body)
		}
		// The blind index is the last cell of /star: it must render empty.
		if strings.Count(body, "private_note_blind=") != strings.Count(body, "private_note_blind=</li>") {
			t.Fatalf("%s: blind index rendered: %s", route, body)
		}
		if body := queryTagBody(t, mux, route, root); !strings.Contains(body, "acme-private-note") || !strings.Contains(body, "globex-private-note") {
			t.Fatalf("%s: global admin lost plaintext: %s", route, body)
		}
	}
}

// Owner unmask needs rows the statement proves are the viewer's. In a <query>
// tag that proof is a ? bound to the viewer's own id, however the page bound
// it, or scope="owner"; a request-chosen id or a forged column proves nothing.
func TestQueryTagOwnerUnmaskNeedsBoundViewer(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"uid.html":    queryTagList(`sql="SELECT private_note FROM projects WHERE user_id = {{user_id}}"`, "private_note"),
		"cur.html":    queryTagList(`sql="SELECT private_note FROM projects WHERE name IS NOT NULL AND user_id = :current_user"`, "private_note"),
		"owned.html":  queryTagList(`from="projects" pick="private_note" owned="true"`, "private_note"),
		"scoped.html": `<page scope="owner">` + queryTagList(`sql="SELECT private_note FROM projects"`, "private_note") + `</page>`,
		"param.html":  queryTagList(`sql="SELECT private_note FROM projects WHERE user_id = {{param_u}}"`, "private_note"),
		"forged.html": queryTagList(`sql="SELECT {{user_id}} AS user_id, private_note FROM projects ORDER BY id"`, "private_note"),
		"bare.html":   queryTagList(`sql="SELECT private_note FROM projects ORDER BY id"`, "private_note"),
	})
	owner, ownerID := tenantMember(t, app, "owner@example.com", "user", 1, "viewer")
	_, peerID := tenantMember(t, app, "peer@example.com", "user", 2, "viewer")
	app.Encrypted.Fields["projects"][0].Roles = []string{"owner"}
	crudScopeMustExec(t, app.DB, fmt.Sprintf("UPDATE projects SET user_id = CASE id WHEN 1 THEN %d ELSE %d END", ownerID, peerID))
	for _, route := range []string{"/uid", "/cur", "/owned", "/scoped"} {
		body := queryTagBody(t, mux, route, owner)
		assertQueryTagPlain(t, route, body, "acme-private-note")
		if strings.Contains(body, "globex") {
			t.Fatalf("%s: another owner's row: %s", route, body)
		}
	}
	body := queryTagBody(t, mux, fmt.Sprintf("/param?u=%d", peerID), owner)
	assertQueryTagMasked(t, "request-chosen owner id", body, "globex-private-note")
	if body = queryTagBody(t, mux, fmt.Sprintf("/param?u=%d", ownerID), owner); !strings.Contains(body, "private_note=acme-private-note") {
		t.Fatalf("request value equal to the viewer's own id: %s", body)
	}
	for _, route := range []string{"/forged", "/bare"} {
		assertQueryTagMasked(t, route, queryTagBody(t, mux, route, owner), "acme-private-note", "globex-private-note")
	}
}

func TestBoundViewerParamProvesOnlyTheViewersOwnID(t *testing.T) {
	viewer := &Session{UserID: 7}
	for _, tc := range []struct {
		sql     string
		args    []any
		session *Session
		want    bool
	}{
		{"SELECT a FROM t WHERE user_id = ?", []any{int64(7)}, viewer, true},
		{"SELECT a FROM t WHERE user_id = ?", []any{"7"}, viewer, true},
		{"SELECT a FROM t WHERE t.user_id = ? ORDER BY a LIMIT 5", []any{int64(7)}, viewer, true},
		{"SELECT a FROM t WHERE b = '?' AND user_id = ?", []any{int64(7)}, viewer, true},
		{"SELECT a FROM t WHERE x = ? AND user_id = ?", []any{"1", int64(7)}, viewer, true},
		{`SELECT "t"."a" FROM "t" WHERE ("x" = ?` + "\n" + `) AND "t"."user_id" = ? ORDER BY "t"."id" DESC LIMIT 100`, []any{"1", int64(7)}, viewer, true},
		{"SELECT a FROM t WHERE x = ? AND user_id = ?", []any{int64(7), "1"}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ?", []any{"8"}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ?", []any{"07"}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ?", []any{nil}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ?", []any{int64(7)}, nil, false},
		{"SELECT a FROM t WHERE user_id = ?", []any{int64(7), int64(8)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ?1", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ? AND b = :b", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ? AND b = @b", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ? AND b = $b", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ? OR 1", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = ? + 0", []any{int64(7)}, viewer, false},
		{"SELECT a FROM t WHERE user_id = :user_id", nil, viewer, false},
	} {
		source := parsePageQuerySource(tc.sql, boundViewerParam(tc.sql, tc.args, tc.session))
		if got := source != nil && source.ownerRows; got != tc.want {
			t.Errorf("%s %v: ownerRows=%v, want %v", tc.sql, tc.args, got, tc.want)
		}
	}
}

func TestQueryTagStripsHiddenColumns(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"star.html":   queryTagList(`sql="SELECT * FROM companies ORDER BY id"`, "name", "api_key"),
		"cached.html": queryTagList(`sql="SELECT name, api_key FROM companies ORDER BY id" cache="5m"`, "name", "api_key"),
	})
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN api_key TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE companies SET api_key='must-stay-hidden'")
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	for _, route := range []string{"/star", "/cached", "/cached"} {
		body := queryTagBody(t, mux, route, viewer)
		if strings.Contains(body, "must-stay-hidden") || !strings.Contains(body, "name=acme") {
			t.Fatalf("%s: %s", route, body)
		}
	}
}

// Every render reads the data, including one served from the cache, so each
// is read-audited for the viewer; a failed query is not.
func TestQueryTagWritesReadAudit(t *testing.T) {
	app, _ := newTenantEncryptionFixture(t)
	ssrLoadPages(t, app, map[string]string{
		"join.html":   queryTagList(`sql="SELECT p.name, c.name AS company FROM projects p JOIN companies c ON c.id = p.company_id" cache="5m"`, "name"),
		"short.html":  queryTagList(`from="projects" pick="name"`, "name"),
		"other.html":  queryTagList(`sql="SELECT name FROM brokers"`, "name"),
		"broken.html": queryTagList(`sql="SELECT nope FROM projects"`, "nope"),
	})
	clearQueryCacheForTest(t)
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "projects,companies"}}
	InitReadAudit(app, false)
	mux := buildAppMux(app, false, "https://report.example.invalid")
	alice, aliceID := tenantMember(t, app, "alice@example.com", "user", 1, "viewer")
	bob, bobID := tenantMember(t, app, "bob@example.com", "user", 2, "viewer")
	count := func(table string, uid int64) int {
		t.Helper()
		FlushReadAudit(app)
		var n int
		if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE table_name=? AND user_id=? AND query_type='page_query'", table, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	get := func(route, actor string, want int) {
		t.Helper()
		if w := ssrGet(mux, route, actor); w.Code != want {
			t.Fatalf("%s: %d %s", route, w.Code, w.Body.String())
		}
	}
	get("/join", alice, http.StatusOK)
	if p, c := count("projects", aliceID), count("companies", aliceID); p != 1 || c != 1 {
		t.Fatalf("a join audits both tables once: projects=%d companies=%d", p, c)
	}
	get("/join", alice, http.StatusOK)
	get("/join", bob, http.StatusOK)
	if p, c := count("projects", aliceID), count("companies", aliceID); p != 2 || c != 2 {
		t.Fatalf("a cached render was not audited: projects=%d companies=%d", p, c)
	}
	if p := count("projects", bobID); p != 1 {
		t.Fatalf("a render from another viewer's cache entry was not audited for its viewer: %d", p)
	}
	get("/short", alice, http.StatusOK)
	if p := count("projects", aliceID); p != 3 {
		t.Fatalf("from= shorthand: projects=%d", p)
	}
	get("/other", alice, http.StatusOK)
	if b := count("brokers", aliceID); b != 0 {
		t.Fatalf("an unlisted table was audited: %d", b)
	}
	get("/broken", alice, http.StatusInternalServerError)
	if p := count("projects", aliceID); p != 3 {
		t.Fatalf("a failed query logged a read: %d", p)
	}
}

// A failed <query> is a visible error: the page answers 500 with the request
// id, instead of 200 with a notice beside a "no rows" empty state.
func TestQueryTagFailureIsAVisibleError(t *testing.T) {
	const marker = "rest-of-page-marker"
	wrap := func(tag string) string { return "<h1>" + marker + "</h1>" + tag }
	app, mux := queryTagFixture(t, map[string]string{
		"bad.html":      wrap(queryTagList(`sql="SELECT nope FROM projects"`, "nope")),
		"cached.html":   wrap(queryTagList(`sql="SELECT nope FROM projects" cache="5m"`, "nope")),
		"ident.html":    wrap(queryTagList(`sql="SELECT 1 AS [{{param_x}}] FROM projects"`, "x")),
		"table.html":    wrap(queryTagList(`from="no_such_table"`, "x")),
		"compound.html": `<page scope="owner">` + wrap(queryTagList(`sql="SELECT name FROM projects UNION SELECT name FROM brokers"`, "name")) + `</page>`,
		"slow.html":     wrap(queryTagList(`sql="WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) AS n FROM c"`, "n")),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	assertGeneric := func(route string, w *httptest.ResponseRecorder) {
		t.Helper()
		body := w.Body.String()
		if w.Code != http.StatusInternalServerError || strings.Contains(body, marker) || strings.Contains(body, "no rows") {
			t.Fatalf("%s: failed query rendered: %d %s", route, w.Code, body)
		}
		id := w.Header().Get(requestIDHeader)
		if id == "" || !strings.Contains(body, id) {
			t.Fatalf("%s: no request id in the answer: header %q body %s", route, id, body)
		}
		for _, secret := range []string{"nope", "no such", "SELECT", "RECURSIVE", "deadline", "UNION"} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s: production answer disclosed %q: %s", route, secret, body)
			}
		}
	}
	for _, route := range []string{"/bad", "/cached", "/cached", "/ident?x=a", "/table", "/compound"} {
		assertGeneric(route, ssrGet(mux, route, viewer))
	}
	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Authorization", "Bearer "+viewer)
	deadline, cancel := context.WithTimeout(req.Context(), 100*time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req.WithContext(deadline))
	assertGeneric("/slow", rec)

	// Dev mode keeps the detail, escaped: it can quote request values.
	app.DevMode = true
	devMux := buildAppMux(app, true, "http://localhost")
	if w := ssrGet(devMux, "/bad", viewer); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "nope") {
		t.Fatalf("dev answer lost its detail: %d %s", w.Code, w.Body.String())
	}
	if w := ssrGet(devMux, "/table?x=1", viewer); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "no_such_table") {
		t.Fatalf("dev answer for a shorthand error: %d %s", w.Code, w.Body.String())
	}
}

// A request value quoted by a failed shorthand is escaped in the dev answer.
func TestQueryTagDevErrorEscapesRequestValues(t *testing.T) {
	app, _ := queryTagFixture(t, map[string]string{
		"pick.html": queryTagList(`from="projects" pick="{{param_cols}}"`, "name"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	app.DevMode = true
	devMux := buildAppMux(app, true, "http://localhost")
	w := ssrGet(devMux, "/pick?cols=%3Cscript%3Ealert(1)%3C/script%3E", viewer)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "<script>alert(1)") {
		t.Fatalf("dev error page: %d %s", w.Code, w.Body.String())
	}
}

// A cached result is dropped when any table the statement read changes, not
// only the first table after FROM.
func TestQueryTagCacheInvalidatedByEveryTableRead(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"join.html": queryTagList(`sql="SELECT p.name, c.name AS company FROM projects p JOIN companies c ON c.id = p.company_id ORDER BY p.id" cache="5m"`, "company"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	if body := queryTagBody(t, mux, "/join", viewer); !strings.Contains(body, "company=acme") {
		t.Fatalf("first render: %s", body)
	}
	crudScopeMustExec(t, app.DB, "UPDATE companies SET name = 'acme-renamed' WHERE id = 1")
	InvalidateQueryCacheForTable("companies")
	if body := queryTagBody(t, mux, "/join", viewer); !strings.Contains(body, "company=acme-renamed") {
		t.Fatalf("joined table changed, cached result kept: %s", body)
	}
}

// The policy is resolved before the query pins its connection, so a tag
// never needs a second connection while it scans.
func TestQueryTagOnASingleConnectionPool(t *testing.T) {
	app, mux := queryTagFixture(t, map[string]string{
		"notes.html": queryTagList(`sql="SELECT company_id, private_note FROM projects ORDER BY id" cache="5m"`, "private_note"),
		"short.html": queryTagList(`from="projects" pick="private_note" owned="true"`, "private_note"),
	})
	viewer, _ := tenantMember(t, app, "viewer@example.com", "user", 1, "company_admin")
	app.DB.SetMaxOpenConns(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, route := range []string{"/notes", "/notes", "/short"} {
			if w := ssrGet(mux, route, viewer); w.Code != http.StatusOK {
				t.Errorf("%s: %d %s", route, w.Code, w.Body.String())
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("query tag deadlocked on a one-connection pool")
	}
}
