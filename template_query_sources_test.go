//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func reportFixturePage(source, extra string) string {
	return "---\nengine: gotmpl\n" + extra + "sources:\n  rows:\n" + source + "\n---\n<pre id=\"report\">{{ toJson .sources.rows }}</pre>"
}

func reportFixtureRows(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("report status %d: %s", w.Code, w.Body.String())
	}
	_, tail, ok := strings.Cut(w.Body.String(), `<pre id="report">`)
	if !ok {
		t.Fatalf("missing rendered report: %s", w.Body.String())
	}
	encoded, _, ok := strings.Cut(tail, "</pre>")
	if !ok {
		t.Fatal("unterminated report")
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(html.UnescapeString(encoded)), &rows); err != nil {
		t.Fatal(err)
	}
	if rows == nil {
		t.Fatal("report must render an array, including empty results")
	}
	return rows
}

func reportFixtureMatchesQuery(t *testing.T, mux *http.ServeMux, route, actor string, spec any) []map[string]any {
	t.Helper()
	rows := reportFixtureRows(t, ssrGet(mux, route, actor))
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", actor, spec)
	var result struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK {
		t.Fatalf("query status %d: %s (%v)", w.Code, w.Body.String(), err)
	}
	if !reflect.DeepEqual(rows, result.Rows) {
		t.Fatalf("report %#v differs from native query %#v", rows, result.Rows)
	}
	return rows
}

func TestReportSourcesOwnerScopeAndLiteralFilters(t *testing.T) {
	app := ssrTestApp(t)
	owner := createCrudScopeSession(t, app, "report-owner@example.com", "user", "", "")
	peer := createCrudScopeSession(t, app, "report-peer@example.com", "user", "", "")
	ownerID := GetSessionFromDB(app.DB, owner).UserID
	peerID := GetSessionFromDB(app.DB, peer).UserID
	crudScopeMustExec(t, app.DB, "ALTER TABLE notes ADD COLUMN deleted_at TEXT")
	for _, row := range []struct {
		uid     int64
		title   string
		deleted any
	}{
		{ownerID, "owner-visible", nil}, {peerID, "peer-visible", nil}, {ownerID, "owner-deleted", "2026-01-01"},
	} {
		if _, err := app.DB.Exec("INSERT INTO notes(user_id,title,deleted_at) VALUES(?,?,?)", row.uid, row.title, row.deleted); err != nil {
			t.Fatal(err)
		}
	}
	app.Tables[0].Columns, _ = GetTableColumns(app.DB, "notes")
	ssrLoadPages(t, app, map[string]string{
		"report.html":        reportFixturePage("    table: notes\n    select: [title]\n    order_by: [{col: id}]", ""),
		"empty.html":         reportFixturePage("    table: notes\n    where: {title: absent}\n    limit: 1", ""),
		"single.html":        reportFixturePage("    table: notes\n    select: [title]\n    limit: 1", ""),
		"literal.html":       reportFixturePage("    table: notes\n    select: [title]\n    where: {title: ':param_title'}", ""),
		"filtered.html":      reportFixturePage("    table: notes\n    select: [title]\n    where: {title: {in: [owner-visible, peer-visible]}}", ""),
		"mine.html":          reportFixturePage("    table: notes\n    select: [title]", "scope: owner\n"),
		"contradiction.html": reportFixturePage(fmt.Sprintf("    table: notes\n    where: {user_id: %d}", peerID), "scope: owner\n"),
		"total.html":         reportFixturePage("    table: notes\n    aggregates: [{fn: count, as: total}]", "scope: owner\n"),
		"mixed.html":         "---\nengine: gotmpl\nqueries:\n  legacy: SELECT title FROM notes WHERE title='peer-visible' LIMIT 1\nsources:\n  mine: {table: notes, select: [title]}\n---\n<div id=\"mixed\">{{ .legacy.title }}:{{range .sources.mine}}{{.title}}{{end}}</div>",
	})
	mux := buildAppMux(app, false, "https://report.example.invalid")
	for _, actor := range []string{owner, peer} {
		rows := reportFixtureMatchesQuery(t, mux, "/report", actor, map[string]any{"table": "notes", "select": []string{"title"}, "order_by": []map[string]string{{"col": "id"}}})
		if len(rows) != 1 || len(rows[0]) != 1 {
			t.Fatalf("owner scope/internal fields: %#v", rows)
		}
		reportFixtureMatchesQuery(t, mux, "/filtered", actor, map[string]any{"table": "notes", "select": []string{"title"}, "where": map[string]any{"title": map[string]any{"in": []string{"owner-visible", "peer-visible"}}}})
	}
	if got := reportFixtureRows(t, ssrGet(mux, "/single", owner)); len(got) != 1 || got[0]["title"] != "owner-visible" {
		t.Fatalf("limit 1 list: %#v", got)
	}
	for _, route := range []string{"/empty", "/literal?title=owner-visible", "/contradiction"} {
		if rows := reportFixtureRows(t, ssrGet(mux, route, owner)); len(rows) != 0 {
			t.Fatalf("%s: %#v", route, rows)
		}
	}
	if w := ssrGet(mux, "/mixed", owner); w.Code != 200 || !strings.Contains(w.Body.String(), "peer-visible:owner-visible") {
		t.Fatalf("legacy compatibility: %d %s", w.Code, w.Body.String())
	}
	// The page's extra owner constraint also applies to an otherwise broader table.
	app.Access = accessFromYAML(t, "access:\n  notes: {read: everyone}\n")
	if got := reportFixtureRows(t, ssrGet(mux, "/mine", owner)); len(got) != 1 || got[0]["title"] != "owner-visible" {
		t.Fatalf("page owner restriction: %#v", got)
	}
	if got := reportFixtureRows(t, ssrGet(mux, "/total", owner)); len(got) != 1 || got[0]["total"] != float64(1) {
		t.Fatalf("scoped aggregate: %#v", got)
	}
	if got := reportFixtureRows(t, ssrGet(mux, "/contradiction", owner)); len(got) != 0 {
		t.Fatalf("extra owner scope replaced the authored condition: %#v", got)
	}
}

func TestReportSourcesPreserveFailureStatusAndTokenScopes(t *testing.T) {
	app := ssrTestApp(t)
	owner := createCrudScopeSession(t, app, "report-status@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, owner).UserID
	EnsureAPITokensTable(app.DB)
	limited := "bmr_synthetic_report_fixture"
	if _, err := app.DB.Exec("INSERT INTO _benmore_api_tokens(user_id,name,token_hash,scopes) VALUES(?,?,?,?)", uid, "fixture", hashToken(limited), "other:read"); err != nil {
		t.Fatal(err)
	}
	ssrLoadPages(t, app, map[string]string{
		"report.html":  reportFixturePage("    table: notes", ""),
		"mine.html":    reportFixturePage("    table: notes", "scope: owner\n"),
		"invalid.html": reportFixturePage("    table: notes\n    select: [missing]", ""),
		"unknown.html": reportFixturePage("    table: missing", ""),
	})
	mux := buildAppMux(app, false, "https://report.example.invalid")
	// A scoped token is nobody on a page (page_scoped_credentials.go): the
	// source answers it as it answers a caller with no credential, and its
	// scopes are never what a page's source is read with.
	for _, tc := range []struct {
		route, actor string
		code         int
	}{{"/report", "", 401}, {"/report", limited, 401}, {"/invalid", owner, 400}, {"/unknown", owner, 404}} {
		w := ssrGet(mux, tc.route, tc.actor)
		if w.Code != tc.code || strings.Contains(w.Body.String(), `<pre id="report">`) {
			t.Fatalf("%s: status %d want %d: %s", tc.route, w.Code, tc.code, w.Body.String())
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store, must-revalidate" {
			t.Fatalf("%s failure can be cached: %q", tc.route, got)
		}
	}
	app.Access = accessFromYAML(t, "access:\n  notes: {read: off}\n")
	if w := ssrGet(mux, "/report", owner); w.Code != 404 {
		t.Fatalf("disabled table status %d: %s", w.Code, w.Body.String())
	}
	app.Access = accessFromYAML(t, "access:\n  notes: {read: anon}\n")
	if w := ssrGet(mux, "/mine", ""); w.Code != 401 {
		t.Fatalf("owner page without identity status %d: %s", w.Code, w.Body.String())
	}
	crudScopeMustExec(t, app.DB, "DROP TABLE notes")
	if w := ssrGet(mux, "/report", owner); w.Code != 500 || strings.Contains(w.Body.String(), "no such table") || !strings.Contains(w.Body.String(), "query failed") || w.Header().Get("Cache-Control") != "no-store, must-revalidate" {
		t.Fatalf("sanitized native query error status %d: %s", w.Code, w.Body.String())
	}
}

func TestReportSourcesMixedFailureNeverRendersPartialResults(t *testing.T) {
	app := ssrTestApp(t)
	owner := createCrudScopeSession(t, app, "report-mixed@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, owner).UserID
	if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES(?,?)", uid, "authorized-result-must-not-escape"); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, "CREATE TABLE restricted (id INTEGER PRIMARY KEY, title TEXT)")
	columns, err := GetTableColumns(app.DB, "restricted")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "restricted", Columns: columns})
	app.Access = accessFromYAML(t, "access:\n  notes: {read: self}\n  restricted: {read: off}\n")
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "notes"}}
	ssrLoadPages(t, app, map[string]string{"mixed.html": `---
engine: gotmpl
sources:
  a_allowed: {table: notes, select: [title]}
  z_denied: {table: restricted}
---
<h1>partial-render-marker</h1>{{range .sources.a_allowed}}<p>{{.title}}</p>{{end}}`})
	mux := buildAppMux(app, false, "https://report.example.invalid")
	w := ssrGet(mux, "/mixed", owner)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "partial-render-marker") || strings.Contains(w.Body.String(), "authorized-result-must-not-escape") {
		t.Fatalf("mixed source failure rendered partial results: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store, must-revalidate" {
		t.Fatal("mixed-source denial is cacheable")
	}
	FlushReadAudit(app)
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE table_name='notes' AND user_id=? AND query_type='query'", uid).Scan(&count); err != nil || count != 1 {
		t.Fatalf("fixture did not execute the authorized source before denial: count=%d error=%v", count, err)
	}
}

func TestReportSourcesTenantEncryptionHiddenFieldsAndAudit(t *testing.T) {
	app := newTenantEncryptionApp(t)
	reviewer, reviewerID := tenantMember(t, app, "report-reviewer@example.com", "user", 1, "company_admin")
	viewer, _ := tenantMember(t, app, "report-viewer@example.com", "user", 1, "viewer")
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN api_key TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE companies SET api_key='must-stay-hidden'")
	app.Tables[0].Columns, _ = GetTableColumns(app.DB, "companies")
	var knownCipher string
	if err := app.DB.QueryRow("SELECT private_note FROM companies WHERE id=2").Scan(&knownCipher); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(knownCipher, "enc:") {
		t.Fatal("fixture must contain stored ciphertext")
	}
	// Deliberate possession prerequisite: ordinary source columns keep this literal.
	if _, err := app.DB.Exec("UPDATE companies SET name=? WHERE id=1", knownCipher); err != nil {
		t.Fatal(err)
	}
	ssrLoadPages(t, app, map[string]string{
		"projection.html": reportFixturePage("    table: companies\n    select: [private_note]\n    order_by: [{col: id}]", ""),
		"all.html":        reportFixturePage("    table: companies\n    order_by: [{col: id}]", ""),
		"count.html":      reportFixturePage("    table: companies\n    aggregates: [{fn: count, col: private_note, as: private_note}]", ""),
		"hidden.html":     reportFixturePage("    table: companies\n    select: [private_note_blind]", ""),
		"sort.html":       reportFixturePage("    table: companies\n    order_by: [{col: private_note}]", ""),
		"sum.html":        reportFixturePage("    table: companies\n    aggregates: [{fn: sum, col: private_note}]", ""),
	})
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "companies"}}
	mux := buildAppMux(app, false, "https://report.example.invalid")
	for _, actor := range []string{reviewer, viewer} {
		rows := reportFixtureMatchesQuery(t, mux, "/projection", actor, map[string]any{"table": "companies", "select": []string{"private_note"}, "order_by": []map[string]string{{"col": "id"}}})
		if len(rows) != 2 || len(rows[0]) != 1 || rows[1]["private_note"] == "globex-private-note" {
			t.Fatalf("tenant projection: %#v", rows)
		}
		if (rows[0]["private_note"] == "acme-private-note") != (actor == reviewer) {
			t.Fatalf("role mask: %#v", rows)
		}
	}
	rows := reportFixtureRows(t, ssrGet(mux, "/all", reviewer))
	if rows[0]["name"] != knownCipher {
		t.Fatal("ordinary column interpreted as ciphertext")
	}
	for _, row := range rows {
		if _, ok := row["private_note_blind"]; ok {
			t.Fatal("blind index disclosed")
		}
		if _, ok := row["api_key"]; ok {
			t.Fatal("credential column disclosed")
		}
	}
	if rows := reportFixtureRows(t, ssrGet(mux, "/count", reviewer)); len(rows) != 1 || rows[0]["private_note"] != float64(1) {
		t.Fatalf("source-authorized aggregate alias: %#v", rows)
	}
	FlushReadAudit(app)
	var before int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE user_id=? AND table_name='companies' AND query_type='query'", reviewerID).Scan(&before); err != nil || before != 4 {
		t.Fatalf("read audit count %d: %v", before, err)
	}
	for _, tc := range []struct{ route, actor string }{{"/count", viewer}, {"/hidden", reviewer}, {"/sort", reviewer}, {"/sum", reviewer}} {
		w := ssrGet(mux, tc.route, tc.actor)
		if w.Code != 400 {
			t.Fatalf("%s status %d: %s", tc.route, w.Code, w.Body.String())
		}
	}
	FlushReadAudit(app)
	var after int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE user_id=?", reviewerID).Scan(&after); err != nil || after != before {
		t.Fatalf("denied reports logged successful reads: %d -> %d (%v)", before, after, err)
	}
}

func TestReportSourcesTenantRowsAndActAs(t *testing.T) {
	app := newTenantEncryptionApp(t)
	app.Access = accessFromYAML(t, "access:\n  projects: {read: group}\n")
	member, _ := tenantMember(t, app, "report-group@example.com", "user", 1, "company_admin")
	stepped := createCrudScopeSession(t, app, "report-stepped@example.com", "admin", "2", "1")
	admin := createCrudScopeSession(t, app, "report-admin@example.com", "admin", "2", "")
	ssrLoadPages(t, app, map[string]string{"group.html": reportFixturePage("    table: projects\n    select: [name, private_note]\n    order_by: [{col: id}]", "")})
	mux := buildAppMux(app, false, "https://report.example.invalid")
	for _, actor := range []string{member, stepped, admin} {
		rows := reportFixtureMatchesQuery(t, mux, "/group", actor, map[string]any{"table": "projects", "select": []string{"name", "private_note"}, "order_by": []map[string]string{{"col": "id"}}})
		want := 1
		if actor == admin {
			want = 2
		}
		if len(rows) != want || rows[0]["name"] != "acme-p" || rows[0]["private_note"] != "acme-private-note" {
			t.Fatalf("group/act-as: %#v", rows)
		}
		for _, row := range rows {
			if len(row) != 2 {
				t.Fatalf("internal owner/tenant projected: %#v", row)
			}
		}
	}
}

func TestReportSourcesOwnerEncryptedProjection(t *testing.T) {
	app := newTenantEncryptionApp(t)
	owner, ownerID := tenantMember(t, app, "encrypted-owner@example.com", "user", 1, "viewer")
	peer, peerID := tenantMember(t, app, "encrypted-peer@example.com", "user", 2, "viewer")
	app.Encrypted.Fields["projects"][0].Roles = []string{"owner"}
	for _, row := range []struct{ id, uid int64 }{{1, ownerID}, {2, peerID}} {
		if _, err := app.DB.Exec("UPDATE projects SET user_id=? WHERE id=?", row.uid, row.id); err != nil {
			t.Fatal(err)
		}
	}
	ssrLoadPages(t, app, map[string]string{
		"owned.html": reportFixturePage("    table: projects\n    select: [private_note]\n    order_by: [{col: id}]", ""),
	})
	mux := buildAppMux(app, false, "https://report.example.invalid")
	for _, tc := range []struct {
		actor  string
		own    int
		secret string
	}{{owner, 0, "acme-private-note"}, {peer, 1, "globex-private-note"}} {
		rows := reportFixtureMatchesQuery(t, mux, "/owned", tc.actor, map[string]any{"table": "projects", "select": []string{"private_note"}, "order_by": []map[string]string{{"col": "id"}}})
		if len(rows) != 2 || rows[tc.own]["private_note"] != tc.secret || !strings.Contains(fmt.Sprint(rows[1-tc.own]["private_note"]), "****") {
			t.Fatalf("owner-only encrypted projection: %#v", rows)
		}
		for _, row := range rows {
			if len(row) != 1 {
				t.Fatalf("internal owner/tenant escaped projection: %#v", row)
			}
		}
	}
}

func TestReportSourcesValidateOnlyNewContract(t *testing.T) {
	for name, source := range map[string]string{
		"sql": "    table: notes\n    sql: SELECT 1", "typo": "    table: notes\n    selct: [title]", "order typo": "    table: notes\n    order_by: [{column: title}]", "missing table": "    select: [title]", "scalar": "    SELECT 1", "join": "    table: notes\n    joins: [users]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ExtractFrontmatter(reportFixturePage(source, "")); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	for _, raw := range []string{
		"---\nengine: raw\nsources: {rows: {table: notes}}\n---\nbody",
		"---\nengine: gotmpl\nsources: {bad-name: {table: notes}}\n---\nbody",
		"---\nengine: gotmpl\nqueries: {sources: SELECT 1}\nsources: {rows: {table: notes}}\n---\nbody",
		"---\nengine: gotmpl\nsources: {rows: null}\n---\nbody",
	} {
		if _, _, err := ExtractFrontmatter(raw); err == nil {
			t.Errorf("invalid contract accepted: %s", raw)
		}
	}
	if _, _, err := ExtractFrontmatter("---\nengine: gotmpl\nqueries: {sources: SELECT 1}\n---\nlegacy"); err != nil {
		t.Fatalf("legacy name without typed sources must remain accepted: %v", err)
	}
	valid := reportFixturePage("    table: notes\n    where: {title: {in: [first, second]}}\n    order_by: [{col: title, dir: desc}]", "")
	if err := validateGotmplParseIn("", "report.html", valid); err != "" {
		t.Fatalf("valid report failed write/check validation: %s", err)
	}
	if err := ValidateOnWrite("report.html", valid); err != "" {
		t.Fatalf("valid report failed public write validator: %s", err)
	}
	if err := ValidateOnWriteIn(t.TempDir(), "report.html", valid); err != "" {
		t.Fatalf("valid report failed app-aware write validator: %s", err)
	}
	invalid := reportFixturePage("    table: notes\n    joins: [users]", "")
	if err := ValidateOnWrite("report.html", invalid); err == "" {
		t.Fatal("public write validator accepted unsupported report source")
	}
	if err := ValidateOnWriteIn(t.TempDir(), "report.html", invalid); err == "" {
		t.Fatal("app-aware write validator accepted unsupported report source")
	}
	if err := validateGotmplParseIn("", "report.html", reportFixturePage("    table: notes\n    joins: [users]", "")); err == "" {
		t.Fatal("authoring validation accepted unsupported report source")
	}
}
